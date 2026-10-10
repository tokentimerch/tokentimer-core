"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  writeKeygenIntent,
  readEnrollmentJournal,
  writeCsrArtifact,
  writeIssuedCertificateArtifacts,
  writeEnrollmentJournal,
  listProtectedEnrollmentContainers,
  looksLikeEnrollmentContainerName,
  enrollmentIdFromContainerName,
  isEnrollmentContainerProtected,
  journalV2Path,
  legacyJournalPath,
  keygenIntentPath,
  csrArtifactPath,
  sha256HexOfString,
} = require("./adcs-enrollment-journal");

const ENROLLMENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const CONTAINER = `tokentimer-enr-${ENROLLMENT_ID}`;
const CSR_PEM = "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n";
const CSR_PEM_NO_NL = "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----";
const LEAF_PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
const TEMPLATE_OID = "1.3.6.1.4.1.311.21.8.1";

async function commitPrepared(stateDir) {
  const { csrSha256 } = await writeCsrArtifact({
    stateDir,
    enrollmentId: ENROLLMENT_ID,
    csrPem: CSR_PEM,
  });
  await writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
    state: "prepared",
    attempt: 1,
    containerName: CONTAINER,
    snapshotSha256: "b".repeat(64),
    csrSha256,
    csrSpkiSha256: "c".repeat(64),
    templateOid: TEMPLATE_OID,
    jobId: "job:1",
  });
  return { csrSha256 };
}

async function commitSubmitting(stateDir, csrSha256) {
  await writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
    state: "submitting",
    attempt: 1,
    containerName: CONTAINER,
    snapshotSha256: "b".repeat(64),
    csrSha256,
    csrSpkiSha256: "c".repeat(64),
    templateOid: TEMPLATE_OID,
    jobId: "job:1",
  });
}

describe("adcs-enrollment-journal", () => {
  let stateDir;

  beforeEach(() => {
    stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "adcs-journal-"));
  });

  afterEach(() => {
    fs.rmSync(stateDir, { recursive: true, force: true });
  });

  it("writes keygen intent and protects the container before prepared", async () => {
    await writeKeygenIntent({
      stateDir,
      enrollmentId: ENROLLMENT_ID,
      containerName: CONTAINER,
      attempt: 1,
      snapshotSha256: "a".repeat(64),
      jobId: "job:1",
    });
    assert.ok(fs.existsSync(keygenIntentPath(stateDir, ENROLLMENT_ID)));

    const read = readEnrollmentJournal(stateDir, ENROLLMENT_ID);
    assert.equal(read.kind, "valid");
    assert.equal(read.journal.state, "keygen_intent");
    assert.equal(read.journal.containerName, CONTAINER);

    const protectedSet = listProtectedEnrollmentContainers(stateDir);
    assert.equal(protectedSet.ok, true);
    assert.ok(protectedSet.containers.has(CONTAINER));
  });

  it("requires csr.pem for prepared and verifies hash on read", async () => {
    const { csrSha256 } = await commitPrepared(stateDir);

    const ok = readEnrollmentJournal(stateDir, ENROLLMENT_ID);
    assert.equal(ok.kind, "valid");
    assert.equal(ok.journal.state, "prepared");
    assert.equal(ok.artifacts.csrPem.includes("BEGIN CERTIFICATE REQUEST"), true);
    assert.equal(ok.journal.csrSha256, csrSha256);

    fs.writeFileSync(csrArtifactPath(stateDir, ENROLLMENT_ID), "tampered\n");
    const corrupt = readEnrollmentJournal(stateDir, ENROLLMENT_ID);
    assert.equal(corrupt.kind, "corrupt");
    assert.match(corrupt.error, /csr\.pem hash/);
  });

  it("hashes the exact CSR bytes persisted (including normalized newline)", async () => {
    const { csrSha256 } = await writeCsrArtifact({
      stateDir,
      enrollmentId: ENROLLMENT_ID,
      csrPem: CSR_PEM_NO_NL,
    });
    const onDisk = fs.readFileSync(csrArtifactPath(stateDir, ENROLLMENT_ID), "utf8");
    assert.equal(onDisk.endsWith("\n"), true);
    assert.equal(csrSha256, sha256HexOfString(onDisk));
    assert.notEqual(csrSha256, sha256HexOfString(CSR_PEM_NO_NL));
  });

  it("rejects prepared journals missing csrSha256", async () => {
    await writeCsrArtifact({
      stateDir,
      enrollmentId: ENROLLMENT_ID,
      csrPem: CSR_PEM,
    });
    await assert.rejects(
      () =>
        writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
          state: "prepared",
          attempt: 1,
          containerName: CONTAINER,
          snapshotSha256: "b".repeat(64),
          csrSpkiSha256: "c".repeat(64),
          templateOid: TEMPLATE_OID,
          jobId: "job:1",
        }),
      /missing required field csrSha256/,
    );
  });

  it("rejects invalid journal transitions and immutable identity changes", async () => {
    const { csrSha256 } = await commitPrepared(stateDir);
    await assert.rejects(
      () =>
        writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
          state: "issued",
          attempt: 1,
          containerName: CONTAINER,
          snapshotSha256: "b".repeat(64),
          csrSha256,
          csrSpkiSha256: "c".repeat(64),
          templateOid: TEMPLATE_OID,
          leafSha256: "d".repeat(64),
          jobId: "job:1",
        }),
      /invalid journal transition prepared -> issued/,
    );

    await assert.rejects(
      () =>
        writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
          state: "submitting",
          attempt: 1,
          containerName: `tokentimer-enr-ffffffff-ffff-ffff-ffff-ffffffffffff`,
          snapshotSha256: "b".repeat(64),
          csrSha256,
          csrSpkiSha256: "c".repeat(64),
          templateOid: TEMPLATE_OID,
          jobId: "job:1",
        }),
      /containerName is immutable/,
    );
  });

  it("persists issued leaf before validation_deferred can be journaled", async () => {
    const { csrSha256 } = await commitPrepared(stateDir);
    await commitSubmitting(stateDir, csrSha256);
    const { leafSha256 } = await writeIssuedCertificateArtifacts({
      stateDir,
      enrollmentId: ENROLLMENT_ID,
      leafPem: LEAF_PEM,
    });
    await writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
      state: "issued",
      attempt: 1,
      containerName: CONTAINER,
      snapshotSha256: "b".repeat(64),
      csrSha256,
      csrSpkiSha256: "c".repeat(64),
      templateOid: TEMPLATE_OID,
      leafSha256,
      jobId: "job:1",
    });
    await writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
      state: "validation_deferred",
      attempt: 1,
      containerName: CONTAINER,
      snapshotSha256: "b".repeat(64),
      csrSha256,
      csrSpkiSha256: "c".repeat(64),
      templateOid: TEMPLATE_OID,
      leafSha256,
      validationDeadlineAt: "2099-01-01T00:00:00.000Z",
      jobId: "job:1",
    });
    const read = readEnrollmentJournal(stateDir, ENROLLMENT_ID);
    assert.equal(read.kind, "valid");
    assert.equal(read.journal.state, "validation_deferred");
    assert.ok(read.artifacts.leafPem.includes("BEGIN CERTIFICATE"));
  });

  it("fails closed when legacy and v2 journals disagree", async () => {
    const { csrSha256 } = await commitPrepared(stateDir);
    await commitSubmitting(stateDir, csrSha256);
    await writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
      state: "pending",
      attempt: 1,
      requestId: 10,
      containerName: CONTAINER,
      snapshotSha256: "b".repeat(64),
      csrSha256,
      csrSpkiSha256: "c".repeat(64),
      templateOid: TEMPLATE_OID,
      jobId: "job:1",
    });
    fs.mkdirSync(path.dirname(legacyJournalPath(stateDir, ENROLLMENT_ID)), { recursive: true });
    fs.writeFileSync(
      legacyJournalPath(stateDir, ENROLLMENT_ID),
      `${JSON.stringify({
        enrollmentId: ENROLLMENT_ID,
        attempt: 1,
        requestId: 99,
        snapshotSha256: "b".repeat(64),
        csrSpkiSha256: "c".repeat(64),
        templateOid: TEMPLATE_OID,
      })}\n`,
    );
    const read = readEnrollmentJournal(stateDir, ENROLLMENT_ID);
    assert.equal(read.kind, "corrupt");
    assert.match(read.error, /disagree/);
  });

  it("fails closed on legacy journal missing decision-6 bindings", () => {
    fs.mkdirSync(path.dirname(legacyJournalPath(stateDir, ENROLLMENT_ID)), { recursive: true });
    fs.writeFileSync(
      legacyJournalPath(stateDir, ENROLLMENT_ID),
      `${JSON.stringify({
        enrollmentId: ENROLLMENT_ID,
        attempt: 1,
        requestId: 7,
        snapshotSha256: "1".repeat(64),
      })}\n`,
    );
    const read = readEnrollmentJournal(stateDir, ENROLLMENT_ID);
    assert.equal(read.kind, "corrupt");
    assert.match(read.error, /csrSpkiSha256/);
  });

  it("fails closed when enrollments root is unreadable or inconsistent", () => {
    const empty = listProtectedEnrollmentContainers(stateDir);
    assert.equal(empty.ok, true);
    assert.equal(empty.containers.size, 0);

    const missing = listProtectedEnrollmentContainers("");
    assert.equal(missing.ok, false);

    fs.mkdirSync(path.join(stateDir, "adcs-enrollments"), { recursive: true });
    fs.writeFileSync(path.join(stateDir, "adcs-enrollments", "not-a-uuid"), "x");
    const bad = listProtectedEnrollmentContainers(stateDir);
    assert.equal(bad.ok, false);
    assert.match(bad.error, /unexpected entry/);
  });

  it("detects enrollment-shaped container names and extracts enrollment ids", () => {
    assert.equal(looksLikeEnrollmentContainerName(CONTAINER), true);
    assert.equal(looksLikeEnrollmentContainerName("tokentimer-abc"), false);
    assert.equal(enrollmentIdFromContainerName(CONTAINER), ENROLLMENT_ID);
    assert.equal(enrollmentIdFromContainerName("tokentimer-abc"), null);
  });

  it("rechecks enrollment protection for orphan-sweep callers", async () => {
    await writeKeygenIntent({
      stateDir,
      enrollmentId: ENROLLMENT_ID,
      containerName: CONTAINER,
      attempt: 1,
      snapshotSha256: "a".repeat(64),
      jobId: "job:1",
    });
    const protectedNow = isEnrollmentContainerProtected(stateDir, ENROLLMENT_ID, CONTAINER);
    assert.equal(protectedNow.protected, true);

    const unprotected = isEnrollmentContainerProtected(
      stateDir,
      ENROLLMENT_ID,
      "tokentimer-enr-ffffffff-ffff-ffff-ffff-ffffffffffff",
    );
    assert.equal(unprotected.protected, false);
  });

  it("exposes journal.json under the enrollment directory", async () => {
    await commitPrepared(stateDir);
    assert.ok(fs.existsSync(journalV2Path(stateDir, ENROLLMENT_ID)));
  });
});

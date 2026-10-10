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
  journalV2Path,
  legacyJournalPath,
  keygenIntentPath,
  csrArtifactPath,
} = require("./adcs-enrollment-journal");

const ENROLLMENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const CONTAINER = `tokentimer-enr-${ENROLLMENT_ID}`;
const CSR_PEM = "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n";
const LEAF_PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

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
      templateOid: "1.3.6.1.4.1.311.21.8.1",
      jobId: "job:1",
    });

    const ok = readEnrollmentJournal(stateDir, ENROLLMENT_ID);
    assert.equal(ok.kind, "valid");
    assert.equal(ok.journal.state, "prepared");
    assert.equal(ok.artifacts.csrPem.includes("BEGIN CERTIFICATE REQUEST"), true);

    fs.writeFileSync(csrArtifactPath(stateDir, ENROLLMENT_ID), "tampered\n");
    const corrupt = readEnrollmentJournal(stateDir, ENROLLMENT_ID);
    assert.equal(corrupt.kind, "corrupt");
    assert.match(corrupt.error, /csr\.pem hash/);
  });

  it("persists issued leaf before validation_deferred can be journaled", async () => {
    const { leafSha256 } = await writeIssuedCertificateArtifacts({
      stateDir,
      enrollmentId: ENROLLMENT_ID,
      leafPem: LEAF_PEM,
    });
    await writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
      state: "validation_deferred",
      attempt: 1,
      containerName: CONTAINER,
      snapshotSha256: "d".repeat(64),
      csrSpkiSha256: "e".repeat(64),
      templateOid: "1.3.6.1.4.1.311.21.8.1",
      leafSha256,
      validationDeadlineAt: "2099-01-01T00:00:00.000Z",
    });
    const read = readEnrollmentJournal(stateDir, ENROLLMENT_ID);
    assert.equal(read.kind, "valid");
    assert.equal(read.journal.state, "validation_deferred");
    assert.ok(read.artifacts.leafPem.includes("BEGIN CERTIFICATE"));
  });

  it("fails closed when legacy and v2 journals disagree", async () => {
    await writeCsrArtifact({ stateDir, enrollmentId: ENROLLMENT_ID, csrPem: CSR_PEM });
    await writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
      state: "pending",
      attempt: 1,
      requestId: 10,
      containerName: CONTAINER,
      snapshotSha256: "f".repeat(64),
      csrSpkiSha256: "a".repeat(64),
      templateOid: "1.3.6.1.4.1.311.21.8.1",
    });
    fs.mkdirSync(path.dirname(legacyJournalPath(stateDir, ENROLLMENT_ID)), { recursive: true });
    fs.writeFileSync(
      legacyJournalPath(stateDir, ENROLLMENT_ID),
      `${JSON.stringify({
        enrollmentId: ENROLLMENT_ID,
        attempt: 1,
        requestId: 99,
        snapshotSha256: "f".repeat(64),
        csrSpkiSha256: "a".repeat(64),
        templateOid: "1.3.6.1.4.1.311.21.8.1",
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

  it("detects enrollment-shaped container names", () => {
    assert.equal(looksLikeEnrollmentContainerName(CONTAINER), true);
    assert.equal(looksLikeEnrollmentContainerName("tokentimer-abc"), false);
  });

  it("exposes journal.json under the enrollment directory", async () => {
    const { csrSha256 } = await writeCsrArtifact({
      stateDir,
      enrollmentId: ENROLLMENT_ID,
      csrPem: CSR_PEM,
    });
    await writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
      state: "prepared",
      attempt: 1,
      containerName: CONTAINER,
      csrSha256,
      csrSpkiSha256: "9".repeat(64),
      templateOid: "1.2.3",
      snapshotSha256: "8".repeat(64),
    });
    assert.ok(fs.existsSync(journalV2Path(stateDir, ENROLLMENT_ID)));
  });
});

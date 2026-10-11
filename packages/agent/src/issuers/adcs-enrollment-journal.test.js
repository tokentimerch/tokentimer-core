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
  clearProvisionalLeafArtifacts,
  writeEnrollmentJournal,
  listProtectedEnrollmentContainers,
  looksLikeEnrollmentContainerName,
  enrollmentIdFromContainerName,
  isEnrollmentContainerProtected,
  journalV2Path,
  legacyJournalPath,
  keygenIntentPath,
  csrArtifactPath,
  leafArtifactPath,
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

  it("rejects RequestId, leafSha256, and validationDeadlineAt mutations", async () => {
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
    await assert.rejects(
      () =>
        writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
          state: "pending",
          attempt: 1,
          requestId: 99,
          containerName: CONTAINER,
          snapshotSha256: "b".repeat(64),
          csrSha256,
          csrSpkiSha256: "c".repeat(64),
          templateOid: TEMPLATE_OID,
          jobId: "job:1",
        }),
      /requestId is immutable/,
    );

    const { leafSha256 } = await writeIssuedCertificateArtifacts({
      stateDir,
      enrollmentId: ENROLLMENT_ID,
      leafPem: LEAF_PEM,
    });
    await writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
      state: "issued",
      attempt: 1,
      requestId: 10,
      containerName: CONTAINER,
      snapshotSha256: "b".repeat(64),
      csrSha256,
      csrSpkiSha256: "c".repeat(64),
      templateOid: TEMPLATE_OID,
      leafSha256,
      jobId: "job:1",
    });
    await assert.rejects(
      () =>
        writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
          state: "issued",
          attempt: 1,
          requestId: 10,
          containerName: CONTAINER,
          snapshotSha256: "b".repeat(64),
          csrSha256,
          csrSpkiSha256: "c".repeat(64),
          templateOid: TEMPLATE_OID,
          leafSha256: "f".repeat(64),
          jobId: "job:1",
        }),
      /leafSha256 is immutable/,
    );

    await writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
      state: "validation_deferred",
      attempt: 1,
      requestId: 10,
      containerName: CONTAINER,
      snapshotSha256: "b".repeat(64),
      csrSha256,
      csrSpkiSha256: "c".repeat(64),
      templateOid: TEMPLATE_OID,
      leafSha256,
      validationDeadlineAt: "2099-01-01T00:00:00.000Z",
      jobId: "job:1",
    });
    await assert.rejects(
      () =>
        writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
          state: "validation_deferred",
          attempt: 1,
          requestId: 10,
          containerName: CONTAINER,
          snapshotSha256: "b".repeat(64),
          csrSha256,
          csrSpkiSha256: "c".repeat(64),
          templateOid: TEMPLATE_OID,
          leafSha256,
          validationDeadlineAt: "2099-06-01T00:00:00.000Z",
          jobId: "job:1",
        }),
      /validationDeadlineAt is immutable/,
    );
  });

  it("preserves RequestId, leafSha256, and validationDeadlineAt when later writes omit them", async () => {
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
    const { leafSha256 } = await writeIssuedCertificateArtifacts({
      stateDir,
      enrollmentId: ENROLLMENT_ID,
      leafPem: LEAF_PEM,
    });
    // issued may omit requestId; the pending RequestId must survive.
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
    let read = readEnrollmentJournal(stateDir, ENROLLMENT_ID);
    assert.equal(read.kind, "valid");
    assert.equal(read.journal.requestId, 10);
    assert.equal(read.journal.leafSha256, leafSha256);

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
    // installing omits requestId, leafSha256, and validationDeadlineAt.
    await writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
      state: "installing",
      attempt: 1,
      containerName: CONTAINER,
      snapshotSha256: "b".repeat(64),
      csrSha256,
      csrSpkiSha256: "c".repeat(64),
      templateOid: TEMPLATE_OID,
      installStep: "accept",
      jobId: "job:1",
    });
    read = readEnrollmentJournal(stateDir, ENROLLMENT_ID);
    assert.equal(read.kind, "valid");
    assert.equal(read.journal.requestId, 10);
    assert.equal(read.journal.leafSha256, leafSha256);
    assert.equal(read.journal.validationDeadlineAt, "2099-01-01T00:00:00.000Z");
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

  it("treats an enrollment directory without a readable receipt as protected", () => {
    const emptyId = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";
    const emptyContainer = `tokentimer-enr-${emptyId}`;
    fs.mkdirSync(path.join(stateDir, "adcs-enrollments", emptyId), { recursive: true });
    const protectedEmpty = isEnrollmentContainerProtected(stateDir, emptyId, emptyContainer);
    assert.equal(protectedEmpty.protected, true);
    assert.match(protectedEmpty.reason, /without readable journal/);

    const missing = isEnrollmentContainerProtected(
      stateDir,
      "cccccccc-dddd-eeee-ffff-000000000000",
      "tokentimer-enr-cccccccc-dddd-eeee-ffff-000000000000",
    );
    assert.equal(missing.protected, false);
  });

  it("exposes journal.json under the enrollment directory", async () => {
    await commitPrepared(stateDir);
    assert.ok(fs.existsSync(journalV2Path(stateDir, ENROLLMENT_ID)));
  });

  it("reloads a deferred tier-2 candidate leaf after restart without CA retrieve", async () => {
    const { csrSha256 } = await commitPrepared(stateDir);
    await commitSubmitting(stateDir, csrSha256);
    await writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
      state: "submission_uncertain",
      attempt: 1,
      containerName: CONTAINER,
      snapshotSha256: "b".repeat(64),
      csrSha256,
      csrSpkiSha256: "c".repeat(64),
      templateOid: TEMPLATE_OID,
      jobId: "job:1",
      reconcileSearchFrom: 105,
    });
    const { leafSha256 } = await writeIssuedCertificateArtifacts({
      stateDir,
      enrollmentId: ENROLLMENT_ID,
      leafPem: LEAF_PEM,
    });
    await writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
      state: "submission_uncertain",
      attempt: 1,
      containerName: CONTAINER,
      snapshotSha256: "b".repeat(64),
      csrSha256,
      csrSpkiSha256: "c".repeat(64),
      templateOid: TEMPLATE_OID,
      jobId: "job:1",
      reconcileSearchFrom: 105,
      reconcileCandidateRequestId: 105,
      leafSha256,
      validationDeadlineAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    });

    const reloaded = readEnrollmentJournal(stateDir, ENROLLMENT_ID);
    assert.equal(reloaded.kind, "valid");
    assert.equal(reloaded.journal.state, "submission_uncertain");
    assert.equal(reloaded.journal.reconcileCandidateRequestId, 105);
    assert.equal(reloaded.artifacts.leafPem, LEAF_PEM);
    assert.equal(sha256HexOfString(reloaded.artifacts.leafPem), leafSha256);
  });

  it("fails closed when a deferred candidate is missing its leaf artifact", async () => {
    const { csrSha256 } = await commitPrepared(stateDir);
    await commitSubmitting(stateDir, csrSha256);
    await writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
      state: "submission_uncertain",
      attempt: 1,
      containerName: CONTAINER,
      snapshotSha256: "b".repeat(64),
      csrSha256,
      csrSpkiSha256: "c".repeat(64),
      templateOid: TEMPLATE_OID,
      jobId: "job:1",
      reconcileSearchFrom: 10,
      reconcileCandidateRequestId: 10,
      leafSha256: "d".repeat(64),
      validationDeadlineAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    });
    const reloaded = readEnrollmentJournal(stateDir, ENROLLMENT_ID);
    assert.equal(reloaded.kind, "corrupt");
    assert.match(reloaded.error, /deferred candidate requires leaf\.pem/);
  });

  it("allows replacing a rejected provisional tier-2 leaf with a later valid candidate", async () => {
    const { csrSha256 } = await commitPrepared(stateDir);
    await commitSubmitting(stateDir, csrSha256);
    await writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
      state: "submission_uncertain",
      attempt: 1,
      containerName: CONTAINER,
      snapshotSha256: "b".repeat(64),
      csrSha256,
      csrSpkiSha256: "c".repeat(64),
      templateOid: TEMPLATE_OID,
      jobId: "job:1",
      reconcileSearchFrom: 105,
    });
    const leafA = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n";
    const leafB = "-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n";
    const { leafSha256: hashA } = await writeIssuedCertificateArtifacts({
      stateDir,
      enrollmentId: ENROLLMENT_ID,
      leafPem: leafA,
    });
    await writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
      state: "submission_uncertain",
      attempt: 1,
      containerName: CONTAINER,
      snapshotSha256: "b".repeat(64),
      csrSha256,
      csrSpkiSha256: "c".repeat(64),
      templateOid: TEMPLATE_OID,
      jobId: "job:1",
      reconcileSearchFrom: 105,
      reconcileCandidateRequestId: 105,
      leafSha256: hashA,
      validationDeadlineAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    });

    // Permanently reject A: clear provisional metadata then remove artifact.
    await writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
      state: "submission_uncertain",
      attempt: 1,
      containerName: CONTAINER,
      snapshotSha256: "b".repeat(64),
      csrSha256,
      csrSpkiSha256: "c".repeat(64),
      templateOid: TEMPLATE_OID,
      jobId: "job:1",
      reconcileSearchFrom: 105,
      reconcileCandidateRequestId: null,
      validationDeadlineAt: null,
      leafSha256: null,
    });
    clearProvisionalLeafArtifacts(stateDir, ENROLLMENT_ID);
    assert.equal(fs.existsSync(leafArtifactPath(stateDir, ENROLLMENT_ID)), false);

    const { leafSha256: hashB } = await writeIssuedCertificateArtifacts({
      stateDir,
      enrollmentId: ENROLLMENT_ID,
      leafPem: leafB,
    });
    assert.notEqual(hashA, hashB);
    await writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
      state: "issued",
      attempt: 1,
      containerName: CONTAINER,
      snapshotSha256: "b".repeat(64),
      csrSha256,
      csrSpkiSha256: "c".repeat(64),
      templateOid: TEMPLATE_OID,
      jobId: "job:1",
      leafSha256: hashB,
      requestId: 110,
    });
    const read = readEnrollmentJournal(stateDir, ENROLLMENT_ID);
    assert.equal(read.kind, "valid");
    assert.equal(read.journal.state, "issued");
    assert.equal(read.journal.leafSha256, hashB);
    assert.equal(read.artifacts.leafPem, leafB);
    assert.equal(read.journal.requestId, 110);
  });

  it("requires caHresult for denied and errorCode for rejected_invalid", async () => {
    const { csrSha256 } = await commitPrepared(stateDir);
    await commitSubmitting(stateDir, csrSha256);
    await assert.rejects(
      () =>
        writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
          state: "denied",
          attempt: 1,
          containerName: CONTAINER,
          snapshotSha256: "b".repeat(64),
          csrSha256,
          csrSpkiSha256: "c".repeat(64),
          templateOid: TEMPLATE_OID,
          jobId: "job:1",
        }),
      /missing required field caHresult/,
    );
    await writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
      state: "denied",
      attempt: 1,
      containerName: CONTAINER,
      snapshotSha256: "b".repeat(64),
      csrSha256,
      csrSpkiSha256: "c".repeat(64),
      templateOid: TEMPLATE_OID,
      jobId: "job:1",
      caHresult: "0x80094012",
    });
    const denied = readEnrollmentJournal(stateDir, ENROLLMENT_ID);
    assert.equal(denied.kind, "valid");
    assert.equal(denied.journal.caHresult, "0x80094012");
  });

  it("requires errorCode when transitioning to rejected_invalid", async () => {
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
      jobId: "job:1",
      leafSha256,
      requestId: 7,
    });
    await assert.rejects(
      () =>
        writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
          state: "rejected_invalid",
          attempt: 1,
          containerName: CONTAINER,
          snapshotSha256: "b".repeat(64),
          csrSha256,
          csrSpkiSha256: "c".repeat(64),
          templateOid: TEMPLATE_OID,
          jobId: "job:1",
          leafSha256,
        }),
      /missing required field errorCode/,
    );
    await writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
      state: "rejected_invalid",
      attempt: 1,
      containerName: CONTAINER,
      snapshotSha256: "b".repeat(64),
      csrSha256,
      csrSpkiSha256: "c".repeat(64),
      templateOid: TEMPLATE_OID,
      jobId: "job:1",
      leafSha256,
      errorCode: "ADCS_CERTIFICATE_INVALID",
    });
    const rejected = readEnrollmentJournal(stateDir, ENROLLMENT_ID);
    assert.equal(rejected.kind, "valid");
    assert.equal(rejected.journal.errorCode, "ADCS_CERTIFICATE_INVALID");
  });

  it("preserves the first predecessorThumbprint across verify-stage journal updates", async () => {
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
      jobId: "job:1",
      leafSha256,
      requestId: 9,
    });
    await writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
      state: "installing",
      attempt: 1,
      containerName: CONTAINER,
      snapshotSha256: "b".repeat(64),
      csrSha256,
      csrSpkiSha256: "c".repeat(64),
      templateOid: TEMPLATE_OID,
      jobId: "job:1",
      leafSha256,
      installStep: "bind",
      predecessorThumbprint: "AA".repeat(20),
    });
    await writeEnrollmentJournal(stateDir, ENROLLMENT_ID, {
      state: "installing",
      attempt: 1,
      containerName: CONTAINER,
      snapshotSha256: "b".repeat(64),
      csrSha256,
      csrSpkiSha256: "c".repeat(64),
      templateOid: TEMPLATE_OID,
      jobId: "job:1",
      leafSha256,
      installStep: "verify",
      predecessorThumbprint: "BB".repeat(20),
    });
    const read = readEnrollmentJournal(stateDir, ENROLLMENT_ID);
    assert.equal(read.kind, "valid");
    assert.equal(read.journal.predecessorThumbprint, "AA".repeat(20));
    assert.equal(read.journal.installStep, "verify");
  });
});

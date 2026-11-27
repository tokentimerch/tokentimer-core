"use strict";

const assert = require("node:assert/strict");
const path = require("node:path").win32;
const { createHash } = require("node:crypto");

const MAX_PHASE_EVIDENCE_BYTES = 8192;
const PHASE_RECEIPT_ID = /^[a-f0-9]{32,64}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const RECORD_ID = /^[1-9][0-9]{0,19}$/;
const FILE_TIME = /^[a-f0-9]{16}$/;

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

// The independent reader returns the canonical receipt bytes. The input hash
// and argv digest come from the observed accept file and Windows launch record.
function verifyNamedStorePhaseEvidence({ raw, expectedSha256, counts, target, observation, fault,
  candidateArchiveSha256, launcherSha256, serviceDrainageSha256, configDir }) {
  assert.ok(Buffer.isBuffer(raw) && raw.length > 0 && raw.length <= MAX_PHASE_EVIDENCE_BYTES,
    "Named Store phase evidence must be a bounded UTF-8 receipt");
  const actualSha256 = digest(raw);
  assert.equal(actualSha256, expectedSha256, "Independent phase readback digest mismatch");
  const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw);
  const observed = JSON.parse(text);

  assert.equal(counts.accepts, 1, "Expected one certreq acceptance attempt in the named phase");
  for (const value of [candidateArchiveSha256, launcherSha256, serviceDrainageSha256, target.snapshotSha256]) {
    assert.match(value, SHA256);
  }
  const events = counts.namedEvidence.events;
  const start = events.find((event) => event.kind === "certreq-accept-start");
  const exit = events.find((event) => event.kind === "certreq-accept-exit");
  assert.ok(start && exit, "Native certreq launch and exit receipts are required");
  assert.equal(exit.pid, start.pid, "certreq exit identifies another process");
  assert.equal(exit.createdFileTime, start.createdFileTime, "certreq exit identifies another process lifetime");
  assert.equal(exit.exitCode, 0, "The observed certreq acceptance failed");
  assert.ok(Number.isSafeInteger(start.parentPid) && start.parentPid > 0 && start.parentPid !== start.pid);
  assert.match(start.parentCreatedFileTime, FILE_TIME);
  assert.match(start.parentProcessSequence, RECORD_ID);
  assert.match(start.auditRecordId, RECORD_ID);
  assert.match(start.argvSha256, SHA256);
  assert.match(fault.fingerprintSha256, SHA256);
  assert.equal(start.certificateSha256, fault.fingerprintSha256, "The certreq input differs from the enrolled certificate");

  const argv = observed?.certreq?.argv;
  assert.ok(Array.isArray(argv) && argv.length === 5 && argv.every((part) => typeof part === "string"));
  assert.match(argv[0], /^(?:[a-z]:\\windows\\system32\\)?certreq\.exe$/i);
  assert.deepEqual(argv.slice(1, 4), ["-q", "-machine", "-accept"]);
  assert.ok(path.isAbsolute(argv[4]));
  assert.equal(path.dirname(argv[4]).toLowerCase(), path.join(configDir, "windows-cert-store-work").toLowerCase(),
    "certreq did not receive a certificate from the owned Windows Store work directory");
  assert.match(path.basename(argv[4]), /^accept-[a-f0-9]{8}\.cer$/i);
  assert.equal(digest(JSON.stringify(argv)), start.argvSha256, "certreq argv differs from the independent launch record");

  const expected = {
    schema: 1,
    candidateArchiveSha256,
    launcherSha256,
    captureId: observation.captureId,
    observationRunId: observation.observationRunId,
    serviceProcess: observation.serviceProcess,
    serviceDrainageSha256,
    target: {
      jobId: target.jobId,
      enrollmentId: target.enrollmentId,
      containerName: target.containerName,
      snapshotSha256: target.snapshotSha256,
      domain: target.domain,
      certificateSha256: fault.fingerprintSha256,
    },
    certreq: {
      pid: start.pid,
      createdFileTime: start.createdFileTime,
      parentPid: start.parentPid,
      parentCreatedFileTime: start.parentCreatedFileTime,
      parentProcessSequence: start.parentProcessSequence,
      auditRecordId: start.auditRecordId,
      startRecordId: start.recordId,
      exitRecordId: exit.recordId,
      argv,
    },
  };
  assert.ok(text === JSON.stringify(expected),
    "Independent phase receipt does not match the service, certreq child and enrolled target");
  return actualSha256;
}

module.exports = { MAX_PHASE_EVIDENCE_BYTES, PHASE_RECEIPT_ID, verifyNamedStorePhaseEvidence };

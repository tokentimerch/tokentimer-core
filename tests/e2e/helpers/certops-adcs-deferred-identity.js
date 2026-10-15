"use strict";
// The production immediate-issued outcome deliberately omits RequestId. A
// durable deferred leaf still has an independently observable exact CA row;
// never fabricate a control-plane/journal ID to make a recovery fixture pass.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { verifyNativeRequestId } = require("./certops-adcs-live-enroll-acl");
const IMMUTABLE = Object.freeze([
  "snapshotSha256",
  "csrSha256",
  "csrSpkiSha256",
  "templateOid",
  "leafSha256",
  "containerName",
]);
function isDeferredPollReady(row) {
  return Boolean(
    row &&
    row.state === "validation_deferred" &&
    typeof row.current_job_id === "string" &&
    row.current_job_id.length > 0 &&
    Number.isFinite(Date.parse(row.next_poll_at)),
  );
}
function observe({ row, journal, nativeRequest, jobId, state }) {
  assert.equal(row.state, state);
  assert.equal(row.current_job_id, jobId);
  assert.equal(journal.kind, "valid");
  assert.equal(journal.journal.state, state);
  assert.equal(journal.journal.jobId, jobId);
  assert.ok(journal.artifacts.leafPem, "Actual deferred public leaf required");
  const leaf = new crypto.X509Certificate(journal.artifacts.leafPem);
  assert.equal(nativeRequest.disposition, 20);
  assert.ok(
    Number.isInteger(nativeRequest.subjectRequestCount) &&
      nativeRequest.subjectRequestCount >= 1 &&
      nativeRequest.subjectRequestCount <= 2048,
    "Independent native subject request count required",
  );
  verifyNativeRequestId(
    nativeRequest.requestId,
    row.request_id,
    journal.journal.requestId,
  );
  for (const name of IMMUTABLE)
    assert.ok(
      typeof journal.journal[name] === "string" &&
        journal.journal[name].length > 0,
      "Durable deferred identity incomplete",
    );
  return {
    requestId: nativeRequest.requestId,
    subjectRequestCount: nativeRequest.subjectRequestCount,
    fingerprint: leaf.fingerprint256,
    immutable: Object.fromEntries(
      IMMUTABLE.map((name) => [name, journal.journal[name]]),
    ),
  };
}
function verifyRecovery(before, after) {
  assert.equal(after.requestId, before.requestId);
  assert.equal(after.subjectRequestCount, before.subjectRequestCount);
  assert.equal(after.fingerprint, before.fingerprint);
  for (const name of IMMUTABLE)
    assert.ok(
      after.immutable[name] === before.immutable[name],
      "Deferred recovery changed durable CSR/key/leaf identity",
    );
  return true;
}
module.exports = { IMMUTABLE, isDeferredPollReady, observe, verifyRecovery };

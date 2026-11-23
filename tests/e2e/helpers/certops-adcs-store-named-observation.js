"use strict";

const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");

const NAMED_STORE_SCOPE = "adcs-named-store-recovery-v1";
const SHA256 = /^[a-f0-9]{64}$/;
const RECORD_ID = /^[1-9][0-9]{0,19}$/;
const CONTAINER = /^tokentimer-enr-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const SOURCE = Object.freeze({
  "ca-submission": "ca",
  "named-key-create": "key",
  "certreq-accept-start": "process",
});

// An authorized collector must establish the provenance of these records and
// their loss diagnostics before the native driver can use the normalized data.
function validateNamedStoreEvidence(counts, previous) {
  const source = counts.namedEvidence;
  assert.ok(Array.isArray(source?.events), "Named Store capture requires independent source records");
  assert.equal(source.captureId, counts.captureId, "Named Store evidence belongs to another capture");
  assert.match(source.candidateSha256, SHA256);
  assert.match(source.calibrationSha256, SHA256);
  assert.deepEqual(source.sourceLoss, { ca: 0, key: 0, process: 0 }, "Named Store observation reported loss");
  assert.notEqual(counts.coverageComplete, true, "Named Store capture cannot report exhaustive CNG coverage");
  assert.equal(counts.cngEvidence, undefined, "Named Store capture cannot contain exhaustive CNG evidence");

  const events = structuredClone(source.events);
  if (previous) {
    assert.equal(source.candidateSha256, previous.candidateSha256, "Named Store candidate changed during capture");
    assert.equal(source.calibrationSha256, previous.calibrationSha256, "Named Store calibration changed during capture");
    assert.deepEqual(events.slice(0, previous.events.length), previous.events, "Named Store evidence rewrote a previous checkpoint");
  }

  const totals = { ca: 0, key: 0, process: 0 };
  const lastRecord = { ca: 0n, key: 0n, process: 0n };
  const accepts = new Set();
  for (const [index, event] of events.entries()) {
    assert.equal(event?.sequence, index + 1, "Named Store observation has a gap or duplicate");
    assert.ok(Object.hasOwn(SOURCE, event.kind), "Unexpected named Store event kind");
    const stream = SOURCE[event.kind];
    assert.equal(typeof event.recordId, "string");
    assert.match(event.recordId, RECORD_ID);
    const recordId = BigInt(event.recordId);
    assert.ok(recordId > lastRecord[stream], "Named Store observation replayed or reordered a source record");
    lastRecord[stream] = recordId;
    totals[stream]++;
    if (stream === "ca") {
      assert.equal(typeof event.requestId, "string");
      assert.match(event.requestId, /^[1-9][0-9]{0,9}$/);
      assert.ok(Number(event.requestId) <= 2147483647);
    } else if (stream === "key") {
      assert.match(event.containerName, CONTAINER);
    } else {
      assert.ok(Number.isSafeInteger(event.pid) && event.pid > 0);
      assert.match(event.createdFileTime, /^[a-f0-9]{16}$/);
      const process = event.pid + ":" + event.createdFileTime;
      assert.ok(!accepts.has(process), "Repeated certreq process identity");
      accepts.add(process);
    }
  }
  assert.equal(counts.submissions, totals.ca, "CA submission count differs from observed records");
  assert.equal(counts.keygens, totals.key, "Named key creation count differs from observed records");
  assert.equal(counts.accepts, totals.process, "Install attempt count differs from observed certreq starts");
  return { captureId: source.captureId, candidateSha256: source.candidateSha256,
    calibrationSha256: source.calibrationSha256, sourceLoss: { ...source.sourceLoss }, events };
}

function verifyNamedStoreIdentity(counts, { containerName, requestId }) {
  if (counts?.scope !== NAMED_STORE_SCOPE) return;
  for (const event of counts.namedEvidence.events) {
    if (event.kind === "named-key-create" && containerName) {
      assert.equal(event.containerName, containerName, "Named Store evidence contains another key container");
    }
    if (event.kind === "ca-submission" && requestId) {
      assert.equal(event.requestId, String(requestId), "Named Store evidence contains another CA RequestId");
    }
  }
}

function namedStoreEvidenceDigest(counts) {
  return createHash("sha256").update(JSON.stringify(counts.namedEvidence)).digest("hex");
}

module.exports = { NAMED_STORE_SCOPE, validateNamedStoreEvidence, verifyNamedStoreIdentity, namedStoreEvidenceDigest };

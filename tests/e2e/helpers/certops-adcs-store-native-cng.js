"use strict";

const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");

const SHA256 = /^[a-f0-9]{64}$/;

// A normalized slice of the capture's raw CNG call events. The producer must
// independently establish its provenance and loss status. Free events cover
// key handles only. The baseline marker separates the controlled ephemeral
// probes (including release of their keys) from enrollment operations.
function validateNativeCngEvidence(counts, previousEvidence) {
  const source = counts.cngEvidence;
  assert.ok(Array.isArray(source?.events), "Raw CNG evidence is required for complete coverage");
  const evidence = { captureId: source.captureId, candidateSha256: source.candidateSha256,
    events: structuredClone(source.events) };
  assert.equal(evidence.captureId, counts.captureId, "Raw CNG evidence belongs to another capture");
  assert.match(evidence.candidateSha256, SHA256, "Raw CNG evidence must identify its candidate archive");
  if (previousEvidence) {
    assert.equal(evidence.candidateSha256, previousEvidence.candidateSha256, "Raw CNG candidate changed during capture");
    assert.deepEqual(evidence.events.slice(0, previousEvidence.events.length), previousEvidence.events,
      "Raw CNG evidence lost or rewrote a previous checkpoint");
  }

  const seen = new Set();
  const pending = new Map();
  const handles = new Map();
  const coveredApis = new Set();
  let baseline = false;
  let keygens = 0;
  for (const [index, event] of evidence.events.entries()) {
    assert.equal(event?.sequence, index + 1, "Raw CNG evidence has a gap or duplicate");
    if (event.kind === "baseline") {
      assert.equal(baseline, false, "Duplicate CNG baseline");
      assert.equal(pending.size, 0, "CNG baseline contains unfinished calls");
      assert.equal(handles.size, 0, "CNG baseline contains open ephemeral probe handles");
      assert.ok(coveredApis.has("ncrypt") && coveredApis.has("bcrypt"),
        "Raw CNG evidence must show successful ephemeral NCrypt and BCrypt probes");
      baseline = true;
      continue;
    }

    assert.ok(event.kind === "cng-api-entry" || event.kind === "cng-api-return", "Unknown CNG event kind");
    const { pid, createdFileTime, payload } = event.evidence ?? {};
    assert.ok(Number.isSafeInteger(pid) && pid > 0, "CNG call lacks a process identity");
    assert.match(createdFileTime, /^[a-f0-9]{16}$/, "CNG call lacks a process creation time");
    assert.ok(Number.isSafeInteger(payload?.tid) && payload.tid > 0 &&
      Number.isSafeInteger(payload.callId) && payload.callId > 0, "CNG call lacks a thread or call ID");
    assert.match(payload.invocationFingerprint, SHA256, "CNG call lacks an invocation fingerprint");
    assert.match(payload.operation, /^(?:ncrypt|bcrypt)-(?:create|finalize|free)$/);
    const [api, operation] = payload.operation.split("-");
    const callId = `${pid}:${createdFileTime}:${payload.tid}:${payload.callId}`;

    if (event.kind === "cng-api-entry") {
      assert.ok(!seen.has(callId), "Duplicate CNG call entry");
      seen.add(callId);
      pending.set(callId, payload);
      if (operation === "create") {
        assert.ok(payload.nameKind === "ephemeral" || payload.nameKind === "non-null", "Unknown CNG key scope");
        if (baseline) keygens++;
      }
      continue;
    }

    const entry = pending.get(callId);
    assert.ok(entry && entry.operation === payload.operation && entry.invocationFingerprint === payload.invocationFingerprint,
      "CNG return does not match an observed call entry");
    pending.delete(callId);
    assert.match(payload.status, /^[a-f0-9]{8}$/, "CNG return lacks a native status");
    if (payload.status !== "00000000") {
      if (operation !== "free") assert.equal(baseline, false, "An enrollment CNG generation call failed");
      continue;
    }

    assert.match(payload.handleCorrelation, SHA256, "CNG return lacks a key handle correlation");
    const handle = `${pid}:${createdFileTime}:${api}:${payload.handleCorrelation}`;
    if (operation === "create") {
      if (!baseline) assert.equal(entry.nameKind, "ephemeral", "CNG coverage probe must use an ephemeral key");
      assert.ok(!handles.has(handle), "CNG handle was reused before release");
      handles.set(handle, false);
    } else if (operation === "finalize") {
      assert.ok(handles.has(handle), "CNG finalized an unobserved or released key");
      assert.equal(handles.get(handle), false, "CNG key was already finalized");
      handles.set(handle, true);
      if (!baseline) coveredApis.add(api);
    } else {
      assert.ok(handles.has(handle), "CNG released an unobserved key");
      assert.equal(handles.get(handle), true, "CNG released a key before finalization");
      handles.delete(handle);
    }
  }

  assert.ok(baseline, "Raw CNG evidence lacks a calibrated baseline");
  assert.equal(pending.size, 0, "Raw CNG evidence has unfinished calls");
  assert.ok([...handles.values()].every(Boolean), "Raw CNG evidence has unfinalized keys");
  assert.equal(counts.keygens, keygens, "Claimed key generations do not match raw CNG create calls");
  return evidence;
}

function nativeCngEvidenceSha256(counts) {
  return createHash("sha256").update(JSON.stringify(counts.cngEvidence)).digest("hex");
}

module.exports = { validateNativeCngEvidence, nativeCngEvidenceSha256 };

"use strict";
/** Synthetic closed-proof adversaries; no native qualification. */
const { test } = require("node:test"), assert = require("node:assert/strict"), h = require("./certops-adcs-ttl24h-proof"), contract = require("./certops-adcs-ttl24h-contract"), { iso, uuid } = require("./fixtures/certops-adcs-ttl24h.cjs");
const {fixture}=require("./fixtures/certops-adcs-ttl24h-proof.cjs");
test("flat native contract binds full actual-day semantics and precise original task identity", () => {
  const f = fixture(); assert.equal(h.verifyProof(f.proof), true); assert.equal(h.verifyAgainstPrepared(f.proof, f.prepared, f.observed), true); assert.equal(Object.keys(f.proof).length, h.FIELDS.length); assert.equal(h.REQUIRED_SCENARIOS.length, 5);
  for (const field of h.FIELDS) { const bad = structuredClone(f.proof); delete bad[field]; assert.throws(() => h.verifyProof(bad)); }
});
test("short waits, privacy extras, skipped controls and ambiguous native generations refuse", () => {
  const f = fixture(); for (const patch of [{ privateCredential: "sentinel" }, { residentTiming: {} }, { monotonicElapsedMs: contract.DAY - 1 }, { configuredValidationTimeoutSeconds: 86400 }, { defaultValidationTimeoutSeconds: 300 }, { residentFinishedAt: iso(contract.MAX) }, { preDeadlineObservedAt: f.proof.deadlineAt }, { requestIds: ["16", "17", "17"] }, { fingerprints: [...f.proof.fingerprints.slice(0, 2), f.proof.fingerprints[0]] }, { caRequestCounts: [0, 1, 2, 4] }, { bootTime: "2026-02-30T12:00:00.000Z" }]) assert.throws(() => h.verifyProof({ ...f.proof, ...patch }));
  for (const flag of h.FLAGS) assert.throws(() => h.verifyProof({ ...f.proof, [flag]: false }));
});
test("well-formed stale original, leaf, source seal and task bindings cannot pass context verification", () => {
  const f = fixture(); for (const patch of [{ issuerId: uuid("0") }, { preparedSha256: "0".repeat(64) }, { snapshotSha256: "0".repeat(64) }, { processId: 1235 }, { taskXmlSha256: "0".repeat(64) }, { requestIds: ["15", "17", "18"] }, { fingerprints: ["0".repeat(64), ...f.proof.fingerprints.slice(1)] }]) assert.throws(() => h.verifyAgainstPrepared({ ...f.proof, ...patch }, f.prepared, f.observed));
});

"use strict";
/** Synthetic contract fixtures only; no native elapsed/CA or Azure authority. */
const { test } = require("node:test"), assert = require("node:assert/strict"), h = require("./certops-adcs-ttl24h-contract");
const { prepared, iso } = require("./fixtures/certops-adcs-ttl24h.cjs");
function resident(p = prepared()) { return { scope: "resident-adcs-ttl24h-timing-only-native-oracles-required", candidateSha: p.lease.candidateSha, nonce: p.lease.nonce, vmId: p.lease.vmId, processId: 1234, bootTime: p.bootTime, processCreatedAt: iso(30500), startedAt: iso(31000), finishedAt: iso(32000 + h.DAY), monotonicElapsedMs: h.DAY + 1000, preDeadlineObservedAt: iso(31000 + 23 * h.HOUR), keptObservationCount: 24, maximumObservationGapMs: h.HOUR, preparedSha256: h.preparedDigest(p) }; }
test("completed task is a distinct closed same-process observation, never a short running receipt", () => {
  const p = prepared(), original = { ...Object.fromEntries(h.IDENTITIES.map(key => [key, p.lease[key]])), preparedSha256: h.preparedDigest(p), taskXmlSha256: "a".repeat(64), processId: 1234, processCreatedAt: iso(30500), bootTime: p.bootTime, principalSid: "S-1-5-18", taskState: "Running", nativeVerificationStartedAt: iso(31000), nativeVerificationFinishedAt: iso(32000), monotonicElapsedMs: 1000, ...Object.fromEntries(h.OBSERVATION_FLAGS.map(key => [key, true])) };
  const completed = { ...original, taskState: "Ready", nativeVerificationStartedAt: iso(h.DAY + 33000), nativeVerificationFinishedAt: iso(h.DAY + 34000), residentTiming: resident(p) };
  assert.equal(h.verifyTaskObservation(original, p), true); assert.equal(h.verifyCompletedTaskObservation(completed, p, original), true); assert.throws(() => h.verifyTaskObservation(completed, p));
  for (const mutate of [v => v.processId++, v => v.taskXmlSha256 = "f".repeat(64), v => v.taskState = "Running", v => v.nativeVerificationStartedAt = iso(33000), v => v.residentTiming.monotonicElapsedMs = h.DAY - 1, v => v.residentTiming.processId++, v => v.privateExtra = "sentinel", v => v.soleAgentStoppedAndDrained = false]) { const bad = structuredClone(completed); mutate(bad); assert.throws(() => h.verifyCompletedTaskObservation(bad, p, original)); }
});
test("TTL purpose uses a separate closed15-key4h/32h lease without extending authority", () => {
  const p = prepared(); assert.equal(h.verifyLease(p.lease), true); assert.equal(Object.keys(p.lease).length, 15);
  for (const patch of [{ kind: "certops-native-retention24h" }, { taskName: "TokenTimer-Retention24h-" + p.lease.nonce }, { expiresAt: iso(h.MAX) }, { hardExpiresAt: iso(h.MAX + 1) }, { credential: "sentinel" }]) assert.throws(() => h.verifyLease({ ...p.lease, ...patch }));
});
test("prepared identity binds real post-confirmation freshness and untouched default validation window", () => {
  const p = prepared(); assert.equal(h.verifyPreparedReceipt(p), true);
  for (const key of Object.keys(p)) { const bad = structuredClone(p); delete bad[key]; assert.throws(() => h.verifyPreparedReceipt(bad)); }
  for (const mutate of [v => v.preflight.createdAt = iso(0), v => v.preflight.status = "failed", v => v.validation.configuredTimeoutSeconds = 300, v => v.validation.configuredTimeoutSeconds = 86400, v => v.validation.deadlineAt = iso(20000 + 300000), v => v.validation.containerName = v.predecessor.containerName, v => v.validation.requestId = v.predecessor.requestId, v => v.validation.csrSpkiSha256 = v.predecessor.spkiSha256, v => v.validation.privateJournal = "sentinel", v => v.sources.push(v.sources[0]), v => v.sources[0].file = "scripts/../../outside", v => v.predecessor.notAfter = v.validation.deadlineAt]) { const bad = structuredClone(p); mutate(bad); assert.throws(() => h.verifyPreparedReceipt(bad)); }
});
test("timer-only receipt needs actualday consistency and exact prepared bytes but cannot qualify native behavior", () => {
  const p = prepared(), r = resident(p); assert.equal(h.verifyResidentTimingReceipt(r, p), true);
  for (const patch of [{ monotonicElapsedMs: h.DAY - 1 }, { finishedAt: iso(30000 + 300000) }, { finishedAt: iso(h.MAX) }, { preDeadlineObservedAt: p.validation.deadlineAt }, { maximumObservationGapMs: h.HOUR + 300001 }, { keptObservationCount: 1 }, { preparedSha256: "f".repeat(64) }, { nonce: "f".repeat(64) }, { bootTime: iso(0) }, { nativeQualified: true }]) assert.throws(() => h.verifyResidentTimingReceipt({ ...r, ...patch }, p));
  const changed = structuredClone(p); changed.sources[0].sha256 = "f".repeat(64); assert.throws(() => h.verifyResidentTimingReceipt(r, changed));
  assert.equal(typeof h.verifyProof, "undefined"); assert.equal(typeof h.attestHandoff, "undefined");
});
test("prepared public trust and CA counters are closed and independently bounded", () => {
  for (const mutate of [p => p.apiTrust.privatePem = "sentinel", p => p.apiTrust.fileId = "0", p => p.apiTrust.sha256 = "invalid", p => p.caRequestCounts.deferred++, p => p.caRequestCounts.before = -1, p => p.caRequestCounts.extra = 3, p => p.configurationSha256 = "invalid"]) { const p = prepared(); mutate(p); assert.throws(() => h.verifyPreparedReceipt(p)); }
});

"use strict";
/** Closed measured-facts contract for the separate real default-grace lane.
 * Loading this module is neither elapsed-time nor native-service qualification. */
const assert = require("node:assert/strict");
const timing = require("../../../apps/api/services/certops/leaseTiming");
const liveness = require("../../../apps/api/services/certops/agentLiveness");
const SCOPE =
  "installed-windows-alive-agent-default-hard-grace-orphan-classification";
const SCENARIO =
  "windows-installed-alive-default-hard-grace-orphan-classification";
const FLAGS = Object.freeze([
  "actualPublicSignedNativeRenewal",
  "actualOwnedCommandBarrier",
  "nativeGeneratedKeyBeforeDelegation",
  "completedNativeMutationAndTrustedTls",
  "exactCurrentClaimDurableSuccessOutbox",
  "currentClaimNativeVerificationEvidence",
  "actualOriginalResult503BeforeForward",
  "originalPersistedLeaseUnmodified",
  "authenticatedHeartbeatContinued",
  "actualDefaultReaperDeferredBeforeGrace",
  "actualDefaultReaperTerminalizedAfterGrace",
  "originalOrphanReconciliationPreserved",
  "ownedNativeCustodyPreserved",
  "storedOperatorProfilePreserved",
  "retainedOriginalNativeHandlesDrainedBeforeCleanup",
  "exactOwnedCleanupCompleted",
]);
const TIMES = Object.freeze([
  "leaseRenewedAt",
  "leaseExpiresAt",
  "nativeCompletedAt",
  "deferredObservedAt",
  "deferredHeartbeatAt",
  "terminalObservedAt",
  "terminalHeartbeatAt",
]);
function epoch(v) {
  assert.equal(typeof v, "string");
  const n = Date.parse(v);
  assert.ok(
    Number.isFinite(n) && new Date(n).toISOString() === v,
    "Canonical measured UTC required",
  );
  return n;
}
function verifyProof(p) {
  assert.ok(p && typeof p === "object" && !Array.isArray(p));
  assert.deepEqual(
    Object.keys(p).sort(),
    [
      "scope",
      "jobId",
      "claimId",
      "attemptCount",
      "terminalStatus",
      "defaultLeaseMs",
      "defaultHardGraceMs",
      "defaultOfflineMs",
      "waitedMonotonicMs",
      "heartbeatUptimeSeconds",
      "originalOperationAutomaticallyRecovered",
      "deployedWorkerLoopQualified",
      "atomicTreeContainmentQualified",
      "claimPollingAvailabilityQualified",
      "fingerprints",
      "spkiFingerprints",
      ...TIMES,
      ...FLAGS,
    ].sort(),
  );
  assert.equal(p.scope, SCOPE);
  for (const k of ["jobId", "claimId"])
    assert.match(p[k], /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  assert.equal(p.attemptCount, 1);
  assert.equal(p.terminalStatus, "orphaned_unknown_effect");
  assert.equal(p.defaultLeaseMs, timing.DEFAULT_JOB_LEASE_SECONDS * 1000);
  assert.equal(p.defaultHardGraceMs, timing.DEFAULT_LEASE_HARD_GRACE_MS);
  assert.equal(p.defaultOfflineMs, liveness.DEFAULT_AGENT_OFFLINE_AFTER_MS);
  assert.ok(
    Array.isArray(p.heartbeatUptimeSeconds) &&
      p.heartbeatUptimeSeconds.length === 3 &&
      p.heartbeatUptimeSeconds.every(
        (x) => Number.isSafeInteger(x) && x >= 0,
      ) &&
      p.heartbeatUptimeSeconds[1] > p.heartbeatUptimeSeconds[0] &&
      p.heartbeatUptimeSeconds[2] > p.heartbeatUptimeSeconds[1],
    "Measured heartbeat-only persisted uptime must increase",
  );
  for (const field of ["fingerprints", "spkiFingerprints"])
    assert.ok(
      Array.isArray(p[field]) &&
        p[field].length === 2 &&
        new Set(p[field]).size === 2 &&
        p[field].every(
          (v) => typeof v === "string" && /^[a-f0-9]{64}$/.test(v),
        ),
      "Actual distinct native leaf/key fingerprints required",
    );
  assert.equal(p.atomicTreeContainmentQualified, false);
  assert.equal(p.claimPollingAvailabilityQualified, false);
  assert.equal(p.originalOperationAutomaticallyRecovered, false);
  assert.equal(p.deployedWorkerLoopQualified, false);
  for (const flag of FLAGS) assert.equal(p[flag], true);
  const t = Object.fromEntries(TIMES.map((k) => [k, epoch(p[k])]));
  assert.equal(t.leaseExpiresAt - t.leaseRenewedAt, p.defaultLeaseMs);
  assert.ok(
    t.nativeCompletedAt < t.leaseExpiresAt &&
      t.nativeCompletedAt <= t.deferredObservedAt,
  );
  assert.ok(
    t.deferredObservedAt > t.leaseExpiresAt &&
      t.deferredObservedAt <= t.leaseExpiresAt + p.defaultHardGraceMs,
  );
  assert.ok(t.terminalObservedAt > t.leaseExpiresAt + p.defaultHardGraceMs);
  for (const [observed, heartbeat] of [
    [t.deferredObservedAt, t.deferredHeartbeatAt],
    [t.terminalObservedAt, t.terminalHeartbeatAt],
  ])
    assert.ok(
      heartbeat <= observed && observed - heartbeat < p.defaultOfflineMs,
      "Actual fresh heartbeat required at each reaper observation",
    );
  assert.ok(t.terminalHeartbeatAt > t.deferredHeartbeatAt);
  assert.ok(
    Number.isSafeInteger(p.waitedMonotonicMs) &&
      p.waitedMonotonicMs >= p.defaultHardGraceMs + p.defaultLeaseMs,
    "Genuine unchanged default elapsed window required",
  );
  return p;
}
module.exports = { SCOPE, SCENARIO, FLAGS, TIMES, verifyProof };

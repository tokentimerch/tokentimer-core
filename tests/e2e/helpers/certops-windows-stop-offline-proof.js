"use strict";
/** Closed source contract for the separate stopped/offline Windows lane.
 * This module validates measured facts only. It does not execute a timer,
 * invoke a reaper or qualify a service merely by loading production defaults. */
const assert = require("node:assert/strict");
const timing = require("../../../apps/api/services/certops/leaseTiming");
const liveness = require("../../../apps/api/services/certops/agentLiveness");
const SCOPE =
  "installed-windows-stop-during-dns-default-expiry-offline-reconciliation";
const SCENARIO = "windows-installed-active-stop-default-offline-recovery";
const FLAGS = Object.freeze([
  "realPublicManualRenewalAndSignedClaim",
  "realHeldDnsPostAfterNativeCngJournal",
  "ownedResultDeliveryBarrierBeforeForward",
  "retainedOriginalNativeHandlesBeforeStop",
  "allCapturedDescendantsExited",
  "nativeHandlesAndObserverClosed",
  "sameServingCngBindingAndTrustedTlsWhileStopped",
  "originalPersistedLeaseUnmodified",
  "actualDefaultProductionReaperInvoked",
  "originalAttemptNeverReplayed",
  "actualOriginalJournalOrDurableOutcomePreserved",
  "originalUnacceptedKeyAbsentAfterRestart",
  "freshAuthenticatedRestart",
  "freshPublicManualRenewalSucceeded",
  "freshLeafSpkiProtectedKeyAndTrustedTls",
  "storedProfilePreserved",
  "exactOwnedCleanupCompleted",
]);
const TIMES = Object.freeze([
  "leaseRenewedAt",
  "leaseExpiresAt",
  "stoppedObservedAt",
  "lastSeenAt",
  "databaseObservedAt",
  "reapedObservedAt",
  "restartedObservedAt",
  "freshRenewalObservedAt",
]);
function epoch(value) {
  assert.equal(typeof value, "string");
  const number = Date.parse(value);
  assert.ok(
    Number.isFinite(number) && new Date(number).toISOString() === value,
    "Canonical measured UTC required",
  );
  return number;
}
function verifyProof(p) {
  assert.ok(p && typeof p === "object" && !Array.isArray(p));
  assert.deepEqual(
    Object.keys(p).sort(),
    [
      "scope",
      "originalJobId",
      "originalClaimId",
      "freshJobId",
      "stopOutcome",
      "capturedProcessCount",
      "originalAttemptCount",
      "originalTerminalStatus",
      "defaultLeaseMs",
      "defaultOfflineMs",
      "defaultHardGraceMs",
      "defaultAliveGraceElapsedQualified",
      "deployedWorkerLoopQualified",
      "atomicTreeContainmentQualified",
      "originalOperationAutomaticallyRecovered",
      "waitedMonotonicMs",
      "fingerprints",
      "spkiFingerprints",
      ...TIMES,
      ...FLAGS,
    ].sort(),
  );
  assert.equal(p.scope, SCOPE);
  for (const name of ["originalJobId", "originalClaimId", "freshJobId"])
    assert.match(p[name], /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  assert.notEqual(p.originalJobId, p.freshJobId);
  assert.ok(
    ["graceful-stop-observed", "host-timeout-fallback-observed"].includes(
      p.stopOutcome,
    ),
  );
  assert.ok(
    Number.isSafeInteger(p.capturedProcessCount) &&
      p.capturedProcessCount >= 2 &&
      p.capturedProcessCount <= 128,
  );
  assert.equal(p.originalAttemptCount, 1);
  assert.equal(p.originalTerminalStatus, "orphaned_unknown_effect");
  assert.equal(p.defaultLeaseMs, timing.DEFAULT_JOB_LEASE_SECONDS * 1000);
  assert.equal(p.defaultOfflineMs, liveness.DEFAULT_AGENT_OFFLINE_AFTER_MS);
  assert.equal(p.defaultHardGraceMs, timing.DEFAULT_LEASE_HARD_GRACE_MS);
  assert.equal(p.defaultAliveGraceElapsedQualified, false);
  assert.equal(p.deployedWorkerLoopQualified, false);
  assert.equal(p.atomicTreeContainmentQualified, false);
  assert.equal(p.originalOperationAutomaticallyRecovered, false);
  const time = Object.fromEntries(TIMES.map((k) => [k, epoch(p[k])]));
  assert.equal(
    time.leaseExpiresAt - time.leaseRenewedAt,
    p.defaultLeaseMs,
    "Actual persisted default lease duration required",
  );
  assert.ok(
    time.leaseRenewedAt <= time.stoppedObservedAt &&
      time.stoppedObservedAt <= time.databaseObservedAt &&
      time.lastSeenAt <= time.databaseObservedAt,
  );
  const due = Math.max(
    time.leaseExpiresAt,
    time.lastSeenAt + p.defaultOfflineMs,
  );
  assert.ok(
    time.databaseObservedAt < due && time.reapedObservedAt >= due,
    "Actual default lease expiry and offline threshold must pass",
  );
  assert.ok(
    time.restartedObservedAt >= time.reapedObservedAt &&
      time.freshRenewalObservedAt > time.restartedObservedAt,
  );
  assert.ok(
    Number.isFinite(p.waitedMonotonicMs) &&
      p.waitedMonotonicMs >= due - time.databaseObservedAt - 1000 &&
      p.waitedMonotonicMs < 1200000,
    "Measured monotonic default deadline wait is mandatory",
  );
  for (const key of ["fingerprints", "spkiFingerprints"])
    assert.ok(
      Array.isArray(p[key]) &&
        p[key].length === 2 &&
        p[key].every(
          (x) => typeof x === "string" && /^[a-f0-9]{64}$/.test(x),
        ) &&
        new Set(p[key]).size === 2,
    );
  for (const flag of FLAGS) assert.equal(p[flag], true, flag);
  return true;
}
module.exports = { SCOPE, SCENARIO, FLAGS, TIMES, verifyProof };

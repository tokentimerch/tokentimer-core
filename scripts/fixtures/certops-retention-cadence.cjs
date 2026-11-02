"use strict";
/** Offline deterministic receipts only; never native evidence. */
const c = require("../certops-retention-cadence-contract");
const p = require("../certops-retention-cadence-proof");
function fixture() {
  const owner = {
    candidateSha: "a".repeat(40),
    runId: "12",
    runAttempt: "1",
    nonce: "b".repeat(64),
    vmResourceId:
      "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/tt-certops-12-1/providers/Microsoft.Compute/virtualMachines/windows-agent",
    vmId: "12345678-1234-1234-1234-123456789abc",
    taskName: `TokenTimer-RetentionCadence-${"b".repeat(64)}`,
    nodeSha256: "c".repeat(64),
    observerSha256: "d".repeat(64),
  };
  const preparedLease = c.createLease(owner, "2026-10-15T00:00:00.000Z");
  const observed = {
    ...owner,
    ...Object.fromEntries(c.FLAGS.map((k) => [k, true])),
    principalSid: "S-1-5-18",
    taskState: "Running",
    processId: 100,
    processCreatedAt: "2026-10-15T00:00:30.0000000Z",
    bootTime: "2026-10-14T23:00:00.000Z",
    serviceHostPid: 101,
    serviceHostCreatedAt: "2026-10-15T00:00:40.0000000Z",
    agentPid: 102,
    agentCreatedAt: "2026-10-15T00:00:41.0000000Z",
    configSha256: "e".repeat(64),
    observerConfigSha256: "1".repeat(64),
    immutableLedgerSha256: "f".repeat(64),
    pendingLedgerFileId: "1:2",
    immediateLedgerFileId: "1:3",
    immediateObservedAt: "2026-10-15T00:01:00.000Z",
    immediateMonotonicMs: 60000,
    oldNotAfter: "2026-10-17T00:00:00.000Z",
    verifiedAt: "2026-10-15T00:02:00.000Z",
  };
  const native = Object.fromEntries(
    p.NATIVE_FIELDS.map((k) => [k, observed[k]]),
  );
  const result = {
    schemaVersion: 1,
    scope: "observed-installed-default-timer-awaiting-independent-finalization",
    startedAt: "2026-10-15T00:00:30.000Z",
    finishedAt: "2026-10-15T06:01:10.000Z",
    immediate: {
      monotonicMs: 60000,
      observedAt: observed.immediateObservedAt,
      fileId: "1:3",
    },
    timer: {
      monotonicMs: 60000 + c.BASE_INTERVAL,
      observedAt: "2026-10-15T06:01:00.000Z",
      fileId: "1:4",
    },
    native,
    configSha256: "1".repeat(64),
    defaultIntervalMs: c.BASE_INTERVAL,
    defaultRetentionHours: 168,
    actualCleanupQualified: false,
    full168HourRetentionQualified: false,
  };
  const preparation = {
    schemaVersion: 1,
    kind: c.KIND,
    preparedLease,
    observed,
    fixtureSources:
      require("../certops-retention-cadence-sources").REQUIRED_SOURCES.map(
        (file) => ({ file, sha256: "2".repeat(64) }),
      ),
  };
  const completion = {
    schemaVersion: 1,
    scope: "completed-installed-default-timer-awaiting-owned-cleanup",
    originalObservation: {
      ...observed,
      verifiedAt: observed.immediateObservedAt,
    },
    result,
    currentNativeVerified: true,
    verifiedAt: "2026-10-15T06:02:00.000Z",
  };
  return {
    preparedLease,
    lease: c.attestHandoff(preparedLease, observed),
    preparation,
    completion,
    cleanup: "completed",
    cleanupFinishedAt: "2026-10-15T06:03:00.000Z",
  };
}
module.exports = { fixture };

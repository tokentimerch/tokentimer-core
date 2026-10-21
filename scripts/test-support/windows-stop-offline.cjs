"use strict";
const {windowsArtifact} = require("./qualification-artifact.cjs");
/** Synthetic contract fixture only; never native execution evidence. */
const h = require("../../tests/e2e/helpers/certops-windows-stop-offline-proof");
function fixture() {
  return {
    scope: h.SCOPE,
    originalJobId: "11111111-1111-4111-8111-111111111111",
    originalClaimId: "22222222-2222-4222-8222-222222222222",
    freshJobId: "33333333-3333-4333-8333-333333333333",
    stopOutcome: "host-timeout-fallback-observed",
    capturedProcessCount: 5,
    originalAttemptCount: 1,
    originalTerminalStatus: "orphaned_unknown_effect",
    defaultLeaseMs: 900000,
    defaultOfflineMs: 600000,
    defaultHardGraceMs: 3600000,
    defaultAliveGraceElapsedQualified: false,
    deployedWorkerLoopQualified: false,
    atomicTreeContainmentQualified: false,
    originalOperationAutomaticallyRecovered: false,
    waitedMonotonicMs: 870000,
    leaseRenewedAt: "2026-10-15T10:00:00.000Z",
    leaseExpiresAt: "2026-10-15T10:15:00.000Z",
    stoppedObservedAt: "2026-10-15T10:00:30.000Z",
    lastSeenAt: "2026-10-15T10:00:01.000Z",
    databaseObservedAt: "2026-10-15T10:00:31.000Z",
    reapedObservedAt: "2026-10-15T10:15:01.000Z",
    restartedObservedAt: "2026-10-15T10:15:02.000Z",
    freshRenewalObservedAt: "2026-10-15T10:15:30.000Z",
    fingerprints: ["a".repeat(64), "b".repeat(64)],
    spkiFingerprints: ["c".repeat(64), "d".repeat(64)],
    ...Object.fromEntries(h.FLAGS.map((k) => [k, true])),
  };
}
const candidateSha = "a".repeat(40);
function artifact(version = "2022") {
 return windowsArtifact(require("../certops-windows-stop-offline"), h, fixture, "nativeWindowsStoppedOffline", version, "2026-10-15T10:20:00.000Z", candidateSha);
}
module.exports = { fixture, artifact, candidateSha };

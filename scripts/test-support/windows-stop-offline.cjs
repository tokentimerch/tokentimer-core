"use strict";
const {reportFacts} = require("./qualification-artifact.cjs");
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
  const producer = require("../certops-windows-stop-offline"),
    fs = require("node:fs"),
    path = require("node:path"),
    crypto = require("node:crypto");
  const source = (file) => ({
    file,
    sha256: crypto
      .createHash("sha256")
      .update(fs.readFileSync(path.resolve(__dirname, "../..", file)))
      .digest("hex"),
  });
  const environment = {
    osFamily: "windows",
    osVersion: version,
    productType: 3,
    measurement: "native",
    identity: "LocalSystem",
    nativeLanguage: "en-US",
    architecture: "x64",
  };
  const stamp = "2026-10-15T10:00:00.000Z";
  const report = {
    ...reportFacts({ids: [h.SCENARIO], capabilities: [...producer.CAPABILITIES], evidenceLevel: "real-host", startedAt: stamp, finishedAt: "2026-10-15T10:20:00.000Z"}),
    suite: producer.SUITE,
    platform: "win32",
    architecture: "x64",
    nodeVersion: "v24.0.0",
    candidateSha,
    artifactQualification: "workflow-checkout-source",
    evidenceLevel: "real-host",
    startedAt: stamp,
    finishedAt: "2026-10-15T10:20:00.000Z",
    qualificationEnvironment: environment,
    fixtureSource: source(producer.SOURCE),
    fixtureSources: producer.REQUIRED_SOURCES.map(source),
    nativeWindowsStoppedOffline: fixture()
  };
  return {
    kind: "host",
    suite: report.suite,
    environment: { ...environment },
    report,
  };
}
module.exports = { fixture, artifact, candidateSha };

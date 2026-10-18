"use strict";
const {reportFacts} = require("./qualification-artifact.cjs");
/** Synthetic contract fixture only; never native execution evidence. */
const h = require("../../tests/e2e/helpers/certops-windows-alive-grace-proof");
function fixture() {
  const base = Date.parse("2026-01-01T00:00:00.000Z"),
    iso = (ms) => new Date(base + ms).toISOString();
  return {
    scope: h.SCOPE,
    jobId: "11111111-1111-4111-8111-111111111111",
    claimId: "22222222-2222-4222-8222-222222222222",
    attemptCount: 1,
    terminalStatus: "orphaned_unknown_effect",
    defaultLeaseMs: 900000,
    defaultHardGraceMs: 3600000,
    defaultOfflineMs: 600000,
    heartbeatUptimeSeconds: [1, 1001, 4501],
    waitedMonotonicMs: 4500001,
    fingerprints: ["a".repeat(64), "b".repeat(64)],
    spkiFingerprints: ["c".repeat(64), "d".repeat(64)],
    atomicTreeContainmentQualified: false,
    claimPollingAvailabilityQualified: false,
    originalOperationAutomaticallyRecovered: false,
    deployedWorkerLoopQualified: false,
    leaseRenewedAt: iso(0),
    leaseExpiresAt: iso(900000),
    nativeCompletedAt: iso(100000),
    deferredObservedAt: iso(1000000),
    deferredHeartbeatAt: iso(999000),
    terminalObservedAt: iso(4500001),
    terminalHeartbeatAt: iso(4500000),
    ...Object.fromEntries(h.FLAGS.map((f) => [f, true])),
  };
}
const candidateSha = "a".repeat(40);
function artifact(version = "2022") {
  const producer = require("../certops-windows-alive-grace"),
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
    ...reportFacts({ids: [h.SCENARIO], capabilities: [...producer.CAPABILITIES], evidenceLevel: "real-host", startedAt: stamp, finishedAt: "2026-10-15T12:00:00.000Z"}),
    suite: producer.SUITE,
    platform: "win32",
    architecture: "x64",
    nodeVersion: "v24.0.0",
    candidateSha,
    artifactQualification: "workflow-checkout-source",
    evidenceLevel: "real-host",
    startedAt: stamp,
    finishedAt: "2026-10-15T12:00:00.000Z",
    qualificationEnvironment: environment,
    fixtureSource: source(producer.SOURCE),
    fixtureSources: producer.REQUIRED_SOURCES.map(source),
    nativeWindowsAliveGrace: fixture()
  };
  return {
    kind: "host",
    suite: report.suite,
    environment: { ...environment },
    report,
  };
}
module.exports = { fixture, artifact, candidateSha };

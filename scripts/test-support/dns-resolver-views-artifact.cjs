"use strict";
// Synthetic verifier fixtures only; these objects are never execution evidence.
const fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  helper = require("../certops-dns-resolver-views");
const SUITE = "dns-routing-host",
  CANDIDATE = "a".repeat(40);
function nativeProof() {
  return {
    schemaVersion: 1,
    scope: helper.SCOPE,
    allAttempts: 2,
    recoveryAttempts: 1,
    quorumAttempts: 1,
    allForwarded: [2, 2],
    quorumForwarded: [1, 1],
    ...Object.fromEntries(helper.FLAGS.map((flag) => [flag, true])),
  };
}
function slot() {
  return require("../../docs/certops/release-qualification-matrix.json").slots.find(
    (row) => row.suite === SUITE,
  );
}
function artifact() {
  const contract = require("../../docs/certops/qualification-suites.json"),
    IDS = contract.suites[SUITE],
    CAPS = contract.requiredCapabilities[SUITE];
  const environment = {
      ...slot().environment,
      measurement: "native",
      executionSurface: "host",
    },
    startedAt = "2026-10-15T01:00:00.000Z",
    finishedAt = "2026-10-15T01:01:00.000Z";
  const source = (file) => ({
    file,
    sha256: crypto
      .createHash("sha256")
      .update(fs.readFileSync(path.resolve(__dirname, "../..", file)))
      .digest("hex"),
  });
  const report = {
    schemaVersion: 1,
    suite: SUITE,
    platform: "linux",
    architecture: "x64",
    nodeVersion: "v24.11.0",
    strict: true,
    candidateSha: CANDIDATE,
    evidenceLevel: "integration",
    status: "passed",
    startedAt,
    finishedAt,
    cleanup: { status: "passed" },
    artifactQualification: "workflow-checkout-source",
    qualificationEnvironment: environment,
    requiredScenarios: IDS,
    requiredCapabilities: CAPS,
    missingScenarios: [],
    missingCapabilities: [],
    capabilities: Object.fromEntries(
      CAPS.map((name) => [name, { available: true }]),
    ),
    scenarios: IDS.map((id) => ({
      id,
      status: "passed",
      evidenceLevel: "integration",
      startedAt,
      finishedAt,
    })),
    fixtureSource: source("scripts/certops-dns-routing-host.js"),
    fixtureSources: [...new Set([...helper.REQUIRED_SOURCES, ...require("../certops-dns-hook-interruption").REQUIRED_SOURCES])].map(source),
    nativeDnsHookInterruption: {schemaVersion:1,scope:require("../certops-dns-hook-interruption").SCOPE,interruptedExitCode:-15,cleanupRuns:2,liveProviderQualified:false,acmeCancellationQualified:false,sameNameSiblingQualified:false,fullPropagationQualified:false,...Object.fromEntries(require("../certops-dns-hook-interruption").FLAGS.map(flag=>[flag,true]))},
    nativeResolverViews: nativeProof(),
  };
  return { kind: "host", suite: SUITE, environment, report };
}
module.exports = { SUITE, CANDIDATE, nativeProof, slot, artifact };

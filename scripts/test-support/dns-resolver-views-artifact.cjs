"use strict";
const {sourceIdentity} = require("./qualification-artifact.cjs");
const {reportFacts} = require("./qualification-artifact.cjs");
// Synthetic verifier fixtures only; these objects are never execution evidence.
const helper = require("../certops-dns-resolver-views");
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
  return require("../certops-qualification-manifest").slots.find(
    (row) => row.suite === SUITE,
  );
}
function artifact() {
  const contract = require("../certops-qualification-manifest"),
    IDS = contract.suites[SUITE],
    CAPS = contract.requiredCapabilities[SUITE];
  const environment = {
      ...slot().environment,
      measurement: "native",
      executionSurface: "host",
    },
    startedAt = "2026-10-15T01:00:00.000Z",
    finishedAt = "2026-10-15T01:01:00.000Z";
  const source = file => sourceIdentity(file, true);
  const report = {
    ...reportFacts({ids: IDS, capabilities: CAPS, evidenceLevel: "integration", startedAt: startedAt, finishedAt: finishedAt}),
    suite: SUITE,
    platform: "linux",
    architecture: "x64",
    nodeVersion: "v24.11.0",
    candidateSha: CANDIDATE,
    evidenceLevel: "integration",
    startedAt,
    finishedAt,
    artifactQualification: "workflow-checkout-source",
    qualificationEnvironment: environment,
    fixtureSource: source("scripts/certops-dns-routing-host.js"),
    fixtureSources: [...new Set([...helper.REQUIRED_SOURCES, ...require("../certops-dns-hook-interruption").REQUIRED_SOURCES])].map(source),
    nativeDnsHookInterruption: {schemaVersion:1,scope:require("../certops-dns-hook-interruption").SCOPE,interruptedExitCode:-15,cleanupRuns:2,liveProviderQualified:false,acmeCancellationQualified:false,sameNameSiblingQualified:false,fullPropagationQualified:false,...Object.fromEntries(require("../certops-dns-hook-interruption").FLAGS.map(flag=>[flag,true]))},
    nativeResolverViews: nativeProof()
  };
  return { kind: "host", suite: SUITE, environment, report };
}
module.exports = { SUITE, CANDIDATE, nativeProof, slot, artifact };

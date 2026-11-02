"use strict";
const {sourceIdentity, reportFacts} = require("./qualification-artifact.cjs");
/** Offline sanitizer/strict-verifier fixture; never native execution proof. */
const helper = require("../../tests/e2e/helpers/certops-acme-browser-console");
function proof() {
  const id = (c) =>
    `${c.repeat(8)}-${c.repeat(4)}-4${c.repeat(3)}-8${c.repeat(3)}-${c.repeat(12)}`;
  const value = {
    schemaVersion: 1,
    scope: helper.SCOPE,
    client: "certbot",
    jobId: id("a"),
    certificateId: id("b"),
    claimId: id("c"),
    agentId: id("d"),
    fingerprint: "a".repeat(64),
    firstLineSha256: "b".repeat(64),
    completionLineSha256: "c".repeat(64),
    acceptedLines: 42,
    browserCertOpsWrites: 0,
    ...Object.fromEntries(helper.FLAGS.map((flag) => [flag, true])),
  };
  helper.verifyProof(value);
  return value;
}
function envelope() {
  return {
    suite: "linux-native-acme-browser-console",
    platform: "linux",
    architecture: "x64",
    qualificationEnvironment: {
      osFamily: "linux",
      measurement: "native",
      distributionId: "ubuntu",
      distributionVersion: "24.04",
      executionSurface: "host",
      libc: "glibc",
    },
    nativeAcmeBrowserConsole: proof(),
  };
}
function artifact() {
  const r = require("../certops-acme-native-console-report");
  const source = sourceIdentity;
  const base = envelope(),
    date = "2026-10-15T01:00:00.000Z";
  return {
    kind: "host",
    suite: r.SUITE,
    environment: base.qualificationEnvironment,
    report: {
 ...reportFacts({ids: [r.SCENARIO], capabilities: ["linux", "api", "browser"], evidenceLevel: "e2e", startedAt: date, finishedAt: date}),
 ...base,
candidateSha: "a".repeat(40),
nodeVersion: "v24.18.0",
evidenceLevel: "e2e",
startedAt: date,
finishedAt: date,
artifactQualification: "workflow-checkout-source",
fixtureSource: source("scripts/certops-acme-native-console.js"),
fixtureSources:
        require("../certops-acme-native-console").REQUIRED_SOURCES.map(source)
},
  };
}
function slot() {
  return require("../certops-qualification-manifest").slots.find(
    (value) => value.suite === "linux-native-acme-browser-console",
  );
}
module.exports = { proof, envelope, artifact, slot };

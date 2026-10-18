"use strict";
const {sourceIdentity, reportFacts} = require("./qualification-artifact.cjs");
/** Offline sanitizer/strict-verifier fixture; never native execution proof. */
const helper = require("../../tests/e2e/helpers/certops-acme-browser-lifecycle");
function proof() {
  const id = (c) =>
    `${c.repeat(8)}-${c.repeat(4)}-4${c.repeat(3)}-8${c.repeat(3)}-${c.repeat(12)}`;
  const value = {
    scope: helper.SCOPE,
    jobIds: [id("a"), id("c")],
    certificateId: id("b"),
    fingerprints: ["a", "b"].map((c) => c.repeat(64)),
    spkiHashes: ["c", "d"].map((c) => c.repeat(64)),
    ...Object.fromEntries(helper.FLAGS.map((flag) => [flag, true])),
  };
  helper.verifyProof(value);
  return value;
}
function envelope() {
  const discovery = require("../../tests/e2e/helpers/certops-native-file-discovery");
  return {
    suite: "linux-native-acme-browser-lifecycle",
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
    nativeAcmeBrowserLifecycle: proof(),
    nativeFileDiscoveryRefusals: {
      scope: discovery.SCOPE,
      uid: 1001,
      gid: 1002,
      positiveFingerprint: "e".repeat(64),
      negativeFingerprint: "f".repeat(64),
      positiveScanCount: 2,
      ...Object.fromEntries(discovery.FLAGS.map((flag) => [flag, true])),
    },
  };
}
function artifact() {
  const r = require("../certops-acme-browser-lifecycle-report");
  const source = sourceIdentity;
  const base = envelope(),
    date = "2026-10-15T01:00:00.000Z";
  return {
    kind: "host",
    suite: r.SUITE,
    environment: base.qualificationEnvironment,
    report: {
 ...reportFacts({ids: [r.SCENARIO, r.DISCOVERY_SCENARIO], capabilities: ["linux", "api", "browser"], evidenceLevel: "e2e", startedAt: date, finishedAt: date}),
 ...base,
candidateSha: "a".repeat(40),
nodeVersion: "v24.18.0",
evidenceLevel: "e2e",
startedAt: date,
finishedAt: date,
artifactQualification: "workflow-checkout-source",
fixtureSource: source("scripts/certops-acme-browser-lifecycle.js"),
fixtureSources:
        require("../certops-acme-browser-lifecycle").REQUIRED_SOURCES.map(
          source,
        )
},
  };
}
function slot() {
  return require("../certops-qualification-manifest").slots.find(
    (value) => value.suite === "linux-native-acme-browser-lifecycle",
  );
}
module.exports = { proof, envelope, artifact, slot };

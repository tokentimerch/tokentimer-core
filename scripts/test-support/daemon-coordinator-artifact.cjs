"use strict";
const {reportFacts} = require("./qualification-artifact.cjs");
/** Synthetic schema fixtures for offline verifier tests; never execution evidence. */
const fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const helper = require("../certops-daemon-coordinator-rollback");
const mismatch = require("../certops-daemon-served-leaf-mismatch");
const root = path.resolve(__dirname, "../..");
const SUITE = "nginx-host",
  CANDIDATE = "a".repeat(40);
const contract = require("../certops-qualification-manifest");
const IDS = contract.suites[SUITE],
  CAPS = contract.requiredCapabilities[SUITE];
function nativeProof(service = "nginx") {
  return {
    schemaVersion: 1,
    scope: helper.SCOPE,
    service,
    evidenceTransport: "read-only-local-recorder-not-signed-api",
    fingerprints: ["a", "b"].map((c) => c.repeat(64)),
    ...Object.fromEntries(helper.FLAGS.map((n) => [n, true])),
  };
}

function artifact(service = "nginx", version = "24.04") {
  const SUITE = service + "-host",
    IDS = contract.suites[SUITE],
    CAPS = contract.requiredCapabilities[SUITE];
  const environment = {
    osFamily: "linux",
    distributionId: "ubuntu",
    distributionVersion: version,
    measurement: "native",
    executionSurface: "host",
  };
  const source = (file) => ({
    file,
    sha256: crypto
      .createHash("sha256")
      .update(fs.readFileSync(path.join(root, file)))
      .digest("hex"),
  });
  const startedAt = "2026-10-15T01:00:00.000Z",
    finishedAt = "2026-10-15T01:01:00.000Z";
  const report = {
    ...reportFacts({ids: IDS, capabilities: CAPS, evidenceLevel: "real-host", startedAt: startedAt, finishedAt: finishedAt}),
    suite: SUITE,
    platform: "linux",
    architecture: "x64",
    nodeVersion: "v24.11.0",
    candidateSha: CANDIDATE,
    evidenceLevel: "real-host",
    startedAt,
    finishedAt,
    artifactQualification: "workflow-checkout-source",
    qualificationEnvironment: environment,
    fixtureSource: source("scripts/certops-nginx-host.js"),
    fixtureSources: [...new Set([...helper.REQUIRED_SOURCES,...mismatch.REQUIRED_SOURCES])].map(source),
    nativeDaemonServedLeafMismatch: {schemaVersion:1,scope:mismatch.SCOPE,service,evidenceTransport:"read-only-local-recorder-not-signed-api",fingerprints:["a","b"].map(c=>c.repeat(64)),...Object.fromEntries(mismatch.FLAGS.map(flag=>[flag,true]))},
    nativeDaemonCoordinatorRollback: nativeProof(service)
  };
  return { kind: "host", suite: SUITE, environment, report };
}
function slot(service = "nginx", version = "24.04") {
  return require("../certops-qualification-manifest").slots.find(
    (row) =>
      row.suite === service + "-host" &&
      row.environment.distributionVersion === version,
  );
}

module.exports = { artifact, slot, nativeProof, SUITE, CANDIDATE, IDS, CAPS };

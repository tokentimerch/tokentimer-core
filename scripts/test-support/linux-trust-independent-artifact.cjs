"use strict";
/** Synthetic schema fixtures for offline verifier tests; never execution evidence. */
const fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const helper = require("../certops-linux-trust-independent-roots");
const root = path.resolve(__dirname, "../..");
const SUITE = "linux-trust-host",
  CANDIDATE = "a".repeat(40);
const contract = require("../../docs/certops/qualification-suites.json");
const IDS = contract.suites[SUITE],
  CAPS = contract.requiredCapabilities[SUITE];
function nativeProof(version = "24.04") {
  return {
    schemaVersion: 1,
    scope: helper.SCOPE,
    family: version === "9.6" ? "rhel" : "debian",
    derivedReferenceKind:
      version === "9.6"
        ? "native-derived-certificate"
        : "native-source-symlink",
    rootFingerprints: ["a", "b"].map((c) => c.repeat(64)),
    leafFingerprints: ["c", "d"].map((c) => c.repeat(64)),
    ...Object.fromEntries(helper.FLAGS.map((n) => [n, true])),
  };
}

function artifact(version = "24.04") {
  const environment = {
    osFamily: "linux",
    distribution: version === "9.6" ? "almalinux" : "ubuntu",
    osVersion: version,
    measurement: "native",
    executionSurface:
      version === "9.6" ? "disposable-container" : "disposable-vm",
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
    schemaVersion: 1,
    suite: SUITE,
    platform: "linux",
    architecture: "x64",
    nodeVersion: "v24.11.0",
    strict: true,
    candidateSha: CANDIDATE,
    evidenceLevel: "real-host",
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
      evidenceLevel: "real-host",
      startedAt,
      finishedAt,
    })),
    fixtureSource: source("scripts/certops-linux-trust.js"),
    fixtureSources: helper.REQUIRED_SOURCES.map(source),
    nativeIndependentTrustRoots: nativeProof(version),
  };
  return { kind: "host", suite: SUITE, environment, report };
}
function slot(version = "24.04") {
  return require("../../docs/certops/release-qualification-matrix.json").slots.find(
    (row) => row.suite === SUITE && row.environment.osVersion === version,
  );
}

module.exports = { artifact, slot, nativeProof, SUITE, CANDIDATE, IDS, CAPS };

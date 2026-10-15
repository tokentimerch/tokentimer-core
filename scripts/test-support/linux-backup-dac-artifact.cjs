"use strict";
/** Synthetic schema fixtures for offline verifier tests; never execution evidence. */
const fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const helper = require("../certops-linux-filesystem-permission");
const root = path.resolve(__dirname, "../..");
const SUITE = "filesystem-linux-backup-dac-host",
  CANDIDATE = "a".repeat(40);
const IDS = [
  "filesystem-linux-nonroot-backup-dac-refusal",
  "filesystem-linux-backup-dac-cleanup",
];
const CAPS = ["native-linux-nonroot-dac", "openssl-key-oracle"];
function nativeProof() {
  return {
    schemaVersion: 1,
    scope: "native-linux-nonroot-backup-dac-refusal",
    uid: 65534,
    gid: 65534,
    ...Object.fromEntries(helper.FLAGS.map((name) => [name, true])),
  };
}
function artifact(version = "24.04") {
  const environment = {
    osFamily: "linux",
    distributionId: "ubuntu",
    distributionVersion: version,
    measurement: "native",
    executionSurface: "disposable-vm",
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
    fixtureSource: source("scripts/certops-linux-filesystem-permission.js"),
    fixtureSources: helper.REQUIRED_SOURCES.map(source),
    nativeLinuxBackupDac: nativeProof(),
  };
  return { kind: "host", suite: SUITE, environment, report };
}
function slot(version = "24.04") {
  return {
    id: `filesystem-linux-backup-dac-${version}`,
    kind: "host",
    suite: SUITE,
    source: "scripts/certops-linux-filesystem-permission.js",
    requiredSources: [...helper.REQUIRED_SOURCES],
    environment: {
      osFamily: "linux",
      distributionId: "ubuntu",
      distributionVersion: version,
      executionSurface: "disposable-vm",
    },
  };
}
module.exports = { artifact, slot, nativeProof, SUITE, CANDIDATE, IDS, CAPS };

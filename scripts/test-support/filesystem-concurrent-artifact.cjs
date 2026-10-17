"use strict";
/** Synthetic schema fixtures for offline verifier tests; never execution evidence. */
const fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const helper = require("../certops-filesystem-concurrent");
const root = path.resolve(__dirname, "../..");
const SUITE = "filesystem-host",
  CANDIDATE = "a".repeat(40);
const contract = require("../../docs/certops/qualification-suites.json");
const IDS = contract.suites[SUITE],
  CAPS = contract.requiredCapabilities[SUITE];
function nativeProof() {
  return {
    schemaVersion: 1,
    scope: helper.SCOPE,
    processScope: "one-native-node-process",
    contenderCount: 2,
    completedMutations: 2,
    backupNamespaces: "default-alongside-target",
    fingerprints: ["a", "b", "c"].map((c) => c.repeat(64)),
    spkiFingerprints: ["d", "e", "f"].map((c) => c.repeat(64)),
    completionOrder: ["contender-b", "contender-c"],
    backupPredecessors: ["a", "b"].map((c) => c.repeat(64)),
    servedBeforeFingerprint: "a".repeat(64),
    servedAfterFingerprint: "c".repeat(64),
    ...Object.fromEntries(helper.FLAGS.map((name) => [name, true])),
  };
}
function artifact(version = "24.04") {
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
    fixtureSource: source("scripts/certops-filesystem-host.js"),
    fixtureSources:
      require("../certops-filesystem-host").ROLLBACK_SOURCES.map(
        source,
      ),
    nativeFilesystemBackupRetention: {
      schemaVersion: 1,
      scope: require("../certops-filesystem-backup-retention").SCOPE,
      retentionCount: 1,
      targetCount: 2,
      actualRotations: 4,
      fingerprints: ["a", "b", "c"].map((c) => c.repeat(64)),
      ...Object.fromEntries(
        require("../certops-filesystem-backup-retention").FLAGS.map((n) => [
          n,
          true,
        ]),
      ),
    },
    nativeFilesystemConcurrency: nativeProof(),
    nativeFilesystemPairedRollback: {
      schemaVersion: 1,
      scope: require("../certops-filesystem-host").ROLLBACK_SCOPE,
      fingerprints: ["a", "b"].map(c => c.repeat(64)),
      ...Object.fromEntries(require("../certops-filesystem-host").ROLLBACK_FLAGS.map(flag => [flag, true])),
    },
    nativeFilesystemBackupAlias: {
      schemaVersion: 1,
      scope: "native-filesystem-explicit-backup-directory-alias-refusal",
      aliasKind: "symlink",
      refusalStage: "realpath-policy",
      fingerprints: ["a", "b"].map((c) => c.repeat(64)),
      ...Object.fromEntries(
        require("../certops-filesystem-backup-alias").FLAGS.map((n) => [
          n,
          true,
        ]),
      ),
    },
  };
  return { kind: "host", suite: SUITE, environment, report };
}
function slot(version = "24.04") {
  return {
    id: `filesystem-linux-${version}`,
    kind: "host",
    suite: SUITE,
    source: "scripts/certops-filesystem-host.js",
    requiredSources: [
      ...require("../certops-filesystem-host").ROLLBACK_SOURCES,
    ],
    environment: {
      osFamily: "linux",
      distributionId: "ubuntu",
      distributionVersion: version,
      executionSurface: "host",
    },
  };
}
module.exports = { artifact, slot, nativeProof, SUITE, CANDIDATE, IDS, CAPS };

"use strict";
/** Synthetic contract fixture only; never native execution evidence. */
const h = require("../../tests/e2e/helpers/certops-windows-installed-failed-rollback");
const {
  fixture,
} = require("../fixtures/certops-windows-installed-failed-rollback.cjs");
const candidateSha = "a".repeat(40);
function artifact(version = "2022") {
  const producer = require("../certops-windows-failed-rollback"),
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
    schemaVersion: 1,
    suite: producer.SUITE,
    strict: true,
    platform: "win32",
    architecture: "x64",
    nodeVersion: "v24.0.0",
    candidateSha,
    artifactQualification: "workflow-checkout-source",
    evidenceLevel: "real-host",
    status: "passed",
    startedAt: stamp,
    finishedAt: "2026-10-15T12:00:00.000Z",
    cleanup: { status: "passed" },
    requiredScenarios: [h.SCENARIO],
    requiredCapabilities: [...producer.CAPABILITIES],
    missingScenarios: [],
    missingCapabilities: [],
    capabilities: Object.fromEntries(
      producer.CAPABILITIES.map((x) => [x, { available: true }]),
    ),
    scenarios: [
      {
        id: h.SCENARIO,
        status: "passed",
        evidenceLevel: "real-host",
        startedAt: stamp,
        finishedAt: "2026-10-15T12:00:00.000Z",
      },
    ],
    qualificationEnvironment: environment,
    fixtureSource: source(producer.SOURCE),
    fixtureSources: producer.REQUIRED_SOURCES.map(source),
    nativeInstalledFailedRollback: fixture(),
  };
  return {
    kind: "host",
    suite: report.suite,
    environment: { ...environment },
    report,
  };
}
module.exports = { fixture, artifact, candidateSha };

"use strict";
/** Synthetic verifier fixtures only. This module never produces host execution evidence. */
function reportFacts({
  ids,
  capabilities,
  evidenceLevel,
  startedAt,
  finishedAt,
}) {
  return {
    schemaVersion: 1,
    strict: true,
    status: "passed",
    cleanup: { status: "passed" },
    requiredScenarios: ids,
    requiredCapabilities: capabilities,
    missingScenarios: [],
    missingCapabilities: [],
    capabilities: Object.fromEntries(
      capabilities.map((name) => [name, { available: true }]),
    ),
    scenarios: ids.map((id) => ({
      id,
      status: "passed",
      evidenceLevel,
      startedAt,
      finishedAt,
    })),
  };
}
function matrixErrors(value, slot, candidateSha) {
  return require("../certops-release-qualification").verifyMatrix([value], {
    candidateSha,
    specification: { schemaVersion: 1, slots: [slot] },
  });
}
module.exports = { reportFacts, matrixErrors, sourceIdentity, windowsArtifact };

// No digest cache: every artifact remains bound to the current source bytes.
function sourceIdentity(file, resolve = false) {
  const fs = require("node:fs"),
    path = require("node:path"),
    crypto = require("node:crypto");
  const root = path.resolve(__dirname, "../..");
  return {
    file,
    sha256: crypto
      .createHash("sha256")
      .update(
        fs.readFileSync(
          resolve ? path.resolve(root, file) : path.join(root, file),
        ),
      )
      .digest("hex"),
  };
}

// Shared installed-host envelope; every actor supplies its original proof factory.
function windowsArtifact(
  producer,
  h,
  fixture,
  field,
  version,
  finishedAt,
  candidateSha,
) {
  const source = (file) => sourceIdentity(file, true);
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
    ...reportFacts({
      ids: [h.SCENARIO],
      capabilities: [...producer.CAPABILITIES],
      evidenceLevel: "real-host",
      startedAt: stamp,
      finishedAt: finishedAt,
    }),
    suite: producer.SUITE,
    platform: "win32",
    architecture: "x64",
    nodeVersion: "v24.0.0",
    candidateSha,
    artifactQualification: "workflow-checkout-source",
    evidenceLevel: "real-host",
    startedAt: stamp,
    finishedAt: finishedAt,
    qualificationEnvironment: environment,
    fixtureSource: source(producer.SOURCE),
    fixtureSources: producer.REQUIRED_SOURCES.map(source),
    [field]: fixture(),
  };
  return {
    kind: "host",
    suite: report.suite,
    environment: { ...environment },
    report,
  };
}

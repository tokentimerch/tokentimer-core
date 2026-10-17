"use strict";
/** Synthetic schema fixture. Manual workflow_dispatch only. Not native execution evidence. */
const crypto = require("node:crypto"),
  fs = require("node:fs"),
  path = require("node:path"),
  h = require("../certops-linux-signed-trust-proof");
const CANDIDATE = "a".repeat(40);
function nativeProof() {
  return {
    scope: h.SUITE,
    workspaceId: "00000000-0000-4000-8000-000000000001",
    agentId: "00000000-0000-4000-8000-000000000002",
    anchorIds: [3, 4].map(
      (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`,
    ),
    jobIds: [5, 6, 7, 8].map(
      (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`,
    ),
    claimIds: [9, 10, 11, 12].map(
      (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`,
    ),
    fingerprints: ["b".repeat(64), "c".repeat(64)],
    backgroundReconciliationQualified: false,
    ...Object.fromEntries(h.FLAGS.map((f) => [f, true])),
  };
}
function artifact() {
  const environment = {
      osFamily: "linux",
      distribution: "ubuntu",
      osVersion: "24.04",
      measurement: "native",
      executionSurface: "disposable-vm",
    },
    startedAt = "2026-10-15T01:00:00.000Z",
    finishedAt = "2026-10-15T01:01:00.000Z",
    caps = ["root-native-trust", "real-api"],
    source = (file) => ({
      file,
      sha256: crypto
        .createHash("sha256")
        .update(fs.readFileSync(path.resolve(__dirname, "../..", file)))
        .digest("hex"),
    });
  return {
    kind: "host",
    suite: h.SUITE,
    environment,
    report: {
      schemaVersion: 1,
      suite: h.SUITE,
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
      requiredScenarios: h.SCENARIOS,
      requiredCapabilities: caps,
      missingScenarios: [],
      missingCapabilities: [],
      capabilities: Object.fromEntries(
        caps.map((c) => [c, { available: true }]),
      ),
      scenarios: h.SCENARIOS.map((id) => ({
        id,
        status: "passed",
        evidenceLevel: "real-host",
        startedAt,
        finishedAt,
      })),
      fixtureSource: source("scripts/certops-linux-signed-trust.js"),
      fixtureSources: h.REQUIRED_SOURCES.map(source),
      [h.FIELD]: nativeProof(),
    },
  };
}
module.exports = { CANDIDATE, nativeProof, artifact };

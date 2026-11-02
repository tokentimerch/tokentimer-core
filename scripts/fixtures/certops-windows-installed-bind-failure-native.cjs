"use strict";
// Synthetic proof fixture only; never measured native execution.
const crypto=require('node:crypto'),helper=require('../../tests/e2e/helpers/certops-windows-installed-bind-failure-native');
const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
function receipt() {
  const originalArgv = ["http", "add", "sslcert", "hostnameport=owned.example.test:443", "certhash=" + "B".repeat(40), "appid={11111111-1111-4111-8111-111111111111}", "certstorename=My"];
  return { jobId: "11111111-1111-4111-8111-111111111111", selector: "owned.example.test:443", candidateThumbprint: "B".repeat(40), predecessorThumbprint: "A".repeat(40), candidateFingerprintSha256: "b".repeat(64), predecessorFingerprintSha256: "a".repeat(64), seedExitCode: 0, forwardedExitCode: 1, nativeErrorCode: 183, originalArgv, originalArgvSha256: sha(JSON.stringify(originalArgv)), systemNetshSha256: "c".repeat(64), nativeChildrenDrained: true, captureOverflow: false, drainFailure: false, certificateStoreModified: false };
}

function proof() {
  return { scope: helper.SCOPE, certificateId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", jobIds: [receipt().jobId, "22222222-2222-4222-8222-222222222222"], claimIds: ["33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444"], fingerprints: ["a".repeat(64), "b".repeat(64), "d".repeat(64)], spkiFingerprints: ["e".repeat(64), "f".repeat(64), "1".repeat(64)], failedJobStatus: "failed", failureCode: "BIND_FAILED", rolledBack: true, retryJobStatus: "succeeded", bindFailureQualified: true, rollbackFailureQualified: false, expiryCleanupQualified: false, transientNewBindingObservationQualified: false, appIdPreservationQualified: false, nativeInterposer: receipt(), serviceEnvironmentRestored: true, ...Object.fromEntries(helper.FLAGS.map(flag => [flag, true])) };
}

const h=helper;
const fixture=proof;
const candidateSha = "a".repeat(40);
function artifact(version = "2022") {
  const producer = require("../certops-windows-bind-failure-native"),
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
    nativeInstalledBindFailure: fixture(),
  };
  return {
    kind: "host",
    suite: report.suite,
    environment: { ...environment },
    report,
  };
}

module.exports={fixture:proof,nativeReceipt:receipt,artifact};

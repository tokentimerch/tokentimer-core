"use strict";
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
  const fs = require("node:fs"),
    path = require("node:path"),
    crypto = require("node:crypto"),
    r = require("../certops-acme-native-console-report");
  const root = path.resolve(__dirname, "../.."),
    source = (file) => ({
      file,
      sha256: crypto
        .createHash("sha256")
        .update(fs.readFileSync(path.join(root, file)))
        .digest("hex"),
    });
  const base = envelope(),
    date = "2026-10-15T01:00:00.000Z";
  return {
    kind: "host",
    suite: r.SUITE,
    environment: base.qualificationEnvironment,
    report: {
      ...base,
      schemaVersion: 1,
      strict: true,
      candidateSha: "a".repeat(40),
      nodeVersion: "v24.18.0",
      evidenceLevel: "e2e",
      status: "passed",
      startedAt: date,
      finishedAt: date,
      artifactQualification: "workflow-checkout-source",
      cleanup: { status: "passed" },
      requiredScenarios: [r.SCENARIO],
      missingScenarios: [],
      requiredCapabilities: ["linux", "api", "browser"],
      missingCapabilities: [],
      capabilities: {
        linux: { available: true },
        api: { available: true },
        browser: { available: true },
      },
      scenarios: [
        {
          id: r.SCENARIO,
          status: "passed",
          evidenceLevel: "e2e",
          startedAt: date,
          finishedAt: date,
        },
      ],
      fixtureSource: source("scripts/certops-acme-native-console.js"),
      fixtureSources:
        require("../certops-acme-native-console").REQUIRED_SOURCES.map(source),
    },
  };
}
function slot() {
  return require("../../docs/certops/release-qualification-matrix.json").slots.find(
    (value) => value.suite === "linux-native-acme-browser-console",
  );
}
module.exports = { proof, envelope, artifact, slot };

"use strict";
/** Offline strict-verifier fixture, never a native systemd execution receipt. */
const helper = require("../../tests/e2e/helpers/certops-linux-installed-discovery");
function proof() {
  const value = {
    scope: helper.SCOPE,
    uid: 1001,
    gid: 1002,
    fingerprint: "b".repeat(64),
    positiveScanCount: 2,
    ...Object.fromEntries(helper.FLAGS.map((flag) => [flag, true])),
  };
  helper.verifyProof(value);
  return value;
}
function artifact(version = "24.04") {
  const fs = require("node:fs"),
    path = require("node:path"),
    crypto = require("node:crypto");
  const root = path.resolve(__dirname, "../.."),
    source = (file) => ({
      file,
      sha256: crypto
        .createHash("sha256")
        .update(fs.readFileSync(path.join(root, file)))
        .digest("hex"),
    });
  const date = "2026-10-15T10:00:00.000Z",
    environment = {
      osFamily: "linux",
      measurement: "native",
      distributionId: "ubuntu",
      distributionVersion: version,
      executionSurface: "host",
    };
  return {
    kind: "host",
    suite: "linux-installed-file-discovery",
    environment,
    report: {
      schemaVersion: 1,
      suite: "linux-installed-file-discovery",
      strict: true,
      candidateSha: "a".repeat(40),
      nodeVersion: "v24.18.0",
      platform: "linux",
      architecture: "x64",
      evidenceLevel: "real-host",
      status: "passed",
      startedAt: date,
      finishedAt: date,
      artifactQualification: "workflow-checkout-source",
      qualificationEnvironment: environment,
      cleanup: { status: "passed" },
      requiredScenarios: ["linux-installed-systemd-public-discovery"],
      missingScenarios: [],
      requiredCapabilities: ["linux", "systemd", "api", "openssl"],
      missingCapabilities: [],
      capabilities: Object.fromEntries(
        ["linux", "systemd", "api", "openssl"].map((capability) => [
          capability,
          { available: true },
        ]),
      ),
      scenarios: [
        {
          id: "linux-installed-systemd-public-discovery",
          status: "passed",
          evidenceLevel: "real-host",
          startedAt: date,
          finishedAt: date,
        },
      ],
      nativeInstalledFileDiscovery: proof(),
      fixtureSource: source(
        "tests/e2e/helpers/certops-linux-installed-discovery.js",
      ),
      fixtureSources: helper.REQUIRED_SOURCES.map(source),
    },
  };
}
module.exports = { proof, artifact };

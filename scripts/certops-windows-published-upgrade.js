"use strict";
const {createHostContractCli} = require("./certops-qualification-report");

/** Host entry for published-package upgrade refusal. A published predecessor
 * without a service host fails closed. This entry does not synthesize an
 * upgrade. */

const fs = require("node:fs");
const helper = require("../tests/e2e/helpers/certops-windows-published-upgrade");

function probeHost() {
  if (process.platform !== "win32") {
    return { windows: false, publishedArchive: false, serviceHostInArchive: false };
  }
  return { windows: true, publishedArchive: false, serviceHostInArchive: false };
}

function run({ probe, execute, manifest, members } = {}) {
  const gate = helper.assessHostCapabilities(probe);
  if (!gate.available) {
    return {
      passed: false,
      nativeQualified: false,
      publishedPackageMigrationQualified: false,
      reason: "host capability absent",
      missing: gate.missing,
    };
  }
  if (execute !== true) {
    return {
      passed: false,
      nativeQualified: false,
      publishedPackageMigrationQualified: false,
      reason: "host execution not requested",
    };
  }
  if (!manifest) {
    return {
      passed: false,
      nativeQualified: false,
      publishedPackageMigrationQualified: false,
      reason: "published archive absent",
    };
  }
  const result = helper.inspectPublishedArchive(manifest, members || []);
  return {
    passed: false,
    nativeQualified: false,
    planSafe: true,
    publishedPackageMigrationQualified: false,
    proof: result.proof,
    reason: "published predecessor archives lack service-host executables",
  };
}

function checkArchive(file) {
  const body = JSON.parse(fs.readFileSync(file, "utf8"));
  const manifest = helper.createRunManifest(body);
  const result = helper.inspectPublishedArchive(manifest, body.members || []);
  return {
    passed: false,
    nativeQualified: false,
    publishedPackageMigrationQualified: false,
    planSafe: true,
    proof: result.proof,
  };
}

const main = createHostContractCli({
  option: "--check", check: checkArchive, run: run, probeHost: probeHost,
  executeEnv: "CERTOPS_WINDOWS_PUBLISHED_UPGRADE_EXECUTE", failureFlags: {publishedPackageMigrationQualified: false},
});

if (require.main === module) main();

module.exports = { run, probeHost, checkArchive, main };

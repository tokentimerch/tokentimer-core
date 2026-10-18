"use strict";
const {createHostContractCli} = require("./certops-qualification-report");

/** Host entry for a full-installer second-rename failure. A missing installer
 * host fails closed. Leaving the original name is not a native pass. */

const fs = require("node:fs");
const helper = require("../tests/e2e/helpers/certops-windows-second-rename");

function probeHost() {
  if (process.platform !== "win32") {
    return { windows: false, installer: false, ownedTarget: false };
  }
  return { windows: true, installer: false, ownedTarget: false };
}

function run({ probe, execute, manifest } = {}) {
  const gate = helper.assessLocalHost(probe);
  if (!gate.available) {
    return {
      passed: false,
      nativeQualified: false,
      reason: "host capability absent",
      missing: gate.missing,
    };
  }
  if (execute !== true) {
    return { passed: false, nativeQualified: false, reason: "host execution not requested" };
  }
  if (!manifest) {
    return { passed: false, nativeQualified: false, reason: "owned rename manifest absent" };
  }
  const result = helper.applySecondRenameFailure(manifest);
  return {
    passed: false,
    nativeQualified: false,
    planSafe: true,
    proof: result.proof,
    reason: "script contract does not claim native execution",
  };
}

function checkManifest(file) {
  const body = JSON.parse(fs.readFileSync(file, "utf8"));
  const manifest = helper.createRunManifest(body);
  if (Array.isArray(body.extraCommands)) helper.assertNoInUseDeletion(manifest, body.extraCommands);
  const result = helper.applySecondRenameFailure(manifest);
  return { passed: false, nativeQualified: false, planSafe: true, proof: result.proof };
}

const main = createHostContractCli({
  option: "--check", check: checkManifest, run: run, probeHost: probeHost,
  executeEnv: "CERTOPS_WINDOWS_SECOND_RENAME_EXECUTE",
});

if (require.main === module) main();

module.exports = { run, probeHost, checkManifest, main };

"use strict";
const {createHostContractCli} = require("./certops-qualification-report");

/** Host entry for protected-key journal recovery. A missing journal host fails
 * closed. Fail-closed preservation does not delete the protected key and does
 * not claim native execution. */

const fs = require("node:fs");
const helper = require("../tests/e2e/helpers/certops-windows-protected-recovery");

function probeHost() {
  if (process.platform !== "win32") {
    return { windows: false, journal: false, protectedKey: false, ownedTarget: false };
  }
  return { windows: true, journal: false, protectedKey: false, ownedTarget: false };
}

function run({ probe, execute, manifest, defect } = {}) {
  const gate = helper.assessHostCapabilities(probe);
  if (!gate.available) {
    return { passed: false, nativeQualified: false, reason: "host capability absent", missing: gate.missing };
  }
  if (execute !== true) {
    return { passed: false, nativeQualified: false, reason: "host execution not requested" };
  }
  if (!manifest || !defect) {
    return { passed: false, nativeQualified: false, reason: "protected recovery defect absent" };
  }
  const result = helper.failClosed(manifest, defect);
  return {
    passed: false,
    nativeQualified: false,
    planSafe: true,
    proof: result.proof,
    reason: "fail closed recovery does not claim native execution",
  };
}

function checkDefect(file) {
  const body = JSON.parse(fs.readFileSync(file, "utf8"));
  const manifest = helper.createRunManifest(body);
  if (Array.isArray(body.extraCommands)) helper.assertNoProtectedKeyDeletion(manifest, body.extraCommands);
  const result = helper.failClosed(manifest, body.defect);
  return { passed: false, nativeQualified: false, planSafe: true, proof: result.proof };
}

const main = createHostContractCli({
  option: "--check", check: checkDefect, run: run, probeHost: probeHost,
  executeEnv: "CERTOPS_WINDOWS_PROTECTED_RECOVERY_EXECUTE",
});

if (require.main === module) main();

module.exports = { run, probeHost, checkDefect, main };

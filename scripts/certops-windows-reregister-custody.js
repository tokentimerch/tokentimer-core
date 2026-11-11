"use strict";
const {createHostContractCli} = require("./certops-qualification-report");

/** Host entry for installed-service re-registration. A missing custody host
 * fails closed. Keeping the same CNG container is not a native pass. */

const fs = require("node:fs");
const helper = require("../tests/e2e/helpers/certops-windows-reregister-custody");

function probeHost() {
  if (process.platform !== "win32") {
    return { windows: false, serviceControl: false, cngCustody: false, ownedTarget: false };
  }
  return { windows: true, serviceControl: false, cngCustody: false, ownedTarget: false };
}

function run({ probe, execute, manifest, request } = {}) {
  const gate = helper.assessHostCapabilities(probe);
  if (!gate.available) {
    return { passed: false, nativeQualified: false, reason: "host capability absent", missing: gate.missing };
  }
  if (execute !== true) {
    return { passed: false, nativeQualified: false, reason: "host execution not requested" };
  }
  if (!manifest || !request) {
    return { passed: false, nativeQualified: false, reason: "owned custody request absent" };
  }
  const result = helper.reRegister(manifest, request);
  return {
    passed: false,
    nativeQualified: false,
    planSafe: true,
    proof: result.proof,
    reason: "script contract does not claim native execution",
  };
}

function checkCustody(file) {
  const body = JSON.parse(fs.readFileSync(file, "utf8"));
  const manifest = helper.createRunManifest(body);
  if (Array.isArray(body.extraCommands)) helper.assertNoInUseKeyDeletion(manifest, body.extraCommands);
  const result = helper.reRegister(manifest, body.request);
  return { passed: false, nativeQualified: false, planSafe: true, proof: result.proof };
}

const main = createHostContractCli({
  option: "--check", check: checkCustody, run: run, probeHost: probeHost,
  executeEnv: "CERTOPS_WINDOWS_REREGISTER_CUSTODY_EXECUTE",
});

if (require.main === module) main();

module.exports = { run, probeHost, checkCustody, main };

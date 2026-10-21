"use strict";
const {createHostContractCli} = require("./certops-qualification-report");

/** Host entry for ACL, path, and environment refusals. A missing host fails
 * closed. A refusal is not a native pass. */

const fs = require("node:fs");
const helper = require("../tests/e2e/helpers/certops-windows-acl-path-env");

function probeHost() {
  if (process.platform !== "win32") {
    return { windows: false, acl: false, quotedPath: false, systemEnvironment: false };
  }
  return { windows: true, acl: false, quotedPath: false, systemEnvironment: false };
}

function refuse(manifest, body) {
  if (body.refusal === "weak-acl") return helper.refuseWeakAcl(manifest, body.acl);
  if (body.refusal === "unquoted-path") return helper.refuseUnquotedPath(manifest, body.path);
  if (body.refusal === "missing-system-environment") {
    return helper.refuseMissingSystemEnvironment(manifest, body.environment);
  }
  throw new Error("unknown ACL path environment refusal");
}

function run({ probe, execute, manifest, body } = {}) {
  const gate = helper.assessHostCapabilities(probe);
  if (!gate.available) {
    return { passed: false, nativeQualified: false, reason: "host capability absent", missing: gate.missing };
  }
  if (execute !== true) {
    return { passed: false, nativeQualified: false, reason: "host execution not requested" };
  }
  if (!manifest || !body) {
    return { passed: false, nativeQualified: false, reason: "owned refusal absent" };
  }
  const result = refuse(manifest, body);
  return {
    passed: false,
    nativeQualified: false,
    planSafe: true,
    proof: result.proof,
    reason: "refusal is not native qualification",
  };
}

function checkRefusal(file) {
  const body = JSON.parse(fs.readFileSync(file, "utf8"));
  const manifest = helper.createRunManifest(body);
  if (Array.isArray(body.extraCommands)) helper.assertOwnedCommands(manifest, body.extraCommands);
  const result = refuse(manifest, body);
  return { passed: false, nativeQualified: false, planSafe: true, proof: result.proof };
}

const main = createHostContractCli({
  option: "--check", check: checkRefusal, run: run, probeHost: probeHost,
  executeEnv: "CERTOPS_WINDOWS_ACL_PATH_ENV_EXECUTE",
});

if (require.main === module) main();

module.exports = { run, probeHost, checkRefusal, main };

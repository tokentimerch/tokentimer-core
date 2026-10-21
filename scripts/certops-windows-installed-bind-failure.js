"use strict";
const {createHostContractCli} = require("./certops-qualification-report");

/** Host entry for the bind-failure script proof. The capability gate and the
 * execute gate both fail closed. A plan check can call the owned-command
 * guard, and that result is still not a native qualification pass. */

const fs = require("node:fs");
const bind = require("../tests/e2e/helpers/certops-windows-installed-bind-failure");

function probeHost() {
  if (process.platform !== "win32") {
    return { windows: false, iis: false, netsh: false, appcmd: false };
  }
  const root = process.env.SystemRoot || "C:\\Windows";
  const netsh = `${root}\\System32\\netsh.exe`;
  const appcmd = `${root}\\System32\\inetsrv\\appcmd.exe`;
  let netshPresent = false;
  let appcmdPresent = false;
  try {
    netshPresent = fs.existsSync(netsh);
    appcmdPresent = fs.existsSync(appcmd);
  } catch {
    netshPresent = false;
    appcmdPresent = false;
  }
  return {
    windows: true,
    iis: appcmdPresent,
    netsh: netshPresent,
    appcmd: appcmdPresent,
  };
}

function run({ probe, execute, plan } = {}) {
  const gate = bind.assessHostCapabilities(probe);
  if (!gate.available) {
    return {
      passed: false,
      nativeQualified: false,
      reason: "host capability absent",
      missing: gate.missing,
    };
  }
  if (execute !== true) {
    return {
      passed: false,
      nativeQualified: false,
      reason: "host execution not requested",
    };
  }
  if (!plan) {
    return {
      passed: false,
      nativeQualified: false,
      reason: "host executor absent",
    };
  }
  bind.assertOwnedPlan(plan.manifest, plan);
  return {
    passed: false,
    nativeQualified: false,
    planSafe: true,
    reason: "native bind-failure execution is not claimed by the script proof",
  };
}

function checkPlan(file) {
  const plan = JSON.parse(fs.readFileSync(file, "utf8"));
  bind.assertOwnedPlan(plan.manifest, plan);
  return { planSafe: true, nativeQualified: false, passed: false };
}

const main = createHostContractCli({
  option: "--check-plan", check: checkPlan, run: run, probeHost: probeHost,
  executeEnv: "CERTOPS_WINDOWS_BIND_FAILURE_EXECUTE",
});

if (require.main === module) main();

module.exports = { run, probeHost, checkPlan, main };

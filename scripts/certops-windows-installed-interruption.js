"use strict";
const {createHostContractCli} = require("./certops-qualification-report");

/** Host entry for deterministic interruption recovery. A missing service or
 * process-control host fails closed. Checking a recorded point is not a
 * native pass, a power-loss result, or a reboot result. */

const fs = require("node:fs");
const recovery = require("../tests/e2e/helpers/certops-windows-installed-interruption");

function probeHost() {
  if (process.platform !== "win32") {
    return {
      windows: false,
      serviceControl: false,
      processControl: false,
      ownedTarget: false,
    };
  }
  const root = process.env.SystemRoot || "C:\\Windows";
  let serviceControl = false;
  let processControl = false;
  try {
    serviceControl = fs.existsSync(`${root}\\System32\\sc.exe`);
    processControl = fs.existsSync(`${root}\\System32\\taskkill.exe`);
  } catch {
    serviceControl = false;
    processControl = false;
  }
  // sc.exe existing on a developer machine is not the owned service or pid.
  return {
    windows: true,
    serviceControl,
    processControl,
    ownedTarget: false,
  };
}

function run({ probe, execute, point, bytes } = {}) {
  const gate = recovery.assessHostCapabilities(probe);
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
  if (!point || !bytes) {
    return {
      passed: false,
      nativeQualified: false,
      reason: "recorded interruption point absent",
    };
  }
  const commands = recovery.buildInterruptionPlan(point);
  recovery.recover({ point, bytes, commands });
  return {
    passed: false,
    nativeQualified: false,
    planSafe: true,
    reason: "host-integration script contract only; native execution is not claimed",
  };
}

function checkPoint(file) {
  const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  const bytes = Buffer.from(parsed.payload, "base64");
  const commands = recovery.buildInterruptionPlan(parsed.point);
  recovery.recover({ point: parsed.point, bytes, commands });
  return {
    planSafe: true,
    nativeQualified: false,
    passed: false,
    evidenceLevel: recovery.EVIDENCE_LEVEL,
    powerLossDurabilityQualified: false,
    realRebootQualified: false,
  };
}

const main = createHostContractCli({
  option: "--check-point", check: checkPoint, run: run, probeHost: probeHost,
  executeEnv: "CERTOPS_WINDOWS_INTERRUPTION_EXECUTE",
});

if (require.main === module) main();

module.exports = { run, probeHost, checkPoint, main };

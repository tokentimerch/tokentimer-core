"use strict";

/** Host entry for certificate-operation interruption. A missing service or
 * process-control host fails closed. Startup of the same owned target is not
 * power-loss durability and it is not a reboot. */

const fs = require("node:fs");
const helper = require("../tests/e2e/helpers/certops-windows-operation-interruption");

function probeHost() {
  if (process.platform !== "win32") {
    return { windows: false, serviceControl: false, processControl: false, ownedTarget: false };
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
  return { windows: true, serviceControl, processControl, ownedTarget: false };
}

function run({ probe, execute, point, bytes } = {}) {
  const gate = helper.assessHostCapabilities(probe);
  if (!gate.available) {
    return { passed: false, nativeQualified: false, reason: "host capability absent", missing: gate.missing };
  }
  if (execute !== true) {
    return { passed: false, nativeQualified: false, reason: "host execution not requested" };
  }
  if (!point || !bytes) {
    return { passed: false, nativeQualified: false, reason: "recorded interruption point absent" };
  }
  const commands = helper.buildInterruptionPlan(point);
  const result = helper.recover({ point, bytes, commands });
  return {
    passed: false,
    nativeQualified: false,
    planSafe: true,
    proof: result.proof,
    powerLossDurabilityQualified: false,
    realRebootQualified: false,
    reason: "host-integration script contract only; native execution is not claimed",
  };
}

function checkPoint(file) {
  const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  const bytes = Buffer.from(parsed.payload, "base64");
  const commands = helper.buildInterruptionPlan(parsed.point);
  const result = helper.recover({ point: parsed.point, bytes, commands });
  return {
    passed: false,
    nativeQualified: false,
    planSafe: true,
    proof: result.proof,
    powerLossDurabilityQualified: false,
    realRebootQualified: false,
  };
}

function main() {
  try {
    if (process.argv[2] === "--check") {
      process.stdout.write(`${JSON.stringify(checkPoint(process.argv[3]))}\n`);
      return;
    }
    const result = run({
      probe: probeHost(),
      execute: process.env.CERTOPS_WINDOWS_OPERATION_INTERRUPTION_EXECUTE === "1",
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    process.exitCode = 1;
  } catch (error) {
    process.stdout.write(
      `${JSON.stringify({ passed: false, nativeQualified: false, reason: error.message })}\n`,
    );
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = { run, probeHost, checkPoint, main };

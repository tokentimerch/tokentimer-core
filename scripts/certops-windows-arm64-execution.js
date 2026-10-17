"use strict";

/** Host entry for native ARM64 execution. Any non-arm64 process, or a missing
 * ARM64 host, fails closed. This entry never reports a pass. */

const fs = require("node:fs");
const helper = require("../tests/e2e/helpers/certops-windows-arm64-execution");

function probeHost() {
  return {
    windows: process.platform === "win32",
    architecture: process.arch,
    arm64Host: false,
    realArm64Probe: false,
  };
}

function run({ probe, execute, manifest } = {}) {
  const gate = helper.assessHostCapabilities(probe);
  if (!gate.available) {
    return {
      passed: false,
      nativeQualified: false,
      nativeArm64ExecutionQualified: false,
      reason: "host capability absent",
      missing: gate.missing,
    };
  }
  if (execute !== true) {
    return {
      passed: false,
      nativeQualified: false,
      nativeArm64ExecutionQualified: false,
      reason: "host execution not requested",
    };
  }
  if (!manifest) {
    return {
      passed: false,
      nativeQualified: false,
      nativeArm64ExecutionQualified: false,
      reason: "owned ARM64 manifest absent",
    };
  }
  const result = helper.evaluate(manifest, probe);
  if (result.passed !== false || result.nativeArm64ExecutionQualified !== false) {
    throw new Error("ARM64 execution must fail closed");
  }
  return {
    passed: false,
    nativeQualified: false,
    nativeArm64ExecutionQualified: false,
    proof: result.proof,
    reason: result.reason,
  };
}

function checkProbe(file) {
  const body = JSON.parse(fs.readFileSync(file, "utf8"));
  const manifest = helper.createRunManifest(body);
  const result = helper.evaluate(manifest, body.probe);
  if (result.passed !== false || result.proof.nativeArm64ExecutionQualified !== false) {
    throw new Error("ARM64 execution must fail closed");
  }
  return {
    passed: false,
    nativeQualified: false,
    nativeArm64ExecutionQualified: false,
    proof: result.proof,
  };
}

function main() {
  try {
    if (process.argv[2] === "--check") {
      process.stdout.write(`${JSON.stringify(checkProbe(process.argv[3]))}\n`);
      return;
    }
    const result = run({
      probe: probeHost(),
      execute: process.env.CERTOPS_WINDOWS_ARM64_EXECUTE === "1",
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    process.exitCode = 1;
  } catch (error) {
    process.stdout.write(
      `${JSON.stringify({
        passed: false,
        nativeQualified: false,
        nativeArm64ExecutionQualified: false,
        reason: error.message,
      })}\n`,
    );
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = { run, probeHost, checkProbe, main };

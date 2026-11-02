"use strict";

/** Host entry for retention boundary classification. A missing clock fails
 * closed. A wait below 24 hours cannot qualify elapsed retention. */

const fs = require("node:fs");
const helper = require("../tests/e2e/helpers/certops-windows-retention-boundaries");

function probeHost() {
  if (process.platform !== "win32") {
    return { windows: false, retentionClock: false, ownedTarget: false };
  }
  return { windows: true, retentionClock: false, ownedTarget: false };
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
    return { passed: false, nativeQualified: false, reason: "retention boundary absent" };
  }
  if (body.kind === "elapsed") {
    helper.evaluateElapsed(manifest, body.waitedMs);
  }
  const result =
    body.kind === "deadline"
      ? helper.classifyDeadline(manifest, body)
      : helper.classifyConfiguration(manifest, body.hours);
  helper.qualificationGate(result.proof);
  return { passed: false, nativeQualified: false, proof: result.proof };
}

function checkBoundary(file) {
  const body = JSON.parse(fs.readFileSync(file, "utf8"));
  const manifest = helper.createRunManifest(body);
  if (body.kind === "elapsed") {
    try {
      helper.evaluateElapsed(manifest, body.waitedMs);
    } catch (error) {
      if (!error.proof) throw error;
      return {
        passed: false,
        nativeQualified: false,
        twentyFourHourElapsedQualified: false,
        proof: error.proof,
        reason: error.message,
      };
    }
  }
  const result =
    body.kind === "deadline"
      ? helper.classifyDeadline(manifest, body)
      : helper.classifyConfiguration(manifest, body.hours);
  assertGateFails(result.proof);
  return {
    passed: false,
    nativeQualified: false,
    twentyFourHourElapsedQualified: false,
    proof: result.proof,
  };
}

function assertGateFails(proof) {
  let failed = false;
  try {
    helper.qualificationGate(proof);
  } catch (error) {
    failed = error.passed === false;
  }
  if (!failed) throw new Error("retention qualification gate must fail");
}

function main() {
  try {
    if (process.argv[2] === "--check") {
      const result = checkBoundary(process.argv[3]);
      process.stdout.write(`${JSON.stringify(result)}\n`);
      process.exitCode = 1;
      return;
    }
    const result = run({
      probe: probeHost(),
      execute: process.env.CERTOPS_WINDOWS_RETENTION_BOUNDARIES_EXECUTE === "1",
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    process.exitCode = 1;
  } catch (error) {
    process.stdout.write(
      `${JSON.stringify({
        passed: false,
        nativeQualified: false,
        twentyFourHourElapsedQualified: false,
        reason: error.message,
      })}\n`,
    );
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = { run, probeHost, checkBoundary, main };

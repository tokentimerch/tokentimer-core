"use strict";

/** Host entry for crash-dump containment. The report stays unqualified.
 * A claim that crashDumpContainmentQualified is true is rejected. */

const fs = require("node:fs");
const helper = require("../tests/e2e/helpers/certops-windows-crash-dump");

function probeHost() {
  if (process.platform !== "win32") {
    return { windows: false, crashDumpPolicy: false, ownedTarget: false };
  }
  return { windows: true, crashDumpPolicy: false, ownedTarget: false };
}

function run({ probe, execute, manifest, report } = {}) {
  const gate = helper.assessHostCapabilities(probe);
  if (!gate.available) {
    return {
      passed: false,
      nativeQualified: false,
      crashDumpContainmentQualified: false,
      reason: "host capability absent",
      missing: gate.missing,
    };
  }
  if (execute !== true) {
    return {
      passed: false,
      nativeQualified: false,
      crashDumpContainmentQualified: false,
      reason: "host execution not requested",
    };
  }
  if (!manifest) {
    return {
      passed: false,
      nativeQualified: false,
      crashDumpContainmentQualified: false,
      reason: "crash dump report absent",
    };
  }
  const result = helper.review(manifest, report || {});
  return {
    passed: false,
    nativeQualified: false,
    qualified: false,
    crashDumpContainmentQualified: false,
    proof: result.proof,
    reason: "crash dump containment is unqualified",
  };
}

function checkReport(file) {
  const body = JSON.parse(fs.readFileSync(file, "utf8"));
  const manifest = helper.createRunManifest(body);
  helper.rejectReport(body.report || {});
  const result = helper.review(manifest, body.report || {});
  return {
    passed: false,
    nativeQualified: false,
    qualified: false,
    crashDumpContainmentQualified: false,
    proof: result.proof,
  };
}

function main() {
  try {
    if (process.argv[2] === "--check") {
      process.stdout.write(`${JSON.stringify(checkReport(process.argv[3]))}\n`);
      return;
    }
    const result = run({
      probe: probeHost(),
      execute: process.env.CERTOPS_WINDOWS_CRASH_DUMP_EXECUTE === "1",
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    process.exitCode = 1;
  } catch (error) {
    process.stdout.write(
      `${JSON.stringify({
        passed: false,
        nativeQualified: false,
        crashDumpContainmentQualified: false,
        reason: error.message,
      })}\n`,
    );
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = { run, probeHost, checkReport, main };

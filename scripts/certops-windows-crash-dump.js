"use strict";
const {createHostContractCli} = require("./certops-qualification-report");

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

const main = createHostContractCli({
  option: "--check", check: checkReport, run: run, probeHost: probeHost,
  executeEnv: "CERTOPS_WINDOWS_CRASH_DUMP_EXECUTE", failureFlags: {crashDumpContainmentQualified: false},
});

if (require.main === module) main();

module.exports = { run, probeHost, checkReport, main };

/**
 * Run the supporting public-API/PostgreSQL suites and verify each current-source report.
 * Invoked by certops-qualification.yml against its disposable stack; requires
 * CERTOPS_CSR_API_URL and explicit disposable-stack authorization. Protocol fixtures
 * exercise server admission and persistence; native certificate deployment has separate suites. */
"use strict";
const path = require("node:path");
const fs = require("node:fs");
const { spawnSync } = require("node:child_process");
const { verifyReport } = require("./certops-qualification-report");
const suites = [
  [
    "adcs-enrollment-policy-api",
    "certops-enrollment-policy-api-e2e.test.js",
    "CERTOPS_ADCS_POLICY_API_REPORT"
  ],
  [
    "adcs-installation-recovery-api",
    "certops-enrollment-recovery-api-e2e.test.js",
    "CERTOPS_ADCS_INSTALL_RECOVERY_API_REPORT"
  ],
  [
    "adcs-api-release-gates",
    "certops-adcs-gates-api-e2e.test.js",
    "CERTOPS_ADCS_GATES_API_REPORT"
  ]
];
function verifySource(report, file, root = path.resolve(__dirname, "..")) {
  const expectedPath = "tests/e2e/" + file;
  const digest = require("node:crypto").createHash("sha256").update(fs.readFileSync(path.join(root, expectedPath))).digest("hex");
  return report?.fixtureSource?.file === expectedPath && report.fixtureSource.sha256 === digest;
}
function run() {
  if (!process.env.CERTOPS_CSR_API_URL || process.env.CERTOPS_CSR_DISPOSABLE_STACK !== "1") throw new Error("Explicit disposable API URL and stack authorization are required");
  if (!/^[a-f0-9]{40}$/i.test(process.env.GITHUB_SHA || "")) throw new Error("Candidate baseline GITHUB_SHA is required for verifiable reports");
  const root = path.resolve(__dirname, "..");
  const outputDirectory = path.resolve(process.env.CERTOPS_API_REPORTS_DIR || path.join(root, "qualification-results", "api"));
  fs.mkdirSync(outputDirectory, { recursive: true });
  const failures = [];
  for (const [name, file, reportVariable] of suites) {
    const reportPath = path.join(outputDirectory, `${name}.json`);
    // Remove an older result so a crashed current process cannot accidentally
    // qualify using a report from a previous candidate or invocation.
    fs.rmSync(reportPath, { force: true });
    const child = spawnSync(process.execPath, ["--test", path.join(root, "tests", "e2e", file)], { cwd: root, stdio: "inherit", timeout: 150000, env: { ...process.env, CERTOPS_E2E_REQUIRED: "1", CERTOPS_QUALIFICATION_STRICT: "1", [reportVariable]: reportPath } });
    if (child.error || child.status !== 0) { failures.push(`${name}: test process failed`); continue; }
    try {
      const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
      if (report.suite !== name) throw new Error("Unexpected suite report");
      if (!verifySource(report, file, root)) throw new Error("Current suite source evidence missing or mismatched");
      const errors = verifyReport(report);
      if (errors.length) failures.push(`${name}: mandatory qualification evidence incomplete`);
      else console.log(`${name}: mandatory execution verified`);
    } catch (_error) { failures.push(`${name}: valid current report missing`); }
  }
  if (failures.length) throw new Error(failures.join("\n"));
}
if (require.main === module) {
  try { run(); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { suites, run, verifySource };

/**
 * Qualification notes: Supporting database integration
 * Run node scripts/certops-integration-qualification.js with CERTOPS_INTEGRATION_GROUP, NODE_ENV=test,
 * CERTOPS_ENABLED=true, DB_* and TEST_API_URL for a disposable migrated stack. The eleven named groups
 * default to adcs; all selection permits at most two concurrent stack jobs. A ten-minute deadline and
 * bounded reporter reject missing, skipped or failed required cases without emitting raw assertion
 * payloads or secrets. Real PostgreSQL and service execution remain supporting evidence, not native
 * host qualification.
 *
 * Shared execution and evidence policy: docs/certops/e2e-qualification.md.
 */
"use strict";
/**
 * Executes one committed integration test group against a disposable API/PostgreSQL fixture.
 * Invoked by its manual workflow with an explicit group; reporter output records exact cases
 * and source identity. Supporting seeded states do not establish native CA or Windows execution.
 */
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const group = process.env.CERTOPS_INTEGRATION_GROUP || "adcs";
const definition = require("./certops-integration-inventory").groups[group];
if (!definition) throw new Error("Unknown CertOps integration qualification group");
const required = definition.requiredTests;
const scope = `${group}-database-integration`;
const { verify } = require("./certops-integration-report");
require("./certops-integration-inventory").validateInventory();
if (process.env.CERTOPS_ENABLED !== "true" || process.env.NODE_ENV !== "test") throw new Error("Qualification requires CERTOPS_ENABLED=true and NODE_ENV=test");
const root = path.resolve(__dirname, "..");
const files = definition.files;
for (const file of files) if (!fs.existsSync(path.join(root, "tests/integration", file))) throw new Error(`Missing required test source ${file}`);
const directory = path.join(root, "qualification-results");
fs.mkdirSync(directory, { recursive: true });
const destination = path.join(directory, `${group}-database-integration.json`);
if (fs.existsSync(destination)) fs.unlinkSync(destination);
const mocha = require.resolve("mocha/bin/mocha.js", { paths: [root] });
const result = spawnSync(process.execPath, [mocha, ...files.map((file) => path.join(root, "tests/integration", file)), "--timeout", "60000", "--exit", "--reporter", path.join(__dirname, "certops-mocha-reporter.js")], { cwd: root, encoding: "utf8", timeout: 600000, maxBuffer: 20 * 1024 * 1024, env: { ...process.env, CERTOPS_MOCHA_REPORT: destination, CERTOPS_MOCHA_SCOPE: scope } });
try {
  const report = JSON.parse(fs.readFileSync(destination, "utf8"));
  if (result.status !== 0 || result.error) throw new Error("AD CS database integration process failed or exceeded its deadline");
  verify(report, required, process.env.GITHUB_SHA, scope);
  for (const file of files) if (!report.tests.some((test) => test.file === file)) throw new Error(`Missing required test file ${file}`);
  console.log("Supporting database integration passed with no pending tests");
} catch (error) { console.error(error.message); process.exitCode = 1; }

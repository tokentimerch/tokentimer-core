"use strict";
// Verify the Compose-owned production scheduler receipt. A browser job alone
// cannot prove that the documented worker started once and drained cleanly.
const assert = require("node:assert/strict");
const fs = require("node:fs");
function verify(report, candidate) {
  assert.match(candidate, /^[a-f0-9]{40}$/);
  assert.deepEqual(Object.keys(report).sort(), ["candidateSha", "containerId", "entrypoint", "defaultCron", "scheduledMaintenanceObserved", "scheduledStarts", "scheduledFinishes", "exitCode", "nativeDrained", "status"].sort());
  assert.equal(report.candidateSha, candidate);
  assert.match(report.containerId, /^[a-f0-9]{64}$/);
  assert.equal(report.entrypoint, "src/runner.js certops");
  assert.equal(report.defaultCron, true);
  assert.equal(report.scheduledMaintenanceObserved, true);
  assert.ok(Number.isSafeInteger(report.scheduledStarts) && report.scheduledStarts > 0 && report.scheduledStarts <= 1000);
  assert.equal(report.scheduledFinishes, report.scheduledStarts);
  assert.equal(report.exitCode, 0);
  assert.equal(report.nativeDrained, true);
  assert.equal(report.status, "passed");
  return true;
}
module.exports = { verify };
if (require.main === module) {
  try { verify(JSON.parse(fs.readFileSync(process.argv[2], "utf8")), process.env.GITHUB_SHA); console.log("Production AD CS worker deployment and drainage receipt passed"); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}

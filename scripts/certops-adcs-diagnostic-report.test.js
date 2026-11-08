"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { verifyDiagnosticReport } = require("./certops-adcs-diagnostic-report");
const { verifyReport } = require("./certops-qualification-report");
const metadata = require("./certops-qualification-manifest");

function report() {
  const suite = "enterprise-adcs-real", time = new Date().toISOString();
  return { schemaVersion: 1, suite, debugDetail: true, candidateSha: "a".repeat(40), evidenceLevel: metadata.suiteEvidenceLevels[suite], strict: true, status: "passed", startedAt: time, finishedAt: time, cleanup: { status: "passed" },
    requiredScenarios: metadata.suites[suite], missingScenarios: [], requiredCapabilities: metadata.requiredCapabilities[suite], missingCapabilities: [],
    capabilities: Object.fromEntries(metadata.requiredCapabilities[suite].map(name => [name, { available: true }])),
    scenarios: metadata.suites[suite].map(id => ({ id, status: "passed", evidenceLevel: metadata.scenarioEvidenceLevels[suite][id], startedAt: time, finishedAt: time })) };
}

test("complete diagnostic evidence passes only the diagnostic verifier", () => {
  const value = report();
  assert.deepEqual(verifyDiagnosticReport(value, { expectedSha: value.candidateSha }), []);
  assert.ok(verifyReport(value).includes("Diagnostic reports are not release evidence"));
  assert.equal(value.debugDetail, true);
});

test("diagnostic verification fails closed on incomplete or failed evidence", () => {
  for (const mutate of [
    r => { r.scenarios[0].status = "failed"; },
    r => { r.scenarios.pop(); },
    r => { r.guardedFailures = []; },
    r => { r.failureBudgetExhausted = true; },
    r => { r.cleanup.status = "failed"; },
    r => { r.candidateSha = "b".repeat(40); },
    r => { delete r.debugDetail; },
  ]) {
    const value = report(); mutate(value);
    assert.ok(verifyDiagnosticReport(value, { expectedSha: "a".repeat(40) }).length);
  }
});

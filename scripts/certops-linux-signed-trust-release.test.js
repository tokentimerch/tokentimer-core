"use strict";
/** Offline strict-report checks. Manual workflow_dispatch only. Not native trust execution. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  h = require("./certops-linux-signed-trust-proof"),
  f = require("./test-support/linux-signed-trust-artifact.cjs"),
  { verifyMatrix } = require("./certops-release-qualification");
const slot = () =>
  require("./certops-qualification-manifest").slots.find(
    (s) => s.suite === h.SUITE,
  );
const errors = (a) =>
  verifyMatrix([a], {
    candidateSha: f.CANDIDATE,
    specification: { schemaVersion: 1, slots: [slot()] },
  });
test("signed native trust slot requires complete closed lifecycle proof and current causal bytes", () => {
  assert.deepEqual(errors(f.artifact()), []);
  for (const flag of h.FLAGS) {
    const a = f.artifact();
    delete a.report[h.FIELD][flag];
    assert.ok(errors(a).length);
  }
  for (const source of h.REQUIRED_SOURCES) {
    const a = f.artifact();
    a.report.fixtureSources.find((r) => r.file === source).sha256 = "e".repeat(
      64,
    );
    assert.ok(errors(a).length);
  }
});
test("signed native trust cannot qualify another host, skipped operation or uncertain cleanup", () => {
  for (const mutate of [
    (a) => delete a.report[h.FIELD],
    (a) => (a.report[h.FIELD].backgroundReconciliationQualified = true),
    (a) => (a.report.cleanup.status = "failed"),
    (a) => (a.report.scenarios[0].status = "skipped"),
    (a) => (a.report.qualificationEnvironment.osVersion = "22.04"),
    (a) => (a.report.platform = "win32"),
    (a) => (a.report[h.FIELD].privateKey = "no"),
  ]) {
    const a = f.artifact();
    mutate(a);
    assert.ok(errors(a).length);
  }
});
test("missing mandatory signed trust scenario id fails strict verification", () => {
  const a = f.artifact();
  const missing = h.SCENARIOS[0];
  a.report.scenarios = a.report.scenarios.filter(
    (scenario) => scenario.id !== missing,
  );
  a.report.missingScenarios = [];
  assert.ok(
    errors(a).some((error) =>
      error.includes("Mandatory runtime evidence incomplete"),
    ),
  );
});
test("public signed trust workflow is workflow_dispatch only", () => {
  const text = fs.readFileSync(
    path.join(__dirname, "../.github/workflows/certops-linux-signed-trust.yml"),
    "utf8",
  );
  assert.match(text, /^on:\r?\n {2}workflow_dispatch:\r?\n/m);
  assert.equal(/\bpull_request\b|\bworkflow_call\b|^push:/m.test(text), false);
});

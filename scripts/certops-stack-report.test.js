/**
 * Regression coverage: mandatory names must execute once without skips or failures.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { verify } = require("./certops-stack-report");
test("mandatory names must execute once without skips or failures", () => {
  const row = { type: "test:pass", name: "mandatory", file: "certops-agent-e2e.test.js", candidateSha: process.env.GITHUB_SHA || null, scope: "agent-protocol-api-worker", skip: false, todo: false };
  const json = (value) => JSON.stringify(value) + "\n";
  assert.equal(verify(json(row), ["mandatory"]).executed, 1);
  assert.throws(() => verify(json({ ...row, file: "other.test.js" }), ["mandatory"]));
  assert.throws(() => verify(json({ ...row, scope: "other" }), ["mandatory"]));
  for (const report of ["", json({ ...row, skip: "missing prerequisite" }), json({ ...row, type: "test:fail" }), json({ ...row, todo: true }), json(row) + json(row)]) {
    assert.throws(() => verify(report, ["mandatory"]));
  }
});

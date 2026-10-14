"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { verify } = require("./certops-integration-report");
test("database qualification rejects wrong candidate missing names and skipped cases", () => {
  const required = [{ file: "fixture.js", name: "mandatory" }];
  const report = { scope: "adcs-database-integration", candidateSha: "candidate", tests: [{ ...required[0], status: "pass" }] };
  assert.equal(verify(report, required, "candidate"), 1);
  assert.throws(() => verify(report, required, "other"));
  for (const tests of [[], [{ ...required[0], status: "pending" }], [{ ...required[0], status: "fail" }], [{ ...required[0], name: "other", status: "pass" }], [...report.tests, ...report.tests]]) assert.throws(() => verify({ ...report, tests }, required, "candidate"));
});

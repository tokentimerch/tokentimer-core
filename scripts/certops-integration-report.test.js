/**
 * Regression coverage: database qualification rejects wrong candidate missing names and skipped cases.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { verify } = require("./certops-integration-report");

test("integration inventory expands runtime parameterized names without executing source", () => {
  const {testNames, validateInventory} = require("./certops-integration-inventory");
  const source = `
    throw new Error("source must not execute");
    it("literal, with punctuation", async () => {});
    for (const state of ["active", "retired"]) {
      it("keeps " + state + ", then " + state, async () => {});
    }
  `;
  assert.deepEqual(testNames(source), ["literal, with punctuation", "keeps active, then active", "keeps retired, then retired"]);
  assert.deepEqual(testNames('it("escaped \\"quote\\"", () => {});'), ['escaped "quote"']);
  for (const source of [
    'it("prefix " + unknown, () => {});',
    'for (const state of ["active"]) { it("prefix " + other, () => {}); }',
    'for (const state of ["active"]) { it("prefix " + state.toUpperCase(), () => {}); }',
    'for (const state of [42]) { it("prefix " + state, () => {}); }',
  ]) assert.throws(() => testNames(source));
  assert.ok(validateInventory() > 0);
});
test("database qualification rejects wrong candidate missing names and skipped cases", () => {
  const required = [{ file: "fixture.js", name: "mandatory" }];
  const report = { scope: "adcs-database-integration", candidateSha: "candidate", tests: [{ ...required[0], status: "pass" }] };
  assert.equal(verify(report, required, "candidate"), 1);
  assert.throws(() => verify(report, required, "other"));
  for (const tests of [[], [{ ...required[0], status: "pending" }], [{ ...required[0], status: "fail" }], [{ ...required[0], name: "other", status: "pass" }], [...report.tests, ...report.tests]]) assert.throws(() => verify({ ...report, tests }, required, "candidate"));
});

test("grouped integration cases preserve order and refuse missing, duplicate or ambiguous declarations", () => {
  const {expandGroups} = require("./certops-integration-inventory");
  const input = {sample: {files: ["a.js", "b.js"], requiredTestsByFile: [
    {file: "a.js", names: ["first"]}, {file: "b.js", names: ["second"]}, {file: "a.js", names: ["third"]},
  ]}};
  const flat = {sample: {files: ["a.js", "b.js"], requiredTests: [
    {file: "a.js", name: "first"}, {file: "b.js", name: "second"}, {file: "a.js", name: "third"},
  ]}};
  assert.deepEqual(expandGroups(input), flat);
  assert.deepEqual(expandGroups(flat), flat);
  assert.ok(input.sample.requiredTestsByFile);
  for (const patch of [
    {requiredTests: []}, {requiredTestsByFile: []},
    {requiredTestsByFile: [{file: "foreign.js", names: ["first"]}]},
    {requiredTestsByFile: [{file: "a.js", names: []}]},
    {requiredTestsByFile: [{file: "a.js", names: ["first", "first"]}]},
  ]) assert.throws(() => expandGroups({sample: {...input.sample, ...patch}}));
});

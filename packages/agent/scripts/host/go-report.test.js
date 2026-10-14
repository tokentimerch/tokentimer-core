"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { verifyGoExecution } = require("./go-report");
const json = (events) => events.map((event) => JSON.stringify({ Package: "example", ...event })).join("\n");
test("Go qualification verifies actual passing test and nested subtest events", () => {
  const report = verifyGoExecution(json([{ Action: "run", Test: "TestFixture" },
    { Action: "run", Test: "TestFixture/native" }, { Action: "pass", Test: "TestFixture/native" },
    { Action: "pass", Test: "TestFixture" }, { Action: "pass" }]));
  assert.equal(report.passedTests, 2);
  assert.equal(report.skippedTests, 0);
});
test("Go qualification rejects skipped nested tests, empty execution and interrupted tests", () => {
  assert.throws(() => verifyGoExecution(json([{ Action: "run", Test: "TestFixture" },
    { Action: "run", Test: "TestFixture/native" }, { Action: "skip", Test: "TestFixture/native" },
    { Action: "pass", Test: "TestFixture" }, { Action: "pass" }])), /must not skip/);
  assert.throws(() => verifyGoExecution(json([{ Action: "pass" }])), /actual tests/);
  assert.throws(() => verifyGoExecution(json([{ Action: "run", Test: "TestFixture" }, { Action: "pass" }])), /must pass/);
  assert.throws(() => verifyGoExecution("sensitive unparseable output"), (error) =>
    error.message.includes("raw output withheld") && !error.message.includes("sensitive"));
});

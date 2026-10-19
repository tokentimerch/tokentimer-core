/**
 * Regression coverage: Mocha evidence records failure and pending without assertion or credential payloads.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const Reporter = require("./certops-mocha-reporter");
test("Mocha evidence records failure and pending without assertion or credential payloads", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "certops-report-test-"));
  const original = process.env.CERTOPS_MOCHA_REPORT;
  process.env.CERTOPS_MOCHA_REPORT = path.join(directory, "report.json");
  try {
    const runner = new EventEmitter();
    new Reporter(runner);
    runner.emit("fail", { title: "mandatory", file: "/fixture/case.test.js", err: { message: "secret-token", actual: "private-key" } });
    runner.emit("pending", { title: "prerequisite", file: "/fixture/case.test.js" });
    runner.emit("end");
    const text = fs.readFileSync(process.env.CERTOPS_MOCHA_REPORT, "utf8");
    assert.doesNotMatch(text, /secret-token|private-key|actual/);
    assert.deepEqual(JSON.parse(text).tests.map((entry) => entry.status), ["fail", "pending"]);
  } finally {
    if (original === undefined) delete process.env.CERTOPS_MOCHA_REPORT;
    else process.env.CERTOPS_MOCHA_REPORT = original;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

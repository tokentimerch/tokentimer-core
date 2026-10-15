"use strict";
/** Keep the real Windows SYSTEM task's outer deadlines above the native test
 * and producer bounds. Portable source checks protect cleanup/report headroom;
 * they do not measure native Windows execution duration. */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const root = path.resolve(__dirname, "..");
const workflow = fs.readFileSync(path.join(root, ".github/workflows/certops-windows-e2e.yml"), "utf8");
const producer = fs.readFileSync(path.join(root, "scripts/certops-windows-e2e.js"), "utf8");
const suite = fs.readFileSync(path.join(root, "tests/e2e/certops-agent-e2e.test.js"), "utf8");
function deadlines(source) {
  const capture = expression => {
    const match = source.match(expression);
    assert.ok(match, `Missing deadline: ${expression}`);
    return Number(match[1]) * 60000;
  };
  return {
    task: capture(/New-ScheduledTaskSettingsSet -ExecutionTimeLimit \(New-TimeSpan -Minutes (\d+)\)/),
    receipt: capture(/\$deadline = \[DateTime\]::UtcNow.AddMinutes\((\d+)\)/),
    job: capture(/timeout-minutes: (\d+)/),
  };
}
function validate(bounds, producerMs, testMs) {
  assert.ok(testMs < producerMs, "Producer must permit test finalization");
  assert.ok(bounds.receipt >= producerMs + 180000, "Receipt must permit three minutes of producer finalization");
  assert.ok(bounds.task >= bounds.receipt + 60000, "Task must outlive receipt by one minute");
  assert.ok(bounds.job >= bounds.task + 600000, "Job must permit setup and independent cleanup");
}
const producerMs = Number(producer.match(/timeout: (\d+)/)[1]);
const nativeExpression = suite.match(/it\("real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence", \{ timeout: ([^}]+) \}/);
assert.ok(nativeExpression, "Actual Windows test timeout expression required");
const testMs = require("node:vm").runInNewContext(nativeExpression[1], { process: { env: {} } });
assert.equal(testMs, 32 * 60000, "Normal Windows deadline must not inherit a separate manual scope");
test("Windows SYSTEM receipt/task bounds retain real producer cleanup headroom", () => validate(deadlines(workflow), producerMs, testMs));
test("premature task, receipt and job deadlines fail the native wiring invariant", () => {
  const valid = deadlines(workflow);
  for (const invalid of [
    { ...valid, task: producerMs },
    { ...valid, receipt: producerMs },
    { ...valid, task: valid.receipt },
    { ...valid, job: valid.task },
  ]) assert.throws(() => validate(invalid, producerMs, testMs));
  assert.throws(() => validate(valid, testMs, testMs));
});

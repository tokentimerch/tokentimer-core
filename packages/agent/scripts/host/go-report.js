"use strict";
const assert = require("node:assert/strict");
function verifyGoExecution(stdout) {
  let events;
  try { events = stdout.split(/\r?\n/).filter((line) => line.trim()).map((line) => JSON.parse(line)); }
  catch { assert.fail("Go qualification emitted invalid JSON; raw output withheld"); }
  const started = new Set();
  const passed = new Set();
  const passedPackages = new Set();
  let skipped = 0;
  let failed = 0;
  for (const event of events) {
    const key = `${event.Package}/${event.Test}`;
    if (event.Action === "run" && event.Test) started.add(key);
    if (event.Action === "pass" && event.Test) passed.add(key);
    if (event.Action === "pass" && !event.Test) passedPackages.add(event.Package);
    if (event.Action === "skip" && event.Test) skipped++;
    if (event.Action === "fail") failed++;
  }
  assert.ok(started.size > 0, "Go qualification must execute actual tests");
  assert.equal(skipped, 0, "Go qualification must not skip any selected test or subtest");
  assert.equal(failed, 0, "Go qualification contains failed test/package events");
  assert.equal(passed.size, started.size, "every started Go test/subtest must pass");
  for (const key of started) assert.equal(passed.has(key), true, "Go test did not complete successfully");
  assert.ok(passedPackages.size > 0, "Go qualification must report passed packages");
  // Persist counts only. Raw test output may contain fixture key material.
  return { startedTests: started.size, passedTests: passed.size, skippedTests: skipped,
    failedEvents: failed, passedPackages: passedPackages.size };
}
module.exports = { verifyGoExecution };

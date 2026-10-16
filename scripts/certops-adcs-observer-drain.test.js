"use strict";
/* Observer lifecycle regression only: child process/stdio are controlled
 * emitters. No PowerShell or native process/service is launched. */
const assert = require("node:assert/strict");
const test = require("node:test");
const { EventEmitter } = require("node:events");
const { PassThrough } = require("node:stream");
const childProcess = require("node:child_process");
test("qualification drains the exact observer close before cleanup while preserving synchronous stop", async () => {
  const original = childProcess.spawn;
  const child = new EventEmitter(); child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.exitCode = null;
  let kills = 0;
  child.kill = () => { kills++; return true; };
  const file = require.resolve("../tests/e2e/helpers/certops-adcs-journal-phase");
  delete require.cache[file]; childProcess.spawn = () => child;
  let observer;
  try { observer = require(file)({ ownedDirectory: "owned", configDirectory: "config", repositoryRoot: "repo", phase: "submitting" }); }
  finally { childProcess.spawn = original; delete require.cache[file]; }
  child.stdout.write("CERTOPS_JOURNAL_FAULT_READY"); await observer.ready;
  assert.equal(observer.stop(), undefined, "Existing callers retain the synchronous stop API");
  let drained = false;
  const wait = observer.stopAndDrain().then(() => { drained = true; });
  await new Promise(resolve => setImmediate(resolve)); assert.equal(drained, false);
  assert.equal(observer.hasLiveChild(), true);
  assert.equal(kills, 2, "Only the returned owned child receives termination");
  child.exitCode = 1; child.emit("exit", 1);
  await new Promise(resolve => setImmediate(resolve)); assert.equal(drained, false, "Exit alone does not drain stdio");
  child.stdout.end(); child.stderr.end(); child.emit("close", 1);
  await wait; assert.equal(drained, true);
  assert.equal(observer.hasLiveChild(), false);
  await assert.rejects(observer.result);
});
test("observer parses final receipt bytes arriving after process exit only at drained close", async () => {
  const original = childProcess.spawn;
  const child = new EventEmitter(); child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.exitCode = null; child.kill = () => true;
  const file = require.resolve("../tests/e2e/helpers/certops-adcs-journal-phase");
  delete require.cache[file]; childProcess.spawn = () => child;
  let observer;
  try { observer = require(file)({ ownedDirectory: "owned", configDirectory: "config", repositoryRoot: "repo", phase: "submitting" }); }
  finally { childProcess.spawn = original; delete require.cache[file]; }
  child.stdout.write("CERTOPS_JOURNAL_FAULT_READY"); await observer.ready;
  let resolved = false; const result = observer.result.then(value => { resolved = true; return value; });
  child.exitCode = 0; child.emit("exit", 0);
  await new Promise(resolve => setImmediate(resolve)); assert.equal(resolved, false);
  child.stdout.write(JSON.stringify({ phase: "submitting", observedDurablePhase: true, unchangedAfterTermination: true, ownedServiceTree: true, nativeIdentity: "LocalSystem" }));
  child.stdout.end(); child.stderr.end(); child.emit("close", 0);
  assert.equal((await result).phase, "submitting");
  await observer.stopAndDrain(); assert.equal(observer.hasLiveChild(), false);
});

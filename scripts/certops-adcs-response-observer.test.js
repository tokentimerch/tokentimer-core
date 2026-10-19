"use strict";
/** Controlled child/stdio lifecycle regressions. These tests launch no native
 * process and never qualify response-loss timing or native AD CS recovery. */
const test = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { PassThrough } = require("node:stream");
const childProcess = require("node:child_process");

function fixture() {
  const child = new EventEmitter();
  child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.exitCode = null;
  let kills = 0; child.kill = () => { kills++; return true; };
  const file = require.resolve("../tests/e2e/helpers/certops-adcs-response-loss");
  const original = childProcess.spawn; delete require.cache[file];
  childProcess.spawn = () => child;
  let observer;
  try { observer = require(file)({ commonName: "owned.example.test", ownedDirectory: "owned" }); }
  finally { childProcess.spawn = original; delete require.cache[file]; }
  return { child, observer, kills: () => kills };
}
function close(child, code) {
  child.exitCode = code; child.stdout.end(); child.stderr.end(); child.emit("close", code);
}
test("response observer waits for close and accepts final receipt bytes after exit", async () => {
  const { child, observer } = fixture();
  child.stdout.write("CERTOPS_FAULT_READY"); await observer.ready;
  let resolved = false; const result = observer.result.then(value => { resolved = true; return value; });
  child.exitCode = 0; child.emit("exit", 0);
  await new Promise(resolve => setImmediate(resolve)); assert.equal(resolved, false);
  assert.equal(observer.hasLiveChild(), true);
  child.stdout.write(JSON.stringify({ caRequestObserved: true, ownedServiceTree: true, requestId: 17 }));
  close(child, 0); assert.equal((await result).requestId, 17);
  await observer.stopAndDrain(); assert.equal(observer.hasLiveChild(), false);
});
test("response observer stops only its returned child and drains stdio before cleanup", async () => {
  const { child, observer, kills } = fixture();
  child.stdout.write("CERTOPS_FAULT_READY"); await observer.ready;
  assert.equal(observer.stop(), undefined);
  let drained = false; const pending = observer.stopAndDrain().then(() => { drained = true; });
  assert.equal(kills(), 2); child.exitCode = 1; child.emit("exit", 1);
  await new Promise(resolve => setImmediate(resolve)); assert.equal(drained, false);
  close(child, 1); await pending; assert.equal(observer.hasLiveChild(), false);
  await assert.rejects(observer.result);
});
test("response observer rejects oversized, malformed and unproven native evidence without raw errors", async () => {
  for (const receipt of ["x".repeat(8193), "{private-native-error", JSON.stringify({ caRequestObserved: 1, ownedServiceTree: true, requestId: 1 }), JSON.stringify({ caRequestObserved: true, ownedServiceTree: true, requestId: 4294967296 })]) {
    const { child, observer } = fixture();
    child.stdout.write("CERTOPS_FAULT_READY"); await observer.ready;
    child.stdout.write(receipt); close(child, 0);
    await assert.rejects(observer.result, error => !error.message.includes("private-native-error"));
    await observer.stopAndDrain();
  }
});

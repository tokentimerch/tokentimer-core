"use strict";
// Exercise common harness mechanics without starting a cluster or signaling real processes.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { EventEmitter } = require("node:events");

function runtime(execute = () => ({ status: 0, stdout: "ok" })) {
  let now = 0;
  const module = { exports: {} };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "certops-kubernetes-runtime.js"), "utf8"), {
    module, process: { env: { CERTOPS_KUBE_CONTEXT: "kind-owned-fixture" } },
    require: name => name === "node:child_process" ? { spawnSync: execute } : require(name),
    Date: { now: () => now },
    setTimeout: (callback, duration) => { now += duration; queueMicrotask(callback); return 1; },
    clearTimeout() {},
  });
  return module.exports;
}

test("shared Kubernetes commands preserve bounded execution and explicit context", () => {
  let observed;
  const tools = runtime((...args) => { observed = args; return { status: 0, stdout: "public result" }; });
  assert.equal(tools.kube(["get", "nodes"], "owned input"), "public result");
  assert.equal(observed[0], "kubectl");
  assert.deepEqual(Array.from(observed[1]), ["--context", "kind-owned-fixture", "get", "nodes"]);
  assert.equal(observed[2].input, "owned input");
  assert.equal(observed[2].timeout, 180000);
  assert.equal(observed[2].maxBuffer, 1024 * 1024);
  for (const result of [{ status: 1, stderr: "private sentinel" }, { status: null, error: new Error("private sentinel") }]) {
    assert.throws(() => runtime(() => result).run("fixture", []), error => error.message === "Disposable controller fixture operation failed");
  }
});

test("shared polling returns observations and refuses an exhausted deadline", async () => {
  let calls = 0;
  assert.equal(await runtime().eventually(() => ++calls === 3 ? "observed" : false), "observed");
  assert.equal(calls, 3);
  await assert.rejects(runtime().eventually(() => false), /exceeded deadline/);
});

test("owned child teardown resumes then terminates, escalating only when necessary", async () => {
  for (const endsOn of ["SIGTERM", "SIGKILL", null]) {
    const child = new EventEmitter();
    Object.assign(child, { pid: 123, exitCode: null, signalCode: null, signals: [] });
    child.kill = signal => {
      child.signals.push(signal);
      if (signal === endsOn) { child.signalCode = signal; child.emit("exit"); }
    };
    const stopped = runtime().stopChild(child);
    if (endsOn) await stopped;
    else await assert.rejects(stopped, /must terminate/);
    assert.deepEqual(child.signals, endsOn === "SIGTERM" ? ["SIGCONT", "SIGTERM"] : ["SIGCONT", "SIGTERM", "SIGKILL"]);
  }
  await runtime().stopChild(undefined);
  await runtime().stopChild({ pid: 123, exitCode: 0, signalCode: null, kill: () => assert.fail("Exited child must not be signaled") });
});

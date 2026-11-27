"use strict";

const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { test } = require("node:test");

const { guardNativeExec, takeAdmissionBinding } = require("./observation-admission");
const { createProtocolClient, ROUTES } = require("./protocol");
const { execWithoutShell } = require("./windows-cert-store");

function deferred() {
  let resolve, reject;
  const promise = new Promise((ok, fail) => { resolve = ok; reject = fail; });
  return { promise, resolve, reject };
}

function mockLaunch(calls) {
  return (file, args, options, callback) => {
    calls.push({ file, args, options });
    const child = new EventEmitter();
    child.kill = () => true;
    queueMicrotask(() => callback(null, "ok", ""));
    return child;
  };
}

function protocol(beforeClaim, fetchImpl, extra = {}) {
  return createProtocolClient({
    serverUrl: "https://example.test", agentId: "agent-1", protocolVersion: "1.0.0",
    getCredential: () => "ttagent_agent-1_0123456789abcdef",
    beforeClaim, fetchImpl, ...extra,
  });
}

test("removes the launch capability from child environment and refuses malformed bindings", () => {
  const env = { TOKENTIMER_AGENT_HOST_ADMISSION: "43210:" + "a".repeat(64) };
  const binding = takeAdmissionBinding(env);
  assert.equal(binding.port, 43210);
  assert.equal(binding.key.length, 32);
  assert.equal(takeAdmissionBinding(env), null);
  assert.throws(() => takeAdmissionBinding({ TOKENTIMER_AGENT_HOST_ADMISSION: "65536:" + "0".repeat(64) }),
    { code: "OBSERVATION_ADMISSION_DENIED" });
});

test("native admission covers CA, CNG, Store and destructive cleanup through both exec interfaces", async () => {
  const calls = [], ops = [];
  const observed = guardNativeExec(async (stage) => { ops.push(stage); }, undefined, mockLaunch(calls));
  await observed("C:\\Windows\\System32\\certreq.exe", ["-q", "-machine", "-new"], {});
  await observed("certreq.exe", ["-config", "labca", "-submit"], {});
  await observed("certreq.exe", ["-retrieve"], {});
  await new Promise((resolve, reject) => {
    observed("certreq.exe", ["-accept"], {}, (error) => error ? reject(error) : resolve());
  });
  await observed("certutil.exe", ["-delkey"], {});
  assert.deepEqual(ops, ["cng-create", "ca-submit", "ca-retrieve", "store-accept", "store-cleanup"]);
  assert.equal(calls.length, ops.length);
});

test("observation refusal and cancellation deny a native launch while admission is suspended", async () => {
  for (const mode of ["denied", "killed"]) {
    const permit = deferred();
    const calls = [];
    const observed = guardNativeExec(() => permit.promise, undefined, mockLaunch(calls));
    let child;
    const result = new Promise((resolve) => {
      child = observed("certreq.exe", ["-accept"], {}, resolve);
    });
    if (mode === "killed") {
      child.kill();
      permit.resolve();
      assert.equal((await result).code, "ABORT_ERR");
    } else {
      permit.reject(Object.assign(new Error("observer lost"), { code: "OBSERVATION_ADMISSION_DENIED" }));
      assert.equal((await result).code, "OBSERVATION_ADMISSION_DENIED");
    }
    assert.equal(calls.length, 0);
  }
});

test("Store cancellation after launch kills the guarded child and waits for its exit", async () => {
  const worker = new AbortController();
  const launched = deferred();
  const child = new EventEmitter();
  let kills = 0;
  let settled = false;
  child.kill = () => { kills++; return true; };
  const observed = guardNativeExec(async () => {}, worker.signal, () => {
    launched.resolve();
    return child;
  });
  const command = execWithoutShell(observed, ["certreq.exe", "-accept"], 1000, worker.signal);
  void command.then(() => { settled = true; });
  await launched.promise;
  worker.abort();
  await Promise.resolve();
  assert.equal(kills, 1);
  assert.equal(settled, false);
  child.emit("exit", 1);
  assert.equal((await command).execError.code, "ABORT_ERR");
});

test("claim admission is queued and refusal neither sends nor consumes a sequence", async () => {
  const sendingHeartbeat = deferred(), completeHeartbeat = deferred(), admitEntered = deferred(), permit = deferred();
  const paths = [];
  let allocated = 0;
  const client = protocol(async () => {
    admitEntered.resolve();
    return permit.promise;
  }, (url) => {
    paths.push(new URL(url).pathname);
    sendingHeartbeat.resolve();
    return completeHeartbeat.promise;
  }, { sequenceAllocator: { next: () => ++allocated } });
  const heartbeat = client.heartbeat({ agentVersion: "0.20.0" });
  await sendingHeartbeat.promise;
  const claim = client.claim();
  await Promise.resolve();
  assert.equal(paths.length, 1);
  assert.equal(allocated, 1);
  completeHeartbeat.resolve(new Response("{}", { status: 200 }));
  await heartbeat;
  await admitEntered.promise;
  permit.reject(new Error("observer lost while waiting"));
  await assert.rejects(claim, /observer lost/);
  assert.equal(allocated, 1);
  assert.equal(paths.length, 1);
});

test("locally stopped claim is neither sent nor sequenced after its permit is issued", async () => {
  const worker = new AbortController();
  const entered = deferred(), permit = deferred();
  let sends = 0;
  let allocated = 0;
  const client = protocol(() => {
    entered.resolve();
    return permit.promise;
  }, () => {
    sends++;
    return Promise.resolve(new Response('{"jobs":[]}', { status: 200 }));
  }, { signal: worker.signal, sequenceAllocator: { next: () => ++allocated } });
  const claim = client.claim();
  await entered.promise;
  permit.resolve();
  worker.abort();
  await assert.rejects(claim, { code: "network_error" });
  assert.equal(allocated, 0);
  assert.equal(sends, 0);
});

test("a permit already issued is not an atomic fence on claim transport or native launch", async () => {
  // Deterministically suspend after grant and before the actual call to the
  // supplied transport or launcher. A remote loss without local cancellation
  // cannot retract this permit. Keep this counterexample until effect-owned
  // admission is available.
  for (const operation of ["claim", "native"]) {
    for (const localCancellation of [false, true]) {
      const issued = deferred(), resume = deferred();
      const worker = new AbortController();
      let effects = 0;
      const admit = async () => {
        issued.resolve();
        await resume.promise;
        if (worker.signal.aborted) throw new Error("locally stopped");
      };
      const run = operation === "claim"
        ? protocol(admit, (url) => {
          assert.ok(url.endsWith(ROUTES.CLAIM));
          effects++;
          return Promise.resolve(new Response('{"jobs":[]}', { status: 200 }));
        }).claim()
        : guardNativeExec(admit, worker.signal, (file, args, options, callback) => {
          effects++;
          callback(null, "", "");
        })("certreq.exe", ["-submit"], {});
      await issued.promise;
      if (localCancellation) worker.abort();
      resume.resolve();
      if (localCancellation) await assert.rejects(run, /locally stopped/);
      else await run;
      assert.equal(effects, localCancellation ? 0 : 1, operation);
    }
  }
});

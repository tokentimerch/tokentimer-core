"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { acquireStoreLock } = require("../../src/windows-cert-store");

async function qualifyStoreLockDeath({ workDir, cooperative = true }) {
  const stateDir = path.join(workDir, cooperative ? "worker-death-state" : "worker-drain-timeout-state");
  assert.equal(fs.existsSync(stateDir), false, "fixture state must be newly owned");
  fs.mkdirSync(stateDir);
  const lock = acquireStoreLock(stateDir, "My");
  let successor, child, closed, readinessTimer;
  try {
    lock.assertHeld();
    assert.throws(() => acquireStoreLock(stateDir, "My"), { code: "STORE_LOCKED" });
    let began;
    const started = new Promise(resolve => { began = resolve; });
    let aborted = false;
    const work = lock.run(async signal => {
      child = spawn(process.execPath, ["-e", "process.send('ready'); setInterval(()=>{},1000)"], { stdio: ["ignore", "ignore", "ignore", "ipc"] });
      closed = new Promise((resolve, reject) => { child.once("error", reject); child.once("close", (code, terminationSignal) => resolve({ code, terminationSignal })); });
      await new Promise((resolve, reject) => { child.once("message", value => { assert.equal(value, "ready"); resolve(); }); child.once("error", reject); });
      const cancellation = new Promise(resolve => signal.addEventListener("abort", () => { aborted = true; if (cooperative) child.kill(); resolve(); }, { once: true }));
      began();
      await cancellation;
      await closed;
    });
    // Observe actual acquisition and a running subprocess before killing the
    // real lock thread. No heartbeat, marker or clock is rewritten.
    const rejected = assert.rejects(work, { code: "STORE_LOCK_LOST" });
    // Keep early spawn errors handled until readiness/teardown completes.
    rejected.catch(() => {});
    try {
      await Promise.race([started, new Promise((resolve, reject) => { readinessTimer = setTimeout(() => reject(new Error("Owned child readiness deadline exceeded")), 10000); })]);
    } finally { clearTimeout(readinessTimer); }
    const killedAt = Date.now();
    await lock._workerForTests.terminate();
    await rejected;
    assert.equal(aborted, true, "lock loss must abort real active work");
    const childStillRunning = child.exitCode === null && child.signalCode === null;
    if (cooperative) assert.equal(childStillRunning, false, "cooperative child must actually exit before loss returns");
    else {
      assert.equal(childStillRunning, true, "fixture must genuinely exercise a non-cooperative live subprocess");
      assert.ok(Date.now() - killedAt >= 4500, "production five-second drain deadline must actually elapse");
    }
    assert.throws(() => lock.assertHeld(), { code: "STORE_LOCK_LOST" });
    successor = acquireStoreLock(stateDir, "My");
    successor.assertHeld();
    const successorMarker = fs.readFileSync(successor.lockPath, "utf8");
    lock.release();
    assert.equal(fs.readFileSync(successor.lockPath, "utf8"), successorMarker, "stale owner release must preserve successor ownership");
    successor.assertHeld();
    return { realWorkerDeath: true, realSubprocessDrained: cooperative, realDrainTimeout: !cooperative, successorAcquired: true, staleReleasePreservedSuccessor: true };
  } finally {
    if (child && child.exitCode === null && child.signalCode === null) child.kill();
    if (closed) await closed;
    lock.release();
    if (successor) successor.release();
  }
}
module.exports = { qualifyStoreLockDeath };
if (require.main === module) qualifyStoreLockDeath({ workDir: process.argv[2], cooperative: process.argv[3] !== "drain-timeout" }).then(result => console.log(JSON.stringify(result))).catch(() => { console.error("Real store-lock worker death fixture failed"); process.exitCode = 1; });

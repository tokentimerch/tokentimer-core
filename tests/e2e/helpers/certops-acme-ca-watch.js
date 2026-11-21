"use strict";

// Consumes the dedicated process-watcher channel. It provides a fail-closed
// liveness primitive only; socket/TLS coverage and the actual continuous
// qualification fixture still require independent evidence.
const assert = require("node:assert/strict");
const { performance } = require("node:perf_hooks");
const { spawn } = require("node:child_process");
const path = require("node:path");
const MAX_LINE = 8192;
function classifyWatcherStart(stderr, reason) {
  if (/AuthorizationManager/i.test(stderr)) return "watcher-authorization-manager-denied";
  return reason === "watcher-not-started" ? "watcher-start-timeout" : reason;
}

function createCaWatchChannel({ stream, process, expectedPid, binarySha256, onFailure, now = () => performance.now(), maxSilenceMs = 3000 }) {
  assert.ok(stream && process);
  assert.ok(Number.isSafeInteger(expectedPid) && expectedPid > 0);
  assert.match(binarySha256, /^[a-f0-9]{64}$/);
  assert.equal(typeof onFailure, "function");
  assert.ok(maxSilenceMs >= 1000 && maxSilenceMs <= 10000);
  let buffer = "", watchId = null, lastHeartbeat = null, failed = null, lastElapsed = -1, closed = false;
  const fail = (reason) => { if (!failed && !closed) { failed = reason; onFailure(reason); } };
  const accept = (line) => {
    let event;
    try { event = JSON.parse(line); } catch { fail("invalid-watcher-record"); return; }
    if (event?.coverageComplete !== false) { fail("invalid-watcher-coverage"); return; }
    if (watchId === null) {
      if (event.event !== "started" || !/^[a-f0-9]{32}$/.test(event.watchId) || event.processId !== expectedPid || event.binarySha256 !== binarySha256) {
        fail("invalid-watcher-start"); return;
      }
      watchId = event.watchId; lastHeartbeat = now(); return;
    }
    if (event.watchId !== watchId) { fail("watcher-identity-changed"); return; }
    if (event.event !== "heartbeat") { fail("watcher-ended"); return; }
    if (!Number.isSafeInteger(event.elapsedSeconds) || event.elapsedSeconds <= lastElapsed) { fail("invalid-watcher-heartbeat"); return; }
    lastElapsed = event.elapsedSeconds; lastHeartbeat = now();
  };
  stream.setEncoding("utf8");
  stream.on("data", (chunk) => {
    if (failed) return;
    buffer += chunk;
    if (buffer.length > MAX_LINE) { fail("watcher-output-overflow"); return; }
    let end;
    while ((end = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, end).trim(); buffer = buffer.slice(end + 1);
      if (line) accept(line);
    }
  });
  stream.once("error", () => fail("watcher-stream-error"));
  stream.once("end", () => fail("watcher-stream-closed"));
  process.once("error", () => fail("watcher-process-error"));
  process.once("exit", () => fail("watcher-process-exited"));
  const timer = setInterval(() => {
    if (!failed && watchId !== null && now() - lastHeartbeat > maxSilenceMs) fail("watcher-heartbeat-lost");
  }, 250);
  timer.unref();
  return {
    inspect() {
      if (!failed && watchId !== null && now() - lastHeartbeat > maxSilenceMs) fail("watcher-heartbeat-lost");
      return { coverageComplete: false, processContinuity: watchId !== null && !failed && !closed,
        captureId: watchId, processId: expectedPid, binarySha256, reason: failed || (closed ? "watcher-closed" : watchId ? "socket-and-tls-coverage-unproven" : "watcher-not-started") };
    },
    close() { closed = true; clearInterval(timer); },
  };
}

async function startCaProcessWatch({ expectedPid, executable, binarySha256, abortController, timeoutMs = 10000 }) {
  assert.ok(path.isAbsolute(executable));
  assert.ok(Number.isSafeInteger(expectedPid) && expectedPid > 0);
  assert.match(binarySha256, /^[a-f0-9]{64}$/);
  assert.ok(abortController && typeof abortController.abort === "function");
  assert.equal(abortController.signal?.aborted, false);
  assert.ok(Number.isSafeInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 30000);
  const script = path.join(__dirname, "certops-acme-ca-process-watch.ps1");
  const child = spawn("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", script,
    "-ObservedProcessId", String(expectedPid), "-ExpectedExecutable", executable,
    "-ExpectedSha256", binarySha256, "-MaximumSeconds", "300"],
  { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  // Retain only a bounded diagnostic in memory; never surface raw stderr,
  // which can contain local paths or other environment-specific details.
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", chunk => { if (stderr.length < 8192) stderr += chunk.slice(0, 8192 - stderr.length); });
  const closed = new Promise(resolve => child.once("close", resolve));
  const watch = createCaWatchChannel({ stream: child.stdout, process: child, expectedPid, binarySha256,
    onFailure: reason => abortController.abort(new Error(reason)) });
  const startedAt = performance.now();
  while (!watch.inspect().processContinuity) {
    const state = watch.inspect();
    if (state.reason !== "watcher-not-started" || performance.now() - startedAt > timeoutMs) {
      watch.close(); child.kill();
      await Promise.race([closed, new Promise(resolve => setTimeout(resolve, 500))]);
      const reason = classifyWatcherStart(stderr, state.reason);
      throw new Error(reason);
    }
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  return {
    inspect: watch.inspect,
    watcherPid: child.pid,
    async stop() {
      watch.close();
      if (child.exitCode !== null || child.signalCode !== null) return;
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("watcher-stop-timeout")), 5000);
        child.once("exit", () => { clearTimeout(timer); resolve(); });
        // A closed stream may arrive just before the child's exit event;
        // kill() can then return false although termination is in progress.
        child.kill();
      });
    },
  };
}

module.exports = { classifyWatcherStart, createCaWatchChannel, startCaProcessWatch };

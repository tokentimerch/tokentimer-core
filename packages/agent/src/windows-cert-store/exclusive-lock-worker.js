"use strict";

/**
 * Holds one exclusive IPC listen for acquireExclusiveLockFile.
 * SharedArrayBuffer Int32 layout:
 *   [0] state: 0=pending, 1=held, 2=busy, 3=error, 4=released
 *   [1] heartbeat: Date.now() truncated; parent assertHeld() uses this so
 *       loss is visible even before the worker `exit` event is delivered
 *
 * ipcKind:
 *   - "pipe": Windows named pipe (no filesystem node; EADDRINUSE => busy)
 *   - "abstract": Linux abstract unix socket (no filesystem node; no reclaim)
 *   - "file": pathname unix socket; stale reclaim is gated and always
 *     re-probes while holding the gate before touching the pathname
 */

const fs = require("node:fs");
const net = require("node:net");
const { parentPort, workerData } = require("node:worker_threads");
const {
  tryAcquireReclaimGate,
  releaseReclaimGate,
} = require("./exclusive-lock-reclaim-gate");

const STATE_HELD = 1;
const STATE_BUSY = 2;
const STATE_ERROR = 3;
const STATE_RELEASED = 4;

const state = new Int32Array(workerData.sab);
const ipcPath = workerData.ipcPath;
const ipcKind = workerData.ipcKind;

/** @type {import('node:net').Server|null} */
let server = null;
let settled = false;
/** @type {ReturnType<typeof setInterval>|null} */
let heartbeatTimer = null;

function signal(code) {
  if (settled) return;
  settled = true;
  stopHeartbeat();
  Atomics.store(state, 0, code);
  Atomics.notify(state, 0);
}

function startHeartbeat() {
  const tick = () => {
    // Never store 0: parent treats beat===0 as "not heartbeating", and
    // Date.now()&0x7fffffff is 0 for 1ms every ~24.85 days.
    Atomics.store(state, 1, (Date.now() & 0x7fffffff) || 1);
  };
  tick();
  heartbeatTimer = setInterval(tick, 50);
  if (typeof heartbeatTimer.unref === "function") heartbeatTimer.unref();
}

function stopHeartbeat() {
  if (heartbeatTimer) {
    clearInterval(heartbeatTimer);
    heartbeatTimer = null;
  }
}

function listenOn(nextServer, onListening) {
  server = nextServer;
  nextServer.once("error", (err) => {
    if (err && err.code === "EADDRINUSE") {
      onAddrInUse();
      return;
    }
    signal(STATE_ERROR);
  });
  nextServer.listen({ path: ipcPath, exclusive: true }, onListening);
}

function onAddrInUse() {
  if (ipcKind === "pipe" || ipcKind === "abstract") {
    signal(STATE_BUSY);
    return;
  }
  recoverStaleFileSocket();
}

/**
 * Probe whether ipcPath currently has a live listener.
 * @returns {Promise<"live"|"stale"|"missing"|"unknown">}
 */
function probeSocketFresh() {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };
    const probe = net.connect({ path: ipcPath });
    const timer = setTimeout(() => {
      try {
        probe.destroy();
      } catch {
        // ignore
      }
      finish("unknown");
    }, 1000);
    if (typeof timer.unref === "function") timer.unref();
    probe.once("connect", () => {
      probe.destroy();
      finish("live");
    });
    probe.once("error", (err) => {
      if (err && err.code === "ECONNREFUSED") {
        finish("stale");
        return;
      }
      if (err && err.code === "ENOENT") {
        finish("missing");
        return;
      }
      finish("unknown");
    });
  });
}

/**
 * Pathname unix sockets only. Gate acquisition serializes reclaimers; every
 * contender re-probes while holding the gate so a peer that already bound
 * the name is never unlinked from a stale pre-gate observation.
 */
function recoverStaleFileSocket() {
  const gatePath = `${ipcPath}.reclaim-gate`;

  // Cheap pre-check: if someone is already live, fail fast without the gate.
  probeSocketFresh().then((pre) => {
    if (settled) return;
    if (pre === "live") {
      signal(STATE_BUSY);
      return;
    }
    if (pre !== "stale" && pre !== "missing") {
      signal(STATE_BUSY);
      return;
    }
    if (!tryAcquireReclaimGate(gatePath)) {
      setTimeout(() => retryListenAfterPeerReclaim(), 25);
      return;
    }
    // Fresh check under the gate — never act on the pre-gate probe alone.
    probeSocketFresh().then((underGate) => {
      if (settled) {
        releaseReclaimGate(gatePath);
        return;
      }
      if (underGate === "live") {
        releaseReclaimGate(gatePath);
        signal(STATE_BUSY);
        return;
      }
      if (underGate !== "stale" && underGate !== "missing") {
        releaseReclaimGate(gatePath);
        signal(STATE_BUSY);
        return;
      }
      if (underGate === "stale") {
        try {
          fs.unlinkSync(ipcPath);
        } catch {
          // already gone
        }
      }
      const retry = net.createServer(() => {});
      retry.once("error", () => {
        releaseReclaimGate(gatePath);
        signal(STATE_BUSY);
      });
      retry.listen({ path: ipcPath, exclusive: true }, () => {
        releaseReclaimGate(gatePath);
        server = retry;
        if (!settled) {
          settled = true;
          startHeartbeat();
          Atomics.store(state, 0, STATE_HELD);
          Atomics.notify(state, 0);
        }
      });
    });
  });
}

function retryListenAfterPeerReclaim() {
  if (settled) return;
  const retry = net.createServer(() => {});
  retry.once("error", (err) => {
    if (err && err.code === "EADDRINUSE") {
      signal(STATE_BUSY);
      return;
    }
    signal(STATE_ERROR);
  });
  retry.listen({ path: ipcPath, exclusive: true }, () => {
    server = retry;
    if (!settled) {
      settled = true;
      startHeartbeat();
      Atomics.store(state, 0, STATE_HELD);
      Atomics.notify(state, 0);
    }
  });
}

listenOn(net.createServer(() => {}), () => {
  if (!settled) {
    settled = true;
    startHeartbeat();
    Atomics.store(state, 0, STATE_HELD);
    Atomics.notify(state, 0);
  }
});

parentPort.on("message", (msg) => {
  if (msg !== "release") return;
  const active = server;
  server = null;
  stopHeartbeat();
  if (!active) {
    Atomics.store(state, 0, STATE_RELEASED);
    Atomics.notify(state, 0);
    return;
  }
  // Do not unlink the pathname after close: Node already removes a unix
  // socket name on close, and an extra unlink can delete a successor's
  // freshly bound pathname.
  active.close(() => {
    Atomics.store(state, 0, STATE_RELEASED);
    Atomics.notify(state, 0);
  });
});

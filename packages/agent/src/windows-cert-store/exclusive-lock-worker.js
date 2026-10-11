"use strict";

/**
 * Holds one exclusive IPC listen for acquireExclusiveLockFile.
 * State Int32Array[0]: 0=pending, 1=held, 2=busy, 3=error, 4=released.
 *
 * ipcKind:
 *   - "pipe": Windows named pipe (no filesystem node; EADDRINUSE => busy)
 *   - "abstract": Linux abstract unix socket (no filesystem node; no reclaim)
 *   - "file": pathname unix socket under a short hashed directory; stale
 *     reclaim is serialized via an exclusive mkdir gate so two reclaimers
 *     cannot both unlink and listen.
 */

const fs = require("node:fs");
const net = require("node:net");
const { parentPort, workerData } = require("node:worker_threads");

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

function signal(code) {
  if (settled) return;
  settled = true;
  Atomics.store(state, 0, code);
  Atomics.notify(state, 0);
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
 * Pathname unix sockets only. Probe for a live holder; if abandoned, win an
 * exclusive mkdir gate before unlinking the stale name and listening. Losers
 * of the gate retry listen once (no independent unlink on a prior probe).
 */
function recoverStaleFileSocket() {
  const gatePath = `${ipcPath}.reclaim-gate`;
  const probe = net.connect({ path: ipcPath });
  probe.once("connect", () => {
    probe.destroy();
    signal(STATE_BUSY);
  });
  probe.once("error", (probeErr) => {
    if (!probeErr || probeErr.code !== "ECONNREFUSED") {
      signal(STATE_BUSY);
      return;
    }
    try {
      fs.mkdirSync(gatePath);
    } catch {
      // Another worker is reclaiming (or left a gate). Retry listen once
      // without unlinking based on this probe observation.
      setTimeout(() => retryListenAfterPeerReclaim(), 25);
      return;
    }
    try {
      try {
        fs.unlinkSync(ipcPath);
      } catch {
        // already gone
      }
      const retry = net.createServer(() => {});
      retry.once("error", () => {
        try {
          fs.rmdirSync(gatePath);
        } catch {
          // best-effort
        }
        // Vacancy filled by a peer between unlink and listen: they own it.
        signal(STATE_BUSY);
      });
      retry.listen({ path: ipcPath, exclusive: true }, () => {
        try {
          fs.rmdirSync(gatePath);
        } catch {
          // best-effort
        }
        server = retry;
        signal(STATE_HELD);
      });
    } catch {
      try {
        fs.rmdirSync(gatePath);
      } catch {
        // best-effort
      }
      signal(STATE_BUSY);
    }
  });
}

function retryListenAfterPeerReclaim() {
  if (settled) return;
  const retry = net.createServer(() => {});
  retry.once("error", (err) => {
    if (err && err.code === "EADDRINUSE") {
      // Peer holds it or still reclaiming — treat as busy (fail-closed).
      signal(STATE_BUSY);
      return;
    }
    signal(STATE_ERROR);
  });
  retry.listen({ path: ipcPath, exclusive: true }, () => {
    server = retry;
    signal(STATE_HELD);
  });
}

listenOn(net.createServer(() => {}), () => {
  signal(STATE_HELD);
});

parentPort.on("message", (msg) => {
  if (msg !== "release") return;
  const active = server;
  server = null;
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

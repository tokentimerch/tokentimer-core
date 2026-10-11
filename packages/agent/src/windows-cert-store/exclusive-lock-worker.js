"use strict";

/**
 * Holds one exclusive IPC listen for acquireExclusiveLockFile.
 * State Int32Array[0]: 0=pending, 1=held, 2=busy, 3=error, 4=released.
 * Exclusion is the listen itself (named pipe on win32, unix socket elsewhere);
 * process/worker death releases the bind without any stale-file reclaim path.
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

/** @type {import('node:net').Server|null} */
let server = null;
let settled = false;

function signal(code) {
  if (settled) return;
  settled = true;
  Atomics.store(state, 0, code);
  Atomics.notify(state, 0);
}

function attachServer(nextServer) {
  server = nextServer;
  server.on("error", (err) => {
    if (err && err.code === "EADDRINUSE") {
      if (process.platform === "win32") {
        signal(STATE_BUSY);
        return;
      }
      recoverStaleUnixSocket();
      return;
    }
    signal(STATE_ERROR);
  });
  server.listen({ path: ipcPath, exclusive: true }, () => {
    signal(STATE_HELD);
  });
}

/**
 * POSIX only: an abandoned unix-socket pathname can remain after the holder
 * died. Probe with a connect; ECONNREFUSED means the name is stale and safe
 * to unlink once before a single retry. A live holder must stay busy.
 */
function recoverStaleUnixSocket() {
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
      fs.unlinkSync(ipcPath);
    } catch {
      signal(STATE_BUSY);
      return;
    }
    const retry = net.createServer(() => {});
    retry.on("error", () => signal(STATE_BUSY));
    retry.listen({ path: ipcPath, exclusive: true }, () => {
      server = retry;
      signal(STATE_HELD);
    });
  });
}

attachServer(net.createServer(() => {}));

parentPort.on("message", (msg) => {
  if (msg !== "release") return;
  const active = server;
  server = null;
  if (!active) {
    Atomics.store(state, 0, STATE_RELEASED);
    Atomics.notify(state, 0);
    return;
  }
  active.close(() => {
    if (process.platform !== "win32") {
      try {
        fs.unlinkSync(ipcPath);
      } catch {
        // best-effort
      }
    }
    Atomics.store(state, 0, STATE_RELEASED);
    Atomics.notify(state, 0);
  });
});

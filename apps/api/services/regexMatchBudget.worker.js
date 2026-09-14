"use strict";

const { parentPort } = require("node:worker_threads");

parentPort.on("message", (msg) => {
  const slot = new Int32Array(msg.sab);
  try {
    const re = new RegExp(msg.pattern, msg.flags);
    Atomics.store(slot, 0, re.test(msg.input) ? 1 : 0);
  } catch (_err) {
    Atomics.store(slot, 0, 2);
  }
  Atomics.notify(slot, 0);
});

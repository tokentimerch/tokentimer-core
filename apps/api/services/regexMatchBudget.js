"use strict";

const { Worker } = require("node:worker_threads");
const path = require("node:path");

const DEFAULT_BUDGET_MS = 50;
const WORKER_PATH = path.join(__dirname, "regexMatchBudget.worker.js");

let worker = null;
let workerWarmed = false;

function killWorker() {
  if (!worker) return;
  try {
    worker.terminate();
  } catch (_err) {
    /* ignore */
  }
  worker = null;
  workerWarmed = false;
}

function getWorker() {
  if (worker) return worker;
  worker = new Worker(WORKER_PATH);
  worker.unref();
  worker.on("error", killWorker);
  worker.on("exit", () => {
    worker = null;
    workerWarmed = false;
  });
  return worker;
}

/**
 * Run `RegExp#test` in a worker so a catastrophic pattern cannot stall
 * this thread. `timedOut` means the worker was killed after `budgetMs`.
 */
function regexTestBounded(pattern, flags, input, budgetMs = DEFAULT_BUDGET_MS) {
  const sab = new SharedArrayBuffer(4);
  const slot = new Int32Array(sab);
  Atomics.store(slot, 0, -1);
  try {
    getWorker().postMessage({ sab, pattern, flags, input });
  } catch (_err) {
    killWorker();
    return { timedOut: false, match: false, error: true };
  }
  const waitMs = workerWarmed ? budgetMs : Math.max(budgetMs, 1000);
  const wait = Atomics.wait(slot, 0, -1, waitMs);
  if (wait === "timed-out") {
    killWorker();
    return { timedOut: true, match: false, error: false };
  }
  workerWarmed = true;
  const code = Atomics.load(slot, 0);
  return {
    timedOut: false,
    match: code === 1,
    error: code === 2,
  };
}

function regexExceedsMatchBudget(
  pattern,
  flags,
  probe = `${"a".repeat(40)}!`,
  budgetMs = DEFAULT_BUDGET_MS,
) {
  return regexTestBounded(pattern, flags, probe, budgetMs).timedOut;
}

module.exports = {
  DEFAULT_BUDGET_MS,
  regexTestBounded,
  regexExceedsMatchBudget,
  _test: { killWorker },
};

"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { runBoundedWorker } = require("./azure-natural-token-supervisor.cjs");

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
function budget(duration) {
  const now = Date.now();
  return { jobDeadlineMs: now + 600000 + duration, resourceDeadlineMs: now + 1200000,
    cleanupReserveMs: 600000 };
}
function makeWorker() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "azure-expiry-supervisor-"));
  const worker = path.join(dir, "worker.cjs"), marker = path.join(dir, "late-write");
  fs.writeFileSync(worker, `setTimeout(() => require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'unexpected'), 1200); setInterval(() => {}, 1000);`);
  return { dir, worker, marker };
}

test("deadline kills and waits for the worker before cleanup can start", async () => {
  const f = makeWorker();
  try {
    await assert.rejects(runBoundedWorker({ workerPath: f.worker, budget: budget(350) }),
      { message: process.platform === "linux" ? "AZURE_EXPIRY_DEADLINE" : "AZURE_EXPIRY_DRAIN_UNVERIFIED" });
    await delay(1300);
    assert.equal(fs.existsSync(f.marker), false);
  } finally { fs.rmSync(f.dir, { recursive: true, force: true }); }
});

test("cancellation kills and waits for the worker before cleanup can start", async () => {
  const f = makeWorker(), controller = new AbortController();
  try {
    const work = runBoundedWorker({ workerPath: f.worker, budget: budget(5000), signal: controller.signal });
    setTimeout(() => controller.abort(), 350);
    await assert.rejects(work, { message: process.platform === "linux" ? "AZURE_EXPIRY_CANCELLED" : "AZURE_EXPIRY_DRAIN_UNVERIFIED" });
    await delay(1300);
    assert.equal(fs.existsSync(f.marker), false);
  } finally { fs.rmSync(f.dir, { recursive: true, force: true }); }
});

test("rejects a missing cleanup reserve before spawning", () => {
  assert.throws(() => runBoundedWorker({ workerPath: path.resolve("missing.cjs"), budget: {} }),
    { code: "AZURE_EXPIRY_BUDGET_INVALID" });
});

test("refuses worker messages containing unexpected fields", async () => {
  const f = makeWorker();
  try {
    fs.writeFileSync(f.worker, "process.send({token: 'private'}); process.exit(0);");
    await assert.rejects(runBoundedWorker({ workerPath: f.worker, budget: budget(5000) }),
      { message: process.platform === "linux" ? "AZURE_EXPIRY_WORKER_FAILED" : "AZURE_EXPIRY_DRAIN_UNVERIFIED" });
  } finally { fs.rmSync(f.dir, { recursive: true, force: true }); }
});

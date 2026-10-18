"use strict";
// Discover the retained AD CS/Vault report and ownership tests. Bounded workers avoid
// multiplying source hashing and filesystem contention on Windows worktrees.
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
// The measured four-worker Windows inventory takes 449 seconds. Leave headroom
// for slower disks while retaining a finite bound within the 30-minute CI job.
const TOOLING_TIMEOUT_MS = 12 * 60 * 1000;
function discover(root = path.resolve(__dirname, "..")) {
  const files = fs.readdirSync(path.join(root, "scripts"))
    .filter(file => /^certops-.*\.test\.js$/.test(file))
    .map(file => `scripts/${file}`).sort();
  assert.ok(files.length > 0, "No qualification framework tests discovered");
  return files;
}
function concurrency(value = process.env.TEST_CONCURRENCY) {
  if (value === undefined || value === "") return Math.min(4, os.availableParallelism());
  assert.match(String(value), /^(?:[1-9]|1[0-6])$/, "TEST_CONCURRENCY must be an integer from 1 to 16");
  return Number(value);
}
function run({ files = discover(), workers = concurrency(), timeoutMs = TOOLING_TIMEOUT_MS, stdio = "inherit" } = {}) {
  assert.ok(files.length > 0, "Empty tooling inventory is not a successful run");
  console.log(`CertOps tooling: ${files.length} files, ${workers} workers, ${timeoutMs / 1000}s limit`);
  const env = { ...process.env, NODE_ENV: "test" };
  // A nested test runner must start its own inventory, not inherit the parent's
  // worker context (which makes Node ignore --test and can report false success).
  delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, ["--test", `--test-concurrency=${workers}`, ...files], {
    stdio, timeout: timeoutMs, env,
  });
  if (result.error?.code === "ETIMEDOUT") console.error(`CertOps tooling exceeded ${timeoutMs / 1000}s; inventory is incomplete and failed`);
  else if (result.error) console.error(`CertOps tooling could not execute (${result.error.code || "spawn error"})`);
  else if (result.signal) console.error(`CertOps tooling terminated by ${result.signal}; inventory is incomplete and failed`);
  return { ...result, exitCode: !result.error && !result.signal && result.status === 0 ? 0 : 1 };
}
if (require.main === module) {
  try { process.exitCode = run().exitCode; }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { discover, concurrency, run, TOOLING_TIMEOUT_MS };

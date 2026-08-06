"use strict";

// Worker used by wcng-03-concurrency.js: one process, tries to acquire the
// store lock, holds it briefly while doing a real enrollment, releases.
// Usage: node wcng-03-worker.js <stateDir> <workDir> <label> <commonName>

const path = require("node:path");

const modRoot = "C:\\TokenTimerAgentTest\\src\\windows-cert-store";
const { acquireStoreLock, generateCsrViaCng } = require(path.join(modRoot, "index.js"));

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
  const [stateDir, workDir, label, commonName] = process.argv.slice(2);
  const startedAt = new Date().toISOString();
  let lock;
  try {
    lock = acquireStoreLock(stateDir, "My");
  } catch (err) {
    console.log(JSON.stringify({ label, startedAt, gotLock: false, error: err.message, code: err.code }));
    return;
  }
  try {
    await sleep(1500);
    const result = await generateCsrViaCng({ commonName, altNames: [commonName], jobId: label, workDir });
    console.log(JSON.stringify({ label, startedAt, gotLock: true, enrollOk: result.ok !== false }));
  } finally {
    lock.release();
  }
}

main().catch((err) => {
  console.log(JSON.stringify({ error: `UNCAUGHT: ${err.message}` }));
  process.exitCode = 1;
});

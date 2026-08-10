"use strict";

// Real two-process repro for the cross-store mutex case: one process targets a
// non-default store (acquiring ["My", targetStore] via the agent's own
// acquireWindowsStoreLocks), the other targets "My" directly (acquiring
// ["My"]). If the two lock sets are not correctly deduplicated/shared, the
// second process can race the first on "My" even though neither process
// shares the other's own target store.
//
// Usage: node windows-iis-cross-store-mutex.js <stateDir> <label> <targetStore> <holdMs>
//
// Two independent node.exe invocations of this script (not two in-process
// calls) are the actual test -- see the accompanying orchestrator PowerShell
// script this is driven from, which starts process A first, waits briefly,
// then starts process B, exactly like an earlier same-store concurrency
// repro did for the same-store case.

const path = require("node:path");

const modRoot = "C:\\TokenTimerAgentTest\\src";
const { acquireWindowsStoreLocks } = require(path.join(modRoot, "index.js"));

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
  const [stateDir, label, targetStore, holdMsRaw] = process.argv.slice(2);
  const holdMs = Number(holdMsRaw) || 1500;
  const startedAt = new Date().toISOString();

  let storeLock;
  try {
    storeLock = acquireWindowsStoreLocks(stateDir, targetStore);
  } catch (err) {
    console.log(
      JSON.stringify({
        label,
        startedAt,
        targetStore,
        gotLock: false,
        error: err.message,
        code: err.code,
        finishedAt: new Date().toISOString(),
      }),
    );
    return;
  }

  try {
    await sleep(holdMs);
    console.log(
      JSON.stringify({
        label,
        startedAt,
        targetStore,
        gotLock: true,
        finishedAt: new Date().toISOString(),
      }),
    );
  } finally {
    storeLock.release();
  }
}

main().catch((err) => {
  console.log(JSON.stringify({ error: `UNCAUGHT: ${err.message}` }));
  process.exitCode = 1;
});

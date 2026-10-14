"use strict";
// Fault controller: execute the actual native collector and terminate this
// owned child only after its exact certificate deletion succeeds, before the
// native key deletion callback or durable ledger completion can execute.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const childProcess = require("node:child_process");
const retention = require("../../src/windows-retention");
const { isAgentOwnedContainerName } = require("../../src/windows-cert-store");

async function main() {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_HOST_TESTS, "1");
  const [stateDir, thumbprint, containerName] = process.argv.slice(2);
  assert.match(thumbprint, /^[A-F0-9]{40}$/);
  assert.equal(isAgentOwnedContainerName(containerName), true);
  const absoluteState = path.resolve(stateDir);
  assert.match(path.basename(path.dirname(absoluteState)), /^elapsed-retention-[a-f0-9-]{36}$/);
  assert.equal(path.basename(absoluteState), "state");
  const row = retention.readLedgerRow(path.join(absoluteState, "windows-retention"), thumbprint);
  assert.equal(row.oldThumbprint, thumbprint);
  assert.equal(row.cngKeyContainerId, containerName);
  assert.equal(row.ownershipProvenance, "tokentimer_installed");
  assert.equal(row.store, "My");
  let nativeDeletionObserved = false;
  const execFileImpl = (file, args, options, callback) => childProcess.execFile(file, args, options, (error, stdout, stderr) => {
    if (!error && path.basename(file).toLowerCase() === "certutil.exe" && args.length === 3 && args[0] === "-delstore" && args[1] === "My" && args[2] === thumbprint) {
      assert.equal(nativeDeletionObserved, false);
      nativeDeletionObserved = true;
      fs.writeFileSync(path.join(absoluteState, "interrupted-native-delete.json"), JSON.stringify({ fault: "process-exit-after-native-delstore-before-delkey", thumbprint, containerName, nativeCommandSucceeded: true, pid: process.pid, observedAt: new Date().toISOString() }));
      process.exit(86);
    }
    callback(error, stdout, stderr);
  });
  await require("../../src/index").runWindowsRetentionSweep({ stateDir: absoluteState, retentionHours: 24, execFileImpl, log: { info() {}, error() {} } });
  throw new Error("Required native deletion fault boundary was not observed");
}
if (require.main === module) main().catch(error => { console.error(error.message); process.exitCode = 1; });

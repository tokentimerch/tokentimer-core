"use strict";
/* Cross-process native store-lock recovery check for windows-host.test.js. Owns only spawned
 * children and a temporary lock directory; an actual dead process must release or safely abandon
 * its lock before a successor proceeds.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { acquireStoreLock } = require("../../src/windows-cert-store");

async function qualifyStoreLockProcessDeath({ workDir }) {
  const stateDir = path.join(workDir, "process-death-state");
  assert.equal(fs.existsSync(stateDir), false);
  fs.mkdirSync(stateDir);
  const readyFile = path.join(stateDir, "ready");
  const lockModule = path.resolve(__dirname, "../../src/windows-cert-store");
  const holder = "require(process.argv[1]).acquireStoreLock(process.argv[2],'My'); require('node:fs').writeFileSync(process.argv[3],'ready'); setInterval(()=>{},1000)";
  const child = spawn(process.execPath, ["-e", holder, lockModule, stateDir, readyFile], { stdio: "ignore" });
  const closed = new Promise((resolve, reject) => { child.once("error", reject); child.once("close", (code, signal) => resolve({ code, signal })); });
  closed.catch(() => {});
  let successor;
  try {
    const deadline = Date.now() + 15000;
    while (!fs.existsSync(readyFile) && Date.now() < deadline && child.exitCode === null && child.signalCode === null) await new Promise(resolve => setTimeout(resolve, 50));
    assert.equal(fs.existsSync(readyFile), true, "actual owned child must acquire IPC before crash");
    const markerPath = path.join(stateDir, "windows-cert-store", "My.lock");
    const predecessorMarker = fs.readFileSync(markerPath, "utf8");
    assert.equal(Number(predecessorMarker.split(/\r?\n/)[0]), child.pid);
    assert.throws(() => acquireStoreLock(stateDir, "My"), { code: "STORE_LOCKED" });
    // Abruptly stop only the exact child launched above. The real OS releases
    // its IPC handle; the diagnostic marker is deliberately left untouched.
    assert.equal(child.kill("SIGKILL"), true);
    await closed;
    assert.equal(fs.readFileSync(markerPath, "utf8"), predecessorMarker, "abrupt death must actually leave the old diagnostic marker for recovery");
    successor = acquireStoreLock(stateDir, "My");
    successor.assertHeld();
    const marker = fs.readFileSync(successor.lockPath, "utf8").split(/\r?\n/);
    assert.equal(Number(marker[0]), process.pid);
    assert.ok(marker.includes(successor.ownerToken), "successor must publish its actual new owner token");
    return { actualOwnerProcessKilled: true, actualSuccessorIpcAcquired: true, realSuccessorMarker: true };
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    await closed;
    if (successor) successor.release();
  }
}
module.exports = { qualifyStoreLockProcessDeath };
if (require.main === module) qualifyStoreLockProcessDeath({ workDir: process.argv[2] }).then(result => console.log(JSON.stringify(result))).catch(() => { console.error("Real store-lock owner-process death fixture failed"); process.exitCode = 1; });

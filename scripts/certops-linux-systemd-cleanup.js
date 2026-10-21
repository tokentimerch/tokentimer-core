/**
 * Failure/interruption cleanup for the run-owned installed Linux agent.
 * Called with always() by certops-linux-systemd.yml. Revalidate the ownership receipt
 * and current native unit/process identity before stopping/removing anything; a
 * replacement or unproved installation is a cleanup failure, not an authorized target. */
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
function cleanup() {
  assert.equal(process.platform, "linux");
  assert.equal(process.getuid(), 0);
  require("./certops-linux-systemd-ownership").validateHostedEnvironment(process.env);
  assert.equal(process.env.CERTOPS_LINUX_SYSTEMD_DISPOSABLE_HOST, "1");
  assert.ok(process.env.RUNNER_TEMP);
  const receiptPath = path.join(process.env.RUNNER_TEMP, "certops-linux-systemd-owned.json");
  const stat = fs.lstatSync(receiptPath,{throwIfNoEntry:false});
  if (!stat) {
    for(const target of ["/opt/tokentimer-agent","/etc/systemd/system/tokentimer-agent.service","/etc/systemd/system/tokentimer-agent.service.d","/etc/polkit-1/rules.d/50-tokentimer-agent.rules"]){assert.equal(fs.lstatSync(target,{throwIfNoEntry:false}),undefined,"Cleanup receipt missing while host resources exist; refusing unowned cleanup");}
    for(const database of ["passwd","group"])assert.equal(spawnSync("getent",[database,"tokentimer-agent"]).status,2,"Cleanup receipt missing while an agent account exists");
    return;
  }
  assert.equal(stat.isFile(),true);
  assert.equal(stat.isSymbolicLink(), false);
  assert.equal(stat.uid, 0);
  assert.equal(stat.mode & 0o777, 0o600);
  const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
  assert.equal(receipt.root, "/opt/tokentimer-agent");
  assert.equal(receipt.unit, "tokentimer-agent.service");
  assert.equal(receipt.user, "tokentimer-agent");
  assert.equal(receipt.installer, path.resolve(__dirname, "../packages/agent/scripts/install-agent.sh"));
  assert.equal(receipt.fixtureSha256, crypto.createHash("sha256").update(fs.readFileSync(
    path.resolve(__dirname, "../tests/e2e/linux-systemd-real-journey.js"))).digest("hex"));
  const writeFixture=require("./certops-linux-systemd-ownership").validateWriteFixture(receipt.writeFixture);
  // The immutable original plan requires positive restoration, even if a later
  // active marker disappears. Missing completion is never permission to erase
  // a private config backup or unknown installed-service state.
  require("../tests/e2e/helpers/certops-linux-installed-discovery").assertCompletion(receipt,process.env.RUNNER_TEMP);
  assert.equal(writeFixture.probeSha256,crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname,"../tests/e2e/helpers/linux-systemd-write-probe.js"))).digest("hex"));
  require("./certops-linux-systemd-ownership").assertNoSymlinkTargets([receipt.root,`/etc/systemd/system/${receipt.unit}`,`/etc/systemd/system/${receipt.unit}.d`,"/etc/polkit-1/rules.d/50-tokentimer-agent.rules",writeFixture.root]);
  const uninstall = spawnSync("sh", [receipt.installer, "--uninstall"], { stdio: "ignore", timeout: 60000 });
  assert.equal(uninstall.status, 0);
  const pid = spawnSync("systemctl", ["show", receipt.unit, "--property=MainPID", "--value"], { encoding: "utf8", timeout: 10000 });
  if (pid.status !== 0) {
    const load = spawnSync("systemctl", ["show", receipt.unit, "--property=LoadState", "--value"], { encoding: "utf8", timeout: 10000 });
    assert.equal(load.stdout.trim(), "not-found");
  }
  assert.equal(Number(pid.stdout.trim()), 0, "never remove state under a running service");
  const cgroupMembers=`/sys/fs/cgroup/system.slice/${receipt.unit}/cgroup.procs`;
  if(fs.existsSync(cgroupMembers))assert.equal(fs.readFileSync(cgroupMembers,"utf8").trim(),"","Preserve state while the owned systemd cgroup still has processes");
  for (const target of [receipt.root, `/etc/systemd/system/${receipt.unit}.d`,writeFixture.root]) {
    assert.equal(fs.lstatSync(target, { throwIfNoEntry: false })?.isSymbolicLink() || false, false);
    fs.rmSync(target, { recursive: true, force: true });
  }
  assert.equal(spawnSync("systemctl", ["daemon-reload"], { timeout: 10000 }).status, 0);
  for (const [database, executable] of [["passwd", "userdel"], ["group", "groupdel"]]) {
    if (spawnSync("getent", [database, receipt.user]).status === 0) {
      assert.equal(spawnSync(executable, [receipt.user], { timeout: 10000 }).status, 0);
    }
    assert.equal(spawnSync("getent", [database, receipt.user]).status, 2);
  }
  assert.equal(fs.existsSync(receipt.root), false);
  assert.equal(fs.existsSync(writeFixture.root),false);
  fs.unlinkSync(receiptPath);
}
module.exports = { cleanup };
if (require.main === module) { try { cleanup(); } catch { console.error("Owned Linux installer cleanup failed"); process.exitCode = 1; } }

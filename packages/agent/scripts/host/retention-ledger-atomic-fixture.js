"use strict";
/**
 * Real Windows filesystem refusal at the retention ledger's atomic replacement.
 * The production writer and ACL enforcement operate on an exclusively created
 * temporary ledger containing public synthetic identifiers. An independently
 * identified native child denies delete sharing; no fs implementation, clock,
 * certificate store, service or cleanup callback is substituted. This proves
 * replacement-refusal durability, not power-loss or every torn-write phase.
 */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");
const ledger = require("../../src/windows-retention");
const FIELDS = ["nativeFileHandleHeld", "nativeFileIdentityMatched", "actualAtomicReplaceRefused", "priorRowBytesPreserved", "priorRowIdentityPreserved", "failedTemporaryFileRemoved", "nativeHandleReleased", "ownedChildDrained", "actualReplacementSucceeded", "freshProcessReadExactReplacement", "restrictivePermissionsVerified", "ownedTemporaryFixtureRemoved"];
const REQUIRED_SOURCES = ["packages/agent/scripts/host/retention-ledger-atomic-fixture.js", "packages/agent/scripts/host/retention-ledger-file-hold.ps1", "packages/agent/src/windows-retention/index.js", "packages/agent/src/platform/index.js", "packages/agent/src/platform/durability.js"];

function verifyAtomicProof(facts) {
  for (const field of FIELDS) assert.equal(facts?.[field], true, field);
  return true;
}

async function qualifyLedgerAtomicReplace() {
  assert.equal(process.platform, "win32", "Native file-sharing semantics require Windows");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "certops-retention-atomic-"));
  const ledgerDir = path.join(root, "ledger");
  const thumbprint = "A1".repeat(20);
  const file = path.join(ledgerDir, thumbprint + ".json");
  const token = crypto.randomBytes(16).toString("hex");
  assert.ok(process.env.SystemRoot && path.isAbsolute(process.env.SystemRoot));
  const powershell = path.join(process.env.SystemRoot, "System32/WindowsPowerShell/v1.0/powershell.exe");
  const entry = path.join(__dirname, "retention-ledger-file-hold.ps1");
  const quote = value => value.replace(/'/g, "''");
  const nativeEnvironment = Object.fromEntries(["SystemRoot", "WINDIR", "ComSpec", "PATH", "PATHEXT", "TEMP", "TMP", "SystemDrive", "ProgramFiles", "ProgramData", "USERPROFILE", "APPDATA", "LOCALAPPDATA"].filter(key => process.env[key] !== undefined).map(key => [key, process.env[key]]));
  const runPowerShell = script => {
    const result = spawnSync(powershell, ["-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop';" + script], { encoding: "utf8", windowsHide: true, timeout: 15000, env: nativeEnvironment });
    assert.ifError(result.error); assert.equal(result.status, 0, "Owned file holder identity check failed");
    return result.stdout.trim();
  };
  let child, completed, exited = false, identity, held, primary;
  const facts = {};
  const observe = () => JSON.parse(runPowerShell(`$p=Get-CimInstance Win32_Process -Filter 'ProcessId=${child.pid}';if(!$p -or $p.ParentProcessId -ne ${process.pid} -or $p.ExecutablePath -ne '${quote(powershell)}' -or !$p.CommandLine.Contains('${quote(entry)}') -or !$p.CommandLine.Contains('${token}')){throw 'Owned ledger holder identity mismatch'};@{pid=$p.ProcessId;parentPid=$p.ParentProcessId;created=$p.CreationDate.ToUniversalTime().ToString('o')}|ConvertTo-Json -Compress`));
  const waitFor = async predicate => {
    const deadline = Date.now() + 15000;
    while (!predicate()) {
      assert.equal(exited, false, "Owned ledger holder exited before its handshake");
      assert.ok(Date.now() < deadline, "Owned ledger holder handshake exceeded its deadline");
      await new Promise(resolve => setTimeout(resolve, 50));
    }
  };
  const joinChild = () => {
    let timer;
    return Promise.race([completed, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("Owned ledger holder did not drain")), 15000); })]).finally(() => clearTimeout(timer));
  };
  try {
    const original = ledger.createLedgerRow({ ledgerDir, oldThumbprint: thumbprint, replacementThumbprint: "B2".repeat(20), cngKeyContainerId: "tokentimer-public-ledger-fixture", verifiedCutoverAt: new Date().toISOString(), oldNotAfter: new Date(Date.now() + 86400000).toISOString(), ownershipProvenance: "tokentimer_installed", store: "My" });
    const originalBytes = fs.readFileSync(file);
    const originalId = fs.statSync(file, { bigint: true }).ino;
    const replacement = { ...original, lifecycleState: "deferred", deferralReason: "deadline_not_reached" };
    child = spawn(powershell, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", entry, "-FixtureRoot", root, "-Thumbprint", thumbprint, "-Token", token, "-OwnerProcessId", String(process.pid)], { windowsHide: true, stdio: "ignore", env: nativeEnvironment });
    completed = new Promise(resolve => { child.once("error", () => { exited = true; resolve({ error: true }); }); child.once("close", code => { exited = true; resolve({ code }); }); });
    await waitFor(() => {
      if (!Number.isInteger(child.pid)) return false;
      try { identity = observe(); return true; } catch { return false; }
    });
    await waitFor(() => fs.existsSync(path.join(root, "held.json")));
    held = JSON.parse(fs.readFileSync(path.join(root, "held.json"), "utf8"));
    assert.deepEqual(observe(), identity);
    for (const field of ["pid", "parentPid", "created"]) assert.equal(held[field], identity[field]);
    assert.equal(held.phase, "held"); assert.equal(held.token, token); assert.equal(held.shareMask, 3);
    assert.match(held.fileId, /^[a-f0-9]{16}$/); assert.ok(originalId > 0n);
    assert.equal(BigInt("0x" + held.fileId), originalId);
    facts.nativeFileHandleHeld = true; facts.nativeFileIdentityMatched = true;
    assert.throws(() => ledger.writeLedgerRow(ledgerDir, replacement), error => {
      assert.ok(["EPERM", "EACCES", "EBUSY"].includes(error.code));
      assert.equal(error.syscall, "rename");
      assert.equal(path.resolve(error.dest), file);
      assert.equal(path.dirname(error.path), ledgerDir);
      assert.match(path.basename(error.path), new RegExp("^" + thumbprint + "\\.json\\." + process.pid + "\\.[a-f0-9]{16}\\.tmp$"));
      return true;
    });
    assert.deepEqual(observe(), identity); assert.equal(exited, false);
    assert.deepEqual(fs.readFileSync(file), originalBytes);
    assert.equal(fs.statSync(file, { bigint: true }).ino, originalId);
    assert.deepEqual(ledger.readLedgerRow(ledgerDir, thumbprint), original);
    assert.deepEqual(fs.readdirSync(ledgerDir), [thumbprint + ".json"]);
    Object.assign(facts, { actualAtomicReplaceRefused: true, priorRowBytesPreserved: true, priorRowIdentityPreserved: true, failedTemporaryFileRemoved: true });
    fs.writeFileSync(path.join(root, "release.txt"), token, { flag: "wx" });
    assert.deepEqual(await joinChild(), { code: 0 });
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(root, "closed.json"), "utf8")), { ...held, phase: "closed" });
    facts.nativeHandleReleased = true; facts.ownedChildDrained = true;
    const written = ledger.writeLedgerRow(ledgerDir, replacement);
    assert.deepEqual(written, replacement);
    assert.notEqual(fs.statSync(file, { bigint: true }).ino, originalId);
    assert.deepEqual(fs.readdirSync(ledgerDir), [thumbprint + ".json"]);
    const readBack = spawnSync(process.execPath, ["-e", "const l=require(process.argv[1]);process.stdout.write(JSON.stringify(l.readLedgerRow(process.argv[2],process.argv[3])))", require.resolve("../../src/windows-retention"), ledgerDir, thumbprint], { encoding: "utf8", windowsHide: true, timeout: 15000, env: nativeEnvironment });
    assert.ifError(readBack.error); assert.equal(readBack.status, 0, "Independent ledger reader failed");
    assert.deepEqual(JSON.parse(readBack.stdout), replacement);
    const platform = require("../../src/platform");
    assert.equal(fs.lstatSync(ledgerDir).isDirectory(), true);
    platform.assertWindowsAcl(ledgerDir, { requireProtected: true });
    platform.assertRestrictivePermissions(file, { requireProtected: true });
    Object.assign(facts, { actualReplacementSucceeded: true, freshProcessReadExactReplacement: true, restrictivePermissionsVerified: true });
  } catch (error) { primary = error; }
  finally {
    try {
      if (child && !exited) {
        const current = observe(); if (identity) assert.deepEqual(current, identity);
        const release = path.join(root, "release.txt");
        if (!fs.existsSync(release)) fs.writeFileSync(release, token, { flag: "wx" });
        else assert.equal(fs.readFileSync(release, "utf8"), token);
        assert.deepEqual(await joinChild(), { code: 0 });
      }
    } catch (error) {
      primary = primary ? new AggregateError([primary, error], "Ledger failure and owned handle drain failed") : error;
    }
    // A live or unverified child keeps the directory for runner disposal. Never
    // race its native handle with recursive removal or terminate an unknown PID.
    if (!child || exited) {
      try {
        assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir()));
        assert.match(path.basename(root), /^certops-retention-atomic-[A-Za-z0-9]{6}$/);
        assert.equal(fs.lstatSync(root).isSymbolicLink(), false);
        fs.rmSync(root, { recursive: true, force: false });
        assert.equal(fs.existsSync(root), false); facts.ownedTemporaryFixtureRemoved = true;
      } catch (error) { primary = primary ? new AggregateError([primary, error], "Ledger failure and temporary cleanup failed") : error; }
    }
  }
  if (primary) throw primary;
  verifyAtomicProof(facts);
  return facts;
}

module.exports = { qualifyLedgerAtomicReplace, verifyAtomicProof, FIELDS, REQUIRED_SOURCES };

"use strict";
/** External source-oplock orchestration for second-rename refusal. The same
 * mechanics support a benign temporary-file control and a genuine installer
 * CLI. This function alone never claims installed-service qualification. */
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const { spawn, spawnSync } = require("node:child_process");
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const fields = ["sourceOplockGranted", "actualSourceOpenBrokeOplock", "stagingHeldBeforeCopyResumed", "nativeOrderedRestoration", "originalDirectoryIdentityPreserved", "installedBytesUnchanged", "explicitStagingCleanupFailure", "sourceBytesUnchanged", "nativeHandleReleased", "ownedInstallerDrained", "ownedDriverDrained", "ownedStagingRemoved"];
const cleanupGuardName = ".certops-cli-cleanup-guard.json";
function assertCleanupSafe(directory) {
  const file = path.join(directory, cleanupGuardName);
  if (!fs.existsSync(file)) return;
  const guard = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.equal(guard.phase, "drained", "Refuse cleanup while installer/holder drain is unproven");
  assert.equal(guard.installerAbsent, true); assert.equal(guard.driverAbsent, true);
}
async function drainInOrder({ drainInstaller, drainHolder }) {
  // Never enter holder teardown when the installer could still resume.
  await drainInstaller(); await drainHolder();
}
function verifyMechanics(facts) { assert.deepEqual(Object.keys(facts).sort(), [...fields].sort()); for (const field of fields) assert.equal(facts[field], true, field); return true; }
function inventory(root) {
  const rows = [];
  function visit(directory) { for (const name of fs.readdirSync(directory).sort()) { const file = path.join(directory, name), stat = fs.lstatSync(file); assert.equal(stat.isSymbolicLink(), false); if (stat.isDirectory()) visit(file); else { assert.equal(stat.isFile(), true); rows.push([path.relative(root, file), crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex")]); } } }
  visit(root); return rows;
}
async function runFault({ installer, installerArgs = [], sourceFile, installRoot, protocolParent, environment = {}, onRestored = async () => {} }) {
  assert.equal(process.platform, "win32");
  for (const file of [installer, sourceFile, installRoot, protocolParent]) assert.ok(path.isAbsolute(file));
  assert.equal(fs.lstatSync(sourceFile).isFile(), true); assert.equal(fs.lstatSync(sourceFile).isSymbolicLink(), false);
  const app = path.join(installRoot, "app"), before = inventory(app), originalInode = fs.statSync(app, { bigint: true }).ino;
  const sourceHash = crypto.createHash("sha256").update(fs.readFileSync(sourceFile)).digest("hex");
  const directory = fs.mkdtempSync(path.join(protocolParent, "certops-cli-oplock-")), token = crypto.randomBytes(16).toString("hex");
  const guardPaths = [...new Set([installRoot, protocolParent])].map(root => path.join(root, cleanupGuardName));
  for (const file of guardPaths) { assert.equal(fs.existsSync(file), false, "Outstanding installer cleanup guard must be resolved first"); fs.writeFileSync(file, JSON.stringify({ token, phase: "active", protocolDirectory: directory }), { flag: "wx" }); }
  const executable = path.join(process.env.SystemRoot, "System32/WindowsPowerShell/v1.0/powershell.exe"), driver = path.join(__dirname, "certops-windows-cli-oplock-driver.ps1");
  const launcher = path.join(__dirname, "certops-windows-cli-oplock-launcher.ps1");
  const nativeEnv = Object.fromEntries(["SystemRoot", "WINDIR", "ComSpec", "PATH", "PATHEXT", "TEMP", "TMP", "SystemDrive", "ProgramFiles", "ProgramData", "USERPROFILE", "APPDATA", "LOCALAPPDATA"].filter(key => process.env[key] !== undefined).map(key => [key, process.env[key]]));
  const observe = (child, expectedFile, expectedToken) => {
    const result = spawnSync(executable, ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(`$ErrorActionPreference='Stop';$p=Get-CimInstance Win32_Process -Filter 'ProcessId=${child.pid}';if(!$p){throw 'Owned child absent'};@{pid=$p.ProcessId;parentPid=$p.ParentProcessId;created=$p.CreationDate.ToUniversalTime().ToString('o');executable=$p.ExecutablePath;command=$p.CommandLine}|ConvertTo-Json -Compress`, "utf16le").toString("base64")], { env: nativeEnv, encoding: "utf8", timeout: 10000, maxBuffer: 32768, windowsHide: true });
    assert.ifError(result.error); assert.equal(result.status, 0, "Owned process measurement failed"); const identity = JSON.parse(result.stdout);
    assert.equal(identity.pid, child.pid); assert.equal(identity.parentPid, process.pid); assert.equal(path.resolve(identity.executable).toLowerCase(), executable.toLowerCase());
    assert.ok(identity.command.toLowerCase().includes(expectedFile.toLowerCase())); if (expectedToken) assert.ok(identity.command.includes(expectedToken)); assert.ok(Number.isFinite(Date.parse(identity.created))); return identity;
  };
  const launch = (file, args, env) => {
    const child = spawn(executable, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", file, ...args], { env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    const state = { child, closed: false, text: "", overflow: false };
    // Overflow must never kill the holder while a blocked installer could
    // resume. Retain bounded output and use the same ordered teardown path.
    for (const stream of [child.stdout, child.stderr]) stream.on("data", chunk => { if (Buffer.byteLength(state.text) + chunk.length > 131072) state.overflow = true; else if (!state.overflow) state.text += chunk.toString("utf8"); });
    state.exit = new Promise(resolve => { child.once("error", () => { state.spawnError = true; }); child.once("close", (code, signal) => { state.closed = true; resolve({ code, signal }); }); }); return state;
  };
  const wait = async (check, milliseconds = 60000) => { const until = Date.now() + milliseconds; while (Date.now() < until) { const result = await check(); if (result) return result; await delay(25); } throw new Error("Native oplock protocol deadline exceeded"); };
  const signal = name => { const file = path.join(directory, name); if (!fs.existsSync(file)) fs.writeFileSync(file, token, { flag: "wx" }); };
  const receipt = name => JSON.parse(fs.readFileSync(path.join(directory, name), "utf8"));
  const absent = state => {
    if (!state?.child.pid) return true;
    const result = spawnSync(executable, ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(`$ErrorActionPreference='Stop';if(Get-CimInstance Win32_Process -Filter 'ProcessId=${state.child.pid}'){'present'}else{'absent'}`, "utf16le").toString("base64")], { env: nativeEnv, encoding: "utf8", timeout: 10000, windowsHide: true });
    assert.ifError(result.error); assert.equal(result.status, 0); return result.stdout.trim() === "absent";
  };
  let holder, worker, holderIdentity, workerIdentity, restored, primary, closedReceipt;
  try {
    holder = launch(driver, ["-SourceFile", sourceFile, "-InstallRoot", installRoot, "-ProtocolDirectory", directory, "-Token", token, "-OwnerProcessId", String(process.pid)], nativeEnv);
    holderIdentity = await wait(() => { assert.equal(holder.closed, false, "Native oplock capability unavailable: driver exited"); try { return observe(holder.child, driver, token); } catch { return null; } }, 10000);
    signal("identity-confirmed");
    await wait(() => { assert.equal(holder.closed, false, "OPLOCK_CAPABILITY_UNAVAILABLE: exclusive source oplock was not granted"); return fs.existsSync(path.join(directory, "ready.json")); }, 30000);
    const ready = receipt("ready.json"); assert.equal(ready.phase, "source-oplock-granted"); assert.equal(ready.token, token); for (const key of ["pid", "parentPid", "created"]) assert.equal(ready[key], holderIdentity[key]);
    assert.equal(BigInt("0x" + ready.originalId.split(":")[1]), originalInode);
    fs.writeFileSync(path.join(directory, "arguments.json"), JSON.stringify(installerArgs), { flag: "wx" });
    worker = launch(launcher, ["-Installer", installer, "-ProtocolDirectory", directory, "-Token", token, "-OwnerProcessId", String(process.pid)], { ...nativeEnv, ...environment });
    workerIdentity = await wait(() => { assert.equal(worker.closed, false, "Installer exited before externally measured staging interception"); try { return observe(worker.child, launcher, token); } catch { return null; } }, 10000);
    fs.writeFileSync(path.join(directory, "installer.json"), JSON.stringify({ ...workerIdentity, token }), { flag: "wx" }); signal("installer-identity-confirmed");
    await wait(() => { assert.equal(holder.closed, false); return fs.existsSync(path.join(directory, "registered.json")); });
    const registered = receipt("registered.json"); assert.equal(registered.token, token); assert.equal(registered.installerPid, worker.child.pid); signal("run-installer");
    await wait(() => { assert.equal(holder.closed, false, "Native source-open break could not establish actual staging hold"); assert.equal(worker.closed, false); return fs.existsSync(path.join(directory, "held.json")); });
    const held = receipt("held.json"); assert.equal(held.token, token); assert.equal(held.installerPid, worker.child.pid); assert.equal(held.phase, "copy-blocked-staging-held"); assert.equal(held.shareMask, 3); assert.equal(held.originalId, ready.originalId);
    assert.equal(JSON.stringify(observe(holder.child, driver, token)) === JSON.stringify(holderIdentity), true, "Holder identity changed"); assert.equal(JSON.stringify(observe(worker.child, launcher, token)) === JSON.stringify(workerIdentity), true, "Installer identity changed");
    const staging = `${app}.staging.${worker.child.pid}`, previous = `${app}.previous.${worker.child.pid}`;
    assert.equal(fs.statSync(staging, { bigint: true }).ino, BigInt("0x" + held.stagingId.split(":")[1]));
    assert.equal(fs.existsSync(previous), false); assert.equal(fs.statSync(app, { bigint: true }).ino, originalInode);
    signal("resume-copy");
    await wait(() => { assert.equal(holder.closed, false, "Native rename observer failed"); return fs.existsSync(path.join(directory, "restored.json")); });
    restored = receipt("restored.json"); assert.equal(restored.token, token); assert.equal(restored.installerPid, worker.child.pid); assert.equal(restored.originalId, held.originalId); assert.equal(restored.stagingId, held.stagingId); assert.equal(restored.shareMask, 3);
    assert.deepEqual(restored.renameEvents, [["app", `app.previous.${worker.child.pid}`], [`app.previous.${worker.child.pid}`, "app"]]);
    await wait(() => worker.closed, 15000); const result = await worker.exit; assert.equal(absent(worker), true); assert.equal(worker.overflow, false); assert.ok(Number.isInteger(result.code) && result.code !== 0);
    assert.match(worker.text, /failed to activate the staged agent package; recovery incomplete \(staging cleanup failed\)/);
    assert.doesNotMatch(worker.text, /previous installation restoration failed/);
    assert.equal(fs.existsSync(previous), false); assert.equal(fs.statSync(app, { bigint: true }).ino, originalInode); assert.deepEqual(inventory(app), before);
    assert.equal(crypto.createHash("sha256").update(fs.readFileSync(sourceFile)).digest("hex"), sourceHash);
    await onRestored();
    signal("release-staging"); await wait(() => holder.closed, 15000); const driverResult = await holder.exit; assert.equal(absent(holder), true); assert.equal(driverResult.code, 0); assert.equal(holder.overflow, false);
    closedReceipt = receipt("closed.json"); assert.deepEqual(closedReceipt, { token, installerPid: worker.child.pid, phase: "closed", originalId: restored.originalId, stagingId: restored.stagingId, stagingAbsent: true });
    assert.equal(fs.existsSync(staging), false); assert.equal(fs.existsSync(previous), false); assert.deepEqual(inventory(app), before);
  } catch (error) { primary = error; }
  finally {
    // Drain the installer before releasing/killing its oplock holder: otherwise
    // an aborted blocked copy could resume the real CLI during error cleanup.
    if (primary && holder?.text) fs.writeFileSync(path.join(directory, "driver-private.log"), holder.text);
    if (primary && worker?.text) fs.writeFileSync(path.join(directory, "installer-private.log"), worker.text);
    const failures = [];
    const drain = async (state, savedIdentity, file, expectedToken) => {
      if (!state) return;
      if (!state.closed) {
        const identity = savedIdentity || observe(state.child, file, expectedToken);
        assert.equal(JSON.stringify(observe(state.child, file, expectedToken)) === JSON.stringify(identity), true, "Refuse changed child identity");
        state.child.kill(); await wait(() => state.closed, 10000); await state.exit;
      }
      assert.equal(absent(state), true, "Owned process must be absent before handle release/root cleanup");
    };
    try {
      await drainInOrder({ drainInstaller: () => drain(worker, workerIdentity, launcher, token), drainHolder: () => drain(holder, holderIdentity, driver, token) });
      for (const file of guardPaths) { const saved = JSON.parse(fs.readFileSync(file, "utf8")); assert.equal(saved.token, token); fs.writeFileSync(file, JSON.stringify({ token, phase: "drained", installerAbsent: true, driverAbsent: true })); }
    } catch (error) { failures.push(error); }
    if (!primary && !failures.length) {
      const parent = path.resolve(protocolParent), target = path.resolve(directory); assert.ok(target.startsWith(parent + path.sep) && path.basename(target).startsWith("certops-cli-oplock-")); fs.rmSync(target, { recursive: true });
    }
    if (failures.length) primary = new AggregateError([...(primary ? [primary] : []), ...failures], "Oplock protocol could not drain owned processes");
  }
  if (primary) throw primary;
  const facts = Object.fromEntries(fields.map(field => [field, true])); verifyMechanics(facts); return facts;
}
module.exports = { runFault, verifyMechanics, fields, assertCleanupSafe, drainInOrder, cleanupGuardName };

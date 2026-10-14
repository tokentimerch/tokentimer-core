"use strict";
/** Real first-rename refusal in the owned installed Windows journey. A verified
 * native directory handle excludes delete sharing while the genuine installer
 * stages the candidate. The healthy predecessor must keep its PID, heartbeat,
 * files, credential and trusted TLS; no second-rename restoration is claimed. */
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto"), tls = require("node:tls");
const { spawn, spawnSync } = require("node:child_process");
const requiredScenarios = ["windows-upgrade-directory-handle-owned", "windows-upgrade-first-rename-refusal-preserves-service", "windows-upgrade-rename-refusal-owned-cleanup"];
const requiredSources = ["tests/e2e/helpers/certops-windows-rename-refusal.js", "tests/e2e/helpers/certops-windows-directory-hold.ps1", "packages/agent/scripts/install-agent.ps1", "scripts/certops-installer-swap.test.ps1", "tests/e2e/windows-real-journey.js"];
function verifyProof(proof) {
  for (const field of ["nativeDirectoryHandleHeld", "nativeHandleIdentityMatched", "actualFirstRenameRefused", "stagingRemoved", "previousDirectoryAbsent", "installedFilesUnchanged", "configurationAndCredentialUnchanged", "sameRunningServicePid", "freshAuthenticatedHeartbeat", "trustedTlsUnchanged", "nativeHandleReleased", "ownedChildDrained"]) assert.equal(proof[field], true, field);
  return true;
}
function fileInventory(directory) {
  const files = [];
  function visit(current) {
    for (const name of fs.readdirSync(current).sort()) {
      const file = path.join(current, name), stat = fs.lstatSync(file);
      assert.equal(stat.isSymbolicLink(), false, "Installed candidate fixture must not contain linked entries");
      if (stat.isDirectory()) visit(file);
      else { assert.equal(stat.isFile(), true); files.push([path.relative(directory, file), crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex")]); }
    }
  }
  visit(directory); return files;
}
async function qualifyRenameRefusal({ pool, workspaceId, agentId, configDir, workDir, repoRoot, installerFixture, createBootstrap, baseUrl, domain, port, roots, thumbprint, powershell, run, waitUntil }) {
  assert.equal(process.platform, "win32"); assert.equal(process.env.CERTOPS_WINDOWS_KEY_PROFILE, "rsa-2048");
  const appDir = path.join(workDir, "app"), directory = fs.mkdtempSync(path.join(workDir, "rename-refusal-"));
  const receiptPrefix = path.join(directory, "native-handle"), releasePath = path.join(directory, "release.txt"), token = crypto.randomBytes(16).toString("hex");
  const hash = file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(repoRoot, file))).digest("hex") });
  const gate = require("../../../packages/agent/scripts/host-gate").createHostGate({ suite: "windows-installer-first-rename-refusal", strict: true, evidenceLevel: "e2e", reportPath: "qualification-results/windows-first-rename-refusal.json", fixtureSource: hash(requiredSources[0]), requiredCapabilities: ["windows", "system", "installedAgent", "api"], probeCapabilities: () => ({ windows: { available: process.platform === "win32" }, system: { available: powershell("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value") === "S-1-5-18" }, installedAgent: { available: powershell("(Get-Service TokenTimerAgent).Status") === "Running" }, api: { available: true } }) });
  gate.report.fixtureSources = requiredSources.map(hash);
  const beforeFiles = fileInventory(appDir), beforeConfig = fs.readFileSync(path.join(configDir, "config.json")), beforeCredential = fs.readFileSync(path.join(configDir, "credential"));
  const pid = () => powershell("[string](Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\").ProcessId");
  const beforePid = pid(); assert.match(beforePid, /^[1-9][0-9]*$/);
  const seen = async () => (await pool.query("SELECT last_seen_at FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2", [workspaceId, agentId])).rows[0]?.last_seen_at;
  assert.ok(await seen());
  const peer = () => new Promise((resolve, reject) => { const socket = tls.connect({ host: "127.0.0.1", port, servername: domain, ca: roots.map(root => root.pem), rejectUnauthorized: true }, () => { try { assert.equal(socket.authorized, true); resolve(socket.getPeerCertificate().fingerprint.replace(/:/g, "")); } catch (error) { reject(error); } finally { socket.destroy(); } }); socket.once("error", reject); socket.setTimeout(10000, () => socket.destroy(new Error("Rename-refusal trusted TLS deadline exceeded"))); });
  const nativeEnv = Object.fromEntries(["SystemRoot", "WINDIR", "ComSpec", "PATH", "PATHEXT", "TEMP", "TMP", "SystemDrive", "ProgramFiles", "ProgramData", "USERPROFILE", "APPDATA", "LOCALAPPDATA"].filter(name => process.env[name] !== undefined).map(name => [name, process.env[name]]));
  assert.ok(process.env.SystemRoot && path.isAbsolute(process.env.SystemRoot));
  const powershellPath = path.join(process.env.SystemRoot, "System32/WindowsPowerShell/v1.0/powershell.exe");
  const holderPath = path.join(__dirname, "certops-windows-directory-hold.ps1");
  const quote = value => value.replace(/'/g, "''");
  let child, exit, closed = false, processIdentity, held, primary;
  const facts = {};
  const observe = () => JSON.parse(powershell(`$p=Get-CimInstance Win32_Process -Filter 'ProcessId=${child.pid}';if(!$p -or $p.ParentProcessId -ne ${process.pid} -or $p.ExecutablePath -ne '${quote(powershellPath)}' -or !$p.CommandLine.Contains('${quote(holderPath)}') -or !$p.CommandLine.Contains('${token}')){throw 'Owned handle child identity mismatch'};@{pid=$p.ProcessId;parentPid=$p.ParentProcessId;created=$p.CreationDate.ToUniversalTime().ToString('o')}|ConvertTo-Json -Compress`));
  await gate.preflight(); gate.report.qualificationEnvironment.identity = "LocalSystem"; gate.report.qualificationEnvironment.keyProfile = "rsa-2048";
  try {
    await gate.scenario(requiredScenarios[0], async () => {
      const stat = fs.statSync(appDir, { bigint: true }); assert.ok(stat.ino > 0n);
      child = spawn(powershellPath, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", holderPath, "-Directory", appDir, "-ReceiptPrefix", receiptPrefix, "-ReleasePath", releasePath, "-Token", token, "-OwnerProcessId", String(process.pid)], { env: nativeEnv, stdio: "ignore", windowsHide: true });
      exit = new Promise(resolve => { child.once("error", () => { closed = true; resolve({ error: true }); }); child.once("close", (code, signal) => { closed = true; resolve({ code, signal }); }); });
      // Save independently observed ownership before consuming any receipt. A
      // malformed or missing receipt must not prevent draining our own child.
      await waitUntil(() => {
        assert.equal(closed, false, "Native handle child exited before identity capture");
        if (!Number.isInteger(child.pid)) return false;
        try { processIdentity = observe(); return true; } catch { return false; }
      });
      await waitUntil(() => { assert.equal(closed, false, "Native handle child exited before its receipt"); return fs.existsSync(receiptPrefix + ".held.json"); });
      held = JSON.parse(fs.readFileSync(receiptPrefix + ".held.json", "utf8")); assert.deepEqual(observe(), processIdentity);
      assert.equal(held.phase, "held"); assert.equal(held.token, token); assert.equal(held.shareMask, 3); assert.equal(path.resolve(held.directory).toLowerCase(), path.resolve(appDir).toLowerCase());
      for (const field of ["pid", "parentPid", "created"]) assert.equal(held[field], processIdentity[field]);
      assert.match(held.fileId, /^[a-f0-9]{16}$/); assert.equal(BigInt(`0x${held.fileId}`), stat.ino);
      assert.equal(fs.statSync(appDir, { bigint: true }).ino, stat.ino);
      facts.nativeDirectoryHandleHeld = true; facts.nativeHandleIdentityMatched = true;
    });
    await gate.scenario(requiredScenarios[1], async () => {
      assert.deepEqual(observe(), processIdentity); assert.equal(closed, false);
      const bootstrap = await createBootstrap();
      const result = spawnSync(powershellPath, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", installerFixture, "--api-url", baseUrl, "--workspace-id", String(workspaceId), "--allow-insecure-local-http", "--no-trust-store"], { encoding: "utf8", timeout: 180000, maxBuffer: 128 * 1024, windowsHide: true, env: { ...nativeEnv, TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: bootstrap.plaintextToken } });
      assert.ifError(result.error); assert.notEqual(result.status, 0); assert.ok(Number.isInteger(result.pid) && result.pid > 0);
      assert.match(`${result.stdout}\n${result.stderr}`, /failed to activate the staged agent package; the previous install was preserved/);
      assert.equal(fs.existsSync(`${appDir}.staging.${result.pid}`), false); assert.equal(fs.existsSync(`${appDir}.previous.${result.pid}`), false);
      assert.deepEqual(observe(), processIdentity); assert.equal(closed, false);
      assert.deepEqual(fileInventory(appDir), beforeFiles); assert.deepEqual(fs.readFileSync(path.join(configDir, "config.json")), beforeConfig); assert.deepEqual(fs.readFileSync(path.join(configDir, "credential")), beforeCredential);
      assert.equal(pid(), beforePid); assert.equal(powershell("(Get-Service TokenTimerAgent).Status"), "Running");
      const afterRefusalSeen = await seen(); assert.ok(afterRefusalSeen);
      await waitUntil(async () => new Date(await seen()).getTime() > new Date(afterRefusalSeen).getTime()); assert.equal(pid(), beforePid); assert.equal(await peer(), thumbprint);
      Object.assign(facts, { actualFirstRenameRefused: true, stagingRemoved: true, previousDirectoryAbsent: true, installedFilesUnchanged: true, configurationAndCredentialUnchanged: true, sameRunningServicePid: true, freshAuthenticatedHeartbeat: true, trustedTlsUnchanged: true });
    });
  } catch (error) { primary = error; }
  finally {
    try { await gate.scenario(requiredScenarios[2], async () => {
      if (child) {
        fs.writeFileSync(releasePath, token, { flag: "wx" });
        let timer; const result = await Promise.race([exit, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("Owned native directory handle did not drain")), 15000); })]).finally(() => clearTimeout(timer));
        assert.equal(result.code, 0);
        const receipt = JSON.parse(fs.readFileSync(receiptPrefix + ".closed.json", "utf8")); assert.deepEqual(receipt, { ...held, phase: "closed" });
        facts.nativeHandleReleased = true; facts.ownedChildDrained = true;
      } else throw new Error("Native directory fault was never established");
      if (!primary) { verifyProof(facts); gate.report.nativeRenameRefusal = facts; }
    }); } catch (error) {
      // Kill only the still-live identity created by this fixture; never delete
      // installation directories while its native handle may remain active.
      if (child && !closed && Number.isInteger(child.pid)) { try { const current = observe(); if (processIdentity) assert.deepEqual(current, processIdentity); run("taskkill.exe", ["/PID", String(child.pid), "/T", "/F"]); let timer; await Promise.race([exit, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("Owned handle child remained live")), 10000); })]).finally(() => clearTimeout(timer)); } catch {} }
      primary = primary ? new AggregateError([primary, error], "Rename refusal and owned handle cleanup failed") : error;
    }
    try { await gate.finish({ requiredScenarios }); } catch (error) { primary = primary ? new AggregateError([primary, error], "Rename refusal report finalization failed") : error; }
  }
  if (primary) throw primary;
  return gate.report;
}
module.exports = { qualifyRenameRefusal, verifyProof, requiredScenarios, requiredSources };

"use strict";
/** Independent always-run safeguard after producer failure or task interruption.
 * A matching run token, external receipt, native root file ID and internal
 * receipt are mandatory. Never adopts a pre-existing service or install root. */
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), { spawnSync } = require("node:child_process");
const { canonicalRoot, assertCanonicalOwnership } = require("../tests/e2e/helpers/certops-windows-fixed-root");
const { assertCleanupSafe } = require("../tests/e2e/helpers/certops-windows-cli-oplock");
function main() {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.GITHUB_ACTIONS, "true"); assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted");
  const token = process.env.CERTOPS_FIXED_ROOT_OWNER_TOKEN; assert.match(token, /^[a-f0-9]{32}$/);
  const receiptFile = path.resolve(process.env.CERTOPS_FIXED_ROOT_RECEIPT || ""), runnerRoot = path.resolve(process.env.RUNNER_TEMP);
  assert.ok(receiptFile.startsWith(runnerRoot + path.sep));
  if (!fs.existsSync(receiptFile)) return; // No completed ownership publication: do not adopt anything.
  const receipt = JSON.parse(fs.readFileSync(receiptFile, "utf8"));
  assert.equal(receipt.token, token); assert.equal(receipt.root, canonicalRoot);
  const workDir = path.resolve(receipt.workDir || "");
  assert.ok(workDir.startsWith(runnerRoot + path.sep) && path.basename(workDir).startsWith("certops-fixed-root-"));
  const assertDrained = () => { assertCleanupSafe(canonicalRoot); assertCleanupSafe(workDir); };
  assertDrained(); // Refuse before stopping any service or removing either root.
  if (!fs.existsSync(canonicalRoot)) return; // Successful producer already removed its exact root.
  assert.equal(fs.lstatSync(workDir).isSymbolicLink(), false); assert.equal(path.resolve(fs.realpathSync(workDir)).toLowerCase(), workDir.toLowerCase());
  assert.equal(String(fs.statSync(workDir, { bigint: true }).ino), receipt.workDirFileId);
  assert.equal(fs.lstatSync(canonicalRoot).isSymbolicLink(), false);
  assert.equal(path.win32.resolve(fs.realpathSync(canonicalRoot)).toLowerCase(), canonicalRoot.toLowerCase());
  assert.equal(String(fs.statSync(canonicalRoot, { bigint: true }).ino), receipt.fileId);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(canonicalRoot, ".qualification-ownership.json"), "utf8")), receipt);
  const powershell = path.join(process.env.SystemRoot, "System32/WindowsPowerShell/v1.0/powershell.exe");
  const env = { ...process.env }; for (const name of Object.keys(env)) if (name.toLowerCase() === "psmodulepath") delete env[name];
  const expectedHost = path.join(canonicalRoot, "app/bin/tokentimer-agent-host-amd64.exe").replace(/'/g, "''");
  const script = `$ErrorActionPreference='Stop';$s=Get-CimInstance Win32_Service -Filter "Name='TokenTimerAgent'";if($s){if(!$s.PathName.StartsWith('"${expectedHost}" ',[StringComparison]::OrdinalIgnoreCase) -or $s.StartName -ne 'LocalSystem'){throw 'Refuse foreign service cleanup'};$service=Get-Service TokenTimerAgent;if($service.Status -ne 'Stopped'){Stop-Service TokenTimerAgent -ErrorAction Stop};$service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20));& sc.exe delete TokenTimerAgent | Out-Null;if($LASTEXITCODE){throw 'Owned service removal failed'}};$until=[DateTime]::UtcNow.AddSeconds(30);while(Get-Service TokenTimerAgent -ErrorAction SilentlyContinue){if([DateTime]::UtcNow -ge $until){throw 'Owned service remains'};Start-Sleep -Milliseconds 200};'absent'`;
  assertDrained(); const result = spawnSync(powershell, ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], { encoding: "utf8", timeout: 60000, maxBuffer: 8192, windowsHide: true, env });
  assert.ifError(result.error); assert.equal(result.status, 0, "Independent owned-service cleanup failed"); assert.equal(result.stdout.trim(), "absent");
  assertCanonicalOwnership({ root: canonicalRoot, token, receipt, fileId: fs.statSync(canonicalRoot, { bigint: true }).ino, serviceAbsent: true });
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(canonicalRoot, ".qualification-ownership.json"), "utf8")), receipt);
  assertDrained(); fs.rmSync(canonicalRoot, { recursive: true }); assert.equal(fs.existsSync(canonicalRoot), false);
}
if (require.main === module) { try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; } }
module.exports = { main };

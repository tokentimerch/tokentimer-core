"use strict";
/** Private same-VM SYSTEM resume state. Ciphertext and identity receipt stay
 * local; neither credential, ciphertext nor path may enter execution artifacts.
 * PowerShell receives sensitive bytes only over stdin, never arguments/env. */
const assert = require("node:assert/strict"), fs = require("node:fs"), crypto = require("node:crypto"), { spawnSync } = require("node:child_process");
const contract = require("./certops-adcs-ttl24h-contract");
const capture = require("../tests/e2e/helpers/certops-adcs-ttl24h-capture");
const { applyRestrictivePermissions } = require("../packages/agent/src/platform");
function entropy(lease) { contract.verifyLease(lease); return crypto.createHash("sha256").update(`${contract.KIND}\0${lease.candidateSha}\0${lease.nonce}\0${lease.vmId}`).digest(); }
function credential(value) { assert.ok(value && typeof value === "object" && !Array.isArray(value)); assert.ok(Object.keys(value).sort().join(",") === "email,password,workspaceId", "Closed private resume fields required"); assert.ok(typeof value.workspaceId === "string" && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value.workspaceId)); assert.ok(typeof value.email === "string" && value.email.length <= 254 && /^[^\s@]+@[^\s@]+$/.test(value.email)); assert.ok(typeof value.password === "string" && value.password.length >= 16 && value.password.length <= 256); }
function localPath(lease) { contract.verifyLease(lease); return `C:\\ttqualification\\adcs-ttl24h\\${lease.nonce}\\resume.dpapi`; }
function dpapiScript(mode, lease) {
  assert.ok(mode === "protect" || mode === "unprotect"); const operation = mode === "protect" ? "Protect" : "Unprotect";
  return `$ErrorActionPreference='Stop';if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){exit 2};Add-Type -AssemblyName System.Security;$inputBytes=$null;$outputBytes=$null;$entropy=[Convert]::FromBase64String('${entropy(lease).toString("base64")}');$memory=[IO.MemoryStream]::new();try{[Console]::OpenStandardInput().CopyTo($memory);$inputBytes=$memory.ToArray();if($inputBytes.Length -lt 1 -or $inputBytes.Length -gt 16384){exit 3};$outputBytes=[Security.Cryptography.ProtectedData]::${operation}($inputBytes,$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser);$stdout=[Console]::OpenStandardOutput();$stdout.Write($outputBytes,0,$outputBytes.Length);$stdout.Flush()}catch{exit 4}finally{if($inputBytes){[Array]::Clear($inputBytes,0,$inputBytes.Length)};if($outputBytes){[Array]::Clear($outputBytes,0,$outputBytes.Length)};[Array]::Clear($entropy,0,$entropy.Length);$memory.Dispose()}`;
}
function transform(mode, lease, bytes) {
  contract.verifyLease(lease); assert.equal(process.platform, "win32"); assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1"); assert.equal(process.env.CERTOPS_ADCS_TTL24H, "1"); assert.ok(Date.now() >= Date.parse(lease.createdAt) - 5000 && Date.now() < Date.parse(lease.expiresAt) && Date.now() < Date.parse(lease.hardExpiresAt), "TTL resume lease expired or not current");
  const env = {}; for (const name of ["PATH", "SystemRoot", "WINDIR", "COMSPEC", "TEMP", "TMP"]) if (process.env[name]) env[name] = process.env[name];
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", dpapiScript(mode, lease)], { input: bytes, env, timeout: 30000, maxBuffer: 16384, windowsHide: true });
  assert.ok(!result.error && result.status === 0 && result.stdout?.length > 0 && result.stdout.length <= 16384, "Private same-VM credential transform refused; preserve local state"); return result.stdout;
}
function protect({ lease, file, value }) {
  credential(value); assert.equal(file, localPath(lease)); assert.equal(fs.existsSync(file), false); const plaintext = Buffer.from(JSON.stringify(value)); let ciphertext;
  try { ciphertext = transform("protect", lease, plaintext); fs.writeFileSync(file, ciphertext, { flag: "wx" }); applyRestrictivePermissions(file); const observed = capture.readFile(file); return { file, fileId: observed.fileId, sha256: observed.sha256 }; }
  finally { plaintext.fill(0); ciphertext?.fill(0); }
}
function unprotect({ lease, receipt }) {
  assert.ok(receipt && Object.keys(receipt).sort().join(",") === "file,fileId,sha256"); assert.equal(receipt.file, localPath(lease)); const observed = capture.readFile(receipt.file); assert.ok(observed.fileId === receipt.fileId && observed.sha256 === receipt.sha256, "Private resume ownership changed; preserve state"); let plaintext;
  try { plaintext = transform("unprotect", lease, observed.bytes); let value; try { value = JSON.parse(plaintext.toString("utf8")); } catch { throw new Error("Private resume payload refused; preserve state"); } credential(value); return value; }
  finally { observed.bytes.fill(0); plaintext?.fill(0); }
}
module.exports = { entropy, localPath, dpapiScript, protect, unprotect };

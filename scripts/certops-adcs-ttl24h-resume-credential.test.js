"use strict";
/** Pure identity/privacy controls; DPAPI is parsed, never executed locally. */
const { test } = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), { spawnSync } = require("node:child_process");
const contract = require("./certops-adcs-ttl24h-contract"), helper = require("./certops-adcs-ttl24h-resume-credential");
function lease(patch = {}) { const uuid = "11111111-1111-1111-1111-111111111111", nonce = "a".repeat(64); return contract.createLease({ candidateSha: "b".repeat(40), runId: "123", runAttempt: "1", nonce, vmResourceId: `/subscriptions/${uuid}/resourceGroups/tt-certops-123-1/providers/Microsoft.Compute/virtualMachines/windows-agent`, vmId: uuid, taskName: contract.TASK_PREFIX + nonce, nodeSha256: "c".repeat(64), keeperSha256: "d".repeat(64), ...patch }, "2026-10-15T12:00:00.000Z"); }
test("resume entropy independently binds candidate, nonce and actual VM identity", () => {
  const original = lease(), first = helper.entropy(original); assert.equal(first.length, 32); assert.ok(first.equals(helper.entropy(original)));
  for (const altered of [lease({ candidateSha: "e".repeat(40) }), lease({ nonce: "f".repeat(64), taskName: contract.TASK_PREFIX + "f".repeat(64) }), lease({ vmId: "22222222-2222-2222-2222-222222222222" })]) assert.equal(first.equals(helper.entropy(altered)), false);
  assert.ok(helper.localPath(original).endsWith(`${original.nonce}\\resume.dpapi`));
});
test("generated DPAPI code uses SYSTEM CurrentUser and stdin/stdout without argument secrets", () => {
  for (const mode of ["protect", "unprotect"]) {
    const source = helper.dpapiScript(mode, lease()); assert.ok(source.includes("S-1-5-18")); assert.ok(source.includes("DataProtectionScope]::CurrentUser")); assert.ok(source.includes("OpenStandardInput")); assert.ok(source.includes("OpenStandardOutput")); assert.doesNotMatch(source, /Write-Host|Write-Output|password|email|LocalMachine/i);
    if (process.platform === "win32") { const encoded = Buffer.from(source).toString("base64"), parser = `$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}'));$t=$null;$e=$null;$null=[Management.Automation.Language.Parser]::ParseInput($s,[ref]$t,[ref]$e);if($e.Count){exit 1}`; const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", parser], { timeout: 30000, windowsHide: true }); assert.ok(!result.error && result.status === 0, "DPAPI source must parse without execution"); }
  }
  assert.throws(() => helper.dpapiScript("other", lease()));
});
test("native transform transports bytes internally and exposes no plaintext parse errors", () => {
  const source = fs.readFileSync(path.join(__dirname, "certops-adcs-ttl24h-resume-credential.js"), "utf8"); assert.ok(source.includes("input: bytes, env")); assert.ok(source.includes("plaintext.fill(0)")); assert.ok(source.includes("plaintext?.fill(0)")); assert.ok(source.includes("Private resume payload refused; preserve state")); assert.doesNotMatch(source, /console\.|process\.stdout|process\.stderr|\.password\s*[,}]/);
});

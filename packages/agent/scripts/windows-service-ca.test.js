"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const source = fs.readFileSync(path.join(__dirname, "install-agent.ps1"), "utf8");
const start = source.indexOf("function Get-WindowsServiceEnvironmentValues {");
const end = source.indexOf("\nfunction Set-ServiceEnvironment {", start);
assert.ok(start >= 0 && end > start, "service environment helper must exist");
const helper = source.slice(start, end);
const readStart = source.indexOf("function Get-ExistingServiceEnvironment {");
const readEnd = source.indexOf("\n# A prior installation", readStart);
assert.ok(readStart >= 0 && readEnd > readStart, "service environment reader must exist");
const reader = source.slice(readStart, readEnd);
const gateStart = source.indexOf("function Test-UnsupportedSystemCaOption {");
const gateEnd = source.indexOf("\n# engines.node", gateStart);
assert.ok(gateStart >= 0 && gateEnd > gateStart, "Node compatibility gate must exist");
const gate = source.slice(gateStart, gateEnd);
const windowsOnly = { skip: process.platform === "win32" ? false : "requires Windows PowerShell" };

test("service environment reader handles absent service and property under strict mode", windowsOnly, () => {
  const script = `Set-StrictMode -Version Latest\nfunction Get-ItemProperty { [CmdletBinding()] param($Path, $Name) switch ($Path) { 'absent' { return $null }; 'missing' { return [pscustomobject]@{Other='value'} }; 'present' { return [pscustomobject]@{Environment=@('NODE_OPTIONS=--trace-warnings')} } } }\n${reader}\n[pscustomobject]@{ absent = @(Get-ExistingServiceEnvironment -ServiceKey 'absent').Count; missing = @(Get-ExistingServiceEnvironment -ServiceKey 'missing').Count; present = @(Get-ExistingServiceEnvironment -ServiceKey 'present').Count } | ConvertTo-Json -Compress`;
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout.trim()), { absent: 0, missing: 0, present: 1 });
  assert.equal((source.match(/Get-ExistingServiceEnvironment -ServiceKey/g) || []).length, 2);
});

test("service environment reader handles real missing registry key and value", windowsOnly, () => {
  const script = `Set-StrictMode -Version Latest\n$ErrorActionPreference='Stop'\n${reader}\n$missingKey = 'HKCU:\\Software\\TokenTimer-Test-Missing-' + [guid]::NewGuid()\n$key = 'HKCU:\\Software'\nif ($null -ne (Get-ItemProperty -Path $key -Name Environment -ErrorAction SilentlyContinue)) { throw 'Unexpected pre-existing test value' }\n[pscustomobject]@{ absent = @(Get-ExistingServiceEnvironment -ServiceKey $missingKey).Count; missing = @(Get-ExistingServiceEnvironment -ServiceKey $key).Count } | ConvertTo-Json -Compress`;
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout.trim()), { absent: 0, missing: 0 });
});

function values(version, existing = [], token = "") {
  const input = Buffer.from(JSON.stringify({ version, existing, token }), "utf8").toString("base64");
  const script = `${helper}\n$inputData = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${input}')) | ConvertFrom-Json\n$result = @(Get-WindowsServiceEnvironmentValues -Existing @($inputData.existing) -ConfigDir 'C:\\Agent State' -Token $inputData.token -NodeVersion ([version]$inputData.version))\nConvertTo-Json -InputObject $result -Compress`;
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout.trim());
}

test("Windows service uses supported system CA controls without changing older Node", windowsOnly, () => {
  for (const version of ["22.19.0", "24.6.0", "24.22.2"]) assert.ok(values(version).includes("NODE_USE_SYSTEM_CA=1"), version);
  for (const version of ["22.15.0", "22.18.0", "23.8.0", "24.0.0", "24.5.0"]) assert.ok(values(version).includes("NODE_OPTIONS=--use-system-ca"), version);
  for (const version of ["22.0.0", "22.14.0", "23.7.0"]) assert.ok(!values(version).some((v) => /NODE_(USE_SYSTEM_CA|OPTIONS)=/.test(v)), version);
});

test("upgrade preserves explicit service settings and replaces managed bootstrap", windowsOnly, () => {
  const previous = ["OTHER=value", "NODE_EXTRA_CA_CERTS=C:\\private.pem", "NODE_OPTIONS=--trace-warnings", "TOKENTIMER_AGENT_CONFIG_DIR=old", "TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=old"];
  const initial = values("22.18.0", previous, "new-token");
  assert.ok(initial.includes("NODE_OPTIONS=--trace-warnings --use-system-ca"));
  assert.ok(initial.includes("NODE_EXTRA_CA_CERTS=C:\\private.pem"));
  assert.ok(initial.includes("TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=new-token"));
  assert.ok(!initial.includes("TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=old"));
  const rollback = values("22.18.0", initial);
  assert.ok(!rollback.some((v) => v.startsWith("TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=")));
  assert.equal(rollback.filter((v) => v.includes("--use-system-ca")).length, 1);
  assert.ok(rollback.includes("OTHER=value"));
});

test("explicit operator CA options are not overridden", windowsOnly, () => {
  assert.ok(values("24.22.2", ["NODE_USE_SYSTEM_CA=0"]).includes("NODE_USE_SYSTEM_CA=0"));
  assert.ok(!values("24.22.2", ["NODE_USE_SYSTEM_CA=0"]).includes("NODE_USE_SYSTEM_CA=1"));
  assert.ok(!values("22.18.0", ["NODE_OPTIONS=--use-openssl-ca"]).some((v) => v.includes("--use-system-ca")));
});

test("downgrading Node fails before mutation when the service option is unsupported", windowsOnly, () => {
  const script = `${gate}\n$old = @('NODE_OPTIONS=--trace-warnings --use-system-ca')\n[pscustomobject]@{ old = (Test-UnsupportedSystemCaOption -Existing $old -NodeVersion ([version]'22.14.0')); supported = (Test-UnsupportedSystemCaOption -Existing $old -NodeVersion ([version]'22.15.0')); bundleOnly = (Test-UnsupportedSystemCaOption -Existing @('NODE_EXTRA_CA_CERTS=C:\\private.pem') -NodeVersion ([version]'22.14.0')) } | ConvertTo-Json -Compress`;
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout.trim()), { old: true, supported: false, bundleOnly: false });
  assert.ok(source.indexOf("if (Test-UnsupportedSystemCaOption") < source.indexOf("# --------------------------------------------------- platform module helper"));
});

"use strict";

// Runs the real login-oidc.ps1 with command doubles, so a transient runner network
// failure cannot abort a long lab run or block its cleanup, while a persistent
// failure still fails closed without exposing the request token.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const script = path.resolve(__dirname, "../infra/certops-adcs/login-oidc.ps1");

function run(t, failures) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "certops-oidc-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const probe = path.join(dir, "probe.ps1");
  fs.writeFileSync(probe, String.raw`
$ErrorActionPreference='Stop'
$script:requests=0
function Start-Sleep { param($Seconds) }
function Invoke-RestMethod {
  param($Uri,$Headers,$TimeoutSec)
  $script:requests++
  if($TimeoutSec -lt 1 -or $TimeoutSec -gt 60){throw 'Token request must have a bounded timeout'}
  if($script:requests -le [int]$env:CERTOPS_OIDC_FAILURES){throw 'upstream connect error SECRET_REQUEST_TOKEN'}
  [pscustomobject]@{value='federated-assertion'}
}
function az { $global:LASTEXITCODE=0 }
$g='00000000-0000-0000-0000-000000000000'
$env:AZURE_CLIENT_ID=$g;$env:AZURE_TENANT_ID=$g;$env:AZURE_SUBSCRIPTION_ID=$g
$env:ACTIONS_ID_TOKEN_REQUEST_URL='https://token.invalid/?x=1'
$env:ACTIONS_ID_TOKEN_REQUEST_TOKEN='SECRET_REQUEST_TOKEN'
try { . $env:CERTOPS_OIDC_SCRIPT | Out-Null; Write-Output ('OIDC_OK requests='+$script:requests) }
catch { Write-Output ('OIDC_FAILED requests='+$script:requests+' message='+$_.Exception.Message) }
`);
  return spawnSync(process.platform === "win32" ? "powershell.exe" : "pwsh", ["-NoProfile", "-NonInteractive", "-File", probe], {
    encoding: "utf8", windowsHide: true, timeout: 30000,
    env: { ...process.env, CERTOPS_OIDC_SCRIPT: script, CERTOPS_OIDC_FAILURES: String(failures) },
  });
}

test("OIDC token request succeeds on the first attempt without retrying", (t) => {
  const result = run(t, 0);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /OIDC_OK requests=1\b/);
});

test("transient OIDC token request failures are retried and recover", (t) => {
  const result = run(t, 3);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /OIDC_OK requests=4\b/);
});

test("persistent OIDC token request failure is bounded and exposes nothing", (t) => {
  const result = run(t, 99);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /OIDC_FAILED requests=4 message=GitHub OIDC token request failed after retries/);
  assert.doesNotMatch(result.stdout + result.stderr, /SECRET_REQUEST_TOKEN|federated-assertion|upstream connect/);
});

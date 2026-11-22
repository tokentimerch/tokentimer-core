"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const path = require("node:path");

function run(mode = "ready", marker = "1", ca = "tt-ca.lab.certops.test\\TTQualificationRoot") {
  const script = String.raw`
function Get-CimInstance {
  param($ClassName,$Filter)
  switch ($ClassName) {
    Win32_ComputerSystem { return [pscustomobject]@{PartOfDomain=$true;Domain=$(if($env:TEST_MODE -eq 'wrong-domain'){'other.test'}else{'lab.certops.test'})} }
    Win32_OperatingSystem { return [pscustomobject]@{ProductType=3;BuildNumber='20348'} }
    Win32_Service { return [pscustomobject]@{State='Running';StartName='LocalSystem';ProcessId=123} }
    Win32_Process { return [pscustomobject]@{ProcessId=123} }
    default { throw 'unexpected CIM class' }
  }
}
function Test-ComputerSecureChannel { return $true }
function Get-WindowsFeature { param($Name,$ErrorAction); return [pscustomobject]@{Installed=($env:TEST_MODE -eq 'iis')} }
function Invoke-CimMethod { param($InputObject,$MethodName); return [pscustomobject]@{Sid=$(if($env:TEST_MODE -eq 'wrong-owner'){'S-1-5-21'}else{'S-1-5-18'})} }
function certutil.exe { param($Config,[switch]$Ping); $global:LASTEXITCODE=$(if($env:TEST_MODE -eq 'ca-down'){1}else{0}) }
& $env:TEST_SCRIPT -CaConfig $env:TEST_CA
`;
  return spawnSync(process.platform === "win32" ? "powershell.exe" : "pwsh", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], {
    encoding: "utf8", windowsHide: true, timeout: 15000,
    env: { ...process.env, TEST_MODE: mode, TEST_CA: ca, TEST_SCRIPT: path.resolve(__dirname, "../infra/certops-adcs/store-member-readiness.ps1"), CERTOPS_ADCS_DISPOSABLE_LAB: marker },
  });
}

test("readiness records infrastructure facts without claiming qualification", () => {
  if (process.platform !== "win32") return;
  const result = run();
  assert.equal(result.status, 0, result.stderr);
  const receipt = JSON.parse(result.stdout);
  assert.equal(receipt.agentServiceIdentity, "LocalSystem");
  assert.equal(receipt.iisInstalled, false);
  assert.equal(receipt.caRpcPing, true);
  assert.equal(receipt.qualificationPassed, false);
  assert.match(receipt.caRpcCallerSid, /^S-/);
});

test("readiness refuses non-lab members, IIS, non-system services and failed CA access", () => {
  if (process.platform !== "win32") return;
  for (const [args, reason] of [
    [["ready", "0"], /Disposable lab marker required/],
    [["wrong-domain"], /domain-joined Windows Server member/],
    [["iis"], /without IIS/],
    [["wrong-owner"], /service process is not LocalSystem/],
    [["ca-down"], /CA RPC ping failed/],
    [["ready", "1", "foreign\\ca"], /Owned lab CA required/],
  ]) {
    const result = run(...args);
    assert.notEqual(result.status, 0, JSON.stringify(args));
    assert.match(result.stderr, reason);
    assert.doesNotMatch(result.stdout, /qualificationPassed/);
  }
});

"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const path = require("node:path");

const observationRunId = "a".repeat(32);

function run(mode = "ready", marker = "1", ca = "tt-ca.lab.certops.test\\TTQualificationRoot", preparedRun) {
  const script = String.raw`
function Get-CimInstance {
  param($ClassName,$Filter)
  switch ($ClassName) {
    Win32_ComputerSystem { return [pscustomobject]@{PartOfDomain=$true;Domain=$(if($env:TEST_MODE -eq 'wrong-domain'){'other.test'}else{'lab.certops.test'})} }
    Win32_OperatingSystem { return [pscustomobject]@{ProductType=3;BuildNumber='20348'} }
    Win32_Service {
      if ($env:TEST_PREPARED -ne '1') { return [pscustomobject]@{State='Running';StartName='LocalSystem';ProcessId=123} }
      if ($env:TEST_MODE -eq 'missing-service') { return }
      return [pscustomobject]@{
        State=$(if ($env:TEST_MODE -eq 'running') { 'Running' } else { 'Stopped' })
        StartMode=$(if ($env:TEST_MODE -eq 'enabled') { 'Manual' } else { 'Disabled' })
        StartName=$(if ($env:TEST_MODE -eq 'wrong-account') { 'LocalService' } else { 'LocalSystem' })
        ProcessId=$(if ($env:TEST_MODE -eq 'has-pid') { 123 } else { 0 })
      }
    }
    Win32_Process {
      if ($env:TEST_PREPARED -eq '1') { throw 'A prepared service must have no process lookup' }
      return [pscustomobject]@{ProcessId=123}
    }
    default { throw 'unexpected CIM class' }
  }
}
function Get-ItemPropertyValue {
  param($LiteralPath, $Name)
  if ($env:TEST_PREPARED -ne '1' -or $LiteralPath -cne 'HKLM:\SYSTEM\CurrentControlSet\Services\TokenTimerAgent' -or $Name -cne 'Environment') {
    throw 'Unexpected service registry read'
  }
  if ($env:TEST_MODE -eq 'unreadable-run') { throw 'private fixture details' }
  'UNRELATED_SERVICE_SETTING=fixture-value'
  if ($env:TEST_MODE -ne 'missing-run') { 'TOKENTIMER_AGENT_HOST_OBSERVATION_RUN=' + ('a' * 32) }
  if ($env:TEST_MODE -eq 'duplicate-run') { 'tokentimer_agent_host_observation_run=' + ('b' * 32) }
}
function Test-ComputerSecureChannel { return $true }
function Get-WindowsFeature { param($Name,$ErrorAction); return [pscustomobject]@{Installed=($env:TEST_MODE -eq 'iis')} }
function Invoke-CimMethod { param($InputObject,$MethodName); return [pscustomobject]@{Sid=$(if($env:TEST_MODE -eq 'wrong-owner'){'S-1-5-21'}else{'S-1-5-18'})} }
function certutil.exe { param($Config,[switch]$Ping); $global:LASTEXITCODE=$(if($env:TEST_MODE -eq 'ca-down'){1}else{0}) }
$options = @{ CaConfig = $env:TEST_CA }
if ($env:TEST_PREPARED -eq '1') { $options.PreparedObservationRunId = [string]$env:TEST_RUN }
& $env:TEST_SCRIPT @options
`;
  return spawnSync(process.platform === "win32" ? "powershell.exe" : "pwsh", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], {
    encoding: "utf8", windowsHide: true, timeout: 15000,
    env: { ...process.env, TEST_MODE: mode, TEST_CA: ca, TEST_SCRIPT: path.resolve(__dirname, "../infra/certops-adcs/store-member-readiness.ps1"),
      CERTOPS_ADCS_DISPOSABLE_LAB: marker, TEST_PREPARED: preparedRun === undefined ? "0" : "1", TEST_RUN: preparedRun ?? "" },
  });
}

test("readiness records infrastructure facts without claiming qualification", () => {
  if (process.platform !== "win32") return;
  const result = run();
  assert.equal(result.status, 0, result.stderr);
  const receipt = JSON.parse(result.stdout);
  assert.equal(receipt.agentServiceIdentity, "LocalSystem");
  assert.equal(receipt.agentServiceRunning, true);
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

test("prepared readiness checks the inert LocalSystem registration without a service process", () => {
  if (process.platform !== "win32") return;
  const result = run("ready", "1", undefined, observationRunId);
  assert.equal(result.status, 0, result.stderr);
  const receipt = JSON.parse(result.stdout);
  assert.equal(receipt.agentServiceRunning, false);
  assert.equal(receipt.agentServiceIdentity, "LocalSystem");
  assert.equal(receipt.iisInstalled, false);
  assert.equal(receipt.qualificationPassed, false);
  assert.doesNotMatch(result.stdout, /fixture-value/);
});

test("prepared readiness fails closed on service state and observation binding", () => {
  if (process.platform !== "win32") return;
  for (const mode of ["running", "enabled", "has-pid", "wrong-account", "missing-service"]) {
    const result = run(mode, "1", undefined, observationRunId);
    assert.notEqual(result.status, 0, mode);
    assert.match(result.stderr, /stopped, disabled LocalSystem agent service with no process/);
    assert.doesNotMatch(result.stdout, /qualificationPassed/);
  }
  for (const [mode, expectedRun, reason] of [
    ["missing-run", observationRunId, /does not bind the expected observation run/],
    ["duplicate-run", observationRunId, /does not bind the expected observation run/],
    ["ready", "b".repeat(32), /does not bind the expected observation run/],
    ["unreadable-run", observationRunId, /binding could not be read/],
    ["ready", "", /lowercase hexadecimal observation run ID/],
    ["ready", observationRunId.toUpperCase(), /lowercase hexadecimal observation run ID/],
  ]) {
    const result = run(mode, "1", undefined, expectedRun);
    assert.notEqual(result.status, 0, mode);
    assert.match(result.stderr, reason);
    assert.doesNotMatch(result.stderr, /private fixture details/);
    assert.doesNotMatch(result.stdout, /qualificationPassed/);
  }
});

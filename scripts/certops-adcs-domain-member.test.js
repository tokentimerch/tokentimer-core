"use strict";

// Execute the actual guest bootstrap with command doubles, so failures cannot
// become a successful join receipt or export exception text containing a secret.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

function run(t, failure = "") {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "certops-member-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const wrapper = path.join(dir, "probe.ps1");
  fs.writeFileSync(wrapper, String.raw`
$ErrorActionPreference='Stop'
# The test host may inherit PowerShell 7's module path while launching Windows
# PowerShell 5.1, which is the Azure guest runtime.
Import-Module (Join-Path $PSHOME 'Modules/Microsoft.PowerShell.Security/Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
function Fail-At([string]$phase) {
  if($env:CERTOPS_MEMBER_FAILURE -eq $phase){throw 'fixture-private-password'}
}
function Get-CimInstance { Fail-At 'membership'; [pscustomobject]@{PartOfDomain=($env:CERTOPS_MEMBER_FAILURE -eq 'already-joined')} }
function Get-NetAdapter {
  [pscustomobject]@{Status='Up';InterfaceIndex=7}
  [pscustomobject]@{Status='Up';InterfaceIndex=5}
  [pscustomobject]@{Status='Down';InterfaceIndex=8}
}
# Model the real Azure guest: indices 7 and 5 are both Up, but only 7 has
# a DNS-client entry and the qualification member's configured private address.
function Get-NetIPAddress {
  param($AddressFamily,$IPAddress,$ErrorAction)
  Fail-At 'dns-config'
  if($AddressFamily -ne 'IPv4' -or $IPAddress -ne '10.64.0.5'){throw 'Wrong member address selector'}
  if($env:CERTOPS_MEMBER_FAILURE -eq 'no-address'){return}
  [pscustomobject]@{InterfaceIndex=7;IPAddress='10.64.0.5'}
  if($env:CERTOPS_MEMBER_FAILURE -eq 'ambiguous-address'){[pscustomobject]@{InterfaceIndex=9;IPAddress='10.64.0.5'}}
}
function Set-DnsClientServerAddress {
  param([Parameter(ValueFromPipeline)]$InputObject,[uint32[]]$InterfaceIndex,[string[]]$ServerAddresses)
  process {
    Fail-At 'dns-config'
    if($null -ne $InputObject){$InterfaceIndex=@($InputObject.InterfaceIndex)}
    if($InterfaceIndex.Count -ne 1 -or $InterfaceIndex[0] -ne 7){throw 'CmdletizationQuery_NotFound_InterfaceIndex'}
    if($ServerAddresses -ne '10.64.0.4'){throw 'Wrong DNS server'}
    Write-Output 'DNS_CONFIGURED'
  }
}
function Resolve-DnsName { param($Name,$Type,$ErrorAction) Fail-At 'dns-lookup'; if($Name -ne '_ldap._tcp.dc._msdcs.lab.certops.test' -or $Type -ne 'SRV'){throw 'Wrong discovery query'} }
function Install-WindowsFeature { param($Name,[switch]$IncludeManagementTools) Fail-At 'iis-install'; [pscustomobject]@{Success=($env:CERTOPS_MEMBER_FAILURE -ne 'iis-unsuccessful')} }
function Add-Computer { param($DomainName,$Credential,[switch]$Force) Fail-At 'domain-join'; if($DomainName -ne 'lab.certops.test' -or $Credential.UserName -ne 'TTQUAL\tt-lab-admin' -or $Credential.GetNetworkCredential().Password -ne 'fixture-private-password'){throw 'Wrong join credential'}; Write-Output 'JOIN_CALLED' }
& $env:CERTOPS_MEMBER_SCRIPT -DomainPassword 'fixture-private-password'
`);
  return spawnSync(process.platform === "win32" ? "powershell.exe" : "pwsh", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", wrapper], {
    encoding: "utf8", windowsHide: true, timeout: 15000,
    env: { ...process.env, CERTOPS_MEMBER_FAILURE: failure, CERTOPS_MEMBER_SCRIPT: path.resolve(__dirname, "../infra/certops-adcs/domain-member.ps1") },
  });
}

test("member bootstrap emits its join receipt only after Add-Computer succeeds", t => {
  const result = run(t);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /DNS_CONFIGURED[\s\S]*JOIN_CALLED[\s\S]*CERTOPS_STAGE=member-joined-reboot-required/);
});

test("member failures expose bounded phase diagnostics without exporting credentials", t => {
  for (const phase of ["membership", "dns-config", "dns-lookup", "iis-install", "domain-join"]) {
    const result = run(t, phase);
    assert.notEqual(result.status, 0);
    assert.doesNotMatch(result.stdout + result.stderr, /fixture-private-password/);
    assert.match(result.stdout, new RegExp(`CERTOPS_MEMBER_FAILURE=${phase}:[0-9]{1,5}:-?[0-9]{1,11}`));
    assert.doesNotMatch(result.stdout, /CERTOPS_STAGE=member-joined-reboot-required/);
  }
});

test("member bootstrap refuses existing membership, missing or ambiguous IPs, and unsuccessful IIS installation", t => {
  for (const failure of ["already-joined", "no-address", "ambiguous-address", "iis-unsuccessful"]) {
    const result = run(t, failure);
    assert.notEqual(result.status, 0);
    assert.doesNotMatch(result.stdout, /JOIN_CALLED|CERTOPS_STAGE=member-joined-reboot-required/);
    if (failure === "no-address" || failure === "ambiguous-address") assert.doesNotMatch(result.stdout, /DNS_CONFIGURED/);
  }
});

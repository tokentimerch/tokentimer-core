"use strict";

// Execute the actual guest bootstrap with command doubles, so failures cannot
// become a successful join receipt or export exception text containing a secret.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

test("native CA exports retain the dotted certutil verb as one PowerShell argument", () => {
  // Unquoted -ca.cert parses as two arguments (-ca and .cert), so the native
  // program selects the unrelated -CA verb and exits before contacting the CA.
  for (const file of ["domain-verify.ps1", "issuer-destination.ps1", "hierarchy-root.ps1"]) {
    const result = spawnSync(process.platform === "win32" ? "powershell.exe" : "pwsh", ["-NoProfile", "-NonInteractive", "-Command", String.raw`
$ast=[System.Management.Automation.Language.Parser]::ParseFile($env:CERTOPS_EXPORT_SCRIPT,[ref]$null,[ref]$null)
$commands=@($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'certutil.exe' -and $node.Extent.Text -match '-ca\.cert'},$true))
if($commands.Count -ne 1){throw 'Expected one public CA export command'}
foreach($command in $commands){
  $verbs=@($command.CommandElements | Where-Object {$_ -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $_.Value -eq '-ca.cert'})
  if($verbs.Count -ne 1){throw 'Dotted certutil verb was split by PowerShell'}
}
`], { encoding: "utf8", windowsHide: true, timeout: 15000,
      env: { ...process.env, CERTOPS_EXPORT_SCRIPT: path.resolve(__dirname, "../infra/certops-adcs", file) } });
    assert.equal(result.status, 0, `${file}: ${result.stdout}${result.stderr}`);
  }
});

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

test("Windows tools bootstrap selects one Node and Go release from REST arrays", t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "certops-tools-selection-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const probe = path.join(dir, "probe.ps1");
  fs.writeFileSync(probe, String.raw`
$ErrorActionPreference='Stop'
$global:certopsDownloads=@()
function Get-CimInstance { [pscustomobject]@{Domain='lab.certops.test'} }
function Test-Path { $false }
function New-Item { }
function Expand-Archive { }
function Get-FileHash { [pscustomobject]@{Hash=('a'*64)} }
function Invoke-RestMethod {
  param($Uri)
  switch($Uri){
    'https://nodejs.org/dist/index.json' {
      Write-Output -NoEnumerate @([pscustomobject]@{version='v26.0.0';files=@('win-x64-zip')},[pscustomobject]@{version='v24.9.0';files=@('win-x64-zip')},[pscustomobject]@{version='v24.8.0';files=@('win-x64-zip')})
    }
    'https://nodejs.org/dist/v24.9.0/SHASUMS256.txt' { ('a'*64)+'  node-v24.9.0-win-x64.zip' }
    'https://go.dev/dl/?mode=json' {
      Write-Output -NoEnumerate @([pscustomobject]@{version='go1.30rc1';stable=$false;files=@()},[pscustomobject]@{version='go1.29.1';stable=$true;files=@([pscustomobject]@{os='windows';arch='amd64';kind='archive';filename='go1.29.1.windows-amd64.zip';sha256=('a'*64)})})
    }
    default { throw 'Unexpected release request' }
  }
}
function Invoke-WebRequest {
  param($Uri,$OutFile)
  $global:certopsDownloads+= $Uri
  if($Uri -eq 'https://nodejs.org/dist/v24.9.0/node-v24.9.0-win-x64.zip'){return}
  if($Uri -eq 'https://go.dev/dl/go1.29.1.windows-amd64.zip'){throw 'TEST_SELECTION_COMPLETE'}
  throw 'Unexpected archive request'
}
try { & $env:CERTOPS_TOOLS_SCRIPT -CandidateSha ('a'*40) -ApiPublicPemBase64 'AA==' }
catch {
  if($_.Exception.Message -ne 'TEST_SELECTION_COMPLETE'){throw ('Guest release selection failed: '+$_.Exception.Message)}
  if($global:certopsDownloads.Count -ne 2){throw 'Expected exactly two selected downloads'}
  Write-Output 'RELEASE_ARRAY_SELECTION_PASSED'
  exit 0
}
throw 'Expected bounded test completion'
`);
  const result = spawnSync(process.platform === "win32" ? "powershell.exe" : "pwsh", ["-NoProfile", "-NonInteractive", "-File", probe], {
    encoding: "utf8", windowsHide: true, timeout: 15000,
    env: { ...process.env, CERTOPS_TOOLS_SCRIPT: path.resolve(__dirname, "../infra/certops-adcs/windows-tools.ps1") },
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /RELEASE_ARRAY_SELECTION_PASSED/);
});

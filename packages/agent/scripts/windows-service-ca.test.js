"use strict";

const { describe, test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const installer = path.join(__dirname, "install-agent.ps1");
const source = fs.readFileSync(installer, "utf8");
const helpers = `Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:TT_CA_TEST_SOURCE,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'installer parser errors' }
foreach ($name in @('Get-ExistingServiceEnvironment','Get-WindowsServiceCaOptions','Get-WindowsServiceBinPath','Get-ServiceCommandNodeInfo','Get-ServiceNodePath','Resolve-WindowsServiceCaOptions','Assert-ServiceCaRecoveryCommand','Get-MachineNodeOptions','Get-MachineNodeSystemCa','Get-WindowsServiceTrustEnvironment','Assert-ServiceTrustSnapshot','Assert-PendingServiceCaRecovery','Get-WindowsServiceEnvironmentValues','Set-ServiceEnvironment')) {
    $fn=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
    if (-not $fn) { throw "missing helper $name" }
    Invoke-Expression $fn.Extent.Text
}
`;

function run(script) {
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", `${helpers}\n${script}`], {
    encoding: "utf8", windowsHide: true, env: { ...process.env, TT_CA_TEST_SOURCE: installer },
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result.stdout.trim();
}

// skip-reason: platform - executes Windows PowerShell service helpers.
describe("Windows service CA arguments", { skip: process.platform !== "win32" }, () => {
  test("service environment freezes captured machine system CA instead of a stale process value", () => {
    const rows=JSON.parse(run(`$ServiceName='SyntheticAgent'; $rows=@()
    function New-ItemProperty { param($Path,$Name,$PropertyType,$Value,[switch]$Force) $script:written=@($Value) }
    foreach ($value in @('0','1')) {
      $script:ServiceTrustSnapshot=[pscustomobject]@{MachineSystemCa=$value}
      $env:NODE_USE_SYSTEM_CA=if($value -ceq '0'){'1'}else{'0'}
      Set-ServiceEnvironment -ConfigDir 'C:\\state' -Token '' -Existing @('OTHER=kept')
      $rows += [pscustomobject]@{machine=$value;values=@($script:written)}
    }
    $rows | ConvertTo-Json -Depth 5 -Compress`));
    for(const row of rows) {
      assert.ok(row.values.includes(`NODE_USE_SYSTEM_CA=${row.machine}`));
      assert.ok(row.values.includes('OTHER=kept'));
    }
  });
  test("machine system CA fallback keeps service overrides and rejects invalid settings", () => {
    assert.equal(run(`if (@(Get-WindowsServiceTrustEnvironment -Existing @() -MachineSystemCa $null).Count) { throw 'fresh default trust changed' }
    foreach ($machine in @($null,'','0','1')) {
      $values=@(Get-WindowsServiceTrustEnvironment -Existing @('OTHER=kept') -MachineSystemCa $machine)
      if ($null -eq $machine) { if ($values.Count -ne 1) { throw 'default trust changed' } }
      elseif ($values -cnotcontains "NODE_USE_SYSTEM_CA=$machine") { throw 'machine setting lost' }
      foreach ($override in @('','0','1')) {
        $prior=@("node_use_system_ca=$override",'OTHER=kept')
        $effective=@(Get-WindowsServiceTrustEnvironment -Existing $prior -MachineSystemCa $machine)
        if (($effective -join '|') -cne ($prior -join '|')) { throw 'service override changed' }
      }
    }
    foreach ($prior in @(@('NODE_USE_SYSTEM_CA=bad'),@('NODE_USE_SYSTEM_CA=0','node_use_system_ca=1'))) {
      $refused=$false;try { [void](Get-WindowsServiceTrustEnvironment -Existing $prior -MachineSystemCa '1') } catch { $refused=$true }; if (-not $refused) { throw 'invalid service setting accepted' }
    }
    $refused=$false;try { [void](Get-WindowsServiceTrustEnvironment -Existing @() -MachineSystemCa 'bad') } catch { $refused=$true }; if (-not $refused) { throw 'invalid machine setting accepted' }
    Write-Output 'safe'`),"safe");
    assert.match(source,/GetEnvironmentVariable\('NODE_USE_SYSTEM_CA', 'Machine'\)/);
    assert.ok(source.indexOf('$effectiveServiceEnvironment = @(Get-WindowsServiceTrustEnvironment') < source.indexOf('Write-Log "Installing agent package'));
  });
  test("fresh installation keeps its default trust and preserves explicit environment settings", () => {
    const result = JSON.parse(run(`$rows=@(foreach ($version in @('22.0.0','22.14.0','22.15.0','22.19.0','24.0.0','24.6.0','24.18.0')) {
      foreach ($override in @('0','1')) {
        $prior=@('NODE_EXTRA_CA_CERTS=C:\\private.pem',"NODE_USE_SYSTEM_CA=$override",'OTHER=literal','TOKENTIMER_AGENT_CONFIG_DIR=old','TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=old')
        [pscustomobject]@{version=$version; override=$override; flags=@(Get-WindowsServiceCaOptions -Existing @() -NodeVersion ([version]$version)); values=@(Get-WindowsServiceEnvironmentValues -Existing $prior -ConfigDir 'C:\\state' -Token 'new')}
      }
    }); ConvertTo-Json -InputObject $rows -Depth 4 -Compress`));
    assert.equal(result.length, 14);
    for (const row of result) {
      assert.deepEqual(row.flags, [], row.version);
      for (const entry of ["NODE_EXTRA_CA_CERTS=C:\\private.pem", `NODE_USE_SYSTEM_CA=${row.override}`, "OTHER=literal", "TOKENTIMER_AGENT_CONFIG_DIR=C:\\state", "TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=new"]) assert.ok(row.values.includes(entry), entry);
      assert.ok(!row.values.includes(`NODE_USE_SYSTEM_CA=${row.override === "0" ? "1" : "0"}`));
      assert.ok(!row.values.includes("TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=old"));
    }
  });

  test("CA switches retain their exact values across versions and command recovery", () => {
    const rows = JSON.parse(run(`$rows=@(foreach ($version in @('22.15.0','22.18.0','22.19.0','24.0.0','24.5.0','24.6.0','24.18.0')) {
      foreach ($option in @('--use-system-ca','--no-use-system-ca','--use-bundled-ca','--use-openssl-ca')) {
        $flags=@(Get-WindowsServiceCaOptions -Existing @("NODE_OPTIONS=$option") -NodeVersion ([version]$version))
        $command=Get-WindowsServiceBinPath -AppDirectory 'C:\\Program Files\\Agent' -NodeExecutable 'C:\\Program Files\\nodejs\\node.exe' -Architecture AMD64 -CaOptions $flags
        $parsed=Get-ServiceCommandNodeInfo -ServiceCommand $command
        [pscustomobject]@{version=$version; option=$option; flags=$flags; parsed=@($parsed.CaOptions); node=(Get-ServiceNodePath $command)}
      }
    }); ConvertTo-Json -InputObject $rows -Depth 4 -Compress`));
    assert.equal(rows.length, 28);
    for (const row of rows) {
      assert.deepEqual(row.flags, [row.option], row.version);
      assert.deepEqual(row.parsed, [row.option], row.version);
      assert.equal(row.node, "C:\\Program Files\\nodejs\\node.exe");
    }
  });

  test("CA flag order and Node environment precedence are preserved", () => {
    const rows = JSON.parse(run(`$rows=@(foreach ($option in @('--use-system-ca --no-use-system-ca','--no-use-system-ca --use-system-ca')) {
      $flags=@(Get-WindowsServiceCaOptions -Existing @('NODE_USE_SYSTEM_CA=0',"NODE_OPTIONS=$option") -NodeVersion ([version]'24.18.0'))
      $command=Get-WindowsServiceBinPath -AppDirectory 'C:\\Agent' -NodeExecutable 'C:\\node.exe' -Architecture AMD64 -CaOptions $flags
      $parsed=Get-ServiceCommandNodeInfo -ServiceCommand $command
      [pscustomobject]@{flags=$flags; parsed=@($parsed.CaOptions); direct=$parsed.DirectSystemCa}
    }); ConvertTo-Json -InputObject $rows -Depth 4 -Compress`));
    assert.deepEqual(rows[0], { flags: ["--use-system-ca", "--no-use-system-ca"], parsed: ["--use-system-ca", "--no-use-system-ca"], direct: false });
    assert.deepEqual(rows[1], { flags: ["--no-use-system-ca", "--use-system-ca"], parsed: ["--no-use-system-ca", "--use-system-ca"], direct: true });
  });

  test("ambiguous CA settings and unsupported runtime flags fail before service changes", () => {
    const cases = [
      ["NODE_OPTIONS=--require=module --use-system-ca"],
      ['NODE_OPTIONS=--require "C:\\module --use-openssl-ca file.cjs"'],
      ["NODE_OPTIONS=--import=module --use-openssl-ca"],
      ["NODE_OPTIONS=--use-system-ca", "node_options=--trace-warnings"],
      ["NODE_OPTIONS=--use-openssl-ca --use-bundled-ca"],
      ["NODE_OPTIONS=--use-system-ca=true"],
      ["NODE_OPTIONS=--USE-SYSTEM-CA"],
    ];
    const encoded = Buffer.from(JSON.stringify(cases)).toString("base64");
    assert.equal(run(`$cases=ConvertFrom-Json -InputObject ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}')))
      foreach ($existing in $cases) { $refused=$false; try { [void](Get-WindowsServiceCaOptions -Existing $existing -NodeVersion ([version]'24.18.0')) } catch { $refused=$true }; if (-not $refused) { throw 'ambiguous CA policy accepted' } }
      foreach ($option in @('--use-system-ca','--no-use-system-ca')) { $refused=$false; try { [void](Get-WindowsServiceCaOptions -Existing @("NODE_OPTIONS=$option") -NodeVersion ([version]'22.14.0')) } catch { $refused=$true }; if (-not $refused) { throw 'old runtime accepted system CA flag' } }
      foreach ($option in @('--require=module','--import=module','--use-system-ca;bad')) { $refused=$false; try { [void](Get-WindowsServiceBinPath -AppDirectory 'C:\\Agent' -NodeExecutable 'C:\\node.exe' -Architecture AMD64 -CaOptions @($option)) } catch { $refused=$true }; if (-not $refused) { throw 'non-CA command argument accepted' } }
      if (@(Get-WindowsServiceCaOptions -Existing @('NODE_OPTIONS=--require=module','NODE_PATH=C:\\module') -NodeVersion ([version]'24.18.0')).Count) { throw 'a preload changed trust policy' }
      Write-Output 'safe'`), "safe");
    assert.ok(source.indexOf("$script:NodeCaOptions =") < source.indexOf("# --------------------------------------------------- platform module helper"));
  });

  test("missing environment is distinct from an unreadable service key", () => {
    assert.equal(run(`function Get-ItemProperty { [CmdletBinding()] param($Path) switch ($Path) {
      'absent' { throw [Management.Automation.ItemNotFoundException]::new('missing') }
      'missing' { return [pscustomobject]@{Other='value'} }
      'present' { return [pscustomobject]@{Environment=@('NODE_OPTIONS=--use-openssl-ca')} }
      default { throw [UnauthorizedAccessException]::new('denied') }
    } }
    if (@(Get-ExistingServiceEnvironment -ServiceKey 'absent').Count -ne 0 -or @(Get-ExistingServiceEnvironment -ServiceKey 'missing').Count -ne 0) { throw 'absent environment changed' }
    if (@(Get-ExistingServiceEnvironment -ServiceKey 'present')[0] -cne 'NODE_OPTIONS=--use-openssl-ca') { throw 'existing CA lost' }
    $refused=$false; try { [void](Get-ExistingServiceEnvironment -ServiceKey 'denied') } catch [UnauthorizedAccessException] { $refused=$true }; if (-not $refused) { throw 'unreadable environment treated as absent' }
    Write-Output 'safe'`), "safe");
  });

  test("repeated installation retains command CA flags and refuses conflicting policy sources", () => {
    assert.equal(run(`$observed=0
    foreach ($option in @('--use-system-ca','--no-use-system-ca','--use-bundled-ca','--use-openssl-ca')) {
      $command=Get-WindowsServiceBinPath -AppDirectory 'C:\\Agent' -NodeExecutable 'C:\\node.exe' -Architecture AMD64 -CaOptions @($option)
      foreach ($existing in @(@(),@("NODE_OPTIONS=$option"))) {
        $flags=@(Resolve-WindowsServiceCaOptions -Existing $existing -NodeVersion ([version]'24.18.0') -ServiceCommand $command)
        $again=Get-WindowsServiceBinPath -AppDirectory 'C:\\Agent' -NodeExecutable 'C:\\node.exe' -Architecture AMD64 -CaOptions $flags
        if ($again -cne $command) { throw 'repeated installation lost a CA flag' }
        $observed++
      }
    }
    if ($observed -ne 8) { throw 'both argv-only and matching-env cases must execute' }
    $command=Get-WindowsServiceBinPath -AppDirectory 'C:\\Agent' -NodeExecutable 'C:\\node.exe' -Architecture AMD64 -CaOptions @('--use-system-ca')
    $refused=$false; try { [void](Resolve-WindowsServiceCaOptions -Existing @('NODE_OPTIONS=--use-bundled-ca') -NodeVersion ([version]'24.18.0') -ServiceCommand $command) } catch { $refused=$true }; if (-not $refused) { throw 'contradictory CA sources accepted' }
    foreach ($version in @('22.0.0','22.14.0')) { $refused=$false; try { [void](Resolve-WindowsServiceCaOptions -Existing @() -NodeVersion ([version]$version) -ServiceCommand $command) } catch { $refused=$true }; if (-not $refused) { throw 'old runtime accepted an existing system CA flag' } }
    Write-Output 'safe'`), "safe");
  });

  test("machine CA options require explicit service policy and never use installer process options", () => {
    assert.equal(run(`foreach ($machine in @('--use-system-ca','--use-openssl-ca','--require=module --use-system-ca')) {
      $refused=$false; try { [void](Resolve-WindowsServiceCaOptions -Existing @() -NodeVersion ([version]'24.18.0') -MachineOptions $machine) } catch { $refused=$true }; if (-not $refused) { throw 'machine CA provenance guessed' }
    }
    $flags=@(Resolve-WindowsServiceCaOptions -Existing @('NODE_OPTIONS=--use-bundled-ca') -NodeVersion ([version]'24.18.0') -MachineOptions '--use-system-ca')
    if ($flags.Count -ne 1 -or $flags[0] -cne '--use-bundled-ca') { throw 'service override did not shadow machine NODE_OPTIONS' }
    if (@(Resolve-WindowsServiceCaOptions -Existing @() -NodeVersion ([version]'24.18.0') -MachineOptions '--require=module').Count) { throw 'blocked preload changed trust' }
    Write-Output 'safe'`), "safe");
    assert.match(source, /GetEnvironmentVariable\('NODE_OPTIONS', 'Machine'\)/);
  });

  test("CA-bearing interrupted commands are refused before any recovery mutation", () => {
    assert.equal(run(`$plain=Get-WindowsServiceBinPath -AppDirectory 'C:\\Agent' -NodeExecutable 'C:\\node.exe' -Architecture AMD64
    Assert-ServiceCaRecoveryCommand -CurrentCommand $plain -PreviousCommand $plain
    foreach ($option in @('--use-system-ca','--no-use-system-ca','--use-bundled-ca','--use-openssl-ca')) {
      $withCa=Get-WindowsServiceBinPath -AppDirectory 'C:\\Agent' -NodeExecutable 'C:\\node.exe' -Architecture AMD64 -CaOptions @($option)
      foreach ($pair in @(@($plain,$withCa),@($withCa,$plain))) {
        $refused=$false; try { Assert-ServiceCaRecoveryCommand -CurrentCommand $pair[0] -PreviousCommand $pair[1] } catch { $refused=$true }; if (-not $refused) { throw 'CA recovery was guessed' }
      }
    }
    Write-Output 'safe'`), "safe");
    const recovery = source.slice(source.indexOf("function Recover-InterruptedUpgrade"), source.indexOf("function Write-UpgradeRecoveryRecord"));
    const guard = recovery.indexOf("Assert-ServiceCaRecoveryCommand -CurrentCommand");
    assert.ok(guard > 0);
    for (const mutation of ["Stop-Service -Name", "Rename-Item -LiteralPath", "Remove-OwnedPackageStaging -Directory", "Invoke-CimMethod -InputObject"]) assert.ok(recovery.indexOf(mutation) > guard, mutation);
    const state = source.slice(source.indexOf('try { Assert-WindowsPackageHelpers -PackageDirectory'), source.indexOf('Write-Log "Installing agent package'));
    assert.ok(state.indexOf('Assert-PendingServiceCaRecovery') < state.indexOf('Invoke-PlatformAcl -TargetPath $StateDir'));
  });

  test("service and environment drift refuse the captured trust settings without printing them", () => {
    assert.equal(run(`$ServiceName='SyntheticAgent'
    $script:currentCommand='"C:\\host.exe" "C:\\node.exe" "C:\\agent.js"'; $script:currentEnv=@('NODE_USE_SYSTEM_CA=0','OTHER=kept'); $script:machineOptions=''; $script:present=$true
    function Get-CimInstance { [CmdletBinding()] param($ClassName,$Filter) if ($script:present) { return [pscustomobject]@{PathName=$script:currentCommand} } }
    function Get-ExistingServiceEnvironment { param($ServiceKey) return $script:currentEnv }
    function Get-MachineNodeOptions { return $script:machineOptions }
    $script:machineSystemCa='0'
    function Get-MachineNodeSystemCa { return $script:machineSystemCa }
    $expected=[pscustomobject]@{Exists=$true;Command=$script:currentCommand;Environment=@($script:currentEnv);MachineOptions='';MachineSystemCa='0'}
    Assert-ServiceTrustSnapshot -Expected $expected
    foreach ($kind in @('command','environment','environment-count','machine','machine-system','presence')) {
      $script:currentCommand=$expected.Command; $script:currentEnv=@($expected.Environment); $script:machineOptions=''; $script:machineSystemCa='0'; $script:present=$true
      switch ($kind) {
        'command' { $script:currentCommand='"C:\\host.exe" "C:\\node.exe" --use-system-ca "C:\\agent.js"' }
        'environment' { $script:currentEnv=@('NODE_USE_SYSTEM_CA=1','OTHER=kept') }
        'environment-count' { $script:currentEnv=@('NODE_USE_SYSTEM_CA=0') }
        'machine' { $script:machineOptions='--use-system-ca' }
        'machine-system' { $script:machineSystemCa='1' }
        'presence' { $script:present=$false }
      }
      $refused=$false; try { Assert-ServiceTrustSnapshot -Expected $expected } catch { $refused=$_.Exception.Message -ceq 'service trust settings changed since preflight; preserve staged files and reconcile before retrying' }; if (-not $refused) { throw 'trust drift accepted' }
    }
    Write-Output 'safe'`), "safe");
    const serviceMutation = source.indexOf('# New-Service fails if another service appears');
    assert.ok(source.lastIndexOf('Assert-ServiceTrustSnapshot -Expected', serviceMutation) > source.indexOf('if ($script:DryRun) {', source.indexOf('$binPath = Get-WindowsServiceBinPath')));
    assert.match(source, /Set-ServiceEnvironment -ConfigDir \$StateDir -Token \$script:BootstrapToken -Existing \$script:ServiceTrustSnapshot\.Environment/);
  });

  test("pending CA recovery is checked read-only before state ACL changes", () => {
    assert.equal(run(`$ServiceName='SyntheticAgent'; $script:previous='"C:\\host.exe" "C:\\node.exe" --use-system-ca "C:\\agent.js"'
    function Get-UpgradeRecoveryPath { return 'C:\\synthetic-journal.json' }
    function Test-Path { [CmdletBinding()] param($LiteralPath) return $true }
    function Get-Item { [CmdletBinding()] param($LiteralPath,[switch]$Force) return [pscustomobject]@{PSIsContainer=$false;Attributes=0;Length=256} }
    function Assert-UpgradeRecoveryAcl { param($JournalPath) }
    function Get-Content { [CmdletBinding()] param($LiteralPath,[switch]$Raw) return (@{previousServicePath=$script:previous}|ConvertTo-Json -Compress) }
    function Get-CimInstance { [CmdletBinding()] param($ClassName,$Filter) return [pscustomobject]@{PathName='"C:\\host.exe" "C:\\node.exe" "C:\\agent.js"'} }
    function Invoke-PlatformAcl { throw 'state ACL must never be changed by preflight' }
    $refused=$false; try { Assert-PendingServiceCaRecovery } catch { $refused=$_.Exception.Message -match '^recovery_required: service CA arguments' }; if (-not $refused) { throw 'pending CA recovery accepted' }
    $script:previous='"C:\\host.exe" "C:\\node.exe" "C:\\agent.js"'; Assert-PendingServiceCaRecovery
    Write-Output 'safe'`), "safe");
  });
});

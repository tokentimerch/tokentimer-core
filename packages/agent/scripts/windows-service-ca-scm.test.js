"use strict";

const { describe, test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const installer = process.env.TT_CA_INSTALLER_SOURCE || path.join(__dirname, "install-agent.ps1");
const source = fs.readFileSync(installer, "utf8").replaceAll("\r\n", "\n");
const gateStart = source.indexOf("try {\n    $script:PreviousServiceConfiguration =");
const gateEnd = source.indexOf("# --------------------------------------------------- platform module helper", gateStart);
assert.ok(gateStart >= 0 && gateEnd > gateStart);
const gate = source.slice(gateStart, gateEnd);
const command = flags => `"C:\\Agent\\bin\\tokentimer-agent-host-amd64.exe" "C:\\Program Files\\nodejs\\node.exe" ${flags.join(" ")} "C:\\Agent\\bin\\tokentimer-agent.js"`;

function admit({ flags = [], environment = [], machine = [], version = "24.18.0", rawCommand, exists = true, after = "" } = {}) {
  const fixture = { command: rawCommand === undefined ? command(flags) : rawCommand, environment, machine, exists, present: environment.length > 0 };
  const encoded = Buffer.from(JSON.stringify(fixture)).toString("base64");
  const script = `Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:Fixture=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}')) | ConvertFrom-Json
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:TT_CA_SOURCE,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'parser errors' }
foreach ($name in @('Get-WindowsServiceCaOptions','Get-WindowsServiceCaEnvironment','Get-WindowsServiceEnvironmentValues','Set-ServiceEnvironment','Restore-WindowsServiceConfiguration','Get-WindowsServiceEnvironmentSnapshot','Get-WindowsServiceConfigurationSnapshot','Get-WindowsServiceCaCommand','Get-WindowsServiceCaIntent','Resolve-WindowsServiceCaOptions','Assert-WindowsServiceCaSnapshot')) {
  $fn=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
  if ($fn) { Invoke-Expression $fn.Extent.Text }
}
$script:OriginalEnvironmentHelper=(Get-Command Get-WindowsServiceCaEnvironment).ScriptBlock
function Get-WindowsServiceCaEnvironment {
  param([string[]]$ServiceValues,[scriptblock]$GetMachineValue)
  if ($null -eq $GetMachineValue) { $GetMachineValue={ param($Name) $entry=@($script:Fixture.machine | Where-Object { $_ -match ('^(?i:' + $Name + ')=') }); if ($entry.Count) { return $entry[0].Substring($entry[0].IndexOf('=')+1) }; return $null } }
  & $script:OriginalEnvironmentHelper -ServiceValues $ServiceValues -GetMachineValue $GetMachineValue
}
function Get-CimInstance { [CmdletBinding()] param($ClassName,$Filter) if ($script:Fixture.exists) { return [pscustomobject]@{PathName=$script:Fixture.command; DisplayName='existing service'} }; return $null }
function Get-ItemProperty { [CmdletBinding()] param($Path) if ($script:Fixture.present) { return [pscustomobject]@{Environment=@($script:Fixture.environment)} }; return [pscustomobject]@{Other='value'} }
function Fail { param($Message) throw $Message }
$ServiceName='TokenTimerAgent'; $script:NodeVersion=[version]'${version}'; $script:NodeCaOptions=@(); $denied=$false; $reason=''
try { ${gate} } catch { $denied=$true; $reason=$_.Exception.Message }
${after}
[pscustomobject]@{options=@($script:NodeCaOptions); denied=$denied; reason=$reason} | ConvertTo-Json -Depth 5 -Compress`;
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
    env: { ...process.env, TT_CA_SOURCE: installer }, windowsHide: true, encoding: "utf8", timeout: 20000,
  });
  assert.equal(result.status, 0, `${fixture.command}\n${result.error?.stack || result.stderr || result.stdout}`);
  return JSON.parse(result.stdout.trim());
}

// skip-reason: platform - executes Windows PowerShell admission against simulated SCM reads.
describe("SCM CA policy admission", { skip: process.platform !== "win32" }, () => {
  test("retains argv-only CA policy and matching environment without adding default trust", () => {
    assert.deepEqual(admit().options, []);
    for (const flag of ["--use-system-ca", "--no-use-system-ca", "--use-bundled-ca", "--use-openssl-ca"]) {
      const alone = admit({ flags: [flag] });
      assert.equal(alone.denied, false, alone.reason);
      assert.deepEqual(alone.options, [flag]);
      const matching = admit({ flags: [flag], environment: [`NODE_OPTIONS=${flag}`] });
      assert.equal(matching.denied, false, matching.reason);
      assert.deepEqual(matching.options, [flag]);
    }
    const variable = admit({ flags: ["--use-system-ca"], environment: ["NODE_USE_SYSTEM_CA=1"] });
    assert.equal(variable.denied, false, variable.reason);
    assert.deepEqual(variable.options, ["--use-system-ca"]);
  });

  test("rejects conflicting command, service and inherited machine CA intent", () => {
    for (const fixture of [
      { flags: ["--use-system-ca"], environment: ["NODE_OPTIONS=--no-use-system-ca"] },
      { flags: ["--no-use-system-ca"], environment: ["NODE_USE_SYSTEM_CA=1"] },
      { flags: ["--use-system-ca"], environment: ["NODE_USE_SYSTEM_CA=0"] },
      { flags: ["--use-openssl-ca"], environment: ["NODE_OPTIONS=--use-bundled-ca"] },
      { flags: ["--use-system-ca"], machine: ["NODE_OPTIONS=--no-use-system-ca"] },
      { flags: ["--use-system-ca"], machine: ["NODE_OPTIONS=--use-system-ca"] },
    ]) assert.equal(admit(fixture).denied, true, JSON.stringify(fixture));
    const override = admit({ flags: ["--no-use-system-ca"], environment: ["NODE_OPTIONS=--no-use-system-ca"], machine: ["NODE_OPTIONS=--use-system-ca"] });
    assert.equal(override.denied, false, override.reason);
    assert.deepEqual(override.options, ["--no-use-system-ca"]);
  });

  test("keeps compatible sources and the system-CA variable transition explicit", () => {
    const compatible = admit({ flags: ["--use-bundled-ca"], environment: ["NODE_USE_SYSTEM_CA=1"], version: "22.18.0" });
    assert.equal(compatible.denied, false, compatible.reason);
    assert.deepEqual(compatible.options, ["--use-bundled-ca", "--use-system-ca"]);
    const denied = admit({ flags: ["--no-use-system-ca"], environment: ["NODE_USE_SYSTEM_CA=1", "NODE_OPTIONS=--no-use-system-ca"], version: "24.5.0" });
    assert.equal(denied.denied, false, denied.reason);
    assert.deepEqual(denied.options, ["--no-use-system-ca"]);
    assert.equal(admit({ flags: ["--use-system-ca"], version: "22.14.0" }).denied, true);
  });

  test("rejects ambiguous quoting, relative paths and non-CA service arguments", () => {
    for (const rawCommand of [
      '"C:\\host.exe" "C:\\node.exe" --require=evil "C:\\agent.js"',
      '"C:\\host.exe" "C:\\node.exe" --trace-warnings "C:\\agent.js"',
      '"C:\\host.exe" "C:\\node.exe"--use-system-ca "C:\\agent.js"',
      '"C:\\host.exe" "C:\\node.exe" --use-system-ca "C:\\agent.js',
      '"C:\\host.exe" "C:node.exe" --use-system-ca "C:\\agent.js"',
      '"C:\\host.exe" "C:\\node.exe" --use-system-ca "agent.js"',
      'C:\\Program Files\\host.exe "C:\\node.exe" --use-system-ca "C:\\agent.js"',
      '"C:\\host.exe" "C:\\node.exe" --use-system-ca "C:\\agent.js" extra',
      '"C:\\host.exe" "C:\\node.exe" --use-system-ca\n "C:\\agent.js"',
    ]) assert.equal(admit({ rawCommand }).denied, true, rawCommand);
  });

  test("pins explicit machine system-CA policy in the service environment on variable-aware runtimes", () => {
    for (const setting of ["1", "0"]) {
      const fixture = { flags: ["--use-bundled-ca"], machine: [`NODE_USE_SYSTEM_CA=${setting}`], version: "22.19.0", after: `
function New-ItemProperty { [CmdletBinding()] param($Path,$Name,$PropertyType,$Value,[switch]$Force) $script:Written=@($Value) }
Set-ServiceEnvironment -ConfigDir 'C:\\state' -Token ''
if ($script:Written -cnotcontains 'NODE_USE_SYSTEM_CA=${setting}') { throw 'machine policy was not pinned to the service environment' }
if ($script:PreviousServiceConfiguration.Environment.Values.Count) { throw 'rollback snapshot was modified' }
function Set-ServiceBinaryPath { param($ServiceName,$BinPath,$DisplayName) $script:RestoredCommand=$BinPath }
function Get-ItemProperty { [CmdletBinding()] param($Path) return [pscustomobject]@{Environment=$script:Written} }
function Remove-ItemProperty { [CmdletBinding()] param($Path,$Name) $script:RemovedEnvironment=$true }
Restore-WindowsServiceConfiguration -Name $ServiceName -Snapshot $script:PreviousServiceConfiguration
if ($script:RestoredCommand -cne $script:Fixture.command -or -not $script:RemovedEnvironment) { throw 'argv-only command or absent environment was not restored' }` };
      const pinned = admit(fixture);
      assert.equal(pinned.denied, false, pinned.reason);
      assert.deepEqual(pinned.options, ["--use-bundled-ca"]);
      const explicitNo = admit({ ...fixture, environment: ["NODE_OPTIONS=--no-use-system-ca"], after: fixture.after.slice(0, fixture.after.indexOf("if ($script:PreviousServiceConfiguration.Environment.Values.Count)")) });
      assert.equal(explicitNo.denied, false, explicitNo.reason);
      assert.deepEqual(explicitNo.options, ["--use-bundled-ca", "--no-use-system-ca"]);
    }
  });

  test("detects changed service and machine policy before each mutation boundary", () => {
    const unchanged = admit({ flags: ["--use-system-ca"], after: "Assert-WindowsServiceCaSnapshot -Name $ServiceName -Expected $script:PreviousServiceConfiguration" });
    assert.equal(unchanged.denied, false);
    for (const change of [
      "$script:Fixture.command += ' extra'",
      "$script:Fixture.environment=@('NODE_USE_SYSTEM_CA=0'); $script:Fixture.present=$true",
      "$script:Fixture.machine=@('NODE_USE_SYSTEM_CA=1')",
      "$script:Fixture.exists=$false",
    ]) {
      const value = admit({ flags: ["--use-system-ca"], after: `${change}\ntry { Assert-WindowsServiceCaSnapshot -Name $ServiceName -Expected $script:PreviousServiceConfiguration } catch { $denied=$true; $reason=$_.Exception.Message }` });
      assert.equal(value.denied, true, change);
    }
    const matches = [...source.matchAll(/Assert-WindowsServiceCaSnapshot -Name \$ServiceName -Expected \$script:PreviousServiceConfiguration/g)].map(match => match.index);
    assert.equal(matches.length, 3);
    assert.ok(matches[0] < source.indexOf('Write-Log "Installing agent package'));
    assert.ok(matches[1] < source.indexOf("        Activate-StagedPackage -AppDirectory $AppDir"));
    assert.ok(matches[2] < source.indexOf("$serviceExisted ="));
  });
});

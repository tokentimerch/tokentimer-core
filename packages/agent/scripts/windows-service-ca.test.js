"use strict";

const { describe, test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const installer = path.join(__dirname, "install-agent.ps1");
const source = fs.readFileSync(installer, "utf8");
const functionNames = ["Invoke-InstallerNode", "Get-WindowsServiceCaOptions", "Get-WindowsServiceCaEnvironment", "Get-WindowsServiceBinPath", "Get-WindowsServiceEnvironmentValues", "Get-WindowsServiceEnvironmentSnapshot", "Get-WindowsServiceConfigurationSnapshot", "Restore-WindowsServiceConfiguration", "Set-ServiceEnvironment"];
const helpers = `Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:TT_CA_TEST_SOURCE,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'installer parser errors' }
foreach ($name in @('${functionNames.join("','")}')) {
    $fn=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
    if (-not $fn) { throw "missing helper $name" }
    Invoke-Expression $fn.Extent.Text
}
`;

function run(script, extraEnv = {}) {
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", `${helpers}\n${script}`], {
    encoding: "utf8", windowsHide: true, env: { ...process.env, TT_CA_TEST_SOURCE: installer, ...extraEnv }, timeout: 20000,
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result.stdout.trim();
}

function rollbackBlock() {
  const input = process.env.TT_CA_ROLLBACK_SOURCE ? fs.readFileSync(process.env.TT_CA_ROLLBACK_SOURCE, "utf8") : source;
  const start = input.indexOf("if (-not $healthy -and $script:IsUpgrade");
  const end = input.indexOf("\nif (Test-Path -LiteralPath $script:AppPrevious)", start);
  assert.ok(start >= 0 && end > start);
  return input.slice(start, end);
}

function rollback(present = true, failRestore = false) {
  return JSON.parse(run(`$ServiceName='TokenTimerAgent'; $ServiceDisplayName='new display'; $StateDir='C:\\state'; $AppDir='C:\\app'; $healthy=$false
$script:IsUpgrade=$true; $script:AppPrevious='C:\\previous'
$script:Events=New-Object System.Collections.Generic.List[object]
$oldPath='"C:\\old host.exe" "C:\\Node24\\node.exe" --use-openssl-ca "C:\\old app\\agent.js"'
$oldValues=@('NODE_OPTIONS=--use-openssl-ca','NODE_USE_SYSTEM_CA=1','OTHER=original')
$script:PreviousServiceConfiguration=[pscustomobject]@{Exists=$true; BinaryPath=$oldPath; DisplayName='old display'; Environment=[pscustomobject]@{Present=$${present}; Values=$oldValues}}
$flags=@(Get-WindowsServiceCaOptions -Existing $oldValues -NodeVersion ([version]'22.18.0'))
$binPath=Get-WindowsServiceBinPath -AppDirectory $AppDir -NodeExecutable 'C:\\Node22\\node.exe' -Architecture AMD64 -CaOptions $flags
function Write-Log { param($Message) }
function Fail { param($Message) throw $Message }
function Test-Path { param($LiteralPath) return $LiteralPath -eq $script:AppPrevious }
function Stop-Service { [CmdletBinding()] param($Name,[switch]$Force) $script:Events.Add([pscustomobject]@{kind='stop'}) }
function Start-Service { [CmdletBinding()] param($Name) $script:Events.Add([pscustomobject]@{kind='start'}) }
function Remove-Item { [CmdletBinding()] param($LiteralPath,[switch]$Recurse,[switch]$Force) $script:Events.Add([pscustomobject]@{kind='remove-app'}) }
function Rename-Item { [CmdletBinding()] param($LiteralPath,$NewName) $script:Events.Add([pscustomobject]@{kind='restore-app'}) }
function Set-ServiceBinaryPath { param($ServiceName,$BinPath,$DisplayName) $script:Events.Add([pscustomobject]@{kind='command'; value=$BinPath; display=$DisplayName}) }
function New-ItemProperty { [CmdletBinding()] param($Path,$Name,$PropertyType,$Value,[switch]$Force)
  if ($${failRestore}) { throw [UnauthorizedAccessException]::new('restore denied') }
  $script:Events.Add([pscustomobject]@{kind='environment'; value=@($Value)})
}
function Get-ItemProperty { [CmdletBinding()] param($Path) return [pscustomobject]@{Environment=@('changed')} }
function Remove-ItemProperty { [CmdletBinding()] param($Path,$Name) $script:Events.Add([pscustomobject]@{kind='remove-environment'}) }
function Invoke-PlatformAcl { param($TargetPath,$Kind) }
$outcome=''
try { ${rollbackBlock()} } catch { $outcome=$_.Exception.Message }
[pscustomobject]@{events=@($script:Events.ToArray()); oldPath=$oldPath; oldValues=$oldValues; outcome=$outcome; flags=$flags} | ConvertTo-Json -Depth 6 -Compress`));
}

// skip-reason: platform - executes Windows PowerShell installer helpers.
describe("Windows service CA policy", { skip: process.platform !== "win32" }, () => {
  test("default trust stays unchanged and explicit environment entries survive", () => {
    const rows = JSON.parse(run(`$rows=@(foreach ($version in @('22.0.0','22.14.0','22.15.0','22.19.0','24.0.0','24.6.0','24.18.0')) {
      $values=@(Get-WindowsServiceEnvironmentValues -Existing @('NODE_EXTRA_CA_CERTS=C:\\private.pem','NODE_USE_SYSTEM_CA=0','OTHER=literal','TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=old') -ConfigDir 'C:\\state' -Token 'new')
      [pscustomobject]@{version=$version; flags=@(Get-WindowsServiceCaOptions -Existing @() -NodeVersion ([version]$version)); values=$values}
    }); ConvertTo-Json -InputObject $rows -Depth 4 -Compress`));
    assert.equal(rows.length, 7);
    for (const row of rows) {
      assert.deepEqual(row.flags, [], row.version);
      for (const entry of ["NODE_EXTRA_CA_CERTS=C:\\private.pem", "NODE_USE_SYSTEM_CA=0", "OTHER=literal", "TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=new"]) assert.ok(row.values.includes(entry));
      assert.ok(!row.values.includes("NODE_USE_SYSTEM_CA=1"));
      assert.ok(!row.values.includes("TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=old"));
    }
  });

  test("only canonical CA switches enter the service command", () => {
    const rows = JSON.parse(run(`$rows=@(foreach ($version in @('22.15.0','22.18.0','22.19.0','24.0.0','24.5.0','24.6.0','24.18.0')) { foreach ($option in @('--use-system-ca','--no-use-system-ca','--use-bundled-ca','--use-openssl-ca')) {
      $flags=@(Get-WindowsServiceCaOptions -Existing @("NODE_OPTIONS=$option") -NodeVersion ([version]$version))
      $command=Get-WindowsServiceBinPath -AppDirectory 'C:\\Program Files\\Agent' -NodeExecutable 'C:\\Program Files\\nodejs\\node.exe' -Architecture AMD64 -CaOptions $flags
      [pscustomobject]@{version=$version; option=$option; flags=$flags; command=$command}
    } }); ConvertTo-Json -InputObject $rows -Depth 4 -Compress`));
    assert.equal(rows.length, 28);
    for (const row of rows) {
      assert.deepEqual(row.flags, [row.option]);
      assert.equal(row.command, `"C:\\Program Files\\Agent\\bin\\tokentimer-agent-host-amd64.exe" "C:\\Program Files\\nodejs\\node.exe" ${row.option} "C:\\Program Files\\Agent\\bin\\tokentimer-agent.js"`);
    }
  });

  test("an explicit system CA environment survives runtimes that ignore the variable", () => {
    const rows = JSON.parse(run(`$rows=@(foreach ($version in @('22.15.0','22.18.0','22.19.0','24.0.0','24.5.0','24.6.0','24.18.0')) {
      [pscustomobject]@{version=$version; flags=@(Get-WindowsServiceCaOptions -Existing @('NODE_USE_SYSTEM_CA=1') -NodeVersion ([version]$version)); denied=@(Get-WindowsServiceCaOptions -Existing @('NODE_USE_SYSTEM_CA=1','NODE_OPTIONS=--no-use-system-ca') -NodeVersion ([version]$version)); ordered=@(Get-WindowsServiceCaOptions -Existing @('NODE_USE_SYSTEM_CA=1','NODE_OPTIONS=--use-system-ca --no-use-system-ca') -NodeVersion ([version]$version))}
    }); ConvertTo-Json -InputObject $rows -Depth 4 -Compress`));
    for (const row of rows) {
      const needsFlag = ["22.15.0", "22.18.0", "24.0.0", "24.5.0"].includes(row.version);
      assert.deepEqual(row.flags, needsFlag ? ["--use-system-ca"] : []);
      assert.deepEqual(row.denied, ["--no-use-system-ca"]);
      assert.deepEqual(row.ordered, ["--use-system-ca", "--no-use-system-ca"]);
    }
  });

  test("service CA overrides replace machine defaults without inheriting user preload settings", () => {
    const value = JSON.parse(run(`$machine={param($Name) if ($Name -eq 'NODE_OPTIONS') { return '--use-openssl-ca' }; return '1'}
      $inherited=@(Get-WindowsServiceCaEnvironment -ServiceValues @() -GetMachineValue $machine)
      $overridden=@(Get-WindowsServiceCaEnvironment -ServiceValues @('node_options=--no-use-system-ca','NODE_USE_SYSTEM_CA=0') -GetMachineValue $machine)
      $cleared=@(Get-WindowsServiceCaEnvironment -ServiceValues @('NODE_OPTIONS=','NODE_USE_SYSTEM_CA=0') -GetMachineValue $machine)
      [pscustomobject]@{inherited=$inherited; overridden=$overridden; cleared=$cleared; flags=@(Get-WindowsServiceCaOptions -Existing $inherited -NodeVersion ([version]'22.18.0'))} | ConvertTo-Json -Depth 4 -Compress`));
    assert.deepEqual(value.inherited, ["NODE_OPTIONS=--use-openssl-ca", "NODE_USE_SYSTEM_CA=1"]);
    assert.deepEqual(value.overridden, ["node_options=--no-use-system-ca", "NODE_USE_SYSTEM_CA=0"]);
    assert.deepEqual(value.cleared, ["NODE_OPTIONS=", "NODE_USE_SYSTEM_CA=0"]);
    assert.deepEqual(value.flags, ["--use-openssl-ca", "--use-system-ca"]);
  });

  test("ambiguous policy and incompatible runtimes stop before installation changes", () => {
    const cases = [["NODE_OPTIONS=--require=module --use-system-ca"], ['NODE_OPTIONS=--require "C:\\module --use-openssl-ca file.cjs"'], ["NODE_OPTIONS=--import=module --use-openssl-ca"], ["NODE_OPTIONS=--use_openssl_ca"], ["NODE_OPTIONS=--use-system-ca", "node_options=--trace-warnings"], ["NODE_USE_SYSTEM_CA=1", "node_use_system_ca=0"], ["NODE_OPTIONS=--use-openssl-ca --use-bundled-ca"], ["NODE_OPTIONS=--use-system-ca=true"]];
    const encoded = Buffer.from(JSON.stringify(cases)).toString("base64");
    assert.equal(run(`$cases=ConvertFrom-Json -InputObject ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}')))
      foreach ($existing in $cases) { $refused=$false; try { [void](Get-WindowsServiceCaOptions -Existing $existing -NodeVersion ([version]'24.18.0')) } catch { $refused=$true }; if (-not $refused) { throw 'ambiguous CA accepted' } }
      foreach ($existing in @(@('NODE_USE_SYSTEM_CA=1'),@('NODE_OPTIONS=--use-system-ca'),@('NODE_OPTIONS=--no-use-system-ca'))) { $refused=$false; try { [void](Get-WindowsServiceCaOptions -Existing $existing -NodeVersion ([version]'22.14.0')) } catch { $refused=$true }; if (-not $refused) { throw 'incompatible runtime accepted' } }
      foreach ($option in @('--require=module','--import=module','--use-system-ca;bad')) { $refused=$false; try { [void](Get-WindowsServiceBinPath -AppDirectory 'C:\\Agent' -NodeExecutable 'C:\\node.exe' -Architecture AMD64 -CaOptions @($option)) } catch { $refused=$true }; if (-not $refused) { throw 'non-CA argument accepted' } }
      Write-Output 'safe'`), "safe");
    assert.ok(source.indexOf("$script:PreviousServiceConfiguration =") < source.indexOf("# ------------------------------------------------------------ install files"));
  });

  test("service snapshots distinguish absent environment from access failure", () => {
    const value = JSON.parse(run(`function Get-CimInstance { [CmdletBinding()] param($ClassName,$Filter) return [pscustomobject]@{PathName='old command'; DisplayName='old display'} }
      function Get-ItemProperty { [CmdletBinding()] param($Path) switch ($Path) { 'absent' { throw [Management.Automation.ItemNotFoundException]::new('missing') }; 'missing' { return [pscustomobject]@{Other=1} }; 'denied' { throw [UnauthorizedAccessException]::new('denied') }; default { return [pscustomobject]@{Environment=@('NODE_USE_SYSTEM_CA=1')} } } }
      $absent=Get-WindowsServiceEnvironmentSnapshot -ServiceKey 'absent'; $missing=Get-WindowsServiceEnvironmentSnapshot -ServiceKey 'missing'; $config=Get-WindowsServiceConfigurationSnapshot -Name 'TokenTimerAgent'
      $refused=$false; try { [void](Get-WindowsServiceEnvironmentSnapshot -ServiceKey 'denied') } catch [UnauthorizedAccessException] { $refused=$true }
      [pscustomobject]@{absent=$absent.Present; missing=$missing.Present; refused=$refused; path=$config.BinaryPath; values=@($config.Environment.Values)} | ConvertTo-Json -Depth 4 -Compress`));
    assert.deepEqual(value, { absent: false, missing: false, refused: true, path: "old command", values: ["NODE_USE_SYSTEM_CA=1"] });
  });

  test("health-check rollback restores the original command and CA environment", () => {
    const value = rollback();
    const command = value.events.find(item => item.kind === "command");
    assert.equal(command.value, value.oldPath);
    assert.equal(command.display, "old display");
    assert.deepEqual(value.events.find(item => item.kind === "environment").value, value.oldValues);
    assert.deepEqual(value.flags, ["--use-openssl-ca", "--use-system-ca"]);
    assert.ok(value.events.findIndex(item => item.kind === "environment") < value.events.findIndex(item => item.kind === "start"));
    assert.match(value.outcome, /was rolled back/);
  });

  test("rollback restores an absent environment and refuses restart after a failed restore", () => {
    const absent = rollback(false);
    assert.ok(absent.events.some(item => item.kind === "remove-environment"));
    assert.ok(!absent.events.some(item => item.kind === "environment"));
    const failed = rollback(true, true);
    assert.match(failed.outcome, /rollback requires service reconciliation/);
    assert.ok(!failed.events.some(item => item.kind === "start"));
  });

  test("installer Node calls block preloads and restore caller settings", (t) => {
    const root = fs.realpathSync(os.tmpdir());
    const dir = fs.mkdtempSync(path.join(root, "tt-ca-preload-"));
    t.after(() => { const relative = path.relative(root, fs.realpathSync(dir)); assert.ok(relative && !relative.startsWith("..") && !path.isAbsolute(relative)); fs.rmSync(dir, { recursive: true, force: true }); });
    const preload = path.join(dir, "preload.cjs");
    const marker = path.join(dir, "preload-ran");
    fs.writeFileSync(preload, 'require("node:fs").writeFileSync(process.env.TT_CA_MARKER,"ran");');
    const result = run(`$script:NodeExe=$env:TT_CA_NODE
      $beforeOptions=$env:NODE_OPTIONS; $beforePath=$env:NODE_PATH
      $version=(Invoke-InstallerNode -NodeArguments @('-v')).Trim()
      if ($LASTEXITCODE -ne 0 -or $version -notmatch '^v[0-9]+\\.') { throw 'Node version unavailable' }
      if ($env:NODE_OPTIONS -cne $beforeOptions -or $env:NODE_PATH -cne $beforePath) { throw 'caller environment changed' }
      Write-Output 'safe'`, { TT_CA_NODE: process.execPath, TT_CA_MARKER: marker, NODE_OPTIONS: `--require "${preload.replaceAll("\\", "/")}"`, NODE_PATH: dir });
    assert.equal(result, "safe");
    assert.equal(fs.existsSync(marker), false);
    const directCalls = source.split(/\r?\n/).filter(line => /& node\b/.test(line));
    assert.deepEqual(directCalls, []);
  });
});

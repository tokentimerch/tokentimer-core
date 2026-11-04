"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawn, spawnSync } = require("node:child_process");

const harness = String.raw`
$ErrorActionPreference = 'Stop'
$PackageDir = $env:TT542_SOURCE
$AppDir = Join-Path $env:TT542_ROOT 'app'
$StateDir = Join-Path $env:TT542_ROOT 'state'
$ServiceName = 'TokenTimerAgentTest'
$script:NodeExe = $env:TT542_NODE
$script:PreviousServicePath = '"C:\test\host.exe" "C:\test\node.exe" "C:\test\agent.js"'
$script:InstalledNodeExe = Join-Path $AppDir 'runtime\amd64\node.exe'
$runtimeArch = 'amd64'
$script:PreviousServiceDisplayName = 'Previous agent'
$script:PreviousServiceStartMode = 'Automatic'
$script:PreviousServiceEnvironment = $null
function Write-Log([string]$Message) { Write-Output $Message }
function Invoke-PlatformAcl { param([string]$TargetPath,[string]$Kind) }
function Assert-UpgradeRecoveryAcl { param([string]$JournalPath) }
function Assert-ProtectedIntentDirectory { param([string]$Directory) }
function Test-ServiceChildStable { param([string]$ExpectedNodePath) return $true }
function Get-CimInstance {
    param($ClassName,$Filter,$ErrorAction)
    $ttPath = $script:PreviousServicePath
    if ($env:TT542_SERVICE_UPDATED -eq '1') {
        $ttHost = Join-Path $AppDir 'bin\tokentimer-agent-host-amd64.exe'
        $ttEntry = Join-Path $AppDir 'bin\tokentimer-agent.js'
        $ttPath = '"' + $ttHost + '" "' + $script:InstalledNodeExe + '" "' + $ttEntry + '"'
    }
    return [pscustomobject]@{ PathName = $ttPath; State = 'Stopped' }
}
function Invoke-CimMethod {
    param($InputObject,$MethodName,$Arguments)
    [IO.File]::WriteAllText((Join-Path $env:TT542_ROOT 'restored-service.txt'),$Arguments.PathName)
    return [pscustomobject]@{ ReturnValue = 0 }
}
function Remove-ItemProperty { param($LiteralPath,$Name,$ErrorAction) }
function Start-Service { param($Name,$ErrorAction) }
function Get-Service { param($Name) $item=[pscustomobject]@{}; $item | Add-Member -MemberType ScriptMethod -Name WaitForStatus -Value { param($State,$Timeout) }; return $item }
$ttTokens=$null
$ttErrors=$null
$ttAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PackageDir 'install-agent.ps1'),[ref]$ttTokens,[ref]$ttErrors)
if ($ttErrors.Count) { throw 'Installer parser errors' }
foreach ($ttName in @('Get-PackageDirectoryIdentity','Remove-OwnedPackageStaging','Get-UpgradeRecoveryPath','Get-ServiceNodePath','Assert-NoQuarantinedLauncherIntent','Recover-InterruptedUpgrade','Write-UpgradeRecoveryRecord')) {
    $ttMatches=@($ttAst.FindAll({ param($ttNode) $ttNode -is [Management.Automation.Language.FunctionDefinitionAst] -and $ttNode.Name -eq $ttName },$true))
    if ($ttMatches.Count -ne 1) { throw "Missing recovery function $ttName" }
    Invoke-Expression $ttMatches[0].Extent.Text
}
if ($env:TT542_MODE -eq 'oversized') {
    $ttStaging = "$AppDir.staging.$PID"
    New-Item -ItemType Directory -Path $ttStaging | Out-Null
    $script:PreviousServiceEnvironment = @('LONG=' + ('x' * 6000))
    Write-UpgradeRecoveryRecord -StagingIdentity (Get-PackageDirectoryIdentity -Directory $ttStaging)
    throw 'oversized recovery record was accepted'
} elseif ($env:TT542_MODE -like 'interrupt*') {
    $ttStaging = "$AppDir.staging.$PID"
    New-Item -ItemType Directory -Path $ttStaging | Out-Null
    [IO.File]::WriteAllText((Join-Path $ttStaging 'candidate.txt'),'candidate')
    $ttIdentity = Get-PackageDirectoryIdentity -Directory $ttStaging
    Write-UpgradeRecoveryRecord -StagingIdentity $ttIdentity
    Rename-Item -LiteralPath $AppDir -NewName ("app.previous.$PID") -ErrorAction Stop
    if ($env:TT542_MODE -eq 'interrupt-after-activation') {
        Rename-Item -LiteralPath $ttStaging -NewName 'app' -ErrorAction Stop
    }
    [IO.File]::WriteAllText((Join-Path $env:TT542_ROOT 'renamed.marker'),'ready')
    Start-Sleep -Seconds 60
} else {
    Recover-InterruptedUpgrade
}
`;

async function exerciseInterruptedUpgrade(mode) {
  const tempParent = fs.realpathSync(os.tmpdir());
  const fixture = fs.mkdtempSync(path.join(tempParent, "tt542-recovery-"));
  const safeFixture = fs.realpathSync(fixture);
  assert.equal(path.dirname(safeFixture).toLowerCase(), tempParent.toLowerCase());
  let child;
  try {
    fs.mkdirSync(path.join(fixture, "app"));
    fs.mkdirSync(path.join(fixture, "state"));
    fs.writeFileSync(path.join(fixture, "app", "original.txt"), "original");
    const encodedHarness = Buffer.from(harness, "utf16le").toString("base64");
    const env = {
      ...process.env,
      TT542_SOURCE: __dirname,
      TT542_ROOT: fixture,
      TT542_NODE: process.execPath,
      TT542_MODE: mode,
    };
    child = spawn("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", encodedHarness], { env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    let errors = "";
    child.stderr.on("data", (chunk) => { errors += chunk.toString(); });
    const deadline = Date.now() + 15000;
    while (!fs.existsSync(path.join(fixture, "renamed.marker")) && Date.now() < deadline && child.exitCode === null) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.ok(fs.existsSync(path.join(fixture, "renamed.marker")), "child never reached rename boundary: " + errors);
    const stopped = new Promise((resolve) => child.once("close", resolve));
    child.kill();
    await stopped;
    child = undefined;
    const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", encodedHarness], {
      env: { ...env, TT542_MODE: "recover", TT542_SERVICE_UPDATED: mode === "interrupt-after-activation" ? "1" : "0" },
      windowsHide: true,
      encoding: "utf8",
      timeout: 15000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(fs.readFileSync(path.join(fixture, "app", "original.txt"), "utf8"), "original");
    assert.match(fs.readFileSync(path.join(fixture, "restored-service.txt"), "utf8"), /test\\node\.exe/);
    assert.equal(fs.existsSync(path.join(fixture, "state", "upgrade-recovery.json")), false);
    assert.equal(fs.readdirSync(fixture).some((name) => /^app\.(previous|staging)\./.test(name)), false);
  } finally {
    if (child) child.kill();
    if (path.dirname(fs.realpathSync(fixture)).toLowerCase() !== tempParent.toLowerCase()) {
      throw new Error("Refusing to remove a fixture outside the temporary directory");
    }
    fs.rmSync(fixture, { recursive: true, force: true });
  }
}

test("restores the original application after a process dies between renames", { skip: process.platform !== "win32", timeout: 30000 }, () => exerciseInterruptedUpgrade("interrupt"));
test("restores the original application and service after activation", { skip: process.platform !== "win32", timeout: 30000 }, () => exerciseInterruptedUpgrade("interrupt-after-activation"));

test("recovery refuses any quarantined launcher intent and enumeration errors", { skip: process.platform !== "win32" }, () => {
  const tempParent = fs.realpathSync(os.tmpdir());
  const root = fs.mkdtempSync(path.join(tempParent, "tt537-intent-"));
  fs.writeFileSync(path.join(root, "TokenTimer-Staging-123.intent"), "untrusted marker");
  try {
  const script = String.raw`
$ErrorActionPreference = 'Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $env:TT542_SOURCE 'install-agent.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'installer parse failed' }
$f=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Assert-NoQuarantinedLauncherIntent'},$true))
if ($f.Count -ne 1) { throw 'missing intent guard' }
Invoke-Expression $f[0].Extent.Text
try { Assert-NoQuarantinedLauncherIntent -LauncherParent $env:TT542_ROOT; throw 'recovery unexpectedly succeeded' }
catch { if ($_.Exception.Message -notmatch 'recovery_required: a launcher execution remains quarantined') { [Console]::Error.WriteLine($_.Exception.Message); exit 1 } }
try { Assert-NoQuarantinedLauncherIntent -LauncherParent (Join-Path $env:TT542_ROOT 'missing'); throw 'missing parent unexpectedly accepted' }
catch { if ($_.Exception.Message -eq 'missing parent unexpectedly accepted') { throw } }
exit 0
`;
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
    env: { ...process.env, TT542_SOURCE: __dirname, TT542_ROOT: root }, windowsHide: true, encoding: "utf8", timeout: 15000,
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  } finally {
    if (path.dirname(fs.realpathSync(root)).toLowerCase() !== tempParent.toLowerCase()) throw new Error("Unsafe fixture cleanup");
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("launcher authorization fails closed on missing or unrelated intent", { skip: process.platform !== "win32" }, () => {
  const tempParent = fs.realpathSync(os.tmpdir());
  const root = fs.mkdtempSync(path.join(tempParent, "tt537-auth-"));
  try {
    const script = String.raw`
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $env:TT542_SOURCE 'install-agent.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'installer parse failed' }
$f=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Assert-AuthorizedLauncherOrNoIntent'},$true))
if ($f.Count -ne 1) { throw 'missing authorization gate' }
$body=$f[0].Extent.Text.Replace('[Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)', '$env:TT542_ROOT')
Invoke-Expression $body
function Assert-ProtectedIntentDirectory { param($Directory) }
$PackageDir=Join-Path $env:TT542_ROOT ('TokenTimer-Staging-' + ('a' * 32))
$env:TEMP=Join-Path $env:TT542_ROOT ('TokenTimer-Staging-' + ('b' * 32))
[Environment]::SetEnvironmentVariable('TOKENTIMER_AGENT_INTENT_HANDLE',$null,'Process')
Assert-AuthorizedLauncherOrNoIntent
[IO.File]::WriteAllText(($PackageDir + '.intent'),'{}')
try { Assert-AuthorizedLauncherOrNoIntent; throw 'one marker unexpectedly accepted' }
catch { if ($_.Exception.Message -notmatch 'launcher execution remains quarantined') { throw } }
[IO.File]::WriteAllText(($env:TEMP + '.intent'),'{}')
[Environment]::SetEnvironmentVariable('TOKENTIMER_AGENT_INTENT_HANDLE','123','Process')
[IO.File]::WriteAllText((Join-Path $env:TT542_ROOT ('TokenTimer-Staging-' + ('c' * 32) + '.intent')),'{}')
try { Assert-AuthorizedLauncherOrNoIntent; throw 'extra marker unexpectedly accepted' }
catch { if ($_.Exception.Message -notmatch 'launcher execution remains quarantined') { throw } }
exit 0
`;
    const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], {
      env: { ...process.env, TT542_SOURCE: __dirname, TT542_ROOT: root }, windowsHide: true, encoding: "utf8", timeout: 15000,
    });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  } finally {
    if (path.dirname(fs.realpathSync(root)).toLowerCase() !== tempParent.toLowerCase()) throw new Error("Unsafe fixture cleanup");
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("rejects an oversized recovery record before touching the existing application", { skip: process.platform !== "win32", timeout: 30000 }, () => {
  const tempParent = fs.realpathSync(os.tmpdir());
  const fixture = fs.mkdtempSync(path.join(tempParent, "tt542-journal-size-"));
  assert.equal(path.dirname(fs.realpathSync(fixture)).toLowerCase(), tempParent.toLowerCase());
  try {
    fs.mkdirSync(path.join(fixture, "app"));
    fs.mkdirSync(path.join(fixture, "state"));
    fs.writeFileSync(path.join(fixture, "app", "original.txt"), "original");
    const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(harness, "utf16le").toString("base64")], {
      env: { ...process.env, TT542_SOURCE: __dirname, TT542_ROOT: fixture, TT542_NODE: process.execPath, TT542_MODE: "oversized" },
      windowsHide: true, encoding: "utf8", timeout: 15000,
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /recovery record exceeds the supported size/);
    assert.equal(fs.readFileSync(path.join(fixture, "app", "original.txt"), "utf8"), "original");
    assert.equal(fs.existsSync(path.join(fixture, "state", "upgrade-recovery.json")), false);
  } finally {
    if (path.dirname(fs.realpathSync(fixture)).toLowerCase() !== tempParent.toLowerCase()) throw new Error("Unsafe fixture cleanup");
    fs.rmSync(fixture, { recursive: true, force: true });
  }
});

test("installer Node helper rejects inherited preloads and restores the caller environment", { skip: process.platform !== "win32" }, () => {
  const tempParent = fs.realpathSync(os.tmpdir());
  const fixture = fs.mkdtempSync(path.join(tempParent, "tt542-preload-"));
  assert.equal(path.dirname(fs.realpathSync(fixture)).toLowerCase(), tempParent.toLowerCase());
  try {
    const preload = path.join(fixture, "preload.js");
    const marker = path.join(fixture, "executed.marker");
    fs.writeFileSync(preload, 'require("node:fs").writeFileSync(process.env.TT542_MARKER, "executed");');
    const script = String.raw`
$ttTokens=$null; $ttErrors=$null
$ttAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $env:TT542_SOURCE 'install-agent.ps1'),[ref]$ttTokens,[ref]$ttErrors)
$ttFunction=@($ttAst.FindAll({ param($ttNode) $ttNode -is [Management.Automation.Language.FunctionDefinitionAst] -and $ttNode.Name -eq 'Invoke-PackagedNode' },$true))
if ($ttErrors.Count -or $ttFunction.Count -ne 1) { throw 'Missing Node helper' }
Invoke-Expression $ttFunction[0].Extent.Text
$script:NodeExe=$env:TT542_NODE
$ttOldOptions=$env:NODE_OPTIONS
$ttOldPath=$env:NODE_PATH
$ttOutput=Invoke-PackagedNode -NodeArguments @('-p','1+1')
if ($ttOutput -ne '2' -or $LASTEXITCODE -ne 0) { throw 'Node helper failed' }
if ($env:NODE_OPTIONS -ne $ttOldOptions -or $env:NODE_PATH -ne $ttOldPath) { throw 'Node environment not restored' }
`;
    const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], {
      env: { ...process.env, TT542_SOURCE: __dirname, TT542_NODE: process.execPath, TT542_MARKER: marker, NODE_OPTIONS: '--require "' + preload + '"', NODE_PATH: fixture },
      windowsHide: true, encoding: "utf8", timeout: 15000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(fs.existsSync(marker), false);
  } finally {
    if (path.dirname(fs.realpathSync(fixture)).toLowerCase() !== tempParent.toLowerCase()) throw new Error("Unsafe fixture cleanup");
    fs.rmSync(fixture, { recursive: true, force: true });
  }
});

test("runtime package marker selects bundled Node and rejects incomplete bundles", { skip: process.platform !== "win32", timeout: 30000 }, () => {
  const tempParent = fs.realpathSync(os.tmpdir());
  const fixture = fs.mkdtempSync(path.join(tempParent, "tt542-runtime-"));
  assert.equal(path.dirname(fs.realpathSync(fixture)).toLowerCase(), tempParent.toLowerCase());
  try {
    const bundle = path.join(fixture, "bundle");
    const legacy = path.join(fixture, "legacy");
    fs.mkdirSync(path.join(bundle, "runtime", "amd64"), { recursive: true });
    fs.mkdirSync(legacy);
    const runtime = path.join(bundle, "runtime", "amd64", "node.exe");
    fs.copyFileSync(process.execPath, runtime);
    const pkg = { engines: { node: ">=22.0.0 <25.0.0" }, windowsBundledRuntime: true };
    fs.writeFileSync(path.join(bundle, "package.json"), JSON.stringify(pkg));
    fs.writeFileSync(path.join(legacy, "package.json"), JSON.stringify({ engines: pkg.engines }));
    const manifestPath = path.join(bundle, "runtime", "manifest.json");
    const manifest = { version: process.version.slice(1), architecture: "amd64", path: "runtime/amd64/node.exe", sha256: crypto.createHash("sha256").update(fs.readFileSync(runtime)).digest("hex") };
    fs.writeFileSync(manifestPath, JSON.stringify(manifest));
    const script = String.raw`
$ErrorActionPreference='Stop'
function Fail([string]$Message) { throw $Message }
function Write-Log([string]$Message) { Write-Output $Message }
function Assert-ProtectedBundleTree { param([string]$Root) }
$ttTokens=$null; $ttErrors=$null
$ttSource=[IO.File]::ReadAllText((Join-Path $env:TT542_SOURCE 'install-agent.ps1'))
$ttAst=[Management.Automation.Language.Parser]::ParseInput($ttSource,[ref]$ttTokens,[ref]$ttErrors)
$ttFunction=@($ttAst.FindAll({ param($ttNode) $ttNode -is [Management.Automation.Language.FunctionDefinitionAst] -and $ttNode.Name -eq 'Invoke-PackagedNode' },$true))
if ($ttErrors.Count -or $ttFunction.Count -ne 1) { throw 'Missing Node helper' }
Invoke-Expression $ttFunction[0].Extent.Text
$PackageDir=$env:TT542_PACKAGE; $AppDir=Join-Path $env:TT542_PACKAGE 'installed'; $arch='AMD64'
$script:RequiresBundledRuntime=($env:TT542_EXPECT_BUNDLE -eq '1')
$ttStart=$ttSource.IndexOf('$runtimeManifestPath =')
$ttEnd=$ttSource.IndexOf('if ([string]::IsNullOrEmpty($script:ApiUrl))',$ttStart)
if ($ttStart -lt 0 -or $ttEnd -le $ttStart) { throw 'Missing runtime validation' }
Invoke-Expression $ttSource.Substring($ttStart,$ttEnd-$ttStart)
`;
    const run = (packageDir) => spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], {
      env: { ...process.env, TT542_SOURCE: __dirname, TT542_PACKAGE: packageDir, TT542_EXPECT_BUNDLE: packageDir === bundle ? '1' : '0' },
      windowsHide: true, encoding: "utf8", timeout: 15000,
    });
    let result = run(bundle);
    assert.equal(result.status, 0, result.stderr || result.stdout);
    manifest.sha256 = "0".repeat(64);
    fs.writeFileSync(manifestPath, JSON.stringify(manifest));
    result = run(bundle);
    assert.notEqual(result.status, 0, "a bad runtime hash must fail even with system Node available");
    fs.unlinkSync(manifestPath);
    result = run(bundle);
    assert.notEqual(result.status, 0, "a missing bundle manifest must fail without a PATH fallback");
    delete pkg.windowsBundledRuntime;
    fs.writeFileSync(path.join(bundle, "package.json"), JSON.stringify(pkg));
    const runtimeDirectory = path.join(bundle, "runtime");
    const hiddenRuntime = path.join(bundle, "hidden-runtime");
    assert.equal(path.dirname(fs.realpathSync(runtimeDirectory)).toLowerCase(), fs.realpathSync(bundle).toLowerCase());
    assert.equal(path.dirname(path.resolve(hiddenRuntime)).toLowerCase(), path.resolve(bundle).toLowerCase());
    fs.renameSync(runtimeDirectory, hiddenRuntime);
    result = run(bundle);
    assert.notEqual(result.status, 0, "removing both the marker and runtime must not downgrade a Windows bundle to system Node");
    result = run(legacy);
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.match(result.stdout, /Legacy generic package/);
  } finally {
    if (path.dirname(fs.realpathSync(fixture)).toLowerCase() !== tempParent.toLowerCase()) throw new Error("Unsafe fixture cleanup");
    fs.rmSync(fixture, { recursive: true, force: true });
  }
});

test("service health requires the expected child to survive a second observation", { skip: process.platform !== "win32" }, () => {
  const script = String.raw`
$ttTokens=$null; $ttErrors=$null
$ttAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $env:TT542_SOURCE 'install-agent.ps1'),[ref]$ttTokens,[ref]$ttErrors)
$ttFunction=@($ttAst.FindAll({ param($ttNode) $ttNode -is [Management.Automation.Language.FunctionDefinitionAst] -and $ttNode.Name -eq 'Test-ServiceChildStable' },$true))
if ($ttErrors.Count -or $ttFunction.Count -ne 1) { throw 'Missing child health helper' }
Invoke-Expression $ttFunction[0].Extent.Text
$ServiceName='test'
$script:Clock=[DateTime]::UtcNow
$script:Queries=0
$script:ExpectedNode='C:\test\node.exe'
function Get-Date { $script:Clock=$script:Clock.AddSeconds(5); return $script:Clock }
function Start-Sleep { param($Seconds) }
function Get-CimInstance {
  param($ClassName,$Filter,$ErrorAction)
  if ($ClassName -eq 'Win32_Service') { return [pscustomobject]@{ State='Running'; ProcessId=10 } }
  $script:Queries++
  if ($script:Queries -eq 1) { return [pscustomobject]@{ ExecutablePath=$script:ExpectedNode; ProcessId=20 } }
  return @()
}
if (Test-ServiceChildStable -ExpectedNodePath $script:ExpectedNode) { throw 'Exited child was accepted' }
`;
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], {
    env: { ...process.env, TT542_SOURCE: __dirname }, windowsHide: true, encoding: "utf8", timeout: 15000,
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
});

test("bundled bootstrap rejects ancestor permissions that can alter a reparse point", { skip: process.platform !== "win32" }, () => {
  const script = String.raw`
$ErrorActionPreference='Stop'
$ttTokens=$null; $ttErrors=$null
$ttAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $env:TT542_SOURCE 'install-agent.ps1'),[ref]$ttTokens,[ref]$ttErrors)
$ttFunction=@($ttAst.FindAll({ param($ttNode) $ttNode -is [Management.Automation.Language.FunctionDefinitionAst] -and $ttNode.Name -eq 'Assert-ProtectedBundleTree' },$true))
if ($ttErrors.Count -or $ttFunction.Count -ne 1) { throw 'Missing bundle protection helper' }
Invoke-Expression $ttFunction[0].Extent.Text
$script:ttRoot='C:\tt542-parent\bundle'
$script:ttBadMask=0
function Get-Item { param($LiteralPath,[switch]$Force,$ErrorAction) return [pscustomobject]@{ Attributes=[IO.FileAttributes]::Directory; PSIsContainer=$true } }
function Get-ChildItem { param($LiteralPath,[switch]$Force,$ErrorAction) return @() }
function Get-Acl {
  param($LiteralPath,$ErrorAction)
  $acl=New-Object System.Security.AccessControl.DirectorySecurity
  $system=New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
  $everyone=New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
  $acl.SetOwner($system)
  $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system,'FullControl','Allow')))
  if ($script:ttBadMask -and $LiteralPath -ieq 'C:\tt542-parent') {
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($everyone,[Security.AccessControl.FileSystemRights]$script:ttBadMask,'Allow')))
  }
  return $acl
}
Assert-ProtectedBundleTree -Root $script:ttRoot
foreach ($mask in @(0x2,0x100)) {
  $script:ttBadMask=$mask
  $rejected=$false
  try { Assert-ProtectedBundleTree -Root $script:ttRoot } catch {
    if ($_.Exception.Message -match 'untrusted principal') { $rejected=$true } else { throw }
  }
  if (-not $rejected) { throw "Writable ancestor accepted for mask $mask" }
}
`;
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], {
    env: { ...process.env, TT542_SOURCE: __dirname }, windowsHide: true, encoding: "utf8", timeout: 15000,
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
});

test("bundled bootstrap rejects a user-owned extraction directory", { skip: process.platform !== "win32" }, () => {
  const tempParent = fs.realpathSync(os.tmpdir());
  const fixture = fs.mkdtempSync(path.join(tempParent, "tt542-untrusted-"));
  assert.equal(path.dirname(fs.realpathSync(fixture)).toLowerCase(), tempParent.toLowerCase());
  try {
    const script = String.raw`
$ErrorActionPreference='Stop'
Import-Module ([IO.Path]::Combine($PSHOME,'Modules','Microsoft.PowerShell.Security','Microsoft.PowerShell.Security.psd1')) -NoClobber
$ttTokens=$null; $ttErrors=$null
$ttAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $env:TT542_SOURCE 'install-agent.ps1'),[ref]$ttTokens,[ref]$ttErrors)
$ttFunction=@($ttAst.FindAll({ param($ttNode) $ttNode -is [Management.Automation.Language.FunctionDefinitionAst] -and $ttNode.Name -eq 'Assert-ProtectedBundleTree' },$true))
if ($ttErrors.Count -or $ttFunction.Count -ne 1) { throw 'Missing bundle protection helper' }
Invoke-Expression $ttFunction[0].Extent.Text
$ttRejected=$false
try { Assert-ProtectedBundleTree -Root $env:TT542_ROOT } catch {
  if ($_.Exception.Message -match 'untrusted owner|untrusted principal') { $ttRejected=$true } else { throw }
}
if (-not $ttRejected) { throw 'Untrusted extraction directory was accepted' }
`;
    const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], {
      env: { ...process.env, TT542_SOURCE: __dirname, TT542_ROOT: fixture },
      windowsHide: true, encoding: "utf8", timeout: 15000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    if (path.dirname(fs.realpathSync(fixture)).toLowerCase() !== tempParent.toLowerCase()) throw new Error("Unsafe fixture cleanup");
    fs.rmSync(fixture, { recursive: true, force: true });
  }
});

test("recovery refuses a journal with inherited, unprotected ACL", { skip: process.platform !== "win32", timeout: 30000 }, () => {
  const tempParent = fs.realpathSync(os.tmpdir());
  const fixture = fs.mkdtempSync(path.join(tempParent, "tt542-journal-acl-"));
  assert.equal(path.dirname(fs.realpathSync(fixture)).toLowerCase(), tempParent.toLowerCase());
  try {
    const journal = path.join(fixture, "upgrade-recovery.json");
    fs.writeFileSync(journal, "{}");
    const script = String.raw`
$ErrorActionPreference='Stop'
Import-Module ([IO.Path]::Combine($PSHOME,'Modules','Microsoft.PowerShell.Security','Microsoft.PowerShell.Security.psd1')) -NoClobber
if ((Get-Acl -LiteralPath $env:TT542_JOURNAL).AreAccessRulesProtected) { throw 'Fixture ACL unexpectedly protected' }
$ttTokens=$null; $ttErrors=$null
$ttAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $env:TT542_SOURCE 'scripts\install-agent.ps1'),[ref]$ttTokens,[ref]$ttErrors)
foreach ($ttName in @('Invoke-PackagedNode','Assert-UpgradeRecoveryAcl')) {
  $ttFunction=@($ttAst.FindAll({ param($ttNode) $ttNode -is [Management.Automation.Language.FunctionDefinitionAst] -and $ttNode.Name -eq $ttName },$true))
  if ($ttErrors.Count -or $ttFunction.Count -ne 1) { throw 'Missing ACL helper' }
  Invoke-Expression $ttFunction[0].Extent.Text
}
$PackageDir=$env:TT542_SOURCE
$script:NodeExe=$env:TT542_NODE
Assert-UpgradeRecoveryAcl -JournalPath $env:TT542_JOURNAL
`;
    const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], {
      env: { ...process.env, TT542_SOURCE: path.resolve(__dirname, ".."), TT542_NODE: process.execPath, TT542_JOURNAL: journal },
      windowsHide: true, encoding: "utf8", timeout: 20000,
    });
    assert.notEqual(result.status, 0, "unprotected journal ACL must be rejected");
    assert.match(result.stderr, /ACL still inherits|inherits from its parent/);
  } finally {
    if (path.dirname(fs.realpathSync(fixture)).toLowerCase() !== tempParent.toLowerCase()) throw new Error("Unsafe fixture cleanup");
    fs.rmSync(fixture, { recursive: true, force: true });
  }
});

test("validated bundled runtime stays locked against replacement during bootstrap", { skip: process.platform !== "win32", timeout: 30000 }, async (t) => {
  const expectedHash = "9a4eb5f1c29c6a2e93852ead46b999e284a6a5ca8bab4d4e241d587d025a52de";
  const actualHash = crypto.createHash("sha256").update(fs.readFileSync(process.execPath)).digest("hex");
  if (process.version !== "v24.18.0" || process.arch !== "x64" || actualHash !== expectedHash) {
    t.skip("test requires the pinned Windows Node runtime fixture");
    return;
  }
  const tempParent = fs.realpathSync(os.tmpdir());
  const fixture = fs.mkdtempSync(path.join(tempParent, "tt542-lock-"));
  assert.equal(path.dirname(fs.realpathSync(fixture)).toLowerCase(), tempParent.toLowerCase());
  let child;
  try {
    const bundle = path.join(fixture, "bundle");
    const runtimeDir = path.join(bundle, "runtime", "amd64");
    fs.mkdirSync(runtimeDir, { recursive: true });
    const runtime = path.join(runtimeDir, "node.exe");
    fs.copyFileSync(process.execPath, runtime);
    fs.writeFileSync(path.join(bundle, "package.json"), JSON.stringify({ engines: { node: ">=22.0.0 <25.0.0" }, windowsBundledRuntime: true }));
    fs.writeFileSync(path.join(bundle, "runtime", "manifest.json"), JSON.stringify({ version: "24.18.0", architecture: "amd64", path: "runtime/amd64/node.exe", sha256: expectedHash }));
    const script = String.raw`
$ErrorActionPreference='Stop'
function Fail([string]$Message) { throw $Message }
function Write-Log([string]$Message) { }
function Assert-ProtectedBundleTree { param([string]$Root) }
$ttTokens=$null; $ttErrors=$null
$ttSource=[IO.File]::ReadAllText((Join-Path $env:TT542_SOURCE 'install-agent.ps1'))
$ttAst=[Management.Automation.Language.Parser]::ParseInput($ttSource,[ref]$ttTokens,[ref]$ttErrors)
$ttFunction=@($ttAst.FindAll({ param($ttNode) $ttNode -is [Management.Automation.Language.FunctionDefinitionAst] -and $ttNode.Name -eq 'Invoke-PackagedNode' },$true))
if ($ttErrors.Count -or $ttFunction.Count -ne 1) { throw 'Missing Node helper' }
Invoke-Expression $ttFunction[0].Extent.Text
$PackageDir=$env:TT542_PACKAGE; $AppDir=Join-Path $PackageDir 'installed'; $arch='AMD64'
$script:RequiresBundledRuntime=$true
$ttStart=$ttSource.IndexOf('$runtimeManifestPath =')
$ttEnd=$ttSource.IndexOf('if ([string]::IsNullOrEmpty($script:ApiUrl))',$ttStart)
Invoke-Expression $ttSource.Substring($ttStart,$ttEnd-$ttStart)
[IO.File]::WriteAllText((Join-Path $env:TT542_ROOT 'locked.marker'),'ready')
Start-Sleep -Seconds 60
`;
    child = spawn("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], {
      env: { ...process.env, TT542_SOURCE: __dirname, TT542_PACKAGE: bundle, TT542_ROOT: fixture },
      windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
    });
    let errors = "";
    child.stderr.on("data", (chunk) => { errors += chunk.toString(); });
    const deadline = Date.now() + 15000;
    while (!fs.existsSync(path.join(fixture, "locked.marker")) && Date.now() < deadline && child.exitCode === null) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.ok(fs.existsSync(path.join(fixture, "locked.marker")), "runtime did not lock: " + errors);
    assert.throws(() => { const fd = fs.openSync(runtime, "r+"); fs.closeSync(fd); }, /EBUSY|EPERM|EACCES/);
    assert.equal(path.dirname(fs.realpathSync(bundle)).toLowerCase(), fs.realpathSync(fixture).toLowerCase());
    const renamed = path.join(fixture, "replacement");
    assert.equal(path.dirname(path.resolve(renamed)).toLowerCase(), path.resolve(fixture).toLowerCase());
    assert.throws(() => fs.renameSync(bundle, renamed), /EBUSY|EPERM|EACCES/);
    const stopped = new Promise((resolve) => child.once("close", resolve));
    child.kill();
    await stopped;
    child = undefined;
  } finally {
    if (child) child.kill();
    if (path.dirname(fs.realpathSync(fixture)).toLowerCase() !== tempParent.toLowerCase()) throw new Error("Unsafe fixture cleanup");
    fs.rmSync(fixture, { recursive: true, force: true });
  }
});

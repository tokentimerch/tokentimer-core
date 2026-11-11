"use strict";
/** Supporting Windows PowerShell filesystem-only regression. Executes only
 * AST-selected staging/detection/uninstall file operations on owned public text
 * fixtures. Never invokes service, registration, CA or certificate operations. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path");
const { spawnSync } = require("node:child_process");

test(
  "prepare-only preserves restored state across simulated SCM interruption",
  // skip-reason: platform
  { skip: process.platform !== "win32" },
  () => {
    const result = spawnSync(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-File",
        path.resolve(
          __dirname,
          "../../../../tests/e2e/helpers/certops-windows-prepare-only-fixture.ps1",
        ),
        "-InstallerPath",
        path.resolve(__dirname, "../install-agent.ps1"),
        "-NodeExecutable",
        process.execPath,
      ],
      { encoding: "utf8", timeout: 60000 },
    );
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /prepare-only-filesystem-controls-pass/);
  },
);

// skip-reason: platform
test("installer isolates Node environment without changing the caller", { skip: process.platform !== "win32" }, () => {
  const installer = path.resolve(__dirname, "../install-agent.ps1").replace(/'/g, "''");
  const script = `$ErrorActionPreference='Stop';
$tokens=$null; $errors=$null;
$ast=[Management.Automation.Language.Parser]::ParseFile('${installer}',[ref]$tokens,[ref]$errors);
if($errors.Count){throw 'Installer parse failed'};
$definition=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-InstallerNode'},$true);
if(!$definition){throw 'Node adapter absent'};
. ([scriptblock]::Create($definition.Extent.Text));
$script:NodeExe='${process.execPath.replace(/'/g, "''")}';
$env:NODE_OPTIONS='--invalid-regression-option'; $env:NODE_PATH='sentinel';
$value=Invoke-InstallerNode -NodeArguments @('-p','!process.env.NODE_OPTIONS&&!process.env.NODE_PATH');
if($value -ne 'true' -or $env:NODE_OPTIONS -ne '--invalid-regression-option' -or $env:NODE_PATH -ne 'sentinel'){throw 'Node environment was not isolated and restored'};
Invoke-InstallerNode -NodeArguments @('-e','process.exit(23)');
if($LASTEXITCODE -ne 23){throw 'Node exit status was not preserved'};`;
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], { encoding: "utf8", timeout: 30000 });
  assert.equal(result.status, 0, result.stderr);
});

test(
  "privileged installer paths verify source and stage before executing package code",
  // skip-reason: platform
  { skip: process.platform !== "win32" },
  () => {
    const parent = fs.mkdtempSync(path.join(os.tmpdir(), "certops-installer-source-"));
    const q = (value) => value.replace(/'/g, "''");
    try {
      const script = `$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$fixture='${q(parent)}'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('${q(path.resolve(__dirname, "../install-agent.ps1"))}',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Installer parse failed'}
foreach($name in @('Get-UnlinkedInstallItem','Assert-TrustedInstallAccess','Assert-TrustedInstallAncestors',
    'Test-PackageCopyExclusion','Get-ProtectedPackageFingerprint','Copy-PackageTree')){
  $definition=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$false)
  if(!$definition){throw "Installer helper absent: $name"}
  . ([scriptblock]::Create($definition.Extent.Text))
}
$sourceGate=@($ast.EndBlock.Statements | Where-Object {$_.Extent.Text -like 'if ($isElevated)*' -and
  $_.Extent.Text.Contains('Get-ProtectedPackageFingerprint -Directory $PackageDir -SourceTree')})
$sourceExecution=$ast.Find({param($n)$n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-InstallerNode'},$true)
if($sourceGate.Count -ne 1 -or !$sourceExecution -or $sourceGate[0].Extent.StartOffset -ge $sourceExecution.Extent.StartOffset){throw 'Source check must precede package execution'}
$sourceGate=[scriptblock]::Create($sourceGate[0].Extent.Text)
$nodeGate=@($ast.EndBlock.Statements | Where-Object {$_.Extent.Text -like 'if ($isElevated)*' -and
  $_.Extent.Text.Contains('select a Node installation protected')})
if($nodeGate.Count -ne 1 -or $nodeGate[0].Extent.EndOffset -ge $sourceExecution.Extent.StartOffset){throw 'Elevated dry-run must also check Node before invoking it'}
$stageGate=$ast.Find({param($n)$n -is [Management.Automation.Language.IfStatementAst] -and
  $n.Extent.Text.StartsWith('if ($fingerprint -cne $sourceFingerprint)')},$true)
if(!$stageGate){throw 'Mandatory source/stage comparison absent'}
$stageGate=[scriptblock]::Create($stageGate.Extent.Text)
$script:SystemSid='S-1-5-18'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$script:AdministratorsSid=if($identity.IsSystem){'S-1-5-32-544'}else{$identity.User.Value}
$identity.Dispose()
$script:TrustedInstallerSid='S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$sealAssignment=$ast.Find({param($n)$n -is [Management.Automation.Language.AssignmentStatementAst] -and
  $n.Left.Extent.Text -ceq '$script:PackageFingerprintName'},$false)
if(!$sealAssignment){throw 'Installer fingerprint filename absent'}
. ([scriptblock]::Create($sealAssignment.Extent.Text))
# Test real ACLs inside the owned tree only, not this runner's profile ACL.
$realAccess=(Get-Item Function:Assert-TrustedInstallAccess).ScriptBlock
function Assert-TrustedInstallAccess([string]$Path,[int]$MutationMask,[switch]$PackageRoot){
  if($Path.StartsWith("$fixture\\",[StringComparison]::OrdinalIgnoreCase)){& $realAccess @PSBoundParameters}
}
function Fail([string]$Message){throw $Message}
function Assert-Refused([scriptblock]$action,[string]$message){
  try { & $action | Out-Null } catch { if($_.Exception.Message -like $message){return}; throw }
  throw "Unexpected acceptance: $message"
}
function Set-FixtureGrant([IO.FileSystemInfo]$Item,[Security.AccessControl.FileSystemRights]$Rights,[bool]$Grant){
  $acl=$Item.GetAccessControl()
  $rule=[Security.AccessControl.FileSystemAccessRule]::new(
    [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),$Rights,'Allow')
  if($Grant){$acl.AddAccessRule($rule)}else{$acl.RemoveAccessRuleSpecific($rule)}
  $Item.SetAccessControl($acl)
}
$trusted=Join-Path $fixture 'trusted'
$security=[Security.AccessControl.DirectorySecurity]::new()
$security.SetSecurityDescriptorSddlForm("O:$($script:AdministratorsSid)D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;$($script:AdministratorsSid))")
$null=[IO.Directory]::CreateDirectory($trusted,$security)
$PackageDir=Join-Path $trusted 'package'
$null=[IO.Directory]::CreateDirectory($PackageDir)
$scripts=Join-Path $PackageDir 'scripts'
$null=[IO.Directory]::CreateDirectory($scripts)
$file=[IO.FileInfo]::new((Join-Path $scripts 'validate-server-url.js'))
[IO.File]::WriteAllText($file.FullName,'public URL validator fixture')
$excluded=Join-Path $scripts 'node_modules'
$null=[IO.Directory]::CreateDirectory($excluded)
Set-FixtureGrant ([IO.DirectoryInfo]::new($excluded)) WriteData $true
[IO.File]::WriteAllText((Join-Path $PackageDir '.git'),'included ordinary file')
$isElevated=$true
Set-FixtureGrant $file WriteData $true
foreach($dryRunCase in @($true,$false)){
  $script:DryRun=$dryRunCase
  Assert-Refused $sourceGate '*protected directory*writable by an untrusted principal*'
}
$isElevated=$false
$script:DryRun=$true
. $sourceGate
if(Get-Variable sourceFingerprint -ErrorAction SilentlyContinue){throw 'Non-elevated dry-run unexpectedly inspected package permissions'}
Set-FixtureGrant $file WriteData $false
$isElevated=$true
$parentItem=[IO.DirectoryInfo]::new($trusted)
Set-FixtureGrant $parentItem DeleteSubdirectoriesAndFiles $true
Assert-Refused $sourceGate '*protected directory*writable by an untrusted principal*'
Set-FixtureGrant $parentItem DeleteSubdirectoriesAndFiles $false
. $sourceGate
$stage=Join-Path $trusted 'stage'
Copy-PackageTree -Source $PackageDir -Destination $stage
if(Test-Path -LiteralPath (Join-Path $stage 'scripts/node_modules')){throw 'Excluded source directory was copied'}
if(-not (Test-Path -LiteralPath (Join-Path $stage '.git') -PathType Leaf)){throw 'Ordinary file was incorrectly excluded'}
$fingerprint=Get-ProtectedPackageFingerprint -Directory $stage
. $stageGate
[IO.File]::WriteAllText((Join-Path $stage 'scripts/validate-server-url.js'),'changed after copy')
$fingerprint=Get-ProtectedPackageFingerprint -Directory $stage
Assert-Refused $stageGate '*staged package differs from the protected source*'
'installer-source-controls-pass'`;
      const result = spawnSync(
        "powershell.exe",
        ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")],
        { encoding: "utf8", timeout: 30000 },
      );
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /installer-source-controls-pass/);
    } finally {
      fs.rmSync(parent, { recursive: true, force: true });
    }
  },
);
test(
  "actual installer filesystem branches preserve literal brackets and wildcard siblings",
  // skip-reason: platform
  { skip: process.platform !== "win32" },
  () => {
    const parent = fs.mkdtempSync(
      path.join(os.tmpdir(), "certops-installer-path-"),
    );
    const literal = path.join(parent, "Windows é [literal]"),
      sibling = path.join(parent, "Windows é l");
    try {
      fs.mkdirSync(literal);
      fs.mkdirSync(sibling);
      fs.writeFileSync(path.join(literal, "owned.txt"), "owned");
      fs.writeFileSync(path.join(sibling, "unrelated.txt"), "preserve");
      const installer = path.resolve(__dirname, "../install-agent.ps1"),
        q = (v) => v.replace(/'/g, "''");
      // Execute only the AST-extracted filesystem expression and uninstall block.
      // Never evaluate installer top-level code or service/registration commands.
      const script = `$ErrorActionPreference='Stop';
$t=$null;
$e=$null;
$ast=[Management.Automation.Language.Parser]::ParseFile('${q(installer)}',[ref]$t,[ref]$e);
if($e.Count){throw 'Installer parse failed'};
$AppDir='${q(literal)}';
$script:DryRun=$false;
$script:AppStaging=$AppDir+'.staging';
$create=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName()-ceq 'New-Item' -and $n.Extent.Text -like '*$script:AppStaging*'},$true));
if($create.Count-ne 1){throw 'Exact staging creation absent'};
$null=& ([scriptblock]::Create($create[0].Extent.Text));
if(!(Test-Path -LiteralPath $script:AppStaging -PathType Container)){throw 'Literal staging directory absent'};
Remove-Item -LiteralPath $script:AppStaging;
$assign=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -ceq '$script:IsUpgrade'},$true));
if($assign.Count-ne 1){throw 'Exact upgrade branch absent'};
if(!(& ([scriptblock]::Create($assign[0].Right.Extent.Text)))){throw 'Literal upgrade not detected'};
$remove=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName()-ceq 'Invoke-Step' -and $n.CommandElements.Count-eq 3 -and $n.CommandElements[1].Extent.Text-ceq '"Remove-Item -Recurse -Force $AppDir"'},$true));
if($remove.Count-ne 1){throw 'Exact filesystem uninstall block absent'};
& $remove[0].CommandElements[2].ScriptBlock.GetScriptBlock();
if(Test-Path -LiteralPath $AppDir){throw 'Literal app survived'};
'actual-filesystem-branches-pass'`;
      const result = spawnSync(
        "powershell.exe",
        [
          "-NoProfile",
          "-NonInteractive",
          "-EncodedCommand",
          Buffer.from(script, "utf16le").toString("base64"),
        ],
        { encoding: "utf8", timeout: 30000 },
      );
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /actual-filesystem-branches-pass/);
      assert.equal(fs.existsSync(literal), false);
      assert.equal(
        fs.readFileSync(path.join(sibling, "unrelated.txt"), "utf8"),
        "preserve",
      );
      // Evaluate only the actual journey's small command adapter, not its
      // privileged main. This catches legacy PowerShell OEM stdout corrupting
      // Unicode IIS physical-path observations read back as UTF-8 by Node.
      const main = fs.readFileSync(path.resolve(__dirname, "../../../../tests/e2e/windows-real-journey.js"), "utf8");
      const adapter = main.match(/^function ps\(script\) \{[^\n]+\}$/m);
      assert.ok(adapter, "Actual Windows journey PowerShell adapter absent");
      const ps = require("node:vm").runInNewContext(`(${adapter[0]})`, {
        command(program, args) {
          const actual = spawnSync(program, args, { encoding: "utf8", timeout: 10000 });
          assert.equal(actual.status, 0, actual.stderr);
          return actual.stdout.trim();
        },
      });
      const observed = JSON.parse(ps(`[pscustomobject]@{path='${q(literal)}'}|ConvertTo-Json -Compress`));
      assert.equal(observed.path, literal, "Actual UTF-8 adapter must preserve Unicode and literal brackets");
    } finally {
      fs.rmSync(parent, { recursive: true, force: true });
    }
  },
);

test(
  "installer rejects writable and unverified predecessor applications",
  // skip-reason: platform
  { skip: process.platform !== "win32" },
  () => {
    const parent = fs.mkdtempSync(path.join(os.tmpdir(), "certops-installer-acl-"));
    const installer = path.resolve(__dirname, "../install-agent.ps1");
    const q = (value) => value.replace(/'/g, "''");
    try {
      const script = `$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null
$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('${q(installer)}',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Installer parse failed'}
$helpers=@('Get-UnlinkedInstallItem','Assert-TrustedInstallAccess','Get-ProtectedPackageFingerprint')
foreach($name in $helpers){
  $definition=$ast.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$false)
  if(!$definition){throw "Installer helper absent: $name"}
  . ([scriptblock]::Create($definition.Extent.Text))
}
$sealAssignment=$ast.Find({param($node)$node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -ceq '$script:PackageFingerprintName'},$false)
if(!$sealAssignment){throw 'Installer fingerprint filename absent'}
. ([scriptblock]::Create($sealAssignment.Extent.Text))
$script:SystemSid='S-1-5-18'
$script:TrustedInstallerSid='S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
# Use this test's owner in place of Administrators to run without elevation.
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$script:AdministratorsSid=if($identity.IsSystem){'S-1-5-32-544'}else{$identity.User.Value}
$identity.Dispose()
$root=Join-Path '${q(parent)}' 'app'
$security=[Security.AccessControl.DirectorySecurity]::new()
$security.SetSecurityDescriptorSddlForm("O:$($script:AdministratorsSid)D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;$($script:AdministratorsSid))")
$null=[IO.Directory]::CreateDirectory($root,$security)
Assert-TrustedInstallAccess -Path $root -MutationMask 0 -PackageRoot
function Assert-Refused([scriptblock]$action,[string]$message){
  try { & $action | Out-Null } catch { if($_.Exception.Message -like $message){return}; throw }
  throw "Unexpected acceptance: $message"
}
$fixture=Join-Path $root 'public [fixture].js'
$seal=Join-Path $root $script:PackageFingerprintName
[IO.File]::WriteAllText($fixture,'before')
Assert-Refused {Get-ProtectedPackageFingerprint -Directory $root -Verify} '*no matching protected installation fingerprint*'
$fingerprint=Get-ProtectedPackageFingerprint -Directory $root
[IO.File]::WriteAllText($seal,$fingerprint)
if((Get-ProtectedPackageFingerprint -Directory $root -Verify) -cne $fingerprint){throw 'Protected predecessor rejected'}
[IO.File]::WriteAllText($fixture,'after')
Assert-Refused {Get-ProtectedPackageFingerprint -Directory $root -Verify} '*no matching protected installation fingerprint*'
[IO.File]::WriteAllText($fixture,'before')
$directory=[IO.DirectoryInfo]::new($root)
$acl=$directory.GetAccessControl()
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
  [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'WriteData','Allow'))
$directory.SetAccessControl($acl)
Assert-Refused {Get-ProtectedPackageFingerprint -Directory $root -Verify} '*writable by an untrusted principal*'
'installer-predecessor-controls-pass'`;
      const result = spawnSync(
        "powershell.exe",
        [
          "-NoProfile",
          "-NonInteractive",
          "-EncodedCommand",
          Buffer.from(script, "utf16le").toString("base64"),
        ],
        { encoding: "utf8", timeout: 30000 },
      );
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /installer-predecessor-controls-pass/);
    } finally {
      fs.rmSync(parent, { recursive: true, force: true });
    }
  },
);

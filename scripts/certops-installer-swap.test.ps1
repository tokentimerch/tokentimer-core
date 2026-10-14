# Supporting installer activation regression using only an exclusively created
# temporary directory. Parse/extract the actual production function without
# executing installer top-level code, then hold a real Win32 directory handle
# denying delete sharing to force first-rename refusal. No service, registry,
# certificate store, fixed install root or privilege changes are performed.
# Run explicitly with Windows PowerShell 5.1, or from the opted-in Windows journey.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$installer = Join-Path $PSScriptRoot '..\packages\agent\scripts\install-agent.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $installer).Path, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Production installer PowerShell parsing failed' }
$functions = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Activate-StagedPackage' }, $true))
if ($functions.Count -ne 1) { throw 'Expected exactly one production package activation function' }
$functionAst = $functions[0]
$tries = @($functionAst.Body.FindAll({ param($node) $node -is [Management.Automation.Language.TryStatementAst] }, $true))
if (!$tries.Count) { throw 'Package activation has no protected failure boundary' }
$protectedRenames = @($tries[0].Body.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Rename-Item' }, $true))
if ($protectedRenames.Count -ne 2) { throw 'Both package renames must be inside the same activation try boundary' }
$callers = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Activate-StagedPackage' }, $true))
if ($callers.Count -ne 1) { throw 'Production installer must invoke the tested package activation function exactly once' }
Invoke-Expression $functionAst.Extent.Text
Add-Type @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class CertopsOwnedDirectoryHandle {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  private static extern SafeFileHandle CreateFile(string path, uint access, uint sharing, IntPtr security, uint disposition, uint attributes, IntPtr template);
  public static SafeFileHandle Open(string path) {
    var handle = CreateFile(path, 0x80000000, 3, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
    if (handle.IsInvalid) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    return handle;
  }
}
'@
$root = Join-Path ([IO.Path]::GetTempPath()) ('certops-installer-swap-' + [Guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $root) { throw 'Owned temporary fixture unexpectedly exists' }
New-Item -ItemType Directory -Path $root | Out-Null
$handle = $null
try {
  $app = Join-Path $root 'app'
  $staging = "$app.staging.$PID"
  $previous = "$app.previous.$PID"
  New-Item -ItemType Directory -Path $app, $staging | Out-Null
  [IO.File]::WriteAllText((Join-Path $app 'version.txt'), 'original-version')
  [IO.File]::WriteAllText((Join-Path $staging 'version.txt'), 'candidate-version')
  $before = (Get-FileHash -LiteralPath (Join-Path $app 'version.txt') -Algorithm SHA256).Hash
  $otherStaging = Join-Path $root 'other-staging'
  New-Item -ItemType Directory -Path $otherStaging | Out-Null
  [IO.File]::WriteAllText((Join-Path $otherStaging 'untouched.txt'), 'owned negative-control marker')
  $wrongPathRefused = $false
  try { Activate-StagedPackage -AppDirectory $app -StagingDirectory $otherStaging -PreviousDirectory $previous }
  catch { $wrongPathRefused = $_.Exception.Message -match 'refusing unexpected package swap paths' }
  if (!$wrongPathRefused -or [IO.File]::ReadAllText((Join-Path $otherStaging 'untouched.txt')) -ne 'owned negative-control marker') { throw 'Unexpected staging path must be refused without deletion' }
  $handle = [CertopsOwnedDirectoryHandle]::Open($app)
  $failure = $null
  try { Activate-StagedPackage -AppDirectory $app -StagingDirectory $staging -PreviousDirectory $previous }
  catch { $failure = $_.Exception.Message }
  if (!$failure -or $failure -notmatch 'previous install was preserved') { throw ('Real first-rename refusal did not report preserved installation: ' + $failure) }
  if ((Get-FileHash -LiteralPath (Join-Path $app 'version.txt') -Algorithm SHA256).Hash -ne $before) { throw 'First-rename refusal changed the existing application' }
  if (Test-Path -LiteralPath $staging) { throw 'First-rename refusal leaked staged files' }
  if (Test-Path -LiteralPath $previous) { throw 'First-rename refusal incorrectly moved the existing application' }
  $handle.Dispose()
  $handle = $null
  New-Item -ItemType Directory -Path $staging | Out-Null
  [IO.File]::WriteAllText((Join-Path $staging 'version.txt'), 'candidate-version')
  Activate-StagedPackage -AppDirectory $app -StagingDirectory $staging -PreviousDirectory $previous
  if ([IO.File]::ReadAllText((Join-Path $app 'version.txt')) -ne 'candidate-version') { throw 'Positive control did not activate actual staged files' }
  if ((Get-FileHash -LiteralPath (Join-Path $previous 'version.txt') -Algorithm SHA256).Hash -ne $before) { throw 'Positive control did not preserve exact predecessor files' }
  if (Test-Path -LiteralPath $staging) { throw 'Positive activation retained the staging path' }
  New-Item -ItemType Directory -Path $staging | Out-Null
  [IO.File]::WriteAllText((Join-Path $staging 'version.txt'), 'another-candidate')
  $existingPreviousRefused = $false
  try { Activate-StagedPackage -AppDirectory $app -StagingDirectory $staging -PreviousDirectory $previous }
  catch { $existingPreviousRefused = $_.Exception.Message -match 'refusing an existing package recovery directory' }
  if (!$existingPreviousRefused -or (Get-FileHash -LiteralPath (Join-Path $previous 'version.txt') -Algorithm SHA256).Hash -ne $before -or [IO.File]::ReadAllText((Join-Path $app 'version.txt')) -ne 'candidate-version') { throw 'Existing recovery files must not be overwritten or removed' }
  [ordered]@{ productionAstParsed = $true; bothRenamesProtected = $true; unexpectedPathsRefused = $true; realFirstRenameRefused = $true; predecessorPreserved = $true; failedStagingRemoved = $true; handleReleased = $true; actualPositiveActivation = $true; existingRecoveryPreserved = $true; scope = 'owned-temporary-filesystem-only' } | ConvertTo-Json -Compress
} finally {
  if ($handle) { $handle.Dispose() }
  $resolved = [IO.Path]::GetFullPath($root)
  if ([IO.Path]::GetDirectoryName($resolved).TrimEnd('\') -ne [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') -or [IO.Path]::GetFileName($resolved) -notmatch '^certops-installer-swap-[a-f0-9]{32}$') { throw 'Refuse cleanup outside exact owned temporary fixture' }
  Remove-Item -LiteralPath $resolved -Recurse -Force
  if (Test-Path -LiteralPath $resolved) { throw 'Owned activation fixture cleanup incomplete' }
}

<# Synthetic policy and ordering tests only. The actual installer functions
are extracted from its AST; filesystem, registry, SCM and directory creation
are simulated. No installer, service, publisher check or native API executes. #>
param([switch]$LegacyParentCheck)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$installer = Join-Path $PSScriptRoot '..\packages\agent\scripts\install-agent.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($installer, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Installer syntax errors' }
$names = @('Assert-ProtectedIntentDirectory','Test-FreshPathExists','Assert-FreshInstallDirectoryAccess',
    'Assert-FreshInstallParents','Assert-BundledFreshMachine','New-BundledFreshInstallRoot','Activate-StagedPackage')
foreach ($name in $names) {
    $definitions = @($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name}, $true))
    if ($definitions.Count -ne 1) { throw "Missing unique product function: $name" }
    Invoke-Expression $definitions[0].Extent.Text
}
# Compile the actual interop declaration to catch language/marshalling syntax
# errors, but never call CreateDirectoryW in these synthetic tests.
$native = $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'New-FreshInstallDirectoryNative'}, $true)[0]
$declaration = @($native.FindAll({param($n) $n -is [Management.Automation.Language.StringConstantExpressionAst] -and $n.Value.Contains('namespace TokenTimer')}, $true))
if ($declaration.Count -ne 1) { throw 'Expected actual interop declaration' }
Add-Type -TypeDefinition $declaration[0].Value

$LegacyInstallRoot = 'C:\ProgramData\TokenTimerAgent'
$InstallParent = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$InstallRoot = Join-Path $InstallParent 'TokenTimerAgent'
$ServiceName = 'TokenTimerAgent'
$AppDir = Join-Path $InstallRoot 'app'; $StateDir = Join-Path $InstallRoot 'state'
$script:AuthorizedLauncherTransaction = 'synthetic-owned-transaction'
$standard = 'O:SYG:SYD:AI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;;0x100004;;;BU)(A;OICIIO;FA;;;CO)'
$protected = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
$script:scenario = ''; $script:rootCreated = $false; $script:nativeCalls = 0; $script:renames = 0; $script:checks = 0
$script:sddl = $standard
function Get-Item {
    param($LiteralPath,[switch]$Force,$ErrorAction)
    if ($script:scenario -eq 'unreadable-parent' -and $LiteralPath -eq $InstallParent) { throw 'parent unreadable' }
    if ($LiteralPath -eq $LegacyInstallRoot -and $script:scenario -ne 'existing-legacy-root') {
        Write-Error 'missing legacy root' -Category ObjectNotFound -ErrorAction Stop
    }
    if ($LiteralPath -eq $InstallRoot -and -not $script:rootCreated) {
        if ($script:scenario -eq 'unreadable-root') { Write-Error 'root unreadable' -Category PermissionDenied -ErrorAction Stop }
        if ($script:scenario -ne 'existing-root') { Write-Error 'missing' -Category ObjectNotFound -ErrorAction Stop }
    }
    $linked = $script:scenario -eq 'linked-parent' -and $LiteralPath -eq $InstallParent
    return [pscustomobject]@{PSIsContainer=($script:scenario -ne 'file-parent'); Attributes=$(if($linked){[IO.FileAttributes]::ReparsePoint}else{[IO.FileAttributes]::Directory})}
}
function Get-Acl {
    param($LiteralPath,$ErrorAction)
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $value = if ($LiteralPath -eq $InstallRoot) { $protected } else { $script:sddl }
    $acl.SetSecurityDescriptorSddlForm($value)
    return $acl
}
function Get-ChildItem {
    param($LiteralPath,[switch]$Force,$ErrorAction)
    if ($LiteralPath -eq $InstallRoot) {
        if ($script:scenario -eq 'populated-root') { return [pscustomobject]@{Name='unexpected-child'} }
        return
    }
    if ($script:scenario -eq 'registry-error') { throw 'registry unavailable' }
    if ($script:scenario -eq 'registry-service') { return [pscustomobject]@{PSChildName=$ServiceName} }
    if ($script:scenario -eq 'registry-generation') { return [pscustomobject]@{PSChildName="$ServiceName-any-generation"} }
    return [pscustomobject]@{PSChildName='UnrelatedService'}
}
function Get-CimInstance {
    param($ClassName,$Filter,$ErrorAction)
    if ($Filter -notmatch 'LIKE') { throw 'generation service query missing' }
    if ($script:scenario -eq 'scm-error') { throw 'SCM unavailable' }
    if ($script:scenario -in @('scm-service','scm-generation')) { return [pscustomobject]@{Name='occupied-slot'} }
}
function New-FreshInstallDirectoryNative {
    param($Directory,[byte[]]$Descriptor)
    $script:nativeCalls++
    $actual = [Security.AccessControl.RawSecurityDescriptor]::new($Descriptor,0)
    $expected = [Security.AccessControl.RawSecurityDescriptor]::new($protected)
    if ($actual.GetSddlForm('All') -cne $expected.GetSddlForm('All')) { throw 'creation descriptor is not protected' }
    if ($script:scenario -eq 'create-race') { throw 'ERROR_ALREADY_EXISTS' }
    $script:rootCreated = $true
}
function Test-Path { param($LiteralPath) return $LiteralPath -eq $AppDir }
function Rename-Item { param($LiteralPath,$NewName,$ErrorAction) $script:renames++ }
function Check([string]$Name,[bool]$Allowed,[scriptblock]$Operation) {
    $accepted = $false
    try { & $Operation; $accepted = $true } catch { if ($Allowed) { throw } }
    if ($accepted -ne $Allowed) { throw "Unexpected policy decision: $Name" }
    $script:checks++
}
if ($LegacyParentCheck) {
    # Reproduce the earlier prototype's parent-policy error by applying the
    # unchanged intent guard to ProgramData. This is not a full install repro.
    Assert-ProtectedIntentDirectory -Directory 'C:\ProgramData'
    throw 'Legacy control unexpectedly accepted standard ProgramData'
}

Check 'protected Program Files' $true { Assert-FreshInstallParents }
$script:sddl = $standard.Replace('0x100004','0x4')
Check 'subdirectory creation without replacement' $true { Assert-FreshInstallParents }
foreach ($mask in @('0x2','0x100','0x40','0x10000','0x40000','0x80000','0x10000000','0x40000000')) {
    $script:sddl = $standard + "(A;;$mask;;;BU)"
    Check "untrusted ancestor mutation $mask" $false { Assert-FreshInstallParents }
}
$script:sddl = $standard.Replace('O:SY','O:BU')
Check 'untrusted ancestor owner' $false { Assert-FreshInstallParents }
$script:sddl = 'O:SYG:SYD:NO_ACCESS_CONTROL'
Check 'null DACL' $false { Assert-FreshInstallParents }
$script:sddl = $standard
foreach ($case in @('linked-parent','file-parent','unreadable-parent','existing-root','existing-legacy-root','unreadable-root',
    'registry-error','registry-service','registry-generation','scm-error','scm-service','scm-generation')) {
    $script:scenario = $case
    Check $case $false { Assert-BundledFreshMachine }
}
$script:scenario = ''; Check 'empty machine slot' $true { Assert-BundledFreshMachine }
Check 'create protected root' $true { New-BundledFreshInstallRoot }
if (-not $script:rootCreated -or $script:nativeCalls -ne 1) { throw 'exclusive creation was not used' }
Check 'second create refuses root' $false { New-BundledFreshInstallRoot }
if ($script:nativeCalls -ne 1) { throw 'existing root reached creation' }
$script:rootCreated = $false; $script:scenario = 'create-race'
Check 'raced root is not adopted' $false { New-BundledFreshInstallRoot }
if ($script:rootCreated) { throw 'raced root was adopted' }
$script:scenario = 'populated-root'
Check 'unexpected root content' $false { New-BundledFreshInstallRoot }
$script:scenario = ''; $script:rootCreated = $true
$originalProtected = $protected
$badRootDescriptors = @(
    $originalProtected.Replace('D:P','D:')
    ($originalProtected+'(A;OICI;FA;;;BU)')
    $originalProtected.Replace('(A;OICI;FA;;;BA)','')
    $originalProtected.Replace('O:BA','O:BU')
    $originalProtected.Replace('OICI','OICIIO')
)
foreach ($sddl in $badRootDescriptors) {
    $protected = $sddl
    Check "root ACL refuses drift: $sddl" $false { Assert-FreshInstallDirectoryAccess -Directory $InstallRoot -ProtectedRoot }
}
$protected = $originalProtected
$script:sddl = $standard
Check 'existing app is never renamed for fresh install' $false {
    Activate-StagedPackage -AppDirectory $AppDir -StagingDirectory "$AppDir.staging.$PID" -PreviousDirectory "$AppDir.previous.$PID" -FreshOnly
}
if ($script:renames -ne 0) { throw 'fresh installation renamed an existing app' }

$source = [IO.File]::ReadAllText($installer)
$gate = $source.IndexOf('try { Assert-BundledFreshMachine }')
$lock = $source.IndexOf('Enter-AgentInstallLock }')
$recovery = $source.IndexOf('            Recover-InterruptedUpgrade')
$stateGuard = $source.IndexOf("if (`$script:RequiresBundledRuntime) { Fail 'existing agent state appeared; preserve it for inspection' }")
if ($gate -le $lock -or $stateGuard -le $gate -or $recovery -le $stateGuard) { throw 'fresh guard must precede state/recovery mutations under the install lock' }
$genericRoot = 'New-Item -ItemType Directory -Force -Path $InstallRoot'
if (-not $source.Contains($genericRoot) -or -not $source.Contains('-FreshOnly:$script:RequiresBundledRuntime')) { throw 'generic path or fresh-only activation flag missing' }
$serviceBlock = [regex]::Match($source,'(?s)if \(\$script:RequiresBundledRuntime\) \{\s*# New-Service fails.*?\n\} else \{')
if (-not $serviceBlock.Success -or $serviceBlock.Value.Contains('Set-ServiceBinaryPath')) { throw 'bundled installation must exclusively create the service' }
if (-not $source.Contains("if (`$script:Uninstall) { Fail 'bundled package supports first installation only; uninstall is unavailable' }")) { throw 'bundled uninstall refusal missing' }
[ordered]@{syntheticDecisions=$script:checks;actualInteropCompiled=$true;nativeCreateDirectoryCalled=$false;installerOrServiceExecuted=$false;publisherVerificationPerformed=$false} | ConvertTo-Json -Compress

# Filesystem-only Windows regression with explicit SCM stubs. Run in a new
# Windows PowerShell process. No real service or registry command is loaded.
param(
    [Parameter(Mandatory)][string]$InstallerPath,
    [Parameter(Mandatory)][string]$NodeExecutable
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($InstallerPath, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Installer syntax failed.' }
$names = @('Get-UnlinkedInstallItem','Assert-TrustedInstallAccess','Get-ProtectedPackageFingerprint',
    'Assert-NoExistingPreparedInstall','Read-RestoredPreparationConfig','Get-WindowsServiceBinPath',
    'Complete-PreparedInstall','Get-PackageDirectoryIdentity')
foreach ($name in $names) {
    $definition = $ast.Find({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $false)
    if (-not $definition) { throw "Installer function absent: $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$script:AdministratorsSid = $identity.User.Value
$identity.Dispose()
$script:SystemSid = 'S-1-5-18'
$script:TrustedInstallerSid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$script:PackageFingerprintName = '.tokentimer-install-sha256'
$script:WorkspaceId = 'workspace-fixture'
$script:NodeExe = $NodeExecutable
$ServiceName = 'PreparedFixture'
$ServiceDisplayName = 'Prepared fixture'
$fixtureParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$fixture = Join-Path $fixtureParent ('prepare-owned-' + [guid]::NewGuid().ToString('N'))
$security = [Security.AccessControl.DirectorySecurity]::new()
$security.SetSecurityDescriptorSddlForm("O:$($script:AdministratorsSid)D:P(A;OICI;FA;;;$($script:AdministratorsSid))")
$null = [IO.Directory]::CreateDirectory($fixture, $security)

function Assert-Refused([scriptblock]$Action, [string]$Message) {
    try { & $Action | Out-Null } catch { if ($_.Exception.Message -like $Message) { return }; throw }
    throw "Unexpected acceptance: $Message"
}
function Get-CimInstance($ClassName, $Filter, $ErrorAction) {
    if ($ClassName -cne 'Win32_Service' -or $Filter -cne "Name='$ServiceName'") { throw 'Unexpected SCM query.' }
    return $script:registration
}
function New-Service($Name, $BinaryPathName, $DisplayName, $StartupType, $ErrorAction) {
    if ($Name -cne $ServiceName -or $StartupType -cne 'Disabled' -or
        $script:registration -or (Test-Path -LiteralPath $AppDir)) { throw 'Service was not created disabled before promotion.' }
    $script:registration = [pscustomobject]@{
        StartMode = $StartupType
        State = 'Stopped'
        ProcessId = 0
        StartName = 'LocalSystem'
        PathName = $BinaryPathName
    }
}
function Set-ServiceEnvironment($ConfigDir, $Token) {
    if ($ConfigDir -cne $StateDir -or $Token -cne '' -or $script:registration.StartMode -cne 'Disabled') {
        throw 'Unexpected bootstrap or config path.'
    }
    if ($script:interrupt) { throw 'injected interruption after CreateService' }
    if ($script:occupyDestination) { [IO.File]::WriteAllText($AppDir, 'late unrelated occupant') }
}
function Start-Service { throw 'Preparation must not call Start-Service.' }
function Stop-Service { throw 'Preparation must not call Stop-Service.' }
function Remove-Service { throw 'Preparation must not delete a service.' }

function New-Fixture([string]$Name) {
    $script:InstallRoot = Join-Path $fixture $Name
    $script:AppDir = Join-Path $InstallRoot 'app'
    $script:StateDir = Join-Path $InstallRoot 'state'
    $script:stage = Join-Path $InstallRoot "app.staging.$PID"
    $script:registration = $null
    $script:interrupt = $false
    $script:occupyDestination = $false
    $null = [IO.Directory]::CreateDirectory($StateDir)
    $null = [IO.Directory]::CreateDirectory($stage)
    [IO.File]::WriteAllText((Join-Path $StateDir 'config.json'),
        '{"agentId":"existing-agent","workspaceId":"workspace-fixture","serverUrl":"https://example.test"}')
    [IO.File]::WriteAllText((Join-Path $StateDir 'credential'), 'public dummy credential')
    [IO.File]::WriteAllText((Join-Path $StateDir 'journal'), 'retain this public journal')
    [IO.File]::WriteAllText((Join-Path $stage 'application'), 'public staged package')
    $script:expected = Get-PackageDirectoryIdentity -Directory $stage
    $hostExe = Join-Path $AppDir 'bin\tokentimer-agent-host-amd64.exe'
    $entry = Join-Path $AppDir 'bin\tokentimer-agent.js'
    $ordinary = Get-WindowsServiceBinPath -AppDirectory $AppDir -NodeExecutable $script:NodeExe -Architecture 'AMD64'
    if ($ordinary -cne ('"{0}" "{1}" "{2}"' -f $hostExe, $script:NodeExe, $entry)) {
        throw 'Ordinary SCM arguments changed.'
    }
    $origin = 'https://prepared.invalid:4443'
    $script:binaryPath = Get-WindowsServiceBinPath -AppDirectory $AppDir -NodeExecutable $script:NodeExe -Architecture 'AMD64' -PreparedServerUrl $origin
    if ($binaryPath -cne ('"{0}" --prepared-server-url "{1}" "{2}" "{3}"' -f $hostExe, $origin, $script:NodeExe, $entry)) {
        throw 'Prepared SCM arguments must carry the verified origin.'
    }
    $loopback = Get-WindowsServiceBinPath -AppDirectory $AppDir -NodeExecutable $script:NodeExe -Architecture 'AMD64' `
        -PreparedServerUrl 'http://[::1]:4400'
    if ($loopback -cne ('"{0}" --prepared-server-url "http://[::1]:4400" "{1}" "{2}"' -f $hostExe, $script:NodeExe, $entry)) {
        throw 'Prepared SCM arguments changed the IPv6 loopback origin.'
    }
    Assert-Refused {
        Get-WindowsServiceBinPath -AppDirectory $AppDir -NodeExecutable $script:NodeExe -Architecture 'AMD64' `
            -PreparedServerUrl 'https://user:fixture@prepared.invalid'
    } '*must be a bare origin*'
    $fingerprint = Get-ProtectedPackageFingerprint -Directory $stage
    [IO.File]::WriteAllText((Join-Path $stage $script:PackageFingerprintName), $fingerprint)
}
function Snapshot-State {
    foreach ($item in @((Get-Item -LiteralPath $StateDir)) + @(Get-ChildItem -LiteralPath $StateDir -Force)) {
        $acl = $item.GetAccessControl().Sddl
        if ($item.PSIsContainer) { $acl }
        else { $acl + '|' + [Convert]::ToBase64String([IO.File]::ReadAllBytes($item.FullName)) }
    }
}

try {
    New-Fixture 'success [literal]'
    $before = (Snapshot-State) -join [char]10
    $config = Read-RestoredPreparationConfig
    if ($config.agentId -cne 'existing-agent') { throw 'Wrong restored identity.' }
    Complete-PreparedInstall -Stage $stage -StagingIdentity $expected -BinaryPath $binaryPath
    if ($script:registration.StartMode -cne 'Disabled' -or $script:registration.ProcessId -ne 0 -or
        -not (Test-Path -LiteralPath $AppDir) -or (Test-Path -LiteralPath $stage) -or
        ((Snapshot-State) -join [char]10) -cne $before) { throw 'Successful preparation changed state or enabled the service.' }
    Assert-Refused { Assert-NoExistingPreparedInstall } '*no existing agent service or application*'

    New-Fixture 'destination conflict'
    $before = (Snapshot-State) -join [char]10
    $script:occupyDestination = $true
    $refused = $false
    try { Complete-PreparedInstall -Stage $stage -StagingIdentity $expected -BinaryPath $binaryPath }
    catch { $refused = $true }
    if (-not $refused -or $script:registration.StartMode -cne 'Disabled' -or
        [IO.File]::ReadAllText($AppDir) -cne 'late unrelated occupant' -or -not (Test-Path -LiteralPath $stage) -or
        ((Snapshot-State) -join [char]10) -cne $before) { throw 'Late destination conflict did not fail closed.' }

    New-Fixture 'interrupted'
    $before = (Snapshot-State) -join [char]10
    $script:interrupt = $true
    Assert-Refused { Complete-PreparedInstall -Stage $stage -StagingIdentity $expected -BinaryPath $binaryPath } '*injected interruption*'
    if ($script:registration.StartMode -cne 'Disabled' -or $script:registration.ProcessId -ne 0 -or
        (Test-Path -LiteralPath $AppDir) -or -not (Test-Path -LiteralPath $stage) -or
        ((Snapshot-State) -join [char]10) -cne $before) { throw 'Interrupted preparation changed state or enabled the service.' }
    Assert-Refused { Assert-NoExistingPreparedInstall } '*no existing agent service or application*'

    New-Fixture 'existing application'
    [IO.File]::WriteAllText($AppDir, 'unrelated occupant')
    Assert-Refused { Complete-PreparedInstall -Stage $stage -StagingIdentity $expected -BinaryPath $binaryPath } '*no existing agent service or application*'
    if ($script:registration -or [IO.File]::ReadAllText($AppDir) -cne 'unrelated occupant') { throw 'Existing app was changed.' }

    New-Fixture 'exchange residue'
    $null = [IO.Directory]::CreateDirectory((Join-Path $InstallRoot 'app.previous.99'))
    Assert-Refused { Complete-PreparedInstall -Stage $stage -StagingIdentity $expected -BinaryPath $binaryPath } '*earlier application exchange*'
    if ($script:registration) { throw 'Unresolved exchange created a registration.' }

    New-Fixture 'untrusted state'
    $credential = [IO.FileInfo]::new((Join-Path $StateDir 'credential'))
    $acl = $credential.GetAccessControl()
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'ReadData', 'Allow')
    $acl.AddAccessRule($rule)
    $credential.SetAccessControl($acl)
    Assert-Refused { Read-RestoredPreparationConfig } '*untrusted principal*'
    $acl.RemoveAccessRuleSpecific($rule)
    $credential.SetAccessControl($acl)
    [IO.File]::WriteAllText((Join-Path $StateDir 'registration.pending.json'), '{}')
    Assert-Refused { Read-RestoredPreparationConfig } '*incomplete bootstrap or registration*'
    'prepare-only-filesystem-controls-pass'
} finally {
    $resolved = [IO.Path]::GetFullPath($fixture)
    if ([IO.Path]::GetDirectoryName($resolved) -ne $fixtureParent -or
        [IO.Path]::GetFileName($resolved) -cnotmatch '^prepare-owned-[a-f0-9]{32}$') { throw 'Unsafe fixture cleanup.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

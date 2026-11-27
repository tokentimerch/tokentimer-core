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
    'Complete-PreparedInstall','Complete-ObservedInstall','Assert-DisabledServiceRegistration',
    'Get-PackageDirectoryIdentity','Get-WindowsServiceEnvironmentValues','Parse-Arguments','Invoke-PackagedNode')
foreach ($name in $names) {
    $definition = $ast.Find({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $false)
    if (-not $definition) { throw "Installer function absent: $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}

$originCheck = @($ast.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.IfStatementAst] -and
    $_.Extent.Text.StartsWith('if ($script:PrepareOnly)') -and $_.Extent.Text.Contains('$restoredOrigin =')
})
if ($originCheck.Count -ne 1) { throw 'Restored server origin validation is missing.' }
$validateRestoredOrigin = [scriptblock]::Create($originCheck[0].Extent.Text)
$ValidateServerUrlJs = Join-Path (Split-Path -Parent $InstallerPath) 'validate-server-url.js'
$script:PrepareOnly = $true
$script:AllowInsecureLocalHttp = $false

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$script:AdministratorsSid = if ($identity.IsSystem) { 'S-1-5-32-544' } else { $identity.Owner.Value }
$identity.Dispose()
$script:SystemSid = 'S-1-5-18'
$script:TrustedInstallerSid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$script:PackageFingerprintName = '.tokentimer-install-sha256'
$script:WorkspaceId = 'workspace-fixture'
$script:NodeExe = $NodeExecutable
$script:ObservationRunId = ''
$script:BootstrapToken = 'ttboot_public_fixture'
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
    if ($Name -cne $ServiceName -or $StartupType -cne 'Disabled' -or $script:registration -or
        (Test-Path -LiteralPath $AppDir) -ne [bool]$script:ObservationRunId) {
        throw 'Service was not created disabled at the expected preparation stage.'
    }
    $script:registration = [pscustomobject]@{
        StartMode = $StartupType
        State = 'Stopped'
        ProcessId = 0
        StartName = 'LocalSystem'
        PathName = $BinaryPathName
    }
}
function Set-ServiceEnvironment($ConfigDir, $Token, $Existing) {
    $expectedToken = if ($script:ObservationRunId) { $script:BootstrapToken } else { '' }
    if ($ConfigDir -cne $StateDir -or $Token -cne $expectedToken -or $script:registration.StartMode -cne 'Disabled') {
        throw 'Unexpected bootstrap or config path.'
    }
    if ($script:interrupt) { throw 'injected interruption after CreateService' }
    $script:scmEnvironment = @(Get-WindowsServiceEnvironmentValues -Existing $Existing -ConfigDir $ConfigDir -Token $Token)
    if ($script:occupyDestination) { [IO.File]::WriteAllText($AppDir, 'late unrelated occupant') }
}
function Get-ExistingServiceEnvironment([string]$ServiceKey) {
    if ($ServiceKey -cne "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName") {
        throw 'Unexpected registry inspection.'
    }
    if ($script:omitObservationBinding) {
        return @($script:scmEnvironment | Where-Object { $_ -notlike 'TOKENTIMER_AGENT_HOST_OBSERVATION_RUN=*' })
    }
    return $script:scmEnvironment
}
function Fail([string]$Message) { throw $Message }
function Start-Service { throw 'Preparation must not call Start-Service.' }
function Stop-Service { throw 'Preparation must not call Stop-Service.' }
function Remove-Service { throw 'Preparation must not delete a service.' }

function New-Fixture([string]$Name) {
    $script:InstallRoot = Join-Path $fixture $Name
    $script:AppDir = Join-Path $InstallRoot 'app'
    $script:StateDir = Join-Path $InstallRoot 'state'
    $script:stage = Join-Path $InstallRoot "app.staging.$PID"
    $script:registration = $null
    $script:scmEnvironment = @()
    $script:omitObservationBinding = $false
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
    $restoredConfig = $config
    $script:ApiUrl = $restoredConfig.serverUrl
    & $validateRestoredOrigin
    $script:ApiUrl = 'https://different.invalid'
    Assert-Refused { & $validateRestoredOrigin } '*restored agent server does not match --api-url*'
    $script:ApiUrl = $restoredConfig.serverUrl
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

    foreach ($invalid in @(@('--prepare-for-observation'), @('--prepare-for-observation', 'A' * 32))) {
        Assert-Refused { Parse-Arguments -Arguments $invalid } '*32-character lowercase hexadecimal run ID*'
    }
    $runId = '0123456789abcdef' * 2
    Parse-Arguments -Arguments @('--prepare-for-observation', $runId)
    if ($script:ObservationRunId -cne $runId) { throw 'The requested observation run was not retained.' }
    Assert-Refused { Parse-Arguments -Arguments @('--prepare-for-observation', $runId) } '*requires one*'
    $mode = $ast.EndBlock.Statements | Where-Object {
        $_.Extent.Text.StartsWith('if ($script:ObservationRunId -and (-not $script:RequiresBundledRuntime')
    }
    $script:RequiresBundledRuntime = $false
    $script:DryRun = $false
    $script:Uninstall = $false
    $script:PrepareOnly = $false
    Assert-Refused { & ([scriptblock]::Create($mode.Extent.Text)) } '*fresh bundled installation*'
    $script:RequiresBundledRuntime = $true
    & ([scriptblock]::Create($mode.Extent.Text))
    $authorized = $ast.Find({ param($node)
        $node -is [Management.Automation.Language.IfStatementAst] -and
        $node.Extent.Text.StartsWith('if ($script:ObservationRunId -and $null -eq $script:AuthorizedLauncherTransaction')
    }, $true)
    $intent = $ast.Find({ param($node)
        $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Assert-AuthorizedLauncherOrNoIntent'
    }, $true)
    $start = $ast.EndBlock.Statements | Where-Object {
        $_.Extent.Text.StartsWith('if ($script:ObservationRunId) {') -and $_.Extent.Text.Contains('Complete-ObservedInstall')
    }
    if (-not $authorized -or -not $intent -or -not $start -or
        $intent.Extent.EndOffset -ge $authorized.Extent.StartOffset -or $authorized.Extent.EndOffset -ge $start.Extent.StartOffset) {
        throw 'The verified launcher guard must precede observation preparation.'
    }
    $script:AuthorizedLauncherTransaction = $null
    Assert-Refused { & ([scriptblock]::Create($authorized.Extent.Text)) } '*verified launcher transaction*'
    if ($start.Extent.Text -match '(?i)\b(?:Start-Service|Restart-Service)\b' -or
        -not $start.Find({ param($node) $node -is [Management.Automation.Language.ExitStatementAst] }, $true)) {
        throw 'Observation preparation must return before normal service startup.'
    }

    foreach ($outcome in @('success', 'registry-write-fails', 'readback-fails')) {
        New-Fixture "observed $outcome"
        Rename-Item -LiteralPath $stage -NewName (Split-Path -Leaf $AppDir)
        $before = (Snapshot-State) -join [char]10
        if ($outcome -ceq 'registry-write-fails') {
            $script:interrupt = $true
            Assert-Refused { Complete-ObservedInstall -BinaryPath $binaryPath } '*injected interruption*'
        } elseif ($outcome -ceq 'readback-fails') {
            $script:omitObservationBinding = $true
            Assert-Refused { Complete-ObservedInstall -BinaryPath $binaryPath } '*run binding could not be verified*'
        } else {
            Complete-ObservedInstall -BinaryPath $binaryPath
            if ($script:scmEnvironment -cnotcontains "TOKENTIMER_AGENT_HOST_OBSERVATION_RUN=$runId" -or
                $script:scmEnvironment -cnotcontains "TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=$script:BootstrapToken") {
                throw 'Prepared SCM environment lost its observation binding or deferred bootstrap.'
            }
        }
        if ($script:registration.StartMode -cne 'Disabled' -or $script:registration.State -cne 'Stopped' -or
            $script:registration.ProcessId -ne 0 -or ((Snapshot-State) -join [char]10) -cne $before) {
            throw 'Observed preparation started the service or changed its protected state.'
        }
    }
    'prepare-only-filesystem-controls-pass'
} finally {
    $resolved = [IO.Path]::GetFullPath($fixture)
    if ([IO.Path]::GetDirectoryName($resolved) -ne $fixtureParent -or
        [IO.Path]::GetFileName($resolved) -cnotmatch '^prepare-owned-[a-f0-9]{32}$') { throw 'Unsafe fixture cleanup.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

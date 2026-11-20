#Requires -Version 5.1
# install-agent.ps1 - install the TokenTimer CertOps Agent as a native Windows Service.
#
# This script installs FROM THE LOCAL PACKAGE DIRECTORY it lives in
# (packages/agent of a checked-out or unpacked release); it never downloads
# remote artifacts. It mirrors install-agent.sh's contract flag-for-flag and
# exit-code-for-exit-code so an operator who knows one script knows the
# other. Any divergence from that contract is a defect, not a feature.
#
# What it does (see -h / --help for flags):
#   1. Verifies the OS is 64-bit Windows (amd64/arm64) and that the
#      installed Node satisfies the package.json "engines" range.
#   2. Copies the agent package to C:\ProgramData\TokenTimerAgent\app and
#      creates the state (config + credential) dir
#      C:\ProgramData\TokenTimerAgent\state with a restricted ACL.
#   3. Writes a config.json skeleton from flags/env, unless one already
#      exists (a re-run never clobbers operator edits to config.json).
#   4. Delivers the bootstrap token to the service's first run via the
#      service's own registry Environment value (the native Windows
#      mechanism for per-service environment variables; there is no
#      Windows equivalent of a systemd EnvironmentFile). The token is
#      single-use and is NEVER echoed back to the terminal by this script.
#   5. Installs a native Windows Service (sc.exe / New-Service; no NSSM or
#      other third-party service wrapper) running as LocalSystem per
#      ADR-0012 decision 11, then starts it.
#   6. Preserves existing Windows Error Reporting policy. DumpType=0 is a
#      custom dump, not suppression; Windows dump containment remains unqualified.
#   7. On an upgrade (the service already exists), health-checks the
#      restarted service and rolls back to the previous app version, with
#      the credential and configuration preserved and its ACL re-asserted,
#      if the health check fails.
#
# Security notes:
#   - config.json and the credential file get a restricted ACL (see
#     src/platform/index.js): the installing administrator's SID plus
#     SYSTEM only, matching what the agent itself enforces on every write.
#   - Prefer passing the bootstrap token via the
#     TOKENTIMER_AGENT_BOOTSTRAP_TOKEN environment variable or the hidden
#     interactive prompt over -BootstrapToken/--bootstrap-token: argv is
#     visible in process listings.
#
# Known platform differences from install-agent.sh (documented, not
# hidden, per ADR-0012's own policy that real-host gaps must be visible):
#   - Windows has no equivalent of systemd's ProtectSystem=strict sandbox,
#     so -WritePath/--write-path, -ReloadService/--reload-service, and
#     --trust-store/--no-trust-store are accepted and validated for CLI-contract
#     parity, but there is no drop-in override to generate: a LocalSystem
#     service already has ambient host-wide access including LocalMachine\Root
#     and LocalMachine\CA (ADR-0012 decision 11), so the enforcement
#     point on Windows is agent-local policy (config.json allowlists),
#     not an OS-level sandbox. --trust-store is therefore a documented no-op.
#   - certbot/acme.sh are POSIX shell tools; the acme/certbot/{config,work,
#     logs} state subdirectories install-agent.sh creates for certbot are
#     not created here (certbot itself creates them on first run on any
#     platform). acme.sh's dnsapi/dns_certops.sh hook copy IS created here
#     (see below) since acme.sh needs it present before its first run, not
#     merely on first use.
#   - A plain Node.js process does not itself speak the Windows Service
#     Control Manager's control protocol (StartServiceCtrlDispatcher), so
#     the service's binPath does not point at node.exe directly. It points
#     at a small native host, windows-service-host/ (built to
#     bin\tokentimer-agent-host-<amd64|arm64>.exe by
#     scripts/build-windows-service-host.js and shipped inside this same
#     package), which answers the SCM's start/stop/interrogate requests
#     and runs the Node agent as its child process, translating a stop
#     request into a graceful shutdown signal (CTRL_BREAK_EVENT) before
#     force-killing the child on a timeout. See ADR-0012 decision 11.

# No [CmdletBinding()]/param() block: this script takes GNU-style
# double-dash flags (--api-url, --dry-run, ...) via $args, the same
# vocabulary as install-agent.sh, rather than PowerShell-style -ApiUrl
# parameters. CmdletBinding's strict parameter binder would otherwise
# reject any argument starting with a single dash before Parse-Arguments
# ever runs (breaking -h and the double-dash-prefixed flags read as
# unbound positionals).

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$InstallRoot = "C:\ProgramData\TokenTimerAgent"
$AppDir = Join-Path $InstallRoot "app"
$StateDir = Join-Path $InstallRoot "state"
$ServiceName = "TokenTimerAgent"
$ServiceDisplayName = "TokenTimer CertOps Agent"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PackageDir = Split-Path -Parent $ScriptDir
$ValidateServerUrlJs = Join-Path $ScriptDir "validate-server-url.js"
$HostSandboxJs = Join-Path $ScriptDir "host-sandbox.js"

$script:ApiUrl = ""
$script:WorkspaceId = ""
$script:BootstrapToken = $env:TOKENTIMER_AGENT_BOOTSTRAP_TOKEN
if ($null -eq $script:BootstrapToken) { $script:BootstrapToken = "" }
$script:CaBundle = ""
$script:DryRun = $false
$script:Uninstall = $false
$script:WritePaths = New-Object System.Collections.Generic.List[string]
$script:ReloadServices = New-Object System.Collections.Generic.List[string]
$script:WritePathsFile = ""
$script:AllowInsecureLocalHttp = $false
$script:TrustStore = $false
$script:NoTrustStore = $false
$script:NodeExe = 'node'

function Write-Log {
    param([string]$Message)
    Write-Host "install-agent: $Message"
}

function Fail {
    param([string]$Message)
    [Console]::Error.WriteLine("install-agent: ERROR: $Message")
    exit 1
}

# Only CA choices enter the service command; arbitrary Node options stay blocked.
function Invoke-InstallerNode {
    param([Parameter(Mandatory)][string[]]$NodeArguments)
    $previousOptions = [Environment]::GetEnvironmentVariable('NODE_OPTIONS', 'Process')
    $previousPath = [Environment]::GetEnvironmentVariable('NODE_PATH', 'Process')
    try {
        [Environment]::SetEnvironmentVariable('NODE_OPTIONS', $null, 'Process')
        [Environment]::SetEnvironmentVariable('NODE_PATH', $null, 'Process')
        & $script:NodeExe @NodeArguments
        $global:LASTEXITCODE = $LASTEXITCODE
    } finally {
        [Environment]::SetEnvironmentVariable('NODE_OPTIONS', $previousOptions, 'Process')
        [Environment]::SetEnvironmentVariable('NODE_PATH', $previousPath, 'Process')
    }
}

function Get-WindowsServiceCaOptions {
    param([string[]]$Existing, [version]$NodeVersion)
    $options = @($Existing | Where-Object { $_ -match '^(?i:NODE_OPTIONS)=' })
    $systemCa = @($Existing | Where-Object { $_ -match '^(?i:NODE_USE_SYSTEM_CA)=' })
    if ($options.Count -gt 1 -or $systemCa.Count -gt 1) { throw 'duplicate service CA settings require operator reconciliation' }
    $caOptions = @()
    if ($options.Count -eq 1) {
        $value = $options[0].Substring($options[0].IndexOf('=') + 1)
        if ($value -match '(?i)--(?:no[-_])?use[-_](?:system|bundled|openssl)[-_]ca') {
            foreach ($option in @($value -split '\s+' | Where-Object { $_ -ne '' })) {
                if ($option -ceq '--trace-warnings') { continue }
                if ($option -cnotin @('--use-system-ca','--no-use-system-ca','--use-bundled-ca','--use-openssl-ca')) {
                    throw 'explicit service CA options must be separate supported switches; remove other NODE_OPTIONS settings before reinstalling'
                }
                $caOptions += $option
            }
        }
    }
    if ($caOptions -ccontains '--use-bundled-ca' -and $caOptions -ccontains '--use-openssl-ca') {
        throw '--use-bundled-ca and --use-openssl-ca cannot be combined'
    }
    $supportsFlag = ($NodeVersion.Major -eq 22 -and $NodeVersion -ge [version]'22.15.0') -or
        ($NodeVersion.Major -eq 23 -and $NodeVersion -ge [version]'23.8.0') -or $NodeVersion.Major -ge 24
    $supportsEnvironment = ($NodeVersion.Major -eq 22 -and $NodeVersion -ge [version]'22.19.0') -or $NodeVersion -ge [version]'24.6.0'
    $hasSystemFlag = @($caOptions | Where-Object { $_ -match '^--(?:no-)?use-system-ca$' }).Count -gt 0
    if ($hasSystemFlag -and -not $supportsFlag) { throw 'the selected Node runtime does not support the existing service system CA option' }
    if ($systemCa.Count -eq 1 -and $systemCa[0].Substring($systemCa[0].IndexOf('=') + 1) -ceq '1' -and -not $supportsEnvironment -and -not $hasSystemFlag) {
        if (-not $supportsFlag) { throw 'the selected Node runtime cannot preserve NODE_USE_SYSTEM_CA=1; upgrade Node or configure an explicit CA bundle' }
        $caOptions += '--use-system-ca'
    }
    return $caOptions
}

function Get-WindowsServiceCaEnvironment {
    param([string[]]$ServiceValues, [scriptblock]$GetMachineValue = { param($Name) [Environment]::GetEnvironmentVariable($Name, 'Machine') })
    $values = New-Object System.Collections.Generic.List[string]
    foreach ($name in @('NODE_OPTIONS','NODE_USE_SYSTEM_CA')) {
        $overrides = @($ServiceValues | Where-Object { $_ -match ('^(?i:' + $name + ')=') })
        if ($overrides.Count) { foreach ($entry in $overrides) { $values.Add($entry) } }
        else {
            $value = & $GetMachineValue $name
            if ($null -ne $value) { $values.Add("$name=$value") }
        }
    }
    return $values.ToArray()
}

function Get-WindowsServiceCaCommand {
    param([Parameter(Mandatory)][string]$ServiceCommand)
    if ($ServiceCommand -match '[\x00-\x08\x0a-\x1f\x7f]' -or $ServiceCommand.Contains('\"')) { throw 'service command has unsupported escaping or control characters' }
    $parts = [regex]::Matches($ServiceCommand, '"([^"]+)"|([^ \t"]+)')
    $rest = [regex]::Replace($ServiceCommand, '"([^"]+)"|([^ \t"]+)', '')
    if ($rest -notmatch '^[ \t]*$') { throw 'service command has unsupported quoting' }
    for ($i = 1; $i -lt $parts.Count; $i++) {
        $gapStart = $parts[$i-1].Index + $parts[$i-1].Length
        if ($ServiceCommand.Substring($gapStart, $parts[$i].Index-$gapStart) -notmatch '^[ \t]+$') { throw 'service command has unsupported token boundaries' }
    }
    $tokens = @($parts | ForEach-Object { if ($_.Groups[1].Success) { $_.Groups[1].Value } else { $_.Groups[2].Value } })
    if ($tokens.Count -lt 3) { throw 'service command must name its host, Node runtime and script' }
    foreach ($value in @($tokens[0],$tokens[1],$tokens[$tokens.Count-1])) {
        if ($value -notmatch '^(?:[A-Za-z]:[\\/]|\\\\[^\\]+\\[^\\]+\\)' -or $value -match '[\x00-\x1f]') { throw 'service command paths must be absolute' }
    }
    if ([IO.Path]::GetExtension($tokens[0]) -ine '.exe' -or [IO.Path]::GetFileName($tokens[1]) -ine 'node.exe' -or [IO.Path]::GetExtension($tokens[$tokens.Count-1]) -ine '.js') { throw 'unsupported service host, runtime or script command' }
    $options = @()
    for ($i = 2; $i -lt $tokens.Count-1; $i++) {
        if ($tokens[$i] -cnotin @('--use-system-ca','--no-use-system-ca','--use-bundled-ca','--use-openssl-ca')) { throw 'service command contains a non-CA Node argument' }
        $options += $tokens[$i]
    }
    return $options
}

function Get-WindowsServiceCaIntent {
    param([string[]]$CaOptions,[string[]]$Environment = @())
    $baseTrust = $null; $systemTrust = $null
    foreach ($option in $CaOptions) {
        switch -CaseSensitive ($option) {
            '--use-openssl-ca' { $baseTrust='openssl' }
            '--use-bundled-ca' { $baseTrust='bundled' }
            '--use-system-ca' { $systemTrust=$true }
            '--no-use-system-ca' { $systemTrust=$false }
        }
    }
    if ($null -eq $systemTrust) {
        $setting = @($Environment | Where-Object { $_ -match '^(?i:NODE_USE_SYSTEM_CA)=' })
        if ($setting.Count) {
            $value = $setting[0].Substring($setting[0].IndexOf('=')+1)
            if ($value -ceq '1') { $systemTrust=$true }
            elseif ($value -ceq '0' -or $value -ceq '') { $systemTrust=$false }
            else { throw 'service system CA environment setting must be 0 or 1' }
        }
    }
    return [pscustomobject]@{ Base=$baseTrust; System=$systemTrust }
}

function Resolve-WindowsServiceCaOptions {
    param([Parameter(Mandatory)]$Snapshot,[version]$NodeVersion)
    $machineSnapshot = @($Snapshot.MachineCaEnvironment)
    $machineReader = { param($Name)
        $entry = @($machineSnapshot | Where-Object { $_ -match ('^(?i:' + $Name + ')=') })
        if ($entry.Count) { return $entry[0].Substring($entry[0].IndexOf('=')+1) }
        return $null
    }.GetNewClosure()
    $effective = @(Get-WindowsServiceCaEnvironment -ServiceValues $Snapshot.Environment.Values -GetMachineValue $machineReader)
    $environmentOptions = @(Get-WindowsServiceCaOptions -Existing $effective -NodeVersion $NodeVersion)
    $serviceHasOptions = @($Snapshot.Environment.Values | Where-Object { $_ -match '^(?i:NODE_OPTIONS)=' }).Count -gt 0
    $machineOptions = @($machineSnapshot | Where-Object { $_ -match '^(?i:NODE_OPTIONS)=' })
    if (-not $serviceHasOptions -and $machineOptions.Count -and @(Get-WindowsServiceCaOptions -Existing $machineOptions -NodeVersion $NodeVersion).Count) {
        throw 'machine NODE_OPTIONS contains CA settings; configure explicit per-service trust before reinstalling'
    }
    $environmentIntent = Get-WindowsServiceCaIntent -CaOptions $environmentOptions -Environment $effective
    $serviceOptions = @()
    if ($Snapshot.Exists) {
        $serviceOptions = @(Get-WindowsServiceCaCommand -ServiceCommand $Snapshot.BinaryPath)
        if ($serviceOptions.Count) { $null = Get-WindowsServiceCaOptions -Existing @('NODE_OPTIONS=' + ($serviceOptions -join ' ')) -NodeVersion $NodeVersion }
    }
    $serviceIntent = Get-WindowsServiceCaIntent -CaOptions $serviceOptions
    foreach ($dimension in @('Base','System')) {
        if ($null -ne $serviceIntent.$dimension -and $null -ne $environmentIntent.$dimension -and $serviceIntent.$dimension -cne $environmentIntent.$dimension) {
            throw 'service command and environment CA settings disagree; reconcile them before reinstalling'
        }
    }
    if (-not $serviceOptions.Count) { return $environmentOptions }
    $resolved = @($serviceOptions)
    foreach ($option in $environmentOptions) {
        if (($option -match '^--(?:no-)?use-system-ca$' -and $null -eq $serviceIntent.System) -or
            ($option -in @('--use-openssl-ca','--use-bundled-ca') -and $null -eq $serviceIntent.Base)) { $resolved += $option }
    }
    return $resolved
}

function Assert-WindowsServiceCaSnapshot {
    param([string]$Name,[Parameter(Mandatory)]$Expected)
    $current = Get-WindowsServiceConfigurationSnapshot -Name $Name
    if ($current.Exists -ne $Expected.Exists -or $current.BinaryPath -cne $Expected.BinaryPath -or $current.Environment.Present -ne $Expected.Environment.Present) { throw 'service trust settings changed since preflight; preserve staged files and reconcile before retrying' }
    $pairs = @(
        [pscustomobject]@{ Current = @($current.Environment.Values); Expected = @($Expected.Environment.Values) },
        [pscustomobject]@{ Current = @($current.MachineCaEnvironment); Expected = @($Expected.MachineCaEnvironment) }
    )
    foreach ($pair in $pairs) {
        if ($pair.Current.Count -ne $pair.Expected.Count) { throw 'service trust settings changed since preflight; preserve staged files and reconcile before retrying' }
        for ($i=0; $i -lt $pair.Current.Count; $i++) {
            if ($pair.Current[$i] -cne $pair.Expected[$i]) { throw 'service trust settings changed since preflight; preserve staged files and reconcile before retrying' }
        }
    }
}

function Get-WindowsServiceBinPath {
    param([string]$AppDirectory, [string]$NodeExecutable, [string]$Architecture, [string[]]$CaOptions = @())
    if (@($CaOptions | Where-Object { $_ -cnotin @('--use-system-ca','--no-use-system-ca','--use-bundled-ca','--use-openssl-ca') }).Count) {
        throw 'unsupported service CA argument'
    }
    $nodeFlags = if ($CaOptions.Count) { ' ' + ($CaOptions -join ' ') } else { '' }
    $hostExe = Join-Path $AppDirectory "bin\tokentimer-agent-host-$($Architecture.ToLowerInvariant()).exe"
    $entry = Join-Path $AppDirectory 'bin\tokentimer-agent.js'
    return '"{0}" "{1}"{2} "{3}"' -f $hostExe, $NodeExecutable, $nodeFlags, $entry
}

function Get-WindowsServiceEnvironmentValues {
    param([string[]]$Existing, [string]$ConfigDir, [string]$Token)
    $values = New-Object System.Collections.Generic.List[string]
    foreach ($entry in $Existing) {
        if ($entry -and $entry -notmatch '^(?i:TOKENTIMER_AGENT_CONFIG_DIR|TOKENTIMER_AGENT_BOOTSTRAP_TOKEN)=') { $values.Add($entry) }
    }
    $values.Add("TOKENTIMER_AGENT_CONFIG_DIR=$ConfigDir")
    if (-not [string]::IsNullOrEmpty($Token)) { $values.Add("TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=$Token") }
    return $values.ToArray()
}

function Get-WindowsServiceEnvironmentSnapshot {
    param([string]$ServiceKey)
    try { $item = Get-ItemProperty -Path $ServiceKey -ErrorAction Stop }
    catch [System.Management.Automation.ItemNotFoundException] { return [pscustomobject]@{ Present = $false; Values = @() } }
    $property = if ($null -ne $item) { $item.PSObject.Properties['Environment'] } else { $null }
    if ($null -eq $property) { return [pscustomobject]@{ Present = $false; Values = @() } }
    $values = @($property.Value | Where-Object { $null -ne $_ })
    if (@($values | Where-Object { $_ -isnot [string] }).Count) { throw 'service environment is not a string list' }
    return [pscustomobject]@{ Present = $true; Values = $values }
}

function Get-WindowsServiceConfigurationSnapshot {
    param([string]$Name)
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
    $environment = Get-WindowsServiceEnvironmentSnapshot -ServiceKey "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $machine = @(Get-WindowsServiceCaEnvironment -ServiceValues @())
    if (-not $service) { return [pscustomobject]@{ Exists = $false; BinaryPath = $null; DisplayName = $null; Environment = $environment; MachineCaEnvironment = $machine } }
    if ([string]::IsNullOrWhiteSpace([string]$service.PathName)) { throw 'the previous service command is unavailable' }
    return [pscustomobject]@{ Exists = $true; BinaryPath = [string]$service.PathName; DisplayName = [string]$service.DisplayName; Environment = $environment; MachineCaEnvironment = $machine }
}

function Restore-WindowsServiceConfiguration {
    param([string]$Name, [Parameter(Mandatory)]$Snapshot)
    if (-not $Snapshot.Exists -or [string]::IsNullOrWhiteSpace([string]$Snapshot.BinaryPath)) {
        throw 'the previous service configuration is unavailable; preserve the application and reconcile the service manually'
    }
    Set-ServiceBinaryPath -ServiceName $Name -BinPath $Snapshot.BinaryPath -DisplayName $Snapshot.DisplayName
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    if ($Snapshot.Environment.Present) {
        New-ItemProperty -Path $key -Name Environment -PropertyType MultiString -Value ([string[]]$Snapshot.Environment.Values) -Force -ErrorAction Stop | Out-Null
    } else {
        $current = Get-ItemProperty -Path $key -ErrorAction Stop
        if ($null -ne $current.PSObject.Properties['Environment']) { Remove-ItemProperty -Path $key -Name Environment -ErrorAction Stop }
    }
}

# Runs (or prints, under -DryRun) a non-secret action. Never pass the
# bootstrap token through this function: its description is printed.
function Invoke-Step {
    param(
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )
    if ($script:DryRun) {
        Write-Host "[dry-run] $Description"
    } else {
        & $Action
    }
}

function Show-Usage {
    @'
Usage:
  install-agent.ps1 --api-url URL --workspace-id ID [options]
  install-agent.ps1 --uninstall [--dry-run]

Installs the TokenTimer CertOps Agent from this local package directory as a
native Windows Service (LocalSystem) named TokenTimerAgent. (No remote
downloads; a hosted one-liner installer comes later.)

Required for install:
  --api-url URL          Control plane base URL (config.json serverUrl).
                         Must be https:// unless --allow-insecure-local-http
                         is set AND the host is loopback (localhost / 127/8 /
                         ::1 / *.localhost), matching the agent runtime.
  --workspace-id ID      Workspace the agent belongs to (recorded in
                         config.json; the bootstrap token is already
                         workspace-scoped server-side).
  Bootstrap token        Supplied interactively: when neither the
                         TOKENTIMER_AGENT_BOOTSTRAP_TOKEN environment
                         variable nor --bootstrap-token is given, the
                         installer reads the token from a hidden prompt
                         (recommended; nothing lands in shell history or
                         process listings). The environment variable is the
                         non-interactive alternative. --bootstrap-token
                         TOKEN still works but is discouraged: argv is
                         visible in process listings. Single-use ttboot_
                         token created in the dashboard (CertOps > Deploy an
                         agent).

Options:
  --ca-bundle PATH       PEM CA bundle for a private-CA control plane
                         (copied into the state dir, config.json
                         caBundlePath).
  --write-path PATH      Absolute directory the agent may write
                         certificates into (repeatable). Accepted for
                         parity with install-agent.sh; Windows has no
                         sandbox to scope (the service runs as LocalSystem
                         with ambient host-wide access), so this only
                         appears in the post-install reminder about
                         ACLing the target directories, and is not written
                         to any drop-in file.
  --write-paths-file F   File with one absolute write path per line (#
                         comments and blank lines allowed). Merged with
                         --write-path.
  --reload-service NAME  Accepted for parity with install-agent.sh
                         (allowed: nginx, apache/apache2/httpd, haproxy).
                         Windows has no polkit/sudo boundary to work around
                         (LocalSystem already has ambient access), so
                         reload authorization on Windows is enforced purely
                         by agent-local policy (config.json
                         commandProfiles.reloadArgv), not by anything this
                         installer configures.
  --trust-store          Accepted for parity with install-agent.sh.
                         LocalSystem already has LocalMachine\Root and
                         LocalMachine\CA on Windows Server 2016+ (the
                         verified 2019/2022/2025 matrix); no extra grant.
  --no-trust-store       Accepted for parity. Has no effect: the service
                         still runs as LocalSystem.
  --allow-insecure-local-http
                         Permit plain http:// ONLY for loopback hosts,
                         matching the runtime allowInsecureLocalHttp gate.
                         Required for local development; never use for
                         production. Also writes allowInsecureLocalHttp=true
                         into config.json.
  --dry-run              Print every action without executing anything.
  --uninstall            Stop and remove the TokenTimerAgent service and
                         the app dir. The state dir (credential, keys) is
                         preserved; remove it manually once you are sure
                         (Remove-Item -Recurse -Force
                         C:\ProgramData\TokenTimerAgent).
  -h, --help             Show this help.

Layout created:
  C:\ProgramData\TokenTimerAgent\app     agent package (read-only at
                                          runtime)
  C:\ProgramData\TokenTimerAgent\state   config dir: config.json,
                                          credential (written by the agent
                                          at registration), bootstrap.env
                                          (deleted automatically by the
                                          agent after its first successful
                                          registration; kept here only for
                                          a manual/dev run, since the
                                          running service itself reads the
                                          token from its own registry
                                          Environment value)

After install:
  Get-Service TokenTimerAgent
  Get-EventLog -LogName Application -Source TokenTimerAgent (if the agent
  logs there) or inspect its own log output per the agent's logging config.

Host permissions note:
  The service runs as LocalSystem, which already has host-wide filesystem
  access and can already write LocalMachine\Root / LocalMachine\CA;
  --write-path/--write-paths-file/--trust-store only remind you which
  directories the agent's own configured allowlist should include
  (see config.json).
'@ | Write-Host
}

function Parse-Arguments {
    param([string[]]$Arguments)
    $i = 0
    while ($i -lt $Arguments.Count) {
        $arg = $Arguments[$i]
        switch -Regex ($arg) {
            '^--api-url$' { $script:ApiUrl = $Arguments[$i + 1]; $i += 2; continue }
            '^--api-url=(.*)$' { $script:ApiUrl = $Matches[1]; $i += 1; continue }
            '^--workspace-id$' { $script:WorkspaceId = $Arguments[$i + 1]; $i += 2; continue }
            '^--workspace-id=(.*)$' { $script:WorkspaceId = $Matches[1]; $i += 1; continue }
            '^--bootstrap-token$' { $script:BootstrapToken = $Arguments[$i + 1]; $i += 2; continue }
            '^--bootstrap-token=(.*)$' { $script:BootstrapToken = $Matches[1]; $i += 1; continue }
            '^--ca-bundle$' { $script:CaBundle = $Arguments[$i + 1]; $i += 2; continue }
            '^--ca-bundle=(.*)$' { $script:CaBundle = $Matches[1]; $i += 1; continue }
            '^--write-path$' {
                $value = $Arguments[$i + 1]
                if ([string]::IsNullOrEmpty($value)) { Fail "--write-path requires an absolute directory path" }
                $script:WritePaths.Add($value)
                $i += 2; continue
            }
            '^--write-path=(.*)$' { $script:WritePaths.Add($Matches[1]); $i += 1; continue }
            '^--write-paths-file$' { $script:WritePathsFile = $Arguments[$i + 1]; $i += 2; continue }
            '^--write-paths-file=(.*)$' { $script:WritePathsFile = $Matches[1]; $i += 1; continue }
            '^--reload-service$' {
                $value = $Arguments[$i + 1]
                if ([string]::IsNullOrEmpty($value)) { Fail "--reload-service requires a service name" }
                $script:ReloadServices.Add($value)
                $i += 2; continue
            }
            '^--reload-service=(.*)$' { $script:ReloadServices.Add($Matches[1]); $i += 1; continue }
            '^--trust-store$' {
                if ($script:NoTrustStore) { Fail "cannot combine --trust-store and --no-trust-store" }
                $script:TrustStore = $true
                $i += 1; continue
            }
            '^--no-trust-store$' {
                if ($script:TrustStore) { Fail "cannot combine --trust-store and --no-trust-store" }
                $script:NoTrustStore = $true
                $i += 1; continue
            }
            '^--allow-insecure-local-http$' { $script:AllowInsecureLocalHttp = $true; $i += 1; continue }
            '^--dry-run$' { $script:DryRun = $true; $i += 1; continue }
            '^--uninstall$' { $script:Uninstall = $true; $i += 1; continue }
            '^(-h|--help)$' { Show-Usage; exit 0 }
            default { Fail "unknown argument: $arg (see --help)" }
        }
    }
}

Parse-Arguments -Arguments $args

# ------------------------------------------------------------- OS/arch gate
$arch = $env:PROCESSOR_ARCHITECTURE
if ($env:PROCESSOR_ARCHITEW6432) { $arch = $env:PROCESSOR_ARCHITEW6432 }
if ($arch -notin @("AMD64", "ARM64")) {
    Fail "unsupported architecture '$arch' (supported: AMD64, ARM64; 32-bit Windows is not supported)"
}
if (-not [System.Environment]::Is64BitOperatingSystem) {
    Fail "a 64-bit Windows OS is required"
}

# Windows Server 2016 / Windows 10 1607 (build 14393) is the floor this
# installer supports: it is the first widely-deployed release with WDAC
# (decision 8's documented hardened PowerShell-trust alternative) and CNG
# non-exportable key custody (decision 1) both generally available, and
# every earlier Windows Server release is already past Microsoft's own
# extended-support lifecycle. Without this check, install-agent.ps1 would
# run to completion on an unsupported, pre-WDAC host and only reveal the
# gap much later, if at all, the first time an operator tries to enable
# the hardened PowerShell-trust alternative decision 8 documents.
$MinimumSupportedBuild = 14393
$osBuild = [System.Environment]::OSVersion.Version.Build
if ($osBuild -lt $MinimumSupportedBuild) {
    Fail "unsupported Windows build $osBuild (running: $([System.Environment]::OSVersion.VersionString)); this installer requires Windows Server 2016 / Windows 10 1607 (build $MinimumSupportedBuild) or later"
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# -------------------------------------------------------------- uninstall
if ($script:Uninstall) {
    if (-not $script:DryRun -and -not (Test-IsAdministrator)) {
        Fail "uninstall must run from an elevated (Administrator) PowerShell session"
    }
    $serviceExists = [bool](Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)
    if ($serviceExists) {
        Invoke-Step "Stop-Service $ServiceName" { Get-Service -Name $ServiceName -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'Stopped' } | Stop-Service -Force -ErrorAction SilentlyContinue }
        Invoke-Step "sc.exe delete $ServiceName" { & sc.exe delete $ServiceName | Out-Null }
    } else {
        Write-Log "No $ServiceName service found; nothing to stop or delete."
    }
    Invoke-Step "Remove-Item -Recurse -Force $AppDir" {
        if (Test-Path -LiteralPath $AppDir) { Remove-Item -LiteralPath $AppDir -Recurse -Force }
    }
    Write-Log ""
    Write-Log "Uninstalled the service and app dir."
    Write-Log "Preserved (remove manually once you are sure):"
    Write-Log "  - $StateDir (agent credential, keys, replay store)"
    exit 0
}

# ----------------------------------------------------------- validate input
if ([string]::IsNullOrEmpty($script:ApiUrl)) { Fail "--api-url is required (control plane base URL)" }
if ([string]::IsNullOrEmpty($script:WorkspaceId)) { Fail "--workspace-id is required" }

# Hidden interactive prompt (preferred path): the dashboard's copyable
# command carries no token; the operator pastes it here, with terminal echo
# disabled (Read-Host -AsSecureString), so it never touches shell history or
# process listings.
if ([string]::IsNullOrEmpty($script:BootstrapToken) -and -not $script:DryRun) {
    if ([System.Environment]::UserInteractive) {
        $secure = Read-Host -Prompt "install-agent: paste the bootstrap token (input hidden)" -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($secure)
        try {
            $script:BootstrapToken = [Runtime.InteropServices.Marshal]::PtrToStringUni($bstr)
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($bstr)
        }
    }
}
if ([string]::IsNullOrEmpty($script:BootstrapToken) -and $script:DryRun) {
    Write-Log "dry-run: no bootstrap token supplied; a real install prompts for it interactively."
} else {
    if ([string]::IsNullOrEmpty($script:BootstrapToken)) {
        Fail "bootstrap token is required: paste it at the interactive prompt, or set TOKENTIMER_AGENT_BOOTSTRAP_TOKEN"
    }
    if ($script:BootstrapToken -notlike "ttboot_*") {
        Fail "bootstrap token does not look like a ttboot_ token (value not shown)"
    }
}
if ($script:ApiUrl -notmatch '^(http|https)://') {
    Fail "--api-url must start with http:// or https://"
}
# These values are interpolated into config.json below; refuse anything
# that could break out of a JSON string instead of trying to escape it.
if ($script:ApiUrl -match '["\\]') {
    Fail "--api-url must not contain double quotes or backslashes"
}
if ($script:WorkspaceId -match '["\\]') {
    Fail "--workspace-id must not contain double quotes or backslashes"
}
if (($script:ApiUrl + $script:WorkspaceId) -match '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]') {
    Fail "--api-url and --workspace-id must not contain control or non-printable characters"
}

# Match the agent runtime serverUrl gate exactly (src/protocol parseServerUrl):
# https always ok; plain http only for loopback when --allow-insecure-local-http.
if (-not (Test-Path -LiteralPath $ValidateServerUrlJs)) { Fail "server URL validator not found: $ValidateServerUrlJs" }
$validateArgs = @($script:ApiUrl)
if ($script:AllowInsecureLocalHttp) { $validateArgs += "--allow-insecure-local-http" }
$normalizedApiUrl = Invoke-InstallerNode -NodeArguments (@($ValidateServerUrlJs) + $validateArgs) 2>$null
if ($LASTEXITCODE -ne 0) {
    Fail "--api-url was rejected by the same rule the agent runtime uses (https required; http only for loopback with --allow-insecure-local-http)"
}
$script:ApiUrl = $normalizedApiUrl.Trim()

if (-not [string]::IsNullOrEmpty($script:CaBundle)) {
    if (-not (Test-Path -LiteralPath $script:CaBundle -PathType Leaf)) { Fail "--ca-bundle file not found: $script:CaBundle" }
    $caBundleContent = Get-Content -Raw -LiteralPath $script:CaBundle
    if ($caBundleContent -notmatch "BEGIN CERTIFICATE") { Fail "--ca-bundle contains no PEM certificate block" }
    if ($caBundleContent -match "PRIVATE KEY") {
        Fail "--ca-bundle contains private key material; a CA bundle must hold public certificates only"
    }
}

if (-not (Test-Path -LiteralPath (Join-Path $PackageDir "package.json"))) {
    Fail "agent package.json not found next to this script (expected $PackageDir\package.json); run from an unpacked agent package"
}
if (-not (Test-Path -LiteralPath (Join-Path $PackageDir "bin\tokentimer-agent.js"))) {
    Fail "agent entrypoint bin\tokentimer-agent.js not found in $PackageDir"
}
if (-not (Test-Path -LiteralPath $HostSandboxJs)) { Fail "host sandbox helper not found: $HostSandboxJs" }

# Windows-native absolute path validator for --write-path: a drive-letter
# rooted path (C:\...) or a UNC path (\\server\share\...), no ".." segments.
# install-agent.sh's validateAbsolutePath (host-sandbox.js) requires a
# POSIX leading "/", so it cannot validate a Windows path; this is a
# deliberately separate, Windows-shaped check rather than forcing POSIX
# path syntax onto Windows operators.
function Test-WindowsAbsolutePath {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { Fail "write path must be a non-empty string" }
    if ($Value.Trim() -ne $Value) { Fail "write path must not include leading/trailing whitespace: '$Value'" }
    if ($Value -notmatch '^([A-Za-z]:\\|\\\\)') {
        Fail "write path must be absolute (e.g. C:\path\to\dir or \\server\share\path): '$Value'"
    }
    if ($Value -match '[\x00-\x1F<>"|?*]') { Fail "write path contains disallowed characters: '$Value'" }
    if ($Value -match '(^|\\)\.\.(\\|$)') { Fail "write path must not contain .. segments: '$Value'" }
    return $Value.TrimEnd('\')
}

# Merge --write-paths-file into WritePaths, then validate every path.
if (-not [string]::IsNullOrEmpty($script:WritePathsFile)) {
    if (-not (Test-Path -LiteralPath $script:WritePathsFile -PathType Leaf)) { Fail "--write-paths-file not found: $script:WritePathsFile" }
    foreach ($line in Get-Content -LiteralPath $script:WritePathsFile) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith("#")) { continue }
        $script:WritePaths.Add($trimmed)
    }
}
$validatedWritePaths = New-Object System.Collections.Generic.List[string]
foreach ($writePath in $script:WritePaths) {
    $validatedWritePaths.Add((Test-WindowsAbsolutePath $writePath))
}
$script:WritePaths = $validatedWritePaths

$validatedReloadServices = New-Object System.Collections.Generic.List[string]
foreach ($reloadService in $script:ReloadServices) {
    Invoke-InstallerNode -NodeArguments @($HostSandboxJs, 'map-reload-service', $reloadService) | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "invalid --reload-service: $reloadService" }
    $validatedReloadServices.Add($reloadService)
}
$script:ReloadServices = $validatedReloadServices

if (-not $script:DryRun -and -not (Test-IsAdministrator)) {
    Fail "install must run from an elevated (Administrator) PowerShell session"
}

# -------------------------------------------------------- node version gate
# engines.node is a single ">=x.y.z <a.b.c" range in this package; a plain
# regex parse of the lower bound avoids needing node before the node check
# itself, mirroring install-agent.sh's sed parse.
$packageJsonText = Get-Content -Raw -LiteralPath (Join-Path $PackageDir "package.json")
$engineMatch = [regex]::Match($packageJsonText, '"node"\s*:\s*"([^"]*)"')
if (-not $engineMatch.Success) {
    Fail "could not find engines.node in $PackageDir\package.json"
}
$requiredRange = $engineMatch.Groups[1].Value
$requiredMajorMatch = [regex]::Match($requiredRange, '[0-9]+')
if (-not $requiredMajorMatch.Success) {
    Fail "could not parse required Node version from $PackageDir\package.json (engines.node='$requiredRange')"
}
$requiredMajor = [int]$requiredMajorMatch.Value

$nodeCommand = Get-Command node -ErrorAction SilentlyContinue
if (-not $nodeCommand) {
    Fail "node is not installed or not on PATH; the agent requires Node '$requiredRange'"
}
$nodeVersionRaw = (Invoke-InstallerNode -NodeArguments @('-v')).Trim()
$nodeMajorMatch = [regex]::Match($nodeVersionRaw, '^v([0-9]+)')
if (-not $nodeMajorMatch.Success) {
    Fail "could not parse installed Node version from 'node -v' (got '$nodeVersionRaw')"
}
$nodeMajor = [int]$nodeMajorMatch.Groups[1].Value
if ($nodeMajor -lt $requiredMajor) {
    Fail "Node $nodeVersionRaw is too old; the agent requires engines.node '$requiredRange'"
}
Write-Log "Node $nodeVersionRaw satisfies engines.node '$requiredRange'."
$script:NodeExe = $nodeCommand.Source
$caVersion = [regex]::Match($nodeVersionRaw, '^v([0-9]+)\.([0-9]+)\.([0-9]+)')
if (-not $caVersion.Success) { Fail 'could not determine Node version for the service CA policy' }
$script:NodeVersion = [version]("{0}.{1}.{2}" -f $caVersion.Groups[1].Value, $caVersion.Groups[2].Value, $caVersion.Groups[3].Value)
try {
    $script:PreviousServiceConfiguration = Get-WindowsServiceConfigurationSnapshot -Name $ServiceName
    $script:NodeCaOptions = @(Resolve-WindowsServiceCaOptions -Snapshot $script:PreviousServiceConfiguration -NodeVersion $script:NodeVersion)
} catch { Fail "service CA policy validation failed before installation changes ($($_.Exception.Message))" }

# --------------------------------------------------- platform module helper
# Reuses the package's own src/platform module (already ACL-tested; see
# platform.test.js) instead of re-implementing icacls logic in this script,
# so the installer and the running agent enforce the exact same ACL matrix
# (ADR-0012 decision 10), including the owner-SID check.
function Invoke-PlatformAcl {
    param(
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [Parameter(Mandatory = $true)][ValidateSet("file", "directory")][string]$Kind
    )
    $platformModule = Join-Path $PackageDir "src\platform\index.js"
    # ConvertTo-Json (built into PowerShell 5.1+) is used rather than a
    # hand-rolled escape so a path containing a quote or backslash can never
    # break out of the generated JS string literal. The script is written to
    # a temp file rather than passed via `node -e "..."`: PowerShell 5.1's
    # native-argument marshalling can strip embedded double quotes from a
    # single command-line argument, which corrupts an inline -e script that
    # itself contains quoted JS string literals.
    $modulePathJson = $platformModule | ConvertTo-Json -Compress
    $targetPathJson = $TargetPath | ConvertTo-Json -Compress
    $kindJson = $Kind | ConvertTo-Json -Compress
    $jsSource = "require($modulePathJson).applyRestrictivePermissions($targetPathJson, { kind: $kindJson });"
    $scriptPath = Join-Path ([System.IO.Path]::GetTempPath()) "tokentimer-acl-$PID-$([guid]::NewGuid().ToString('N')).js"
    try {
        [System.IO.File]::WriteAllText($scriptPath, $jsSource, (New-Object System.Text.UTF8Encoding($false)))
        Invoke-InstallerNode -NodeArguments @($scriptPath)
        if ($LASTEXITCODE -ne 0) {
            Fail "failed to apply a restricted ACL to $TargetPath (kind=$Kind)"
        }
    } finally {
        Remove-Item -LiteralPath $scriptPath -Force -ErrorAction SilentlyContinue
    }
}

# Native package checks run before any installed application/state mutation.
function Assert-WindowsPeImage {
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][ValidateSet('AMD64','ARM64')][string]$Architecture
    )
    if (-not [IO.Path]::IsPathRooted($LiteralPath)) { throw 'Native helper path must be absolute' }
    $ancestor = [IO.Path]::GetFullPath($LiteralPath)
    while ($ancestor) {
        $item = Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Refusing linked native helper path' }
        $next = [IO.Path]::GetDirectoryName($ancestor)
        if (!$next -or $next -eq $ancestor) { break }
        $ancestor = $next
    }
    $stream = $null
    try {
        # Hold a read-only, non-write/delete-shared handle while inspecting the
        # bounded public image. Never execute an unvalidated candidate helper.
        $stream = [IO.FileStream]::new($LiteralPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        if ($stream.Length -lt 64 -or $stream.Length -gt 67108864) { throw 'Native helper size is outside supported PE bounds' }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $read = 0
        while ($read -lt $bytes.Length) {
            $count = $stream.Read($bytes,$read,$bytes.Length-$read)
            if ($count -eq 0) { throw 'Native helper truncated during PE read' }
            $read += $count
        }
        if ([BitConverter]::ToUInt16($bytes,0) -ne 0x5a4d) { throw 'Native helper DOS signature invalid' }
        [UInt64]$pe = [BitConverter]::ToUInt32($bytes,60)
        if ($pe -lt 64 -or $pe+24 -gt $bytes.Length) { throw 'Native helper PE offset invalid' }
        if ([BitConverter]::ToUInt32($bytes,[int]$pe) -ne 0x4550) { throw 'Native helper PE signature invalid' }
        $expected = if ($Architecture -eq 'AMD64') { 0x8664 } else { 0xaa64 }
        if ([BitConverter]::ToUInt16($bytes,[int]$pe+4) -ne $expected) { throw 'Native helper architecture mismatch' }
        [UInt64]$sections = [BitConverter]::ToUInt16($bytes,[int]$pe+6)
        [UInt64]$optionalSize = [BitConverter]::ToUInt16($bytes,[int]$pe+20)
        $characteristics = [BitConverter]::ToUInt16($bytes,[int]$pe+22)
        if ($sections -lt 1 -or $sections -gt 96 -or ($characteristics -band 2) -eq 0 -or ($characteristics -band 0x2000) -ne 0) { throw 'Native helper executable COFF header invalid' }
        [UInt64]$optional = $pe+24
        [UInt64]$table = $optional+$optionalSize
        if ($optionalSize -lt 112 -or $optionalSize -gt 4096 -or $table+$sections*40 -gt $bytes.Length) { throw 'Native helper optional or section header truncated' }
        if ([BitConverter]::ToUInt16($bytes,[int]$optional) -ne 0x20b) { throw 'Native helper must be a PE32+ image' }
        [UInt64]$entry = [BitConverter]::ToUInt32($bytes,[int]$optional+16)
        [UInt64]$sectionAlignment = [BitConverter]::ToUInt32($bytes,[int]$optional+32)
        [UInt64]$fileAlignment = [BitConverter]::ToUInt32($bytes,[int]$optional+36)
        [UInt64]$imageSize = [BitConverter]::ToUInt32($bytes,[int]$optional+56)
        [UInt64]$headers = [BitConverter]::ToUInt32($bytes,[int]$optional+60)
        [UInt64]$directories = [BitConverter]::ToUInt32($bytes,[int]$optional+108)
        if ($directories -gt 16 -or 112+$directories*8 -gt $optionalSize) { throw 'Native helper data directory header invalid' }
        if ($fileAlignment -lt 512 -or $fileAlignment -gt 65536 -or ($fileAlignment -band ($fileAlignment-1)) -ne 0 -or $sectionAlignment -lt $fileAlignment -or ($sectionAlignment -band ($sectionAlignment-1)) -ne 0) { throw 'Native helper image alignment invalid' }
        if ($headers -lt $table+$sections*40 -or $headers -gt $bytes.Length -or $headers % $fileAlignment -ne 0 -or $imageSize -eq 0 -or $imageSize % $sectionAlignment -ne 0 -or $entry -eq 0 -or $entry -ge $imageSize) { throw 'Native helper image/header/entry bounds invalid' }
        $ranges = @()
        $entryBacked = $false
        for ($index=0; $index -lt $sections; $index++) {
            [int]$offset = [int]($table+$index*40)
            [UInt64]$virtualSize = [BitConverter]::ToUInt32($bytes,$offset+8)
            [UInt64]$address = [BitConverter]::ToUInt32($bytes,$offset+12)
            [UInt64]$rawSize = [BitConverter]::ToUInt32($bytes,$offset+16)
            [UInt64]$raw = [BitConverter]::ToUInt32($bytes,$offset+20)
            [UInt64]$flags = [BitConverter]::ToUInt32($bytes,$offset+36)
            [UInt64]$span = [Math]::Max($virtualSize,$rawSize)
            if ($address % $sectionAlignment -ne 0 -or $address -lt $headers -or $address+$span -gt $imageSize) { throw 'Native helper virtual section bounds invalid' }
            if ($rawSize -gt 0 -and ($raw -lt $headers -or $raw % $fileAlignment -ne 0 -or $rawSize % $fileAlignment -ne 0 -or $raw+$rawSize -gt $bytes.Length)) { throw 'Native helper raw section bounds invalid' }
            foreach ($prior in $ranges) {
                if ($rawSize -gt 0 -and $prior.rawSize -gt 0 -and $raw -lt $prior.raw+$prior.rawSize -and $prior.raw -lt $raw+$rawSize) { throw 'Native helper overlapping raw sections' }
                if ($span -gt 0 -and $prior.span -gt 0 -and $address -lt $prior.address+$prior.span -and $prior.address -lt $address+$span) { throw 'Native helper overlapping virtual sections' }
            }
            if ($entry -ge $address -and $entry -lt $address+$span -and $entry-$address -lt $rawSize -and ($flags -band 0x20000000) -ne 0 -and ($flags -band 0x20) -ne 0) { $entryBacked=$true }
            $ranges += @{raw=$raw;rawSize=$rawSize;address=$address;span=$span}
        }
        if (!$entryBacked) { throw 'Native helper entry point is not file-backed executable code' }
    } finally { if ($stream) { $stream.Dispose() } }
}

function Assert-WindowsPackageHelpers {
    param(
        [Parameter(Mandatory)][string]$PackageDirectory,
        [Parameter(Mandatory)][ValidateSet('AMD64','ARM64')][string]$Architecture
    )
    $tag = $Architecture.ToLowerInvariant()
    foreach ($name in @("tokentimer-agent-host-$tag.exe","tokentimer-adcs-chain-$tag.exe")) {
        Assert-WindowsPeImage -LiteralPath (Join-Path $PackageDirectory "bin\$name") -Architecture $Architecture
    }
}

function Get-PackageDirectoryIdentity {
    param([Parameter(Mandatory)][string]$Directory)
    if (-not [IO.Path]::IsPathRooted($Directory)) { throw 'Package directory identity requires an absolute path' }
    $item = Get-Item -LiteralPath $Directory -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Refusing nonregular package directory identity' }
    $ancestor = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Directory))
    while ($ancestor) {
        $parentItem = Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop
        if (($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Refusing linked package directory ancestor' }
        $next = [IO.Path]::GetDirectoryName($ancestor)
        if (!$next -or $next -eq $ancestor) { break }
        $ancestor = $next
    }
    $prior = [Environment]::GetEnvironmentVariable('TOKENTIMER_INSTALLER_STAGE_ID_PATH','Process')
    $priorNodeOptions = [Environment]::GetEnvironmentVariable('NODE_OPTIONS','Process')
    $priorNodePath = [Environment]::GetEnvironmentVariable('NODE_PATH','Process')
    try {
        $env:TOKENTIMER_INSTALLER_STAGE_ID_PATH = $Directory
        # Do not allow inherited preload/module search settings into this identity probe.
        [Environment]::SetEnvironmentVariable('NODE_OPTIONS',$null,'Process')
        [Environment]::SetEnvironmentVariable('NODE_PATH',$null,'Process')
        # Built-in fs obtains the volume/file index, never package code. Passing
        # the literal path through an environment value avoids argv quoting.
        $identity = & $script:NodeExe -p '(()=>{const s=require(''fs'').statSync(process.env.TOKENTIMER_INSTALLER_STAGE_ID_PATH,{bigint:true});return s.dev.toString()+ '':'' + s.ino.toString()})()'
        if ($LASTEXITCODE -ne 0 -or [string]$identity -notmatch '^\d+:[1-9]\d*$') { throw 'Package directory file identity unavailable' }
        return ([string]$identity).Trim()
    } finally {
        [Environment]::SetEnvironmentVariable('TOKENTIMER_INSTALLER_STAGE_ID_PATH',$prior,'Process')
        [Environment]::SetEnvironmentVariable('NODE_OPTIONS',$priorNodeOptions,'Process')
        [Environment]::SetEnvironmentVariable('NODE_PATH',$priorNodePath,'Process')
    }
}

function Remove-OwnedPackageStaging {
    param([Parameter(Mandatory)][string]$Directory,[Parameter(Mandatory)][string]$ExpectedIdentity)
    if ((Get-PackageDirectoryIdentity -Directory $Directory) -ne $ExpectedIdentity) { throw 'Refusing replaced package staging directory' }
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push($Directory)
    while ($pending.Count) {
        foreach ($entry in Get-ChildItem -LiteralPath $pending.Pop() -Force -ErrorAction Stop) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Refusing linked package staging content' }
            if ($entry.PSIsContainer) { $pending.Push($entry.FullName) }
        }
    }
    Remove-Item -LiteralPath $Directory -Recurse -Force -ErrorAction Stop
}

# ------------------------------------------------------------ install files
# Staged, atomic-swap install: copy into a fresh staging dir next to the app
# dir, then swap it into place. A failed copy can never leave a half-written
# app dir behind, and a running service keeps its old files until the swap
# (a subsequent service restart picks up the new tree). Mirrors
# install-agent.sh's tar-pipe staging, using a plain recursive copy instead
# of tar (not reliably present on Windows) that excludes node_modules and
# .git the same way the tar pipe's --exclude does.
function Copy-PackageTree {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    $excludedDirNames = @("node_modules", ".git")
    # Validate the whole candidate and any existing destination before creating
    # or copying a single destination entry. A later activation guard cannot
    # undo a staging copy that already followed a source/destination junction.
    # Literal paths also keep brackets and other valid filename characters
    # from becoming wildcard selectors during this safety preflight.
    function Get-UnlinkedCopyItem {
        param([string]$LiteralPath)
        $item = $null
        try { $item = Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop }
        catch [System.Management.Automation.ItemNotFoundException] { return $null }
        if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'refusing linked package copy paths'
        }
        return $item
    }
    function Assert-UnlinkedCopyAncestors {
        param([string]$LiteralPath)
        if (-not [IO.Path]::IsPathRooted($LiteralPath)) { throw 'refusing relative package copy paths' }
        $current = [IO.Path]::GetFullPath($LiteralPath)
        while ($current) {
            $null = Get-UnlinkedCopyItem -LiteralPath $current
            $parent = [IO.Path]::GetDirectoryName($current)
            if (!$parent -or $parent.Equals($current,[StringComparison]::OrdinalIgnoreCase)) { break }
            $current = $parent
        }
    }
    function Assert-UnlinkedCopyTree {
        param([string]$LiteralPath,[bool]$Required,[bool]$SkipExcluded = $false)
        $item = Get-UnlinkedCopyItem -LiteralPath $LiteralPath
        if (!$item) { if ($Required) { throw 'required package source directory is missing' }; return }
        if (!$item.PSIsContainer) { throw 'refusing non-directory package copy root' }
        foreach ($entry in Get-ChildItem -LiteralPath $LiteralPath -Force -ErrorAction Stop) {
            if ($SkipExcluded -and $entry.PSIsContainer -and $excludedDirNames -contains $entry.Name) { continue }
            $null = Get-UnlinkedCopyItem -LiteralPath $entry.FullName
            if ($entry.PSIsContainer) { Assert-UnlinkedCopyTree -LiteralPath $entry.FullName -Required $true -SkipExcluded $SkipExcluded }
        }
    }
    Assert-UnlinkedCopyAncestors -LiteralPath $Source
    Assert-UnlinkedCopyAncestors -LiteralPath $Destination
    Assert-UnlinkedCopyTree -LiteralPath $Source -Required $true -SkipExcluded $true
    Assert-UnlinkedCopyTree -LiteralPath $Destination -Required $false
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Get-ChildItem -LiteralPath $Source -Force | ForEach-Object {
        if ($_.PSIsContainer) {
            if ($excludedDirNames -contains $_.Name) { return }
            Copy-PackageTree -Source $_.FullName -Destination (Join-Path $Destination $_.Name)
        } else {
            Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $Destination $_.Name) -Force
        }
    }
}

# Both directory renames belong to the same recovery boundary. In particular,
# a sharing violation on the still-running predecessor must remove the copied
# staging tree without changing the predecessor or restarting its service.
function Activate-StagedPackage {
    param(
        [Parameter(Mandatory = $true)][string]$AppDirectory,
        [Parameter(Mandatory = $true)][string]$StagingDirectory,
        [Parameter(Mandatory = $true)][string]$PreviousDirectory,
        [string]$ExpectedStagingIdentity = ""
    )
    $ErrorActionPreference = 'Stop'
    $appPath = [IO.Path]::GetFullPath($AppDirectory).TrimEnd('\')
    $stagingPath = [IO.Path]::GetFullPath($StagingDirectory).TrimEnd('\')
    $previousPath = [IO.Path]::GetFullPath($PreviousDirectory).TrimEnd('\')
    if (-not [IO.Path]::IsPathRooted($AppDirectory) -or
        -not $stagingPath.Equals("$appPath.staging.$PID", [StringComparison]::OrdinalIgnoreCase) -or
        -not $previousPath.Equals("$appPath.previous.$PID", [StringComparison]::OrdinalIgnoreCase)) {
        throw 'refusing unexpected package swap paths'
    }
    foreach ($targetPath in @([IO.Path]::GetDirectoryName($appPath), $appPath, $stagingPath, $previousPath)) {
        $item = Get-Item -LiteralPath $targetPath -Force -ErrorAction SilentlyContinue
        if ($item -and (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or -not $item.PSIsContainer)) {
            throw 'refusing linked or non-directory package swap targets'
        }
    }
    if (Test-Path -LiteralPath $PreviousDirectory) { throw 'refusing an existing package recovery directory' }
    if ($ExpectedStagingIdentity -and (Get-PackageDirectoryIdentity -Directory $StagingDirectory) -ne $ExpectedStagingIdentity) { throw 'refusing replaced package staging before activation' }
    $previousMoved = $false
    try {
        if (Test-Path -LiteralPath $AppDirectory) {
            Rename-Item -LiteralPath $AppDirectory -NewName (Split-Path -Leaf $PreviousDirectory) -ErrorAction Stop
            $previousMoved = $true
        }
        Rename-Item -LiteralPath $StagingDirectory -NewName (Split-Path -Leaf $AppDirectory) -ErrorAction Stop
    } catch {
        $activationError = $_.Exception.Message
        $recoveryErrors = @()
        if ($previousMoved) {
            try { Rename-Item -LiteralPath $PreviousDirectory -NewName (Split-Path -Leaf $AppDirectory) -ErrorAction Stop }
            catch { $recoveryErrors += 'previous installation restoration failed' }
        }
        try {
            $stagedItem = Get-Item -LiteralPath $StagingDirectory -Force -ErrorAction SilentlyContinue
            if ($stagedItem) {
                if (($stagedItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or -not $stagedItem.PSIsContainer) { throw 'staging ownership changed' }
                if ($ExpectedStagingIdentity) { Remove-OwnedPackageStaging -Directory $StagingDirectory -ExpectedIdentity $ExpectedStagingIdentity }
                else { Remove-Item -LiteralPath $StagingDirectory -Recurse -Force -ErrorAction Stop }
            }
        } catch { $recoveryErrors += 'staging cleanup failed' }
        if ($recoveryErrors.Count) {
            throw "failed to activate the staged agent package; recovery incomplete ($($recoveryErrors -join '; ')); $activationError"
        }
        $previousOutcome = if ($previousMoved) { 'restored' } else { 'preserved' }
        throw "failed to activate the staged agent package; the previous install was $previousOutcome ($activationError)"
    }
}

if (-not $script:DryRun) {
    try { Assert-WindowsPackageHelpers -PackageDirectory $PackageDir -Architecture $arch }
    catch { Fail "native package preflight failed before installation changes ($($_.Exception.Message))" }
}

if (-not $script:DryRun) { Assert-WindowsServiceCaSnapshot -Name $ServiceName -Expected $script:PreviousServiceConfiguration }
Write-Log "Installing agent package from $PackageDir to $AppDir"
if (-not $script:DryRun) {
    New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
}

$script:AppStaging = "$AppDir.staging.$PID"
$script:AppPrevious = "$AppDir.previous.$PID"
$script:IsUpgrade = (Test-Path -LiteralPath $AppDir)

if ($script:DryRun) {
    Write-Host "[dry-run] copy $PackageDir into $($script:AppStaging) (excluding node_modules, .git), then atomically swap into $AppDir"
} else {
    if (Test-Path -LiteralPath $script:AppStaging) { Fail 'refusing an existing package staging directory' }
    New-Item -ItemType Directory -Path $script:AppStaging -ErrorAction Stop | Out-Null
    $stagingIdentity = Get-PackageDirectoryIdentity -Directory $script:AppStaging
    try {
        Copy-PackageTree -Source $PackageDir -Destination $script:AppStaging
        Assert-WindowsPackageHelpers -PackageDirectory $script:AppStaging -Architecture $arch
    } catch {
        $stagingError = $_.Exception.Message
        try {
            Remove-OwnedPackageStaging -Directory $script:AppStaging -ExpectedIdentity $stagingIdentity
        } catch {
            Fail "failed to stage the agent package; staging cleanup refused; preserve $($script:AppStaging) for inspection; $AppDir was left untouched ($stagingError)"
        }
        Fail "failed to stage the agent package; $AppDir was left untouched ($stagingError)"
    }
    try {
        Assert-WindowsServiceCaSnapshot -Name $ServiceName -Expected $script:PreviousServiceConfiguration
        Activate-StagedPackage -AppDirectory $AppDir -StagingDirectory $script:AppStaging -PreviousDirectory $script:AppPrevious -ExpectedStagingIdentity $stagingIdentity
    } catch {
        Fail $_.Exception.Message
    }
}

if (-not $script:DryRun) {
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
}
Invoke-Step "apply restricted ACL to $StateDir" { Invoke-PlatformAcl -TargetPath $StateDir -Kind "directory" }

# ---------------------------------------------- acme.sh dnsapi hook (Windows)
# install-agent.sh symlinks bin/dns_certops.sh into
# <stateDir>/acme/acme.sh/dnsapi/ so acme.sh's `--dns dns_certops` resolves
# it by name; this installer had no equivalent, so `acmeKind: "acme.sh"`
# jobs failed at the DNS-01 step on every Windows install with "dns_certops
# not found" (found 2026-08-05 during the first real acme.sh run on Windows,
# via Git Bash - see docs/certops/agent.md's Windows hook note). A plain
# copy is used instead of a symlink: creating symlinks needs
# SeCreateSymbolicLinkPrivilege, which is not guaranteed even for an
# elevated installer session, while a copy has no such dependency and
# dns_certops.sh does not change independently of the package it ships in.
$AcmeShDnsApiDir = Join-Path $StateDir "acme\acme.sh\dnsapi"
$DnsCertopsSrc = Join-Path $PackageDir "bin\dns_certops.sh"
Invoke-Step "install acme.sh dnsapi\dns_certops.sh hook" {
    New-Item -ItemType Directory -Force -Path $AcmeShDnsApiDir | Out-Null
    if (Test-Path -LiteralPath $DnsCertopsSrc) {
        Copy-Item -LiteralPath $DnsCertopsSrc -Destination (Join-Path $AcmeShDnsApiDir "dns_certops.sh") -Force
    } else {
        Write-Log "WARNING: $DnsCertopsSrc not found; acme.sh --dns dns_certops will fail until the package includes bin\dns_certops.sh"
    }
}

# ------------------------------------------------------- config.json
# Fields consumed by the agent's config loader (src/config/index.js):
# serverUrl (required) and caBundlePath (optional). workspaceId is recorded
# for operators; the loader ignores unknown fields and the bootstrap token
# is already workspace-scoped server-side. agentId and the credential are
# written by the agent itself at first-run registration.
$configPath = Join-Path $StateDir "config.json"
$caBundleDest = ""
if (-not [string]::IsNullOrEmpty($script:CaBundle)) {
    $caBundleDest = Join-Path $StateDir "ca-bundle.pem"
    Invoke-Step "copy $($script:CaBundle) to $caBundleDest" { Copy-Item -LiteralPath $script:CaBundle -Destination $caBundleDest -Force }
}

if ((Test-Path -LiteralPath $configPath) -and -not $script:DryRun) {
    Write-Log "Existing $configPath found; leaving it untouched (delete it to re-generate)."
} elseif ($script:DryRun) {
    $caNote = if ($caBundleDest) { " caBundlePath=$caBundleDest" } else { "" }
    Write-Host "[dry-run] write $configPath with serverUrl=$($script:ApiUrl) workspaceId=$($script:WorkspaceId)$caNote"
} else {
    # Values were charset-validated above (no quotes/backslashes/control
    # chars), so plain interpolation cannot produce malformed JSON. Written
    # to a temp file first and renamed so a crash never leaves a torn file.
    $configTmp = "$configPath.tmp.$PID"
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("{")
    $lines.Add("  `"serverUrl`": `"$($script:ApiUrl)`",")
    $lines.Add("  `"workspaceId`": `"$($script:WorkspaceId)`",")
    if ($caBundleDest) {
        $caBundleDestJson = $caBundleDest.Replace('\', '\\')
        $lines.Add("  `"caBundlePath`": `"$caBundleDestJson`",")
    }
    if ($script:AllowInsecureLocalHttp) {
        $lines.Add("  `"allowInsecureLocalHttp`": true,")
    }
    $lines.Add('  "observedRevocation": { "enabled": true, "allowedOrigins": [] }')
    $lines.Add("}")
    $configContent = ($lines -join "`n") + "`n"
    [System.IO.File]::WriteAllText($configTmp, $configContent, (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -Force $configTmp $configPath
    Invoke-PlatformAcl -TargetPath $configPath -Kind "file"
    # Sanity-parse the result with the node we already verified, so a bad
    # value can never install an unreadable config.
    Invoke-InstallerNode -NodeArguments @('-e', "JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'))", $configPath)
    if ($LASTEXITCODE -ne 0) {
        Fail "generated $configPath is not valid JSON (unexpected characters in --api-url/--workspace-id?)"
    }
}

# --------------------------------------- bootstrap token env file
# Written for parity with install-agent.sh (documentation, and a manual/dev
# run: "node bin\tokentimer-agent.js" with $env:TOKENTIMER_AGENT_CONFIG_DIR
# set picks this up via a .env-style file only if the operator loads it
# themselves; unlike systemd's EnvironmentFile, Windows has no service-level
# equivalent). The single-use ttboot_ token is never printed by this script.
# The agent deletes bootstrap.env itself right after a successful
# registration. The service itself gets the token via its own registry
# Environment value, set below.
$bootstrapEnvPath = Join-Path $StateDir "bootstrap.env"
if ($script:DryRun) {
    Write-Host "[dry-run] write $bootstrapEnvPath with TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=<redacted>"
} else {
    $bootstrapEnvTmp = "$bootstrapEnvPath.tmp.$PID"
    [System.IO.File]::WriteAllText(
        $bootstrapEnvTmp,
        "TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=$($script:BootstrapToken)`n",
        (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -Force $bootstrapEnvTmp $bootstrapEnvPath
    Invoke-PlatformAcl -TargetPath $bootstrapEnvPath -Kind "file"
}

# ------------------------------------------------------------- Windows service
# Native tooling only (sc.exe): no NSSM or other third-party service
# wrapper. LocalSystem per ADR-0012 decision 11.
function Set-ServiceEnvironment {
    param([string]$ConfigDir, [string]$Token)
    $existing = @($script:PreviousServiceConfiguration.Environment.Values)
    if (-not @($existing | Where-Object { $_ -match '^(?i:NODE_USE_SYSTEM_CA)=' }).Count) {
        $existing += @($script:PreviousServiceConfiguration.MachineCaEnvironment | Where-Object { $_ -match '^(?i:NODE_USE_SYSTEM_CA)=' })
    }
    $values = @(Get-WindowsServiceEnvironmentValues -Existing $existing -ConfigDir $ConfigDir -Token $Token)
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name Environment -PropertyType MultiString -Value $values -Force | Out-Null
}

function Test-ServiceHealthy {
    param([int]$TimeoutSeconds = 20)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') { return $true }
        if ($svc -and $svc.Status -eq 'Stopped') { return $false }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

# Reconfigures an existing service's binPath/DisplayName/StartupType via
# Win32_Service.Change (WMI), which -- like New-Service above -- calls
# ChangeServiceConfig directly with no command-line tokenizer in between.
# `sc.exe config` cannot be used here for the same reason `sc.exe create`
# cannot be used above: see the binPath-construction comment below this
# function for the live repro.
function Set-ServiceBinaryPath {
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $true)][string]$BinPath,
        [Parameter(Mandatory = $true)][string]$DisplayName
    )
    $wmiService = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'"
    if (-not $wmiService) { Fail "service $ServiceName not found via Win32_Service for reconfiguration" }
    $changeResult = Invoke-CimMethod -InputObject $wmiService -MethodName Change -Arguments @{
        PathName    = $BinPath
        DisplayName = $DisplayName
        StartMode   = "Automatic"
    }
    if ($changeResult.ReturnValue -ne 0) {
        Fail "Win32_Service.Change failed to update $ServiceName (ReturnValue $($changeResult.ReturnValue))"
    }
}


# The service's binPath is the native host, not node.exe: node never calls
# StartServiceCtrlDispatcher, so the SCM would otherwise fail the start
# after 30s (error 1053) and, combined with the failure/restart policy
# below, loop forever. The host answers the SCM directly and runs
# node.exe + the agent entry point as its child (see windows-service-host/
# and the header comment above). $arch (AMD64/ARM64, validated above)
# selects which of the two binaries this OS can execute.
$hostArchTag = $arch.ToLowerInvariant()
$serviceHostExe = Join-Path $AppDir "bin\tokentimer-agent-host-$hostArchTag.exe"
if (-not $script:DryRun -and -not (Test-Path -LiteralPath $serviceHostExe)) {
    Fail (
        "service host binary not found at $serviceHostExe; the staged app dir looks incomplete " +
        "or was not built with 'pnpm run build:windows-service-host' before packaging"
    )
}
$binPath = Get-WindowsServiceBinPath -AppDirectory $AppDir -NodeExecutable $script:NodeExe -Architecture $arch -CaOptions $script:NodeCaOptions

# sc.exe's binPath= value here is three separately-quoted path segments
# (host exe, node.exe, entry script). An earlier fix wrapped the whole
# three-segment value in one more outer pair of quotes with the inner
# quotes doubled (sc.exe's own escaping convention), which survives
# PowerShell's native-argument passing and round-trips through `sc qc`
# when every path segment is itself space-free. It does NOT survive
# sc.exe's own command-line tokenizer once any inner segment contains a
# space, e.g. Node's default install path `C:\Program Files\nodejs\node.exe`:
# live-repro'd on Windows Server 2019 build 17763 (exit 1639, invalid
# command line) with the doubled-quote value reaching sc.exe byte-for-byte
# unmodified even via a cmd.exe /c script file, proving the tokenizer
# itself, not any shell's re-quoting, rejects it. sc.exe's binPath=
# argument parsing cannot be made to carry an embedded space reliably no
# matter how it is escaped going in. New-Service/Win32_Service.Change call
# CreateService/ChangeServiceConfig directly with no command-line tokenizer
# in between, so $binPath's embedded spaces and quoted segments survive
# unmodified; both are used below instead of `sc.exe create`/`sc.exe config`
# for this reason. $binPath itself (unescaped) is what both now take
# directly, and is also used verbatim for -DryRun/log output.

if ($script:DryRun) {
    Write-Host "[dry-run] sc.exe create/config $ServiceName binPath= $binPath start= auto obj= LocalSystem"
    Write-Host "[dry-run] sc.exe failure $ServiceName reset= 86400 actions= restart/5000"
    Write-Host "[dry-run] set HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName\Environment"
    Write-Host "[dry-run] preserve existing Windows Error Reporting policy"
    Write-Host "[dry-run] (re)start $ServiceName and health-check it"
    Write-Log ""
    Write-Log "Dry run complete. No changes were made."
    exit 0
}

# Preserve operator WER policy. Microsoft's LocalDumps DumpType=0 selects a
# custom dump and may enable collection; it does not disable dumps. Do not
# rewrite the machine-wide node.exe policy or infer containment from a registry
# value. Native crash containment remains a separate qualification requirement.

Assert-WindowsServiceCaSnapshot -Name $ServiceName -Expected $script:PreviousServiceConfiguration
$serviceExisted = [bool](Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)
if (-not $serviceExisted) {
    New-Service -Name $ServiceName -BinaryPathName $binPath -DisplayName $ServiceDisplayName `
        -StartupType Automatic -ErrorAction Stop | Out-Null
} else {
    Set-ServiceBinaryPath -ServiceName $ServiceName -BinPath $binPath -DisplayName $ServiceDisplayName
}
& sc.exe failureflag $ServiceName 1 | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/5000 | Out-Null

Set-ServiceEnvironment -ConfigDir $StateDir -Token $script:BootstrapToken

# restart, not start-if-stopped-only: on a re-run (upgrade) the service is
# usually already running, and Start-Service is a no-op there, so the
# freshly swapped app dir would keep being ignored while the old process
# ran on. Restarting also starts a stopped/fresh service, so it is the
# correct verb for both the install and the upgrade path (mirrors
# install-agent.sh's use of `systemctl restart` for the same reason).
$currentStatus = (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue).Status
# A build broken badly enough that the
# service host can't even reach a running state (not merely "started but
# unhealthy") makes Restart-Service/Start-Service themselves raise a
# terminating error under this script's script-wide $ErrorActionPreference
# = "Stop" -- live-repro'd on a real Windows Server host with a sabotaged
# entry point: the uncaught exception killed the script before Line 766's
# health check ever ran, so the rollback below never executed and the host
# was left with a Stopped service running the broken build. The fix routes
# every restart-time failure through the same Test-ServiceHealthy() gate
# below instead of a second, divergent failure path: swallow the error here
# (logged, not silent) and let the unhealthy Stopped/Running state that
# Test-ServiceHealthy already understands decide whether to roll back.
try {
    if ($currentStatus -eq 'Running') {
        Restart-Service -Name $ServiceName -Force -ErrorAction Stop
    } else {
        Start-Service -Name $ServiceName -ErrorAction Stop
    }
} catch {
    Write-Log "failed to (re)start ${ServiceName}: $($_.Exception.Message)"
}

$healthy = Test-ServiceHealthy -TimeoutSeconds 20

if (-not $healthy -and $script:IsUpgrade -and (Test-Path -LiteralPath $script:AppPrevious)) {
    Write-Log "Health check failed after upgrade; rolling back to the previous version."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $AppDir -Recurse -Force
    Rename-Item -LiteralPath $script:AppPrevious -NewName (Split-Path -Leaf $AppDir)
    try { Restore-WindowsServiceConfiguration -Name $ServiceName -Snapshot $script:PreviousServiceConfiguration }
    catch { Fail "rollback requires service reconciliation; preserve the restored application and state ($($_.Exception.Message))" }
    Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
    # The credential file's ACL must be re-asserted after rollback, not
    # inherited from whatever the failed install left behind.
    $credentialPath = Join-Path $StateDir "credential"
    if (Test-Path -LiteralPath $credentialPath) {
        Invoke-PlatformAcl -TargetPath $credentialPath -Kind "file"
    }
    Fail "upgrade failed its post-install health check and was rolled back to the previous version; the agent credential and configuration were preserved and the credential file's ACL was re-asserted"
}

if (Test-Path -LiteralPath $script:AppPrevious) { Remove-Item -LiteralPath $script:AppPrevious -Recurse -Force }

if (-not $healthy) {
    Fail "the $ServiceName service did not reach the Running state within 20 seconds; check 'Get-Service $ServiceName' and the agent's own logs"
}

Write-Log ""
Write-Log "Install complete. Existing Windows Error Reporting policy was preserved."
Write-Log "Windows crash-dump containment is not qualified."
Write-Log "Next steps:"
Write-Log "  1. Check the service:      Get-Service $ServiceName"
Write-Log "  2. Confirm registration in the dashboard (CertOps > Agent fleet):"
Write-Log "     the agent should appear as active within about a minute."
Write-Log "     (The agent deletes the single-use $bootstrapEnvPath itself after"
Write-Log "     registering; no manual cleanup is needed.)"
Write-Log "  3. Configure agent-local policy and discovery in $configPath"
Write-Log "     (allowlists are default-deny until you set them), then:"
Write-Log "     Restart-Service $ServiceName"
Write-Log "  4. Trust-store: LocalSystem already has LocalMachine\Root and"
Write-Log "     LocalMachine\CA on Windows Server 2016+ (verified 2019/2022/2025)."
if ($script:NoTrustStore) {
    Write-Log "     --no-trust-store has no effect; the service still runs as LocalSystem."
}
if ($script:WritePaths.Count -gt 0) {
    Write-Log "  5. Ensure the LocalSystem service account can write the configured cert paths:"
    foreach ($writePath in $script:WritePaths) {
        Write-Log "       $writePath"
    }
    Write-Log "     (LocalSystem already has ambient access; this is a reminder to set"
    Write-Log "     config.json's own write-path allowlist, not an OS-level grant.)"
}
if ($script:ReloadServices.Count -gt 0) {
    Write-Log "  6. Reload authorization is enforced by agent-local policy on Windows"
    Write-Log "     (no polkit/sudoers equivalent needed): configure policy"
    Write-Log "     commandProfiles.reloadArgv for: $($script:ReloadServices -join ', ')"
}
exit 0

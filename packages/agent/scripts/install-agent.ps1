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
$script:NodeRuntimeLock = $null
$script:AuthorizedLauncherTransaction = $null
# The release packer changes this constant only in Windows-specific archives.
$script:RequiresBundledRuntime = $false

function Write-Log {
    param([string]$Message)
    Write-Host "install-agent: $Message"
}

function Fail {
    param([string]$Message)
    if ($null -ne $script:NodeRuntimeLock) {
        $script:NodeRuntimeLock.Dispose()
        $script:NodeRuntimeLock = $null
    }
    [Console]::Error.WriteLine("install-agent: ERROR: $Message")
    exit 1
}

# Bundled packages may be used only after authenticated extraction to a
# location which unprivileged users cannot replace or modify.
function Assert-ProtectedBundleTree {
    param([Parameter(Mandatory)][string]$Root)
    $trustedOwners = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $trustedWriters = $trustedOwners
    # Setting a reparse point can require FILE_WRITE_DATA or
    # FILE_WRITE_ATTRIBUTES. Reject these rights on ancestors as well as
    # delete/ACL ownership rights and generic write/all.
    $ancestorMask = [int64]0x500D0142
    $payloadMask = [int64]0x500D0156
    function Assert-ProtectedItem([string]$Path, [bool]$AncestorOnly) {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'bundle path contains a reparse point' }
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin $trustedOwners) { throw 'bundle path has an untrusted owner' }
        $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
        if (-not $rules.Count) { throw 'bundle path has an empty or unreadable DACL' }
        $mask = if ($AncestorOnly) { $ancestorMask } else { $payloadMask }
        foreach ($rule in $rules) {
            if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
                ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
            if ($rule.IdentityReference.Value -notin $trustedWriters -and
                (([int64]$rule.FileSystemRights -band $mask) -ne 0)) {
                throw 'bundle path permits an untrusted principal to modify or replace it'
            }
        }
    }
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $parents = New-Object 'System.Collections.Generic.Stack[string]'
    $cursor = $rootPath
    while ($cursor) {
        $parents.Push($cursor)
        $next = [IO.Path]::GetDirectoryName($cursor)
        if (!$next -or $next -eq $cursor) { break }
        $cursor = $next
    }
    while ($parents.Count) {
        $path = $parents.Pop()
        Assert-ProtectedItem $path (-not $path.Equals($rootPath, [StringComparison]::OrdinalIgnoreCase))
    }
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push($rootPath)
    while ($pending.Count) {
        foreach ($entry in Get-ChildItem -LiteralPath $pending.Pop() -Force -ErrorAction Stop) {
            Assert-ProtectedItem $entry.FullName $false
            if ($entry.PSIsContainer) { $pending.Push($entry.FullName) }
        }
    }
}

# Do not allow the caller's Node preload/module-path settings to run code
# inside the elevated installer or its local validation helpers.
function Invoke-PackagedNode {
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

# Cooperating installers and launchers serialize creation of a protected
# execution intent with upgrade recovery. Earlier installers do not honor this
# lock; they must not run concurrently with a verified launcher.
function Enter-AgentInstallLock {
    $trusted = @('S-1-5-18', 'S-1-5-32-544')
    $security = New-Object System.Security.AccessControl.MutexSecurity
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in $trusted) {
        $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object System.Security.AccessControl.MutexAccessRule($identity, 'FullControl', 'Allow')
        $security.AddAccessRule($rule)
    }
    $created = $false
    $mutex = New-Object System.Threading.Mutex($false, 'Global\TokenTimer.Agent.Install.v1', [ref]$created, $security)
    try {
        $actual = $mutex.GetAccessControl()
        $owner = $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin $trusted -or -not $actual.AreAccessRulesProtected) { throw 'untrusted installation lock owner or ACL' }
        $rules = @($actual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
        if (-not $rules.Count) { throw 'installation lock has no access rules' }
        foreach ($rule in $rules) {
            if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $rule.IdentityReference.Value -notin $trusted) {
                throw 'installation lock grants untrusted access'
            }
        }
        try { $acquired = $mutex.WaitOne([TimeSpan]::FromSeconds(60)) }
        catch [Threading.AbandonedMutexException] { $acquired = $true }
        if (-not $acquired) { throw 'another installer or launcher owns the installation lock' }
        return $mutex
    } catch {
        $mutex.Dispose()
        throw
    }
}

function Assert-ProtectedIntentDirectory {
    param([Parameter(Mandatory)][string]$Directory)
    $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $cursor = [IO.Path]::GetFullPath($Directory).TrimEnd('\')
    $first = $true
    while ($cursor) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'intent directory is not a trusted directory' }
        $acl = Get-Acl -LiteralPath $cursor -ErrorAction Stop
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { throw 'untrusted intent directory owner' }
        $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
        if (-not $rules.Count) { throw 'intent directory ACL unavailable' }
        $mask = if ($first) { [int64]0x500D0156 } else { [int64]0x500D0142 }
        foreach ($rule in $rules) {
            if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and
                $rule.IdentityReference.Value -notin $trusted -and (([int64]$rule.FileSystemRights -band $mask) -ne 0)) {
                throw 'intent directory permits untrusted modification'
            }
        }
        $first = $false
        $next = [IO.Path]::GetDirectoryName($cursor)
        if (-not $next -or $next -eq $cursor) { break }
        $cursor = $next
    }
}

function Assert-NoQuarantinedLauncherIntent {
    param([Parameter(Mandatory)][string]$LauncherParent)
    $intents = @(Get-ChildItem -LiteralPath $LauncherParent -Filter 'TokenTimer-Staging-*.intent' -Force -ErrorAction Stop)
    if ($intents.Count -gt 0) { throw 'recovery_required: a launcher execution remains quarantined' }
}

if (-not $script:DryRun) {
    if (-not (Test-IsAdministrator)) { Fail 'installation or uninstall requires an elevated PowerShell session' }
    try { $script:AgentInstallMutex = Enter-AgentInstallLock }
    catch { Fail "cannot acquire trusted installation lock ($($_.Exception.Message))" }
}

# -------------------------------------------------------------- uninstall
if ($script:Uninstall) {
    if (-not $script:DryRun -and -not (Test-IsAdministrator)) {
        Fail "uninstall must run from an elevated (Administrator) PowerShell session"
    }
    if (-not $script:DryRun) {
        try {
            if (-not [Environment]::Is64BitProcess) { throw 'native 64-bit PowerShell is required' }
            $launcherParent = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
            Assert-ProtectedIntentDirectory -Directory $launcherParent
            Assert-NoQuarantinedLauncherIntent -LauncherParent $launcherParent
        } catch { Fail "recovery_required: launcher execution remains quarantined ($($_.Exception.Message))" }
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
$runtimeManifestPath = Join-Path $PackageDir "runtime\manifest.json"
$runtimeArch = $arch.ToLowerInvariant()
$runtimeManifest = $null
try {
    Import-Module ([IO.Path]::Combine($PSHOME, 'Modules', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Utility.psd1')) -NoClobber -ErrorAction Stop
    $package = Get-Content -LiteralPath (Join-Path $PackageDir "package.json") -Raw | ConvertFrom-Json -ErrorAction Stop
    $runtimeMarker = $package.PSObject.Properties['windowsBundledRuntime']
    if ($runtimeMarker -and (($runtimeMarker.Value -isnot [bool]) -or (-not $runtimeMarker.Value))) { throw "invalid bundled runtime marker" }
    if ($script:RequiresBundledRuntime -and -not $runtimeMarker) { throw "Windows package bundled runtime marker is missing" }
    if (-not $script:RequiresBundledRuntime -and $runtimeMarker) { throw "generic package unexpectedly contains a bundled runtime marker" }
    $script:HasBundledRuntime = $null -ne $runtimeMarker
    if (-not $script:HasBundledRuntime) {
        if (Test-Path -LiteralPath (Join-Path $PackageDir "runtime")) { throw "runtime files exist without the bundled runtime marker" }
        $nodeCommand = Get-Command node -ErrorAction SilentlyContinue
        if (-not $nodeCommand) { throw "legacy generic package requires system Node on PATH" }
        $script:NodeExe = $nodeCommand.Source
        $script:InstalledNodeExe = $script:NodeExe
        Write-Log "Legacy generic package: using system Node. The Windows-specific package includes its own runtime."
    } else {
    Import-Module ([IO.Path]::Combine($PSHOME, 'Modules', 'Microsoft.PowerShell.Security', 'Microsoft.PowerShell.Security.psd1')) -NoClobber -ErrorAction Stop
    Assert-ProtectedBundleTree -Root $PackageDir
    if (-not (Test-Path -LiteralPath $runtimeManifestPath -PathType Leaf)) { throw "packaged Node runtime manifest is missing" }
    $runtimeManifest = Get-Content -LiteralPath $runtimeManifestPath -Raw | ConvertFrom-Json -ErrorAction Stop
    $expectedRuntimePath = "runtime/$runtimeArch/node.exe"
    if ($runtimeManifest.architecture -cne $runtimeArch -or
        $runtimeManifest.path -cne $expectedRuntimePath -or
        $runtimeManifest.version -notmatch '^\d+\.\d+\.\d+$' -or
        $runtimeManifest.sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "invalid runtime manifest"
    }
    $script:NodeExe = Join-Path $PackageDir ("runtime\$runtimeArch\node.exe")
    $script:InstalledNodeExe = Join-Path $AppDir ("runtime\$runtimeArch\node.exe")
    if (-not (Test-Path -LiteralPath $script:NodeExe -PathType Leaf)) { throw "packaged runtime is missing" }
    $pinnedHash = if ($runtimeArch -eq 'amd64') { '9a4eb5f1c29c6a2e93852ead46b999e284a6a5ca8bab4d4e241d587d025a52de' } else { 'c7225670c3f477778e18c43a55867f7a0d76468221245e5981ab80eb953c8102' }
    if ($runtimeManifest.version -cne '24.18.0' -or $runtimeManifest.sha256 -cne $pinnedHash) { throw "runtime manifest does not match the release pin" }
    $script:NodeRuntimeLock = [IO.File]::Open($script:NodeExe, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $runtimeHash = [BitConverter]::ToString($sha.ComputeHash($script:NodeRuntimeLock)).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
    if ($runtimeHash -cne $pinnedHash) {
        throw "packaged runtime checksum mismatch"
    }
    $runtimeStream = $script:NodeRuntimeLock
    $runtimeStream.Position = 0
    try {
        $runtimeReader = New-Object IO.BinaryReader($runtimeStream)
        if ($runtimeStream.Length -lt 64 -or $runtimeReader.ReadUInt16() -ne 0x5A4D) { throw "invalid runtime PE image" }
        $runtimeStream.Position = 0x3c
        $peOffset = $runtimeReader.ReadUInt32()
        if ($peOffset -gt ($runtimeStream.Length - 6)) { throw "invalid runtime PE header" }
        $runtimeStream.Position = $peOffset
        if ($runtimeReader.ReadUInt32() -ne 0x00004550) { throw "invalid runtime PE signature" }
        $machine = $runtimeReader.ReadUInt16()
        $expectedMachine = if ($runtimeArch -eq 'amd64') { 0x8664 } else { 0xaa64 }
        if ($machine -ne $expectedMachine) { throw "runtime architecture mismatch" }
    } finally { $runtimeStream.Position = 0 }
    }
    $engineRange = [regex]::Match([string]$package.engines.node, '^>=([0-9]+\.[0-9]+\.[0-9]+)\s+<([0-9]+\.[0-9]+\.[0-9]+)$')
    if (-not $engineRange.Success) { throw "unsupported Node engine range" }
    $nodeVersionRaw = (Invoke-PackagedNode -NodeArguments @('-v')).Trim()
    if ($LASTEXITCODE -ne 0 -or $nodeVersionRaw -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+$') { throw "unable to determine Node runtime version" }
    $runtimeVersion = [version]$nodeVersionRaw.Substring(1)
    if ($runtimeVersion -lt [version]$engineRange.Groups[1].Value -or $runtimeVersion -ge [version]$engineRange.Groups[2].Value) {
        throw "packaged runtime is outside the supported Node engine range"
    }
    if ($script:HasBundledRuntime -and $nodeVersionRaw -cne "v$($runtimeManifest.version)") {
        throw "packaged runtime version does not match its manifest"
    }
} catch {
    Fail "packaged Node runtime validation failed ($($_.Exception.Message))"
}
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
$normalizedApiUrl = Invoke-PackagedNode -NodeArguments (@($ValidateServerUrlJs) + $validateArgs) 2>$null
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
    Invoke-PackagedNode -NodeArguments @($HostSandboxJs, 'map-reload-service', $reloadService) | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "invalid --reload-service: $reloadService" }
    $validatedReloadServices.Add($reloadService)
}
$script:ReloadServices = $validatedReloadServices

if (-not $script:DryRun -and -not (Test-IsAdministrator)) {
    Fail "install must run from an elevated (Administrator) PowerShell session"
}

Write-Log "Packaged Node $nodeVersionRaw satisfies engines.node '$($package.engines.node)'."

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
        Invoke-PackagedNode -NodeArguments @($scriptPath)
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

# The recovery record lives in the protected state directory, never in the
# application directory being swapped. It identifies directories by their
# filesystem identity as well as their bounded, installer-generated names.
function Get-UpgradeRecoveryPath {
    return (Join-Path $StateDir "upgrade-recovery.json")
}

function Get-ServiceNodePath {
    param([Parameter(Mandatory)][string]$ServiceCommand)
    $parts = [regex]::Matches($ServiceCommand, '"([^"]+)"|([^\s"]+)')
    if ($parts.Count -ne 3) { throw 'previous service command is not a supported host, runtime and entrypoint command' }
    $node = if ($parts[1].Groups[1].Success) { $parts[1].Groups[1].Value } else { $parts[1].Groups[2].Value }
    if (-not [IO.Path]::IsPathRooted($node) -or [IO.Path]::GetFileName($node) -ine 'node.exe') {
        throw 'previous service runtime path is invalid'
    }
    return [IO.Path]::GetFullPath($node)
}

function Test-ServiceChildStable {
    param([Parameter(Mandatory)][string]$ExpectedNodePath)
    $deadline = (Get-Date).AddSeconds(20)
    $previousChild = 0
    while ((Get-Date) -lt $deadline) {
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
        if (-not $service -or $service.State -ne 'Running' -or -not $service.ProcessId) { return $false }
        $children = @(Get-CimInstance -ClassName Win32_Process -Filter "ParentProcessId=$($service.ProcessId)" -ErrorAction Stop |
            Where-Object { $_.ExecutablePath -and $_.ExecutablePath.Equals($ExpectedNodePath, [StringComparison]::OrdinalIgnoreCase) })
        if ($children.Count -eq 1) {
            if ($previousChild -eq $children[0].ProcessId) { return $true }
            $previousChild = $children[0].ProcessId
        } else { $previousChild = 0 }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Assert-UpgradeRecoveryAcl {
    param(
        [Parameter(Mandatory)][string]$JournalPath,
        [ValidateSet('file','directory')][string]$Kind = 'file'
    )
    $oldModule = [Environment]::GetEnvironmentVariable('TOKENTIMER_RECOVERY_ACL_MODULE', 'Process')
    $oldJournal = [Environment]::GetEnvironmentVariable('TOKENTIMER_RECOVERY_ACL_PATH', 'Process')
    try {
        $env:TOKENTIMER_RECOVERY_ACL_MODULE = Join-Path $PackageDir "src\platform\index.js"
        $env:TOKENTIMER_RECOVERY_ACL_PATH = $JournalPath
        $method = if ($Kind -eq 'directory') { 'assertWindowsAcl' } else { 'assertRestrictivePermissions' }
        $requireProtected = if ($Kind -eq 'directory') { 'false' } else { 'true' }
        $validation = "require(process.env.TOKENTIMER_RECOVERY_ACL_MODULE).$method(process.env.TOKENTIMER_RECOVERY_ACL_PATH,{label:'upgrade recovery',requireProtected:$requireProtected})"
        Invoke-PackagedNode -NodeArguments @('-e', $validation)
        if ($LASTEXITCODE -ne 0) { throw 'upgrade recovery record owner or ACL is not trusted' }
    } finally {
        [Environment]::SetEnvironmentVariable('TOKENTIMER_RECOVERY_ACL_MODULE', $oldModule, 'Process')
        [Environment]::SetEnvironmentVariable('TOKENTIMER_RECOVERY_ACL_PATH', $oldJournal, 'Process')
    }
}

# The inherited pipe carries a one-use secret, not the environment. The two
# immutable intent records and their protected parent bind it to these exact
# directories. This gate never authorizes automatic recovery after a crash.
function Assert-AuthorizedLauncherOrNoIntent {
    if (-not [Environment]::Is64BitProcess) { throw 'native 64-bit PowerShell is required' }
    $parent = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    if ([string]::IsNullOrWhiteSpace($parent)) { throw 'launcher staging parent unavailable' }
    Assert-ProtectedIntentDirectory -Directory $parent
    $intents = @(Get-ChildItem -LiteralPath $parent -Filter 'TokenTimer-Staging-*.intent' -Force -ErrorAction Stop)
    $handleText = [Environment]::GetEnvironmentVariable('TOKENTIMER_AGENT_INTENT_HANDLE', 'Process')
    [Environment]::SetEnvironmentVariable('TOKENTIMER_AGENT_INTENT_HANDLE', $null, 'Process')
    if ($intents.Count -eq 0) {
        if ($handleText) { throw 'unexpected launcher authorization handle' }
        return
    }
    if ($intents.Count -ne 2 -or $handleText -notmatch '^[1-9][0-9]{0,18}$') { throw 'launcher execution remains quarantined' }
    $payload = [IO.Path]::GetFullPath($PackageDir).TrimEnd('\')
    $scratch = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')
    foreach ($stage in @($payload, $scratch)) {
        if (-not ([IO.Path]::GetDirectoryName($stage).Equals($parent, [StringComparison]::OrdinalIgnoreCase)) -or
            [IO.Path]::GetFileName($stage) -cnotmatch '^TokenTimer-Staging-[a-f0-9]{32}$') { throw 'launcher stage path rejected' }
    }
    if ($payload.Equals($scratch, [StringComparison]::OrdinalIgnoreCase)) { throw 'launcher stages are not distinct' }
    $expected = @($payload + '.intent', $scratch + '.intent')
    foreach ($entry in $intents) {
        if (-not @($expected | Where-Object { $_.Equals($entry.FullName, [StringComparison]::OrdinalIgnoreCase) }).Count) { throw 'unrelated launcher intent remains quarantined' }
    }
    $records = @()
    for ($i = 0; $i -lt 2; $i++) {
        $file = Get-Item -LiteralPath $expected[$i] -Force -ErrorAction Stop
        if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $file.Length -le 0 -or $file.Length -gt 4096) { throw 'invalid launcher intent file' }
        Assert-UpgradeRecoveryAcl -JournalPath $expected[$i]
        $record = Get-Content -LiteralPath $expected[$i] -Raw | ConvertFrom-Json -ErrorAction Stop
        $stage = @($payload, $scratch)[$i]
        if ($record.schemaVersion -ne 1 -or $record.phase -cne 'execution-intent' -or $record.stageName -cne [IO.Path]::GetFileName($stage) -or
            ([string]$record.secret) -cnotmatch '^[a-f0-9]{64}$' -or ([string]$record.transaction) -cnotmatch '^[a-f0-9]{32}$' -or
            ([string]$record.archiveSha256) -cnotmatch '^[a-f0-9]{64}$') { throw 'invalid launcher intent record' }
        $index = ([uint64]$record.indexHigh -shl 32) -bor [uint64]$record.indexLow
        if ((Get-PackageDirectoryIdentity -Directory $stage) -cne ("{0}:{1}" -f [uint32]$record.volume, $index)) { throw 'launcher stage identity changed' }
        $records += $record
    }
    if ($records[0].transaction -cne $records[1].transaction -or $records[0].secret -cne $records[1].secret -or
        $records[0].archiveSha256 -cne $records[1].archiveSha256) { throw 'launcher intents do not match' }
    $handle = New-Object Microsoft.Win32.SafeHandles.SafeFileHandle([IntPtr]([int64]$handleText), $true)
    $stream = New-Object IO.FileStream($handle, [IO.FileAccess]::Read, 64, $false)
    try {
        $bytes = New-Object byte[] 64
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $count = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($count -le 0) { throw 'incomplete launcher authorization' }
            $offset += $count
        }
        $actual = [Text.Encoding]::ASCII.GetString($bytes)
        if ($actual -cne $records[0].secret) { throw 'launcher authorization rejected' }
        $script:AuthorizedLauncherTransaction = [string]$records[0].transaction
    } finally { $stream.Dispose(); $handle.Dispose() }
}

function Recover-InterruptedUpgrade {
    $journal = Get-UpgradeRecoveryPath
    if (-not (Test-Path -LiteralPath $journal)) { return }
    # A launcher intent is only a denial signal. It is never parsed or used to
    # authorize recovery. Keep the shared lock through all later mutations.
    if (-not [Environment]::Is64BitProcess) { throw 'recovery_required: native 64-bit PowerShell is required' }
    $launcherParent = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    if ([string]::IsNullOrWhiteSpace($launcherParent)) { throw 'recovery_required: launcher staging parent unavailable' }
    Assert-ProtectedIntentDirectory -Directory $launcherParent
    Assert-NoQuarantinedLauncherIntent -LauncherParent $launcherParent
    $journalItem = Get-Item -LiteralPath $journal -Force -ErrorAction Stop
    if ($journalItem.PSIsContainer -or ($journalItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $journalItem.Length -gt 4096) {
        throw 'refusing an unsafe upgrade recovery record'
    }
    Assert-UpgradeRecoveryAcl -JournalPath $journal
    $record = Get-Content -LiteralPath $journal -Raw | ConvertFrom-Json -ErrorAction Stop
    # A launcher-backed upgrade can have external actors even if its marker
    # later disappeared. A transaction is a denial signal, never authority to
    # replay or delete any staging path.
    if ($null -ne $record.PSObject.Properties['launcherIntent']) { throw 'recovery_required: launcher upgrade remains quarantined' }
    if ($record.version -ne 1 -or ([string]$record.pid) -notmatch '^[1-9][0-9]{0,9}$' -or
        ([string]$record.previousIdentity) -notmatch '^\d+:[1-9]\d*$' -or
        ([string]$record.stagingIdentity) -notmatch '^\d+:[1-9]\d*$' -or
        [string]::IsNullOrWhiteSpace([string]$record.previousServicePath) -or
        [string]::IsNullOrWhiteSpace([string]$record.previousServiceDisplayName) -or
        $record.previousServiceStartMode -notin @('Automatic','Manual','Disabled')) {
        throw 'invalid upgrade recovery record'
    }
    $priorPid = [int]$record.pid
    if (Get-Process -Id $priorPid -ErrorAction SilentlyContinue) {
        throw 'another installer may still own the upgrade recovery record'
    }
    $previous = "$AppDir.previous.$priorPid"
    $staging = "$AppDir.staging.$priorPid"
    $appExists = Test-Path -LiteralPath $AppDir
    $previousExists = Test-Path -LiteralPath $previous
    if ($previousExists -and (Get-PackageDirectoryIdentity -Directory $previous) -ne $record.previousIdentity) {
        throw 'upgrade backup identity changed; manual recovery is required'
    }
    if ($appExists) {
        $appIdentity = Get-PackageDirectoryIdentity -Directory $AppDir
        if ($appIdentity -eq $record.stagingIdentity -and $previousExists) {
            $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
            $expectedHost = Join-Path $AppDir ("bin\tokentimer-agent-host-$runtimeArch.exe")
            $expectedEntry = Join-Path $AppDir "bin\tokentimer-agent.js"
            $newServicePath = '"' + $expectedHost + '" "' + $script:InstalledNodeExe + '" "' + $expectedEntry + '"'
            if (-not $service -or ([string]$service.PathName -cne [string]$record.previousServicePath -and [string]$service.PathName -cne $newServicePath) -or (Test-Path -LiteralPath $staging)) {
                throw 'upgrade activation is ambiguous; manual recovery is required'
            }
            if ($service.State -ne 'Stopped') {
                Stop-Service -Name $ServiceName -Force -ErrorAction Stop
                (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
            }
            Rename-Item -LiteralPath $AppDir -NewName (Split-Path -Leaf $staging) -ErrorAction Stop
            $appExists = $false
        } elseif ($appIdentity -ne $record.previousIdentity -or $previousExists) {
            throw 'active application identity is ambiguous; manual recovery is required'
        }
    }
    if (-not $appExists) {
        if (-not $previousExists) { throw 'upgrade backup is missing; manual recovery is required' }
        Rename-Item -LiteralPath $previous -NewName (Split-Path -Leaf $AppDir) -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $staging) {
        Remove-OwnedPackageStaging -Directory $staging -ExpectedIdentity $record.stagingIdentity
    }
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
    if (-not $service) { throw 'previous service is missing; manual recovery is required' }
    if ($service.State -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        (Get-Service -Name $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
    }
    $result = Invoke-CimMethod -InputObject $service -MethodName Change -Arguments @{
        PathName = [string]$record.previousServicePath
        DisplayName = [string]$record.previousServiceDisplayName
        StartMode = [string]$record.previousServiceStartMode
    }
    if ($result.ReturnValue -ne 0) { throw 'previous service configuration could not be restored' }
    $serviceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    if ($record.hadPreviousServiceEnvironment) {
        New-ItemProperty -LiteralPath $serviceRegistryPath -Name "Environment" -PropertyType MultiString -Value @($record.previousServiceEnvironment) -Force | Out-Null
    } else {
        Remove-ItemProperty -LiteralPath $serviceRegistryPath -Name "Environment" -ErrorAction SilentlyContinue
    }
    Start-Service -Name $ServiceName -ErrorAction Stop
    (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(20))
    $previousNode = Get-ServiceNodePath -ServiceCommand $record.previousServicePath
    if (-not (Test-ServiceChildStable -ExpectedNodePath $previousNode)) {
        throw 'previous service started without a stable expected Node child; manual recovery is required'
    }
    Remove-Item -LiteralPath $journal -Force -ErrorAction Stop
    Write-Log "Recovered the previous application after an interrupted upgrade; remote agent readiness has not been checked."
}

function Write-UpgradeRecoveryRecord {
    param([Parameter(Mandatory)][string]$StagingIdentity)
    if (-not (Test-Path -LiteralPath $StateDir -PathType Container)) {
        throw 'protected agent state is missing; refusing an upgrade without a recovery record'
    }
    $null = Get-PackageDirectoryIdentity -Directory $StateDir
    Assert-UpgradeRecoveryAcl -JournalPath $StateDir -Kind "directory"
    Invoke-PlatformAcl -TargetPath $StateDir -Kind "directory"
    $record = [ordered]@{
        version = 1
        pid = $PID
        previousIdentity = Get-PackageDirectoryIdentity -Directory $AppDir
        stagingIdentity = $StagingIdentity
        previousServicePath = $script:PreviousServicePath
        previousServiceDisplayName = $script:PreviousServiceDisplayName
        previousServiceStartMode = $script:PreviousServiceStartMode
        hadPreviousServiceEnvironment = $null -ne $script:PreviousServiceEnvironment
        previousServiceEnvironment = @($script:PreviousServiceEnvironment)
    }
    if ($null -ne $script:AuthorizedLauncherTransaction) {
        if ($script:AuthorizedLauncherTransaction -cnotmatch '^[a-f0-9]{32}$') { throw 'invalid authorized launcher transaction' }
        $record['launcherIntent'] = $script:AuthorizedLauncherTransaction
    }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($record | ConvertTo-Json -Compress))
    if ($bytes.Length -gt 4096) {
        throw 'upgrade recovery record exceeds the supported size; the existing application was not changed'
    }
    $journal = Get-UpgradeRecoveryPath
    $stream = [IO.File]::Open($journal, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
    Invoke-PlatformAcl -TargetPath $journal -Kind "file"
}

if (-not $script:DryRun) {
    try { Assert-WindowsPackageHelpers -PackageDirectory $PackageDir -Architecture $arch }
    catch { Fail "native package preflight failed before installation changes ($($_.Exception.Message))" }
    try { Assert-AuthorizedLauncherOrNoIntent }
    catch { Fail "recovery_required: launcher authorization failed ($($_.Exception.Message))" }
    if (Test-Path -LiteralPath $StateDir -PathType Container) {
        try {
            $null = Get-PackageDirectoryIdentity -Directory $StateDir
            Assert-UpgradeRecoveryAcl -JournalPath $StateDir -Kind "directory"
            Invoke-PlatformAcl -TargetPath $StateDir -Kind "directory"
            Recover-InterruptedUpgrade
        } catch { Fail "interrupted upgrade recovery failed ($($_.Exception.Message))" }
    }
}

Write-Log "Installing agent package from $PackageDir to $AppDir"
if (-not $script:DryRun) {
    New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
}

$script:AppStaging = "$AppDir.staging.$PID"
$script:AppPrevious = "$AppDir.previous.$PID"
$script:IsUpgrade = (Test-Path -LiteralPath $AppDir)
$script:PreviousServicePath = ""
$script:PreviousServiceEnvironment = $null
$script:PreviousServiceDisplayName = ""
$script:PreviousServiceStartMode = ""
if ($script:IsUpgrade -and -not $script:DryRun) {
    $previousService = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
    if ($previousService) {
        $script:PreviousServicePath = [string]$previousService.PathName
        if ([string]::IsNullOrWhiteSpace($script:PreviousServicePath) -or $script:PreviousServicePath -match '[\x00-\x1F]') {
            Fail "cannot preserve the existing service command before upgrading"
        }
        try { $script:PreviousNodeExe = Get-ServiceNodePath -ServiceCommand $script:PreviousServicePath }
        catch { Fail "cannot validate the previous service runtime before upgrading ($($_.Exception.Message))" }
        $script:PreviousServiceDisplayName = [string]$previousService.DisplayName
        $script:PreviousServiceStartMode = switch ([string]$previousService.StartMode) {
            'Auto' { 'Automatic' }
            'Manual' { 'Manual' }
            'Disabled' { 'Disabled' }
            default { Fail "cannot preserve the existing service start mode before upgrading" }
        }
        if ([string]::IsNullOrWhiteSpace($script:PreviousServiceDisplayName)) {
            Fail "cannot preserve the existing service display name before upgrading"
        }
        $serviceKey = Get-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -ErrorAction Stop
        $script:PreviousServiceEnvironment = $serviceKey.GetValue("Environment", $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    } else {
        Fail "an existing application has no service configuration to preserve; manual recovery is required"
    }
}

if ($script:DryRun) {
    Write-Host "[dry-run] copy $PackageDir into $($script:AppStaging) (excluding node_modules, .git), then atomically swap into $AppDir"
} else {
    if (Test-Path -LiteralPath $script:AppStaging) { Fail 'refusing an existing package staging directory' }
    New-Item -ItemType Directory -Path $script:AppStaging -ErrorAction Stop | Out-Null
    $stagingIdentity = Get-PackageDirectoryIdentity -Directory $script:AppStaging
    try {
        Copy-PackageTree -Source $PackageDir -Destination $script:AppStaging
        Assert-WindowsPackageHelpers -PackageDirectory $script:AppStaging -Architecture $arch
        if ($script:HasBundledRuntime) {
            $stagedRuntime = Join-Path $script:AppStaging ("runtime\$runtimeArch\node.exe")
            if (-not (Test-Path -LiteralPath $stagedRuntime -PathType Leaf) -or
                (Get-FileHash -LiteralPath $stagedRuntime -Algorithm SHA256).Hash.ToLowerInvariant() -cne $runtimeManifest.sha256) {
                throw "staged Node runtime checksum mismatch"
            }
        }
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
        if ($script:IsUpgrade) { Write-UpgradeRecoveryRecord -StagingIdentity $stagingIdentity }
        Activate-StagedPackage -AppDirectory $AppDir -StagingDirectory $script:AppStaging -PreviousDirectory $script:AppPrevious -ExpectedStagingIdentity $stagingIdentity
    } catch {
        $activationError = $_.Exception.Message
        if ($script:IsUpgrade -and -not (Test-Path -LiteralPath (Get-UpgradeRecoveryPath)) -and (Test-Path -LiteralPath $script:AppStaging)) {
            try { Remove-OwnedPackageStaging -Directory $script:AppStaging -ExpectedIdentity $stagingIdentity }
            catch { Fail "upgrade preparation failed; staging cleanup refused; manual inspection is required ($activationError)" }
        }
        Fail $activationError
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
    if ($caBundleDest -or $script:AllowInsecureLocalHttp) {
        $lines.Add("  `"workspaceId`": `"$($script:WorkspaceId)`",")
    } else {
        $lines.Add("  `"workspaceId`": `"$($script:WorkspaceId)`"")
    }
    if ($caBundleDest) {
        $caBundleDestJson = $caBundleDest.Replace('\', '\\')
        if ($script:AllowInsecureLocalHttp) {
            $lines.Add("  `"caBundlePath`": `"$caBundleDestJson`",")
        } else {
            $lines.Add("  `"caBundlePath`": `"$caBundleDestJson`"")
        }
    }
    if ($script:AllowInsecureLocalHttp) {
        $lines.Add("  `"allowInsecureLocalHttp`": true")
    }
    $lines.Add("}")
    $configContent = ($lines -join "`n") + "`n"
    [System.IO.File]::WriteAllText($configTmp, $configContent, (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -Force $configTmp $configPath
    Invoke-PlatformAcl -TargetPath $configPath -Kind "file"
    # Sanity-parse the result with the node we already verified, so a bad
    # value can never install an unreadable config.
    Invoke-PackagedNode -NodeArguments @('-e', "JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'))", $configPath)
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
    $values = New-Object System.Collections.Generic.List[string]
    $values.Add("TOKENTIMER_AGENT_CONFIG_DIR=$ConfigDir")
    if (-not [string]::IsNullOrEmpty($Token)) {
        $values.Add("TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=$Token")
    }
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" `
        -Name "Environment" -PropertyType MultiString -Value $values.ToArray() -Force | Out-Null
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
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [ValidateSet("Automatic", "Manual", "Disabled")][string]$StartMode = "Automatic"
    )
    $wmiService = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'"
    if (-not $wmiService) { Fail "service $ServiceName not found via Win32_Service for reconfiguration" }
    $changeResult = Invoke-CimMethod -InputObject $wmiService -MethodName Change -Arguments @{
        PathName    = $BinPath
        DisplayName = $DisplayName
        StartMode   = $StartMode
    }
    if ($changeResult.ReturnValue -ne 0) {
        Fail "Win32_Service.Change failed to update $ServiceName (ReturnValue $($changeResult.ReturnValue))"
    }
}

$quotedNode = '"' + $script:InstalledNodeExe + '"'
$quotedEntry = '"' + (Join-Path $AppDir "bin\tokentimer-agent.js") + '"'

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
$quotedServiceHost = '"' + $serviceHostExe + '"'
$binPath = "$quotedServiceHost $quotedNode $quotedEntry"

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
    if ($null -ne $script:NodeRuntimeLock) { $script:NodeRuntimeLock.Dispose(); $script:NodeRuntimeLock = $null }
    exit 0
}

# Preserve operator WER policy. Microsoft's LocalDumps DumpType=0 selects a
# custom dump and may enable collection; it does not disable dumps. Do not
# rewrite the machine-wide node.exe policy or infer containment from a registry
# value. Native crash containment remains a separate qualification requirement.

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

$healthy = (Test-ServiceHealthy -TimeoutSeconds 20) -and (Test-ServiceChildStable -ExpectedNodePath $script:InstalledNodeExe)

if (-not $healthy -and $script:IsUpgrade -and (Test-Path -LiteralPath $script:AppPrevious)) {
    if ($null -ne $script:AuthorizedLauncherTransaction) {
        # SCM and WMI can outlive the installer. Until they are reconciled,
        # stopping the service silently is not proof it is safe to remove or
        # replace the active application. Keep both app copies and the journal.
        Fail "recovery_required: upgrade health check failed; the application, backup and recovery journal were retained"
    }
    Write-Log "Health check failed after upgrade; rolling back to the previous version."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $AppDir -Recurse -Force
    Rename-Item -LiteralPath $script:AppPrevious -NewName (Split-Path -Leaf $AppDir)
    if ([string]::IsNullOrWhiteSpace($script:PreviousServicePath)) {
        Fail "previous application was restored, but its service command was unavailable; manual recovery is required"
    }
    $rollbackBinPath = $script:PreviousServicePath
    Set-ServiceBinaryPath -ServiceName $ServiceName -BinPath $rollbackBinPath -DisplayName $script:PreviousServiceDisplayName -StartMode $script:PreviousServiceStartMode
    $serviceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    if ($null -eq $script:PreviousServiceEnvironment) {
        Remove-ItemProperty -LiteralPath $serviceRegistryPath -Name "Environment" -ErrorAction SilentlyContinue
    } else {
        New-ItemProperty -LiteralPath $serviceRegistryPath -Name "Environment" -PropertyType MultiString -Value $script:PreviousServiceEnvironment -Force | Out-Null
    }
    try {
        Start-Service -Name $ServiceName -ErrorAction Stop
    } catch {
        Fail "previous application and service command were restored, but the service could not start; manual recovery is required"
    }
    if (-not (Test-ServiceHealthy -TimeoutSeconds 20) -or -not (Test-ServiceChildStable -ExpectedNodePath $script:PreviousNodeExe)) {
        Fail "previous application and service command were restored, but the expected child did not remain healthy; manual recovery is required"
    }
    # The credential file's ACL must be re-asserted after rollback, not
    # inherited from whatever the failed install left behind.
    $credentialPath = Join-Path $StateDir "credential"
    if (Test-Path -LiteralPath $credentialPath) {
        Invoke-PlatformAcl -TargetPath $credentialPath -Kind "file"
    }
    Remove-Item -LiteralPath (Get-UpgradeRecoveryPath) -Force -ErrorAction Stop
    Fail "upgrade failed its post-install health check and was rolled back to the previous version; the agent credential and configuration were preserved and the credential file's ACL was re-asserted"
}

if ($healthy -and $script:IsUpgrade -and $null -eq $script:AuthorizedLauncherTransaction) { Remove-Item -LiteralPath (Get-UpgradeRecoveryPath) -Force -ErrorAction Stop }
if ($null -eq $script:AuthorizedLauncherTransaction -and (Test-Path -LiteralPath $script:AppPrevious)) { Remove-Item -LiteralPath $script:AppPrevious -Recurse -Force }

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
if ($null -ne $script:NodeRuntimeLock) { $script:NodeRuntimeLock.Dispose(); $script:NodeRuntimeLock = $null }
exit 0

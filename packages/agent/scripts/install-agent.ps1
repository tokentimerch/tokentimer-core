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
#   6. Sets the Windows Error Reporting LocalDumps DumpType=0 for node.exe
#      (ADR-0012 decision 19: core dumps are disabled by a named,
#      explicit mechanism, not an unspecified machine-wide default).
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
#     so -WritePath/--write-path and -ReloadService/--reload-service are
#     accepted and validated for CLI-contract parity, but there is no
#     drop-in override to generate: a LocalSystem service already has
#     ambient host-wide access (ADR-0012 decision 11), so the enforcement
#     point on Windows is agent-local policy (config.json allowlists),
#     not an OS-level sandbox.
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

function Write-Log {
    param([string]$Message)
    Write-Host "install-agent: $Message"
}

function Fail {
    param([string]$Message)
    [Console]::Error.WriteLine("install-agent: ERROR: $Message")
    exit 1
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
  access; --write-path/--write-paths-file only remind you which directories
  the agent's own configured allowlist should include (see config.json).
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
        if (Test-Path $AppDir) { Remove-Item -Recurse -Force $AppDir }
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
if (-not (Test-Path $ValidateServerUrlJs)) { Fail "server URL validator not found: $ValidateServerUrlJs" }
$validateArgs = @($script:ApiUrl)
if ($script:AllowInsecureLocalHttp) { $validateArgs += "--allow-insecure-local-http" }
$normalizedApiUrl = & node $ValidateServerUrlJs @validateArgs 2>$null
if ($LASTEXITCODE -ne 0) {
    Fail "--api-url was rejected by the same rule the agent runtime uses (https required; http only for loopback with --allow-insecure-local-http)"
}
$script:ApiUrl = $normalizedApiUrl.Trim()

if (-not [string]::IsNullOrEmpty($script:CaBundle)) {
    if (-not (Test-Path $script:CaBundle -PathType Leaf)) { Fail "--ca-bundle file not found: $script:CaBundle" }
    $caBundleContent = Get-Content -Raw $script:CaBundle
    if ($caBundleContent -notmatch "BEGIN CERTIFICATE") { Fail "--ca-bundle contains no PEM certificate block" }
    if ($caBundleContent -match "PRIVATE KEY") {
        Fail "--ca-bundle contains private key material; a CA bundle must hold public certificates only"
    }
}

if (-not (Test-Path (Join-Path $PackageDir "package.json"))) {
    Fail "agent package.json not found next to this script (expected $PackageDir\package.json); run from an unpacked agent package"
}
if (-not (Test-Path (Join-Path $PackageDir "bin\tokentimer-agent.js"))) {
    Fail "agent entrypoint bin\tokentimer-agent.js not found in $PackageDir"
}
if (-not (Test-Path $HostSandboxJs)) { Fail "host sandbox helper not found: $HostSandboxJs" }

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
    if (-not (Test-Path $script:WritePathsFile -PathType Leaf)) { Fail "--write-paths-file not found: $script:WritePathsFile" }
    foreach ($line in Get-Content $script:WritePathsFile) {
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
    & node $HostSandboxJs map-reload-service $reloadService | Out-Null
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
$packageJsonText = Get-Content -Raw (Join-Path $PackageDir "package.json")
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
$nodeVersionRaw = (& node -v).Trim()
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
        & node $scriptPath
        if ($LASTEXITCODE -ne 0) {
            Fail "failed to apply a restricted ACL to $TargetPath (kind=$Kind)"
        }
    } finally {
        Remove-Item -Force -ErrorAction SilentlyContinue $scriptPath
    }
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

Write-Log "Installing agent package from $PackageDir to $AppDir"
if (-not $script:DryRun) {
    New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
}

$script:AppStaging = "$AppDir.staging.$PID"
$script:AppPrevious = "$AppDir.previous.$PID"
$script:IsUpgrade = (Test-Path $AppDir)

if ($script:DryRun) {
    Write-Host "[dry-run] copy $PackageDir into $($script:AppStaging) (excluding node_modules, .git), then atomically swap into $AppDir"
} else {
    if (Test-Path $script:AppStaging) { Remove-Item -Recurse -Force $script:AppStaging }
    try {
        Copy-PackageTree -Source $PackageDir -Destination $script:AppStaging
    } catch {
        if (Test-Path $script:AppStaging) { Remove-Item -Recurse -Force $script:AppStaging }
        Fail "failed to stage the agent package; $AppDir was left untouched ($($_.Exception.Message))"
    }
    if (Test-Path $script:AppPrevious) { Remove-Item -Recurse -Force $script:AppPrevious }
    if (Test-Path $AppDir) {
        Rename-Item -LiteralPath $AppDir -NewName (Split-Path -Leaf $script:AppPrevious)
    }
    try {
        Rename-Item -LiteralPath $script:AppStaging -NewName (Split-Path -Leaf $AppDir)
    } catch {
        if (Test-Path $script:AppPrevious) { Rename-Item -LiteralPath $script:AppPrevious -NewName (Split-Path -Leaf $AppDir) }
        if (Test-Path $script:AppStaging) { Remove-Item -Recurse -Force $script:AppStaging }
        Fail "failed to activate the staged agent package; the previous install was restored ($($_.Exception.Message))"
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
    Invoke-Step "copy $($script:CaBundle) to $caBundleDest" { Copy-Item -Force $script:CaBundle $caBundleDest }
}

if ((Test-Path $configPath) -and -not $script:DryRun) {
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
    & node -e "JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'))" $configPath
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

$quotedNode = '"' + $script:NodeExe + '"'
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
if (-not $script:DryRun -and -not (Test-Path $serviceHostExe)) {
    Fail (
        "service host binary not found at $serviceHostExe; the staged app dir looks incomplete " +
        "or was not built with 'pnpm run build:windows-service-host' before packaging"
    )
}
$quotedServiceHost = '"' + $serviceHostExe + '"'
$binPath = "$quotedServiceHost $quotedNode $quotedEntry"

# sc.exe's binPath= value here is three separately-quoted path segments
# (host exe, node.exe, entry script), which is the documented pattern for
# a service whose binary takes quoted arguments. Windows PowerShell 5.1's
# native-argument passing does not re-escape a string that already starts
# and ends with a double quote, so $binPath reaches sc.exe's own (naive)
# command-line tokenizer as raw, unwrapped `"..." "..." "..."` text --
# sc.exe's tokenizer stops at the first embedded quoted segment and
# treats what follows as unrecognized extra arguments, failing every
# single time with exit 1639 (invalid command line), confirmed by a live
# repro on Windows Server 2025 build 26100 / PowerShell 5.1, this script's
# first real-host run. Wrapping the whole three-segment value in
# one more outer pair of quotes, with the inner quotes doubled rather than
# backslash-escaped (sc.exe's own convention, not cmd.exe's), survives
# PowerShell's native-argument passing intact and round-trips through
# `sc qc`/WMI PathName byte-for-byte, confirmed live against both
# `sc.exe create` and `sc.exe config`. $binPath itself is left as the
# human-readable form for -DryRun/log output; only this escaped variant is
# ever passed to sc.exe.
$binPathForScExe = '"' + $binPath.Replace('"', '""') + '"'

if ($script:DryRun) {
    Write-Host "[dry-run] sc.exe create/config $ServiceName binPath= $binPath start= auto obj= LocalSystem"
    Write-Host "[dry-run] sc.exe failure $ServiceName reset= 86400 actions= restart/5000"
    Write-Host "[dry-run] set HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName\Environment"
    Write-Host "[dry-run] set HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\node.exe DumpType=0"
    Write-Host "[dry-run] (re)start $ServiceName and health-check it"
    Write-Log ""
    Write-Log "Dry run complete. No changes were made."
    exit 0
}

# --------------------------------------- Windows Error Reporting dump suppression
# ADR-0012 decision 19: core dumps must be disabled for the production
# agent by a named, platform-specific mechanism, not an unspecified
# "disabled" claim, since a crash dump is an alternate, unlocked copy of
# process memory that no in-process buffer discipline can prevent. This
# was previously documented in ADR-0012 but never implemented; a real-host
# verification pass found the gap.
#
# WER's LocalDumps key is scoped by executable *file name*, not full path,
# and Windows has no path-scoped equivalent. node.exe is the process that
# actually runs the agent's key-handling JS code; the windows-service-host
# shim (see windows-service-host/) is a thin SCM adapter that spawns
# node.exe as its child and never itself holds key bytes, so suppressing
# dumps only for the service-host executable would not protect the
# process that matters. Setting this for node.exe suppresses WER dumps for
# any node.exe process on this host, not only this agent's -- an accepted
# trade-off per decision 10's own established principle that a
# narrow-but-ineffective control is worse than a broad-but-deterministic
# one. An operator who needs WER dumps for an unrelated Node service on
# the same host should not colocate it with this agent.
function Set-WindowsDumpSuppression {
    param([string]$ExeName)
    $key = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\$ExeName"
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name "DumpType" -PropertyType DWord -Value 0 -Force | Out-Null
}
Invoke-Step "set WER LocalDumps DumpType=0 for node.exe" { Set-WindowsDumpSuppression -ExeName "node.exe" }

$serviceExisted = [bool](Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)
if (-not $serviceExisted) {
    & sc.exe create $ServiceName type= own start= auto obj= LocalSystem DisplayName= $ServiceDisplayName binPath= $binPathForScExe | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "sc.exe create failed for $ServiceName (exit $LASTEXITCODE)" }
} else {
    & sc.exe config $ServiceName binPath= $binPathForScExe obj= LocalSystem start= auto DisplayName= $ServiceDisplayName | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "sc.exe config failed to update $ServiceName (exit $LASTEXITCODE)" }
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

if (-not $healthy -and $script:IsUpgrade -and (Test-Path $script:AppPrevious)) {
    Write-Log "Health check failed after upgrade; rolling back to the previous version."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $AppDir
    Rename-Item -LiteralPath $script:AppPrevious -NewName (Split-Path -Leaf $AppDir)
    $rollbackBinPath = $binPathForScExe
    & sc.exe config $ServiceName binPath= $rollbackBinPath | Out-Null
    Set-ServiceEnvironment -ConfigDir $StateDir -Token ""
    Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
    # The credential file's ACL must be re-asserted after rollback, not
    # inherited from whatever the failed install left behind.
    $credentialPath = Join-Path $StateDir "credential"
    if (Test-Path $credentialPath) {
        Invoke-PlatformAcl -TargetPath $credentialPath -Kind "file"
    }
    Fail "upgrade failed its post-install health check and was rolled back to the previous version; the agent credential and configuration were preserved and the credential file's ACL was re-asserted"
}

if (Test-Path $script:AppPrevious) { Remove-Item -Recurse -Force $script:AppPrevious }

if (-not $healthy) {
    Fail "the $ServiceName service did not reach the Running state within 20 seconds; check 'Get-Service $ServiceName' and the agent's own logs"
}

Write-Log ""
Write-Log "Install complete. Crash dumps (WER LocalDumps) are suppressed for node.exe on this host."
Write-Log "Next steps:"
Write-Log "  1. Check the service:      Get-Service $ServiceName"
Write-Log "  2. Confirm registration in the dashboard (CertOps > Agent fleet):"
Write-Log "     the agent should appear as active within about a minute."
Write-Log "     (The agent deletes the single-use $bootstrapEnvPath itself after"
Write-Log "     registering; no manual cleanup is needed.)"
Write-Log "  3. Configure agent-local policy and discovery in $configPath"
Write-Log "     (allowlists are default-deny until you set them), then:"
Write-Log "     Restart-Service $ServiceName"
if ($script:WritePaths.Count -gt 0) {
    Write-Log "  4. Ensure the LocalSystem service account can write the configured cert paths:"
    foreach ($writePath in $script:WritePaths) {
        Write-Log "       $writePath"
    }
    Write-Log "     (LocalSystem already has ambient access; this is a reminder to set"
    Write-Log "     config.json's own write-path allowlist, not an OS-level grant.)"
}
if ($script:ReloadServices.Count -gt 0) {
    Write-Log "  5. Reload authorization is enforced by agent-local policy on Windows"
    Write-Log "     (no polkit/sudoers equivalent needed): configure policy"
    Write-Log "     commandProfiles.reloadArgv for: $($script:ReloadServices -join ', ')"
}
exit 0

#!/usr/bin/env pwsh
# tokentimer-protocol.ps1 - Node-free PowerShell reference client for the
# TokenTimer CertOps agent protocol.
#
# Usage:
#   tokentimer-protocol.ps1 -Step STEP [options]
#
# Steps:
#   all        register, heartbeat, claim, verify and report a result for
#              one protocol_smoke job. Requires -Live.
#   register   bootstrap a new diagnostic agent identity via the
#              session-authenticated diagnostic-bootstrap route. Requires
#              -Live, -WorkspaceId, a session cookie, and a CSRF token;
#              never the normal agent-registration endpoint (this client
#              only ever produces diagnostic protocol_smoke jobs, never
#              real certificate work).
#   heartbeat  send a heartbeat for an already-registered agent. Requires
#              -Live and a credential.
#   claim      poll for jobs and verify any that come back. Requires -Live
#              and a credential.
#   verify     verify one v2 envelope against a pinned public key. Runs
#              fully offline; -Live is neither required nor used.
#   result     report a result for a previously claimed and verified job.
#              Requires -Live, a credential, and -ClaimStateFile.
#
# Flags:
#   -Live                        Contact the real control plane.
#   -Json                        Emit machine-readable JSON, from an
#                                explicit field allowlist.
#   -ServerUrl URL               Control-plane origin (https:// required).
#   -AgentId ID                  Agent id (heartbeat/claim/result).
#   -AgentVersion VERSION        Reported agentVersion string.
#   -WorkspaceId UUID            Workspace id. Required for register: the
#                                diagnostic-bootstrap route is scoped to
#                                one workspace by path segment.
#   -SessionCookieFile PATH      File holding the operator's session
#                                Cookie header value (register).
#                                Diagnostic-bootstrap is session-
#                                authenticated, not a bearer-token agent
#                                call: the operator logs into the
#                                dashboard (or drives POST /auth/login
#                                directly) and supplies the resulting
#                                Cookie header here.
#   -CsrfTokenFile PATH          File holding the X-CSRF-Token header
#                                value paired with the session cookie
#                                above (register). Fetched by the
#                                operator from GET /api/csrf-token using
#                                the same session.
#   -RequestId ID                Idempotency key for the diagnostic-
#                                bootstrap request (register). A fresh
#                                UUID is generated when omitted; the
#                                request is single-use server-side, so
#                                retrying with the same id after a
#                                partial failure never double-bootstraps.
#   -CredentialFile PATH         File holding the ttagent_... credential.
#   -EnvelopeFile PATH           v2 envelope JSON to verify (or stdin).
#   -ClaimStateFile PATH         File where `claim` records the verified
#                                jobId/attemptId/claimId/nonce it just
#                                confirmed (written only after a passing
#                                Ed25519 verdict), and where a later,
#                                separate `result` invocation reads that
#                                same state from. Required for `result`
#                                unless run via `-Step all`. There is no
#                                environment-variable equivalent: see
#                                Write-ClaimState's header comment.
#   -Pubkey PATH                 Pinned Ed25519 PEM public key.
#   -SigningKeyId ID             Pinned signing key id.
#   -VerifierPath PATH           Path to the bundled tokentimer-verify.exe.
#   -PinnedSignerSubject SUBJ    Expected Authenticode signer subject.
#   -PinnedSignerThumbprint TP   Accepted Authenticode signer thumbprint(s),
#                                comma-separated. May be repeated.
#   -SkipSelfCheck               Skip the Authenticode self-check (defense
#                                in depth only; never the security boundary;
#                                see ADR-0012 decision 8).
#   -Echo TEXT                   protocol_smoke echo string (-Step all).
#   -AllowInsecureLocalHttp      Permit http:// for localhost only.
#
# Exit codes: 0 ok, 1 signature verification failed, 2 usage error,
# 3 network/HTTP error, 4 local pre-gate failure, 5 size limit exceeded.
#
# This file must contain ONLY ASCII bytes (ADR-0012 decision 8): a signed
# PowerShell script's Authenticode hash is sensitive to how the
# interpreter reads non-ASCII bytes under a host's ANSI code page, so a
# signature that validates in the build locale can fail on a different
# locale for a reason that looks like an attack. No smart quotes, no
# accented characters, no box-drawing, anywhere in this file including
# comments and the help text above.
#
# PowerShell verifies Ed25519 exclusively through the bundled
# tokentimer-verify.exe (a minimal Go binary); this script never shells
# out to OpenSSL for the verify step, because the two reference clients
# are required to exercise two independent Ed25519 implementations
# (ADR-0012 decision 8). The payload bytes travel to that process through
# a byte-preserving binary stream, never the PowerShell text pipeline or
# a string conversion, since either can transcode bytes before Go sees
# them.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("all", "register", "heartbeat", "claim", "verify", "result")]
    [string]$Step,

    [switch]$Live,
    [switch]$Json,
    [string]$ServerUrl,
    [string]$AgentId,
    [string]$AgentVersion = "tokentimer-protocol.ps1/1.0.0",
    [string]$WorkspaceId,
    [string]$SessionCookieFile,
    [string]$CsrfTokenFile,
    [string]$RequestId,
    [string]$CredentialFile,
    [string]$EnvelopeFile,
    [string]$ClaimStateFile,
    [string]$Pubkey,
    [string]$SigningKeyId,
    [string]$VerifierPath,
    [string]$PinnedSignerSubject,
    [string[]]$PinnedSignerThumbprint,
    [switch]$SkipSelfCheck,
    [string]$Echo = "tokentimer-protocol.ps1 smoke test",
    [switch]$AllowInsecureLocalHttp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ExitOk = 0
$ExitVerifyFailed = 1
$ExitUsage = 2
$ExitNetwork = 3
$ExitPregate = 4
$ExitSizeLimit = 5

$script:HeartbeatPath = "/api/v1/certops/agent/heartbeat"
$script:ClaimPath = "/api/v1/certops/agent/jobs/claim"
$script:ResultsPath = "/api/v1/certops/agent/jobs/results"

$script:ProtocolVersion = "1.0.0"
$script:SchemaVersion = 1

$script:MaxClaimResponseBytes = 1048576
# ADR-0012's ninth amendment (2026-08-04): 65536 was the tightest value that
# still decodes to exactly the 49152-byte decoded bound, which made the
# decoded-byte check below mathematically unreachable. 98304 gives real
# headroom (floor(98304/4)*3 = 73728 decoded bytes) so a payload between the
# two bounds is actually rejected by the decoded-byte check that enforces the
# real content-size policy, matching packages/agent/src/signing/index.js.
$script:MaxEncodedPayloadChars = 98304
$script:MaxDecodedPayloadBytes = 49152
$script:DefaultClockSkewToleranceSeconds = 300

$script:IdPattern = '^[A-Za-z0-9_.:-]{1,128}$'

$script:JsonMode = [bool]$Json
$script:JsonFields = New-Object System.Collections.Generic.List[string]

function ConvertTo-JsonEscaped {
    param([string]$Value)
    if ($null -eq $Value) { return "" }
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        $code = [int]$ch
        if ($ch -eq '"') { [void]$sb.Append('\"') }
        elseif ($ch -eq '\') { [void]$sb.Append('\\') }
        elseif ($code -eq 10) { [void]$sb.Append('\n') }
        elseif ($code -eq 13) { [void]$sb.Append('\r') }
        elseif ($code -eq 9) { [void]$sb.Append('\t') }
        elseif ($code -lt 32) { [void]$sb.Append([string]::Format('\u{0:x4}', $code)) }
        else { [void]$sb.Append($ch) }
    }
    return $sb.ToString()
}

function Add-JsonField {
    param([string]$Key, [string]$Value)
    if ($script:JsonMode) {
        $escapedKey = ConvertTo-JsonEscaped $Key
        $escapedValue = ConvertTo-JsonEscaped $Value
        $script:JsonFields.Add('"' + $escapedKey + '":"' + $escapedValue + '"')
    }
}

function Add-JsonFieldRaw {
    param([string]$Key, [string]$RawValue)
    if ($script:JsonMode) {
        $escapedKey = ConvertTo-JsonEscaped $Key
        $script:JsonFields.Add('"' + $escapedKey + '":' + $RawValue)
    }
}

function Write-Info {
    param([string]$Message)
    if (-not $script:JsonMode) {
        [Console]::Error.WriteLine($Message)
    }
}

function Write-ErrorLine {
    param([string]$Message)
    if (-not $script:JsonMode) {
        [Console]::Error.WriteLine("error: " + $Message)
    }
}

function Write-JsonSummary {
    if ($script:JsonMode) {
        $joined = [string]::Join(",", $script:JsonFields.ToArray())
        [Console]::Out.WriteLine("{" + $joined + "}")
    }
}

function Exit-Usage {
    param([string]$Message)
    Add-JsonField "errorCode" "usage_error"
    Write-ErrorLine $Message
    Write-JsonSummary
    exit $ExitUsage
}

function Exit-Pregate {
    param([string]$Message)
    Add-JsonField "errorCode" "pregate_failure"
    Write-ErrorLine $Message
    Write-JsonSummary
    exit $ExitPregate
}

function Exit-Network {
    param([string]$Message)
    Add-JsonField "errorCode" "network_error"
    Write-ErrorLine $Message
    Write-JsonSummary
    exit $ExitNetwork
}

function Exit-SizeLimit {
    param([string]$Message)
    Add-JsonField "errorCode" "size_limit_exceeded"
    Write-ErrorLine $Message
    Write-JsonSummary
    exit $ExitSizeLimit
}

function Exit-VerifyFailed {
    param([string]$Message)
    Add-JsonField "errorCode" "verify_failed"
    Write-ErrorLine $Message
    Write-JsonSummary
    exit $ExitVerifyFailed
}

# --- canonical base64 (ADR-0012 decision 2 steps 2-4) ------------------
#
# [Convert]::FromBase64String is lenient about embedded whitespace and
# some malformed padding, which is exactly what decision 2 says a
# canonical-base64 check must reject. Canonicality is therefore enforced
# the only implementable way: decode, re-encode, and require an exact
# match against the original string, on top of an explicit alphabet and
# length check so a non-canonical string never reaches the decoder
# silently.
$script:Base64Pattern = '^[A-Za-z0-9+/]+={0,2}$'

function Test-CanonicalBase64 {
    param([string]$Value, [int]$MaxChars)
    if ($Value.Length -eq 0 -or $Value.Length -gt $MaxChars) { return $false }
    if ($Value -notmatch $script:Base64Pattern) { return $false }
    if ($Value.Length % 4 -ne 0) { return $false }
    try {
        $decoded = [Convert]::FromBase64String($Value)
    } catch {
        return $false
    }
    $reencoded = [Convert]::ToBase64String($decoded)
    return $reencoded -eq $Value
}

# --- exactly one JSON value, then end-of-input (decision 2 steps 7-8) ---
#
# ConvertFrom-Json (built into PowerShell 5.1's Microsoft.PowerShell.Utility
# module) already rejects trailing non-whitespace content after one value
# and rejects a second whitespace-separated value with the same error
# (confirmed empirically: "{}garbage" and "{}{}"  both throw "invalid JSON
# primitive"), and it also rejects a leading byte-order mark on the
# decoded text. Trailing or leading whitespace alone is accepted, matching
# decision 2's framing note that canonical control-plane output carries
# none but a tolerant parser must still be defended against here. This
# wrapper adds only the strict-UTF-8 decode ConvertFrom-Json does not do
# on its own: it is handed a .NET string, so the byte-to-string decode
# already happened by the time it runs, and .NET's UTF8Encoding with
# throwOnInvalidBytes:$true is the strict decoder for that step, run
# first, over the raw bytes.
$script:StrictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)

function ConvertFrom-SingleJsonValue {
    param([byte[]]$Bytes)
    if ($Bytes.Length -eq 0) { return $null }
    try {
        $text = $script:StrictUtf8.GetString($Bytes)
    } catch {
        return $null
    }
    if ($text.Length -eq 0) { return $null }
    try {
        return , (ConvertFrom-Json -InputObject $text -ErrorAction Stop)
    } catch {
        return $null
    }
}

# --- ISO-8601 to epoch seconds (decision 2 step 14 support) -------------
#
# Canonical control-plane timestamps are always
# YYYY-MM-DDTHH:MM:SS.sssZ (decision 2's framing note). A fixed-format
# parse against DateTimeOffset with the "o"-adjacent round-trip pattern,
# rather than a locale-sensitive general parse, avoids any dependency on
# the host's current culture, which is exactly the class of bug decision
# 8's locale note warns about for this script.
$script:Iso8601Pattern = '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$'

function ConvertFrom-Iso8601ToEpochSeconds {
    param([string]$Value)
    if ($Value -notmatch $script:Iso8601Pattern) { return $null }
    try {
        $dto = [DateTimeOffset]::ParseExact(
            $Value,
            "yyyy-MM-ddTHH:mm:ss.fffZ",
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
        )
        return $dto.ToUnixTimeSeconds()
    } catch {
        return $null
    }
}

function Get-NowEpochSeconds {
    return [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
}

function Get-NowIso8601 {
    return [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", [System.Globalization.CultureInfo]::InvariantCulture)
}

# --- reading an unverified JSON value without StrictMode surprises -----
#
# Set-StrictMode -Version Latest makes ConvertFrom-Json's PSCustomObject
# throw PropertyNotFoundException on a missing property (confirmed
# empirically), which is the wrong failure mode for reading an
# attacker-controlled or simply absent field: decision 2's own idiom for
# this, mirrored from the bash client's `// empty`, is "absent or wrong
# type is the same as absent", never a crash.
function Get-JsonStringField {
    param($JsonObject, [string]$Name)
    if ($null -eq $JsonObject) { return "" }
    $prop = $JsonObject.PSObject.Properties[$Name]
    if ($null -eq $prop) { return "" }
    $val = $prop.Value
    if ($val -is [string]) { return $val }
    return ""
}

function Get-JsonIntField {
    param($JsonObject, [string]$Name)
    if ($null -eq $JsonObject) { return $null }
    $prop = $JsonObject.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    $val = $prop.Value
    if ($val -is [int] -or $val -is [long] -or $val -is [double]) { return [int64]$val }
    return $null
}

# --- FIPS policy detection (decision 8: fail before the verifier runs) -
#
# Go's standard library computes Ed25519 even where Windows FIPS policy
# forbids it, so a passing verification is not evidence of compliance on
# a FIPS-only host; this must be detected and refused before
# tokentimer-verify.exe is ever invoked, not after. Two independent
# signals are checked because either can be authoritative depending on
# how the host was configured: the .NET CryptoConfig flag (reflects the
# policy the current process actually observes) and the
# FipsAlgorithmPolicy registry value (reflects the machine-wide Local
# Security Policy setting, which a process started before a policy
# change might not yet observe). Either one reporting FIPS-only is
# treated as FIPS-only.
function Test-FipsOnlyPolicy {
    $fipsFromCryptoConfig = $false
    try {
        $fipsFromCryptoConfig = [System.Security.Cryptography.CryptoConfig]::AllowOnlyFipsAlgorithms
    } catch {
        $fipsFromCryptoConfig = $false
    }

    $fipsFromRegistry = $false
    try {
        $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" -Name "Enabled" -ErrorAction SilentlyContinue
        if ($null -ne $regValue -and $regValue.Enabled -eq 1) {
            $fipsFromRegistry = $true
        }
    } catch {
        $fipsFromRegistry = $false
    }

    return ($fipsFromCryptoConfig -or $fipsFromRegistry)
}

# --- Authenticode self-check (defense in depth ONLY) --------------------
#
# ADR-0012 decision 8 is explicit that this cannot be the security
# boundary: a script that checks its own signature is running code an
# attacker who tampered with the file already had the opportunity to
# delete, so the tampered copy simply omits the check. The real boundary
# is external to this file (a trusted launcher, or Windows App Control /
# WDAC script enforcement validating the signature before any statement
# here runs). This function exists only to catch an honest deployment
# mistake, such as an unsigned or wrong-build copy landing in the wrong
# place, at zero cost, and it is documented as such everywhere it is
# invoked. -SkipSelfCheck bypasses it deliberately, since skipping a
# defense-in-depth check is a legitimate choice for a developer running
# an unsigned working copy and must not be disguised as a security
# decision either way.
function Test-SelfCheckSignature {
    param(
        [string]$ScriptPath,
        [string]$ExpectedSubject,
        [string[]]$ExpectedThumbprints
    )
    $result = [ordered]@{
        Attempted = $true
        Valid = $false
        Reason = ""
    }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $ScriptPath -ErrorAction Stop
    } catch {
        $result.Reason = "could not read an Authenticode signature from this file"
        return $result
    }
    if ($sig.Status -ne "Valid") {
        $result.Reason = "Authenticode signature status is $($sig.Status), not Valid"
        return $result
    }
    if ($null -eq $sig.SignerCertificate) {
        $result.Reason = "signature reported Valid but no signer certificate was returned"
        return $result
    }
    if (-not [string]::IsNullOrEmpty($ExpectedSubject)) {
        if ($sig.SignerCertificate.Subject -ne $ExpectedSubject) {
            $result.Reason = "signer subject does not match the pinned subject"
            return $result
        }
    }
    if ($ExpectedThumbprints -and $ExpectedThumbprints.Count -gt 0) {
        $actualThumbprint = $sig.SignerCertificate.Thumbprint
        $matched = $false
        foreach ($tp in $ExpectedThumbprints) {
            if ($actualThumbprint -eq $tp) { $matched = $true; break }
        }
        if (-not $matched) {
            $result.Reason = "signer thumbprint does not match any pinned thumbprint"
            return $result
        }
    }
    $result.Valid = $true
    return $result
}

# --- Win32 command-line argument quoting --------------------------------
#
# ProcessStartInfo.ArgumentList (which would avoid manual quoting
# entirely) is not present on this host's CLR (confirmed empirically:
# .NET Framework 4.x, which is what Windows PowerShell 5.1 runs on, does
# not have it; it was added in later .NET runtimes only), so .Arguments
# is built as one pre-quoted string instead, using the documented
# Microsoft C runtime argv-quoting algorithm so a path containing a
# space or a literal double quote round-trips correctly. This is applied
# only to this script's own fixed flag names and to file paths the
# operator supplied on its own command line, never to any byte from an
# unverified payload.
function ConvertTo-Win32QuotedArgument {
    param([string]$Value)
    if ($Value.Length -eq 0) { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    $backslashes = 0
    foreach ($ch in $Value.ToCharArray()) {
        if ($ch -eq '\') {
            $backslashes++
            [void]$sb.Append('\')
        } elseif ($ch -eq '"') {
            for ($i = 0; $i -lt $backslashes; $i++) { [void]$sb.Append('\') }
            [void]$sb.Append('\"')
            $backslashes = 0
        } else {
            $backslashes = 0
            [void]$sb.Append($ch)
        }
    }
    for ($i = 0; $i -lt $backslashes; $i++) { [void]$sb.Append('\') }
    [void]$sb.Append('"')
    return $sb.ToString()
}

# --- tokentimer-verify.exe invocation (byte-preserving stdin) -----------
#
# The decoded payload travels to the Go verifier through
# Process.StandardInput.BaseStream, the raw underlying stream beneath
# the StreamWriter PowerShell would otherwise hand back (confirmed
# empirically: BaseStream.Write of an arbitrary byte array, including
# NUL, 0xFF and non-UTF8 sequences, round-trips unchanged through a
# child process's stdin/stdout; the StreamWriter wrapper on top of it
# applies a text encoding and must never be used for this). The
# signature travels as --signature-b64 on argv: base64 text cannot
# contain a NUL or be mistaken for a second flag, so this is safe on
# argv in a way the payload bytes are not (main.go's own header comment
# makes the same argument). This function shells out to exactly one
# process, tokentimer-verify.exe, and never to OpenSSL: PowerShell's half
# of the two-independent-implementations requirement in decision 8 is
# this Go binary, exclusively.
function Invoke-TokenTimerVerify {
    param(
        [string]$VerifierPath,
        [string]$PubkeyPath,
        [string]$SignatureB64,
        [byte[]]$PayloadBytes
    )
    if (-not (Test-Path -LiteralPath $VerifierPath -PathType Leaf)) {
        return @{ ExitCode = 2; StdErr = "verifier binary not found: $VerifierPath" }
    }
    $argString = (ConvertTo-Win32QuotedArgument "--pubkey") + " " + (ConvertTo-Win32QuotedArgument $PubkeyPath) + " " + (ConvertTo-Win32QuotedArgument "--signature-b64") + " " + (ConvertTo-Win32QuotedArgument $SignatureB64)

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $VerifierPath
    $psi.Arguments = $argString
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $proc = $null
    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
    } catch {
        return @{ ExitCode = 2; StdErr = "could not start the verifier process: $($_.Exception.Message)" }
    }

    $stderrTask = $proc.StandardError.ReadToEndAsync()
    $stdoutTask = $proc.StandardOutput.BaseStream

    try {
        $inStream = $proc.StandardInput.BaseStream
        if ($PayloadBytes.Length -gt 0) {
            $inStream.Write($PayloadBytes, 0, $PayloadBytes.Length)
        }
    } finally {
        $proc.StandardInput.Close()
    }

    $outMs = New-Object System.IO.MemoryStream
    $stdoutTask.CopyTo($outMs)
    $proc.WaitForExit()
    $stderrText = $stderrTask.Result

    return @{ ExitCode = $proc.ExitCode; StdErr = $stderrText }
}

# --- server URL validation -----------------------------------------------

function Test-IsLocalhostAuthority {
    param([string]$Authority)
    $host_ = $Authority
    if ($host_.StartsWith("[") -and $host_.EndsWith("]")) {
        $host_ = $host_.Substring(1, $host_.Length - 2)
    }
    $host_ = $host_.ToLowerInvariant()
    if ($host_ -eq "localhost" -or $host_ -eq "::1") { return $true }
    if ($host_.EndsWith(".localhost")) { return $true }
    if ($host_ -match '^127(\.[0-9]{1,3}){3}$') { return $true }
    return $false
}

function Confirm-ServerUrl {
    param([string]$Url, [bool]$AllowInsecureLocal)
    if ($Url -match '^https://[^\s]+$') {
        if ($Url -match '[/?#@]' -and $Url -notmatch '^https://[^/\s]+/?$') {
            Exit-Usage "server URL must not contain credentials, a query, fragment, or path"
        }
        return $Url
    }
    if ($Url -match '^http://([^/\s]+)$') {
        $authority = $Matches[1]
        $hostOnly = $authority -replace ':\d+$', ''
        if ($AllowInsecureLocal -and (Test-IsLocalhostAuthority $hostOnly)) {
            return $Url
        }
    }
    Exit-Usage "server URL must use https:// (http:// is only allowed for an explicit -AllowInsecureLocalHttp localhost target)"
}

# --- credential handling --------------------------------------------------
#
# Unlike the bash client, PowerShell never spawns curl as a subprocess
# for the HTTP steps: the bearer token is set directly on an
# HttpWebRequest's Headers collection inside this same process, so the
# /proc/<pid>/cmdline leak decision 8 warns about for `-H "Authorization:
# ..."` on an external curl's argv does not apply here (there is no
# argv). What still applies is never writing the credential to a log
# line or a --json field.

function Test-SecretFileAcl {
    param([string]$Path)
    # Windows has no direct analogue of Unix mode bits; this is a
    # best-effort advisory warning (never a hard failure, matching the
    # bash client's own check_secret_file_mode) for a secret file whose
    # ACL grants read access to a broad, non-owner principal.
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        foreach ($rule in $acl.Access) {
            if ($rule.AccessControlType -eq "Allow" -and
                ($rule.IdentityReference.Value -match 'Everyone|BUILTIN\\Users|Authenticated Users') -and
                ($rule.FileSystemRights -match 'Read')) {
                Write-Info "warning: $Path grants read access to $($rule.IdentityReference.Value); consider restricting it to the current user only"
            }
        }
    } catch {
        # Advisory only; a failure to read the ACL is not itself an error.
    }
}

function Read-SecretFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Exit-Usage "secret file not found: $Path"
    }
    Test-SecretFileAcl $Path
    $lines = [System.IO.File]::ReadAllLines($Path)
    $value = if ($lines.Length -eq 0) { "" } else { $lines[0] }
    # A secret file saved with the wrong encoding (for example UTF-16
    # without a BOM, which ReadAllLines will misread as a stream of
    # NUL-interleaved bytes) decodes to a .NET string containing
    # embedded control characters. Left unchecked, that string reaches
    # HttpWebRequest.Headers.Add(...) and throws a raw ArgumentException
    # from deep inside .NET, bypassing this script's own Exit-*
    # diagnostic/JSON-summary contract entirely and risking an
    # unhandled-exception dump of unrelated process state. Fail closed
    # here, before the value is ever used, with the same safe
    # usage-error path every other malformed-input case goes through.
    foreach ($ch in $value.ToCharArray()) {
        $code = [int]$ch
        if ($code -lt 0x20 -and $code -ne 0x09) {
            Exit-Usage "secret file at $Path contains a control character; it must be a plain single-line ASCII/UTF-8 text file (check for a wrong save encoding, e.g. UTF-16)"
        }
        if ($code -eq 0x7F) {
            Exit-Usage "secret file at $Path contains a control character; it must be a plain single-line ASCII/UTF-8 text file (check for a wrong save encoding, e.g. UTF-16)"
        }
    }
    return $value
}

function Resolve-AgentCredential {
    param([string]$CredentialFilePath)
    if (-not [string]::IsNullOrEmpty($CredentialFilePath)) {
        return Read-SecretFile $CredentialFilePath
    }
    $envCred = [Environment]::GetEnvironmentVariable("TOKENTIMER_AGENT_CREDENTIAL")
    if (-not [string]::IsNullOrEmpty($envCred)) {
        return $envCred
    }
    Exit-Usage "no credential available: pass -CredentialFile or set TOKENTIMER_AGENT_CREDENTIAL"
}

function Resolve-SessionCookie {
    param([string]$SessionCookieFilePath)
    # The diagnostic-bootstrap route is session-authenticated (an
    # operator action), not a bearer-token agent call: it needs the
    # Cookie header from an already-authenticated operator session, not
    # an agent credential. There is no login flow in this client; the
    # operator obtains this value out of band (their browser session, or
    # their own POST /auth/login call) and hands it to this flag or
    # environment variable, the same way a credential is handed in.
    if (-not [string]::IsNullOrEmpty($SessionCookieFilePath)) {
        return Read-SecretFile $SessionCookieFilePath
    }
    $envCookie = [Environment]::GetEnvironmentVariable("TOKENTIMER_SESSION_COOKIE")
    if (-not [string]::IsNullOrEmpty($envCookie)) {
        return $envCookie
    }
    Exit-Usage "no session cookie available: pass -SessionCookieFile or set TOKENTIMER_SESSION_COOKIE"
}

function Resolve-CsrfToken {
    param([string]$CsrfTokenFilePath)
    # Paired with Resolve-SessionCookie: the control plane's double-
    # submit CSRF check requires this value on X-CSRF-Token in addition
    # to the CSRF cookie already present in the Cookie header above.
    # Fetched by the operator from GET /api/csrf-token using the same
    # session.
    if (-not [string]::IsNullOrEmpty($CsrfTokenFilePath)) {
        return Read-SecretFile $CsrfTokenFilePath
    }
    $envToken = [Environment]::GetEnvironmentVariable("TOKENTIMER_CSRF_TOKEN")
    if (-not [string]::IsNullOrEmpty($envToken)) {
        return $envToken
    }
    Exit-Usage "no CSRF token available: pass -CsrfTokenFile or set TOKENTIMER_CSRF_TOKEN"
}

# --- claim-state file: the explicit, file-based handoff between a
# `claim` invocation and a later, separate `result` invocation -----------
#
# `result` needs the verified jobId/attemptId/claimId/nonce that a prior
# `claim` invocation already confirmed with a passing Ed25519 verdict.
# `-Step all` never needs this because both steps run in the same
# process and the values are already in script-scope variables; two
# separate invocations have no such shared memory, and there is
# deliberately no ambient-environment-variable path for this data: an
# operator's wrapper script, a leaked/inherited environment, or a
# copy-pasted assignment could otherwise plant a jobId a `result` call
# never actually verified, letting it report a fabricated
# dry_run_complete without ever running Confirm-V2Envelope. Requiring an
# explicit -ClaimStateFile (a path the operator names, not a name this
# script picks) makes that injection path structurally unavailable: the
# file's content only ever comes from this script's own
# Write-ClaimState, called only after Confirm-V2Envelope has already
# returned successfully.
#
# The file is a small, non-secret JSON object (job/claim/attempt
# identifiers and a nonce -- none of this is a credential or key
# material); it is not swept or auto-deleted, since a stale claim-state
# file is inert data whose only effect if reused is a `result` call for
# a job already reported, which the control plane's own idempotency at
# the results endpoint handles independently of this script.
function Write-ClaimState {
    param([string]$Path)
    if ([string]::IsNullOrEmpty($Path)) { return }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('{"jobId":"' + (ConvertTo-JsonEscaped $script:VerifiedJobId) + '",')
    [void]$sb.Append('"claimId":"' + (ConvertTo-JsonEscaped $script:VerifiedClaimId) + '",')
    [void]$sb.Append('"attemptId":"' + (ConvertTo-JsonEscaped $script:VerifiedAttemptId) + '",')
    [void]$sb.Append('"nonce":"' + (ConvertTo-JsonEscaped $script:VerifiedNonce) + '",')
    [void]$sb.Append('"agentId":"' + (ConvertTo-JsonEscaped $AgentId) + '"}')
    try {
        [System.IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
    } catch {
        Exit-Pregate "could not write -ClaimStateFile: $Path ($($_.Exception.Message))"
    }
}

function Read-ClaimState {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Exit-Usage "-ClaimStateFile not found: $Path (run -Step claim first, or use -Step all)"
    }
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $parsed = ConvertFrom-SingleJsonValue $bytes
    if ($null -eq $parsed) {
        Exit-Pregate "-ClaimStateFile does not contain exactly one well-formed JSON value"
    }
    $script:VerifiedJobId = Get-JsonStringField $parsed "jobId"
    $script:VerifiedClaimId = Get-JsonStringField $parsed "claimId"
    $script:VerifiedAttemptId = Get-JsonStringField $parsed "attemptId"
    $script:VerifiedNonce = Get-JsonStringField $parsed "nonce"
    $stateAgentId = Get-JsonStringField $parsed "agentId"
    if ([string]::IsNullOrEmpty($script:VerifiedJobId)) {
        Exit-Pregate "-ClaimStateFile is missing jobId"
    }
    if (-not [string]::IsNullOrEmpty($stateAgentId) -and -not [string]::IsNullOrEmpty($AgentId) -and $stateAgentId -ne $AgentId) {
        Exit-Pregate "-ClaimStateFile was written for a different -AgentId than this invocation"
    }
}

# --- HTTP transport (bounded, no redirects, no TLS-insecure escape) ----
#
# AllowAutoRedirect is forced off (a 3xx is a hard failure here, same as
# the bash client's rule) and the response body is read through a
# bounded loop that stops as soon as it has proof of overrun, rather
# than buffering an attacker- or bug-controlled response fully into
# memory first and checking its length afterward.

function Read-BoundedStream {
    param([System.IO.Stream]$Stream, [int]$MaxBytes)
    $buffer = New-Object byte[] 65536
    $ms = New-Object System.IO.MemoryStream
    $total = 0
    $truncated = $false
    while ($true) {
        $read = $Stream.Read($buffer, 0, $buffer.Length)
        if ($read -le 0) { break }
        $ms.Write($buffer, 0, $read)
        $total += $read
        if ($total -gt $MaxBytes) {
            $truncated = $true
            break
        }
    }
    return @{ Bytes = $ms.ToArray(); Truncated = $truncated }
}

function Invoke-BoundedHttpPostJson {
    param(
        [string]$Url,
        [string]$Token,
        [string]$JsonBody,
        [int]$MaxResponseBytes,
        [hashtable]$ExtraHeaders
    )
    $req = [System.Net.HttpWebRequest]::Create($Url)
    $req.Method = "POST"
    $req.ContentType = "application/json"
    $req.AllowAutoRedirect = $false
    $req.Timeout = 30000
    $req.ReadWriteTimeout = 30000
    if (-not [string]::IsNullOrEmpty($Token)) {
        $req.Headers.Add("Authorization", "Bearer $Token")
    }
    if ($null -ne $ExtraHeaders) {
        # The diagnostic-bootstrap step authenticates with a session
        # Cookie and a paired X-CSRF-Token instead of a bearer token
        # (see Resolve-SessionCookie/Resolve-CsrfToken); both travel
        # here, on the request-header collection, never interpolated
        # into argv or a command line.
        foreach ($headerName in $ExtraHeaders.Keys) {
            $req.Headers.Add($headerName, $ExtraHeaders[$headerName])
        }
    }
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($JsonBody)
    $req.ContentLength = $bodyBytes.Length
    try {
        $reqStream = $req.GetRequestStream()
        try {
            $reqStream.Write($bodyBytes, 0, $bodyBytes.Length)
        } finally {
            $reqStream.Close()
        }
    } catch [System.Net.WebException] {
        Exit-Network "control-plane request failed: $($_.Exception.Message)"
    }

    $statusCode = 0
    $bodyResult = $null
    try {
        $resp = $req.GetResponse()
        $statusCode = [int]$resp.StatusCode
        $bodyResult = Read-BoundedStream $resp.GetResponseStream() $MaxResponseBytes
        $resp.Close()
    } catch [System.Net.WebException] {
        $webEx = $_.Exception
        if ($null -ne $webEx.Response) {
            $errResp = [System.Net.HttpWebResponse]$webEx.Response
            $statusCode = [int]$errResp.StatusCode
            $bodyResult = Read-BoundedStream $errResp.GetResponseStream() $MaxResponseBytes
            $errResp.Close()
        } else {
            Exit-Network "control-plane request failed: $($webEx.Message)"
        }
    }

    if ($bodyResult.Truncated) {
        Exit-SizeLimit "control-plane response exceeded $MaxResponseBytes bytes while reading"
    }
    if ($statusCode -ge 300 -and $statusCode -lt 400) {
        Exit-Network "control-plane redirect was refused (HTTP $statusCode)"
    }
    $bodyText = [System.Text.Encoding]::UTF8.GetString($bodyResult.Bytes)
    return @{ StatusCode = $statusCode; Body = $bodyText; BodyBytes = $bodyResult.Bytes }
}

# --- envelope builder (outbound requests) ---------------------------------

function New-RequestId {
    # A fresh UUIDv4 per diagnostic-bootstrap attempt when the operator
    # does not pass -RequestId explicitly. The diagnostic-bootstrap route
    # enforces this id as single-use (workspace_id, request_id) server-
    # side, so a retried request with a fresh id here simply bootstraps a
    # new diagnostic agent rather than colliding with a prior run.
    return [guid]::NewGuid().ToString()
}

function Get-DiagnosticBootstrapPath {
    param([string]$WorkspaceIdValue)
    # The diagnostic-bootstrap route is scoped to one workspace by path
    # segment (apps/api/routes/certops.js), unlike the envelope-based
    # register/heartbeat/claim/results endpoints, which resolve the
    # workspace from the agent's own credential instead.
    return "/api/v1/workspaces/$WorkspaceIdValue/certops/agents/diagnostic-bootstrap"
}

function New-OutboundEnvelope {
    param(
        [string]$MessageType,
        [string]$BodyJson,
        [string]$AgentIdValue
    )
    $sentAt = Get-NowIso8601
    $agentIdOut = if ([string]::IsNullOrEmpty($AgentIdValue)) { "pending" } else { $AgentIdValue }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('{')
    [void]$sb.Append('"schemaVersion":' + $script:SchemaVersion + ',')
    [void]$sb.Append('"protocolVersion":"' + (ConvertTo-JsonEscaped $script:ProtocolVersion) + '",')
    [void]$sb.Append('"messageType":"' + (ConvertTo-JsonEscaped $MessageType) + '",')
    [void]$sb.Append('"agentId":"' + (ConvertTo-JsonEscaped $agentIdOut) + '",')
    [void]$sb.Append('"sentAt":"' + (ConvertTo-JsonEscaped $sentAt) + '",')
    [void]$sb.Append('"body":' + $BodyJson)
    [void]$sb.Append('}')
    return $sb.ToString()
}

# --- decision 2: the normative verification order ------------------------
#
# Mirrors the bash client's verify_v2_envelope, step for step, over the
# same published protocol contract, but through PowerShell's own
# primitives: ConvertFrom-Json (not jq) for JSON, Test-CanonicalBase64
# (not openssl base64 -d -A twice) for the encoding check, and
# Invoke-TokenTimerVerify (not openssl pkeyutl) for the Ed25519 verdict.
# The two independent decodes of the same immutable payloadB64 --
# decision 2's requirement that no parsing happens before a pass verdict
# is known -- are reproduced here: [Convert]::FromBase64String is called
# twice on the same string, once to build the byte array handed to the
# verifier and, only after that verdict is a pass, again to build the
# byte array handed to ConvertFrom-SingleJsonValue. Both calls are pure
# functions of the same input and therefore byte-identical by
# construction.
#
# On success, sets $script:VerifiedPayload / VerifiedJobId / etc. and
# returns normally. On failure, calls Exit-VerifyFailed or Exit-Pregate
# itself and never returns to the caller with a bad verdict.
$script:VerifiedPayload = $null
$script:VerifiedJobId = ""
$script:VerifiedClaimId = ""
$script:VerifiedAttemptId = ""
$script:VerifiedNonce = ""

function Confirm-V2Envelope {
    param(
        [string]$EnvelopeJsonText,
        [string]$PubkeyPath,
        [string]$VerifierExePath,
        [string]$ExpectedKeyId,
        [string]$ExpectedWorkspaceId,
        [string]$ExpectedAgentId,
        [int64]$ClockOffsetMs
    )

    if (Test-FipsOnlyPolicy) {
        Exit-Pregate "this host enforces a FIPS-only cryptographic policy; Ed25519 is not a FIPS-approved algorithm and this client refuses to verify rather than silently using a non-compliant implementation"
    }

    # Step 1: parse and structurally validate the UNSIGNED outer wrapper.
    $envelopeBytes = [System.Text.Encoding]::UTF8.GetBytes($EnvelopeJsonText)
    $wrapper = ConvertFrom-SingleJsonValue $envelopeBytes
    if ($null -eq $wrapper -or $wrapper -isnot [System.Management.Automation.PSCustomObject]) {
        Exit-Pregate "envelope is not exactly one well-formed JSON value"
    }

    $envelopeVersion = Get-JsonIntField $wrapper "envelopeVersion"
    if ($null -eq $envelopeVersion) {
        Exit-Pregate "envelope wrapper is missing envelopeVersion or it is not an integer"
    }
    if ($envelopeVersion -ne 2) {
        Exit-VerifyFailed "unrecognized envelopeVersion (got $envelopeVersion, expected 2); failing closed rather than guessing a format"
    }

    $payloadB64 = Get-JsonStringField $wrapper "payloadB64"
    $signatureB64 = Get-JsonStringField $wrapper "signatureB64"
    $signingKeyIdHint = Get-JsonStringField $wrapper "signingKeyId"
    if ([string]::IsNullOrEmpty($payloadB64) -or [string]::IsNullOrEmpty($signatureB64) -or [string]::IsNullOrEmpty($signingKeyIdHint)) {
        Exit-Pregate "envelope is missing one or more required v2 fields"
    }
    if ($signingKeyIdHint -notmatch $script:IdPattern) {
        Exit-Pregate "envelope signingKeyId does not match the id pattern"
    }

    # Steps 2-4: bound the encoded length, reject alphabet/padding
    # violations, decode, and enforce canonical base64 by re-encode-compare.
    if (-not (Test-CanonicalBase64 $payloadB64 $script:MaxEncodedPayloadChars)) {
        Exit-Pregate "payloadB64 is not canonical base64 or exceeds the encoded-length bound"
    }
    if ($signatureB64.Length -ne 88 -or -not (Test-CanonicalBase64 $signatureB64 88)) {
        Exit-Pregate "signatureB64 is not canonical base64 or is not exactly 88 base64 characters (64 decoded bytes)"
    }

    if (-not (Test-Path -LiteralPath $PubkeyPath -PathType Leaf)) {
        Exit-Pregate "pinned public key file not found: $PubkeyPath"
    }

    # Step 5: decode #1 of payloadB64, handed to the verifier through a
    # byte-preserving binary stream (never the text pipeline).
    $payloadBytesDecode1 = [Convert]::FromBase64String($payloadB64)
    $decodedSize = $payloadBytesDecode1.Length
    if ($decodedSize -gt $script:MaxDecodedPayloadBytes) {
        Exit-Pregate "decoded payload exceeds $($script:MaxDecodedPayloadBytes) bytes"
    }

    $verifyResult = Invoke-TokenTimerVerify -VerifierPath $VerifierExePath -PubkeyPath $PubkeyPath -SignatureB64 $signatureB64 -PayloadBytes $payloadBytesDecode1
    if ($verifyResult.ExitCode -eq 2) {
        Exit-Pregate "verifier usage error: $($verifyResult.StdErr)"
    }
    if ($verifyResult.ExitCode -ne 0) {
        # decision 2: a signature-verdict failure produces no result, no
        # evidence, no lease renewal, and no other post-verdict request.
        Exit-VerifyFailed "Ed25519 signature verification failed"
    }

    # Steps 6-8: only now, with a pass verdict in hand, decode #2 of the
    # same immutable payloadB64 and parse exactly one JSON value.
    $payloadBytesDecode2 = [Convert]::FromBase64String($payloadB64)
    if ($payloadBytesDecode2.Length -ge 3 -and
        $payloadBytesDecode2[0] -eq 0xEF -and $payloadBytesDecode2[1] -eq 0xBB -and $payloadBytesDecode2[2] -eq 0xBF) {
        Exit-Pregate "verified payload begins with a UTF-8 byte-order mark, which decision 2 step 6 rejects"
    }
    $parsedPayload = ConvertFrom-SingleJsonValue $payloadBytesDecode2
    if ($null -eq $parsedPayload -or $parsedPayload -isnot [System.Management.Automation.PSCustomObject]) {
        Exit-Pregate "verified payload is not exactly one well-formed JSON value with no trailing content"
    }

    # Step 9: extract and validate jobId / claimId / nonce / workspaceId.
    $jobId = Get-JsonStringField $parsedPayload "jobId"
    $workspaceId = Get-JsonStringField $parsedPayload "workspaceId"
    $agentId = Get-JsonStringField $parsedPayload "agentId"
    $nonce = Get-JsonStringField $parsedPayload "nonce"
    $claimId = Get-JsonStringField $parsedPayload "claimId"
    $attemptId = Get-JsonStringField $parsedPayload "attemptId"
    $signingKeyId = Get-JsonStringField $parsedPayload "signingKeyId"
    $issuedAt = Get-JsonStringField $parsedPayload "issuedAt"
    $expiresAt = Get-JsonStringField $parsedPayload "expiresAt"
    $action = Get-JsonStringField $parsedPayload "action"
    $mode = Get-JsonStringField $parsedPayload "mode"

    if ([string]::IsNullOrEmpty($jobId) -or $jobId -notmatch $script:IdPattern) {
        Exit-Pregate "verified payload has a missing or malformed jobId"
    }
    if ([string]::IsNullOrEmpty($nonce) -or $nonce.Length -lt 16 -or $nonce.Length -gt 128) {
        Exit-Pregate "verified payload has a missing or malformed nonce"
    }

    # Step 10 (TRUSTED-IDENTITY GATE): confirm the workspace binding.
    if (-not [string]::IsNullOrEmpty($ExpectedWorkspaceId) -and $workspaceId -ne $ExpectedWorkspaceId) {
        Exit-Pregate "verified payload's workspaceId does not match this client's bound workspace"
    }

    # Step 11: validate agentId against the client's own bound identity.
    # The control plane now always emits agentId (PR certops/agent-id-
    # required), so once this client is bound to an expected agent id, an
    # absent agentId is failed closed exactly like a mismatched one
    # rather than silently passing the gate.
    if (-not [string]::IsNullOrEmpty($ExpectedAgentId)) {
        if ([string]::IsNullOrEmpty($agentId)) {
            Exit-Pregate "verified payload is missing agentId; this client requires the control plane to bind every job to an agent identity"
        }
        if ($agentId -ne $ExpectedAgentId) {
            Exit-Pregate "verified payload's agentId does not match this client's bound identity"
        }
    }

    # Step 12: remaining required fields/types/enums (protocol_smoke shape).
    if ($action -ne "protocol_smoke") {
        Exit-Pregate "this reference client only verifies protocol_smoke jobs (got action=$action)"
    }
    if ($mode -ne "dry_run") {
        Exit-Pregate "protocol_smoke jobs must be mode=dry_run (got mode=$mode)"
    }

    # Step 13: the signed signingKeyId must equal the pinned key id, and
    # the wrapper's pre-verification hint must equal the signed copy.
    if ($signingKeyId -ne $signingKeyIdHint) {
        Exit-Pregate "wrapper signingKeyId hint does not match the signed payload's signingKeyId"
    }
    if (-not [string]::IsNullOrEmpty($ExpectedKeyId) -and $signingKeyId -ne $ExpectedKeyId) {
        Exit-Pregate "signed signingKeyId does not match the pinned key id"
    }

    # Step 14: time window, using the heartbeat-derived clock offset.
    $now = Get-NowEpochSeconds
    $offsetSeconds = [int64]($ClockOffsetMs / 1000)
    if (-not [string]::IsNullOrEmpty($issuedAt)) {
        $issuedEpoch = ConvertFrom-Iso8601ToEpochSeconds $issuedAt
        if ($null -ne $issuedEpoch) {
            if (($now + $offsetSeconds + $script:DefaultClockSkewToleranceSeconds) -lt $issuedEpoch) {
                Exit-Pregate "verified payload's issuedAt is in the future beyond clock-skew tolerance"
            }
        }
    }
    if (-not [string]::IsNullOrEmpty($expiresAt)) {
        $expiresEpoch = ConvertFrom-Iso8601ToEpochSeconds $expiresAt
        if ($null -ne $expiresEpoch) {
            if (($now + $offsetSeconds - $script:DefaultClockSkewToleranceSeconds) -gt $expiresEpoch) {
                Exit-Pregate "verified payload's expiresAt is in the past beyond clock-skew tolerance"
            }
        }
    }

    # Step 15: act. This function's job stops at handing back the
    # verified, parsed job object; the caller decides what "act" means.
    $script:VerifiedPayload = $parsedPayload
    $script:VerifiedJobId = $jobId
    $script:VerifiedClaimId = if (-not [string]::IsNullOrEmpty($claimId)) { $claimId } else { $attemptId }
    $script:VerifiedAttemptId = if (-not [string]::IsNullOrEmpty($attemptId)) { $attemptId } else { $claimId }
    $script:VerifiedNonce = $nonce
}

# --- argument validation ---------------------------------------------------

switch ($Step) {
    "verify" {
        if ($Live) { Exit-Usage "-Step verify runs fully offline and does not accept -Live" }
    }
    default {
        if (-not $Live) { Exit-Usage "-Step $Step requires -Live; this client never contacts a server unless told to" }
    }
}

function Get-DefaultVerifierPath {
    $scriptDir = Split-Path -Parent $PSCommandPath
    return Join-Path $scriptDir "verifier\dist\tokentimer-verify.exe"
}

$script:ResolvedVerifierPath = if (-not [string]::IsNullOrEmpty($VerifierPath)) { $VerifierPath } else { Get-DefaultVerifierPath }
$script:AgentIdResolved = $AgentId

function Assert-ServerUrlRequired {
    if ([string]::IsNullOrEmpty($ServerUrl)) {
        Exit-Usage "-ServerUrl is required for -Live steps"
    }
    Confirm-ServerUrl $ServerUrl $AllowInsecureLocalHttp.IsPresent | Out-Null
}

function Invoke-SelfCheckIfNeeded {
    if ($SkipSelfCheck) { return }
    $result = Test-SelfCheckSignature -ScriptPath $PSCommandPath -ExpectedSubject $PinnedSignerSubject -ExpectedThumbprints $PinnedSignerThumbprint
    if (-not $result.Valid) {
        Write-Info "warning: Authenticode self-check did not pass ($($result.Reason)); this is defense in depth only and is not the security boundary (ADR-0012 decision 8) -- continuing"
    }
}

# --- step: register (diagnostic-bootstrap) ---------------------------------
#
# This client only ever produces diagnostic protocol_smoke jobs, so
# registration goes through the session-authenticated diagnostic-
# bootstrap route (ADR-0012 decision 7), never the normal bearer-token
# agent-registration endpoint: the normal path assigns agent_kind =
# 'normal' server-side, which would let this client claim and hold a
# lease on genuine certificate work in a real workspace. The bootstrap
# route is an operator action, not a machine credential call, so this
# step needs a session Cookie and a paired X-CSRF-Token instead of a
# bootstrap token, and it never touches the agent-protocol envelope
# wrapper (schemaVersion/messageType/agentId/sentAt/body): the request
# and response bodies here are the diagnostic-bootstrap route's own
# plain JSON shape (apps/api/services/certops/diagnosticBootstrap.js),
# not the wire protocol New-OutboundEnvelope produces for every other
# step.

function Invoke-StepRegister {
    Assert-ServerUrlRequired
    if ([string]::IsNullOrEmpty($WorkspaceId)) {
        Exit-Usage "-Step register requires -WorkspaceId (the diagnostic-bootstrap route is scoped to one workspace)"
    }
    $sessionCookie = Resolve-SessionCookie $SessionCookieFile
    $csrfToken = Resolve-CsrfToken $CsrfTokenFile
    $reqId = $RequestId
    if ([string]::IsNullOrEmpty($reqId)) { $reqId = New-RequestId }
    $body = '{"requestId":"' + (ConvertTo-JsonEscaped $reqId) + '"}'
    $extraHeaders = @{ "Cookie" = $sessionCookie; "X-CSRF-Token" = $csrfToken }
    $bootstrapPath = Get-DiagnosticBootstrapPath $WorkspaceId
    $result = Invoke-BoundedHttpPostJson -Url ($ServerUrl + $bootstrapPath) -Token "" -JsonBody $body -MaxResponseBytes $script:MaxClaimResponseBytes -ExtraHeaders $extraHeaders
    $sessionCookie = $null
    $csrfToken = $null

    if ($result.StatusCode -ne 200 -and $result.StatusCode -ne 201) {
        Exit-Network "diagnostic bootstrap failed with HTTP $($result.StatusCode)"
    }
    $responseObj = ConvertFrom-SingleJsonValue $result.BodyBytes
    if ($null -eq $responseObj) {
        Exit-Pregate "diagnostic bootstrap response is not valid JSON"
    }
    $responseAgentId = Get-JsonStringField $responseObj "agentId"
    $responseCredential = Get-JsonStringField $responseObj "credential"
    if ([string]::IsNullOrEmpty($responseAgentId) -or $responseAgentId -notmatch $script:IdPattern) {
        Exit-Pregate "diagnostic bootstrap response is missing a valid agentId"
    }
    $script:AgentIdResolved = $responseAgentId
    Add-JsonFieldRaw "ok" "true"
    Add-JsonField "step" "register"
    Add-JsonField "agentId" $responseAgentId
    Write-Info "diagnostic agent bootstrapped as agentId=$responseAgentId"
    if (-not [string]::IsNullOrEmpty($responseCredential)) {
        Write-Info "credential issued (not printed); pass it via -CredentialFile or TOKENTIMER_AGENT_CREDENTIAL for subsequent steps"
    }
    $responseCredential = $null
    Write-JsonSummary
}

# --- step: heartbeat -------------------------------------------------------

function Invoke-StepHeartbeat {
    Assert-ServerUrlRequired
    if ([string]::IsNullOrEmpty($AgentId)) {
        Exit-Usage "-Step heartbeat requires -AgentId"
    }
    $credential = Resolve-AgentCredential $CredentialFile
    # declaredCapabilities is advertised here, not at registration: the
    # diagnostic-bootstrap route (Invoke-StepRegister) has its own fixed
    # request shape (requestId only) and does not accept it. Heartbeat's
    # declaredCapabilities is three-valued and re-sent on every heartbeat
    # (ADR-0002 addendum), so this is the first and every subsequent
    # declaration point for this client. agent-id-binding-v1 asserts
    # this client's step-11 identity gate fails closed on an absent
    # agentId, not only a mismatched one (see Confirm-V2Envelope).
    $body = '{"agentVersion":"' + (ConvertTo-JsonEscaped $AgentVersion) + '","declaredCapabilities":["signed-payload-b64-v1","agent-id-binding-v1"]}'
    $envelope = New-OutboundEnvelope -MessageType "heartbeat" -BodyJson $body -AgentIdValue $AgentId
    $result = Invoke-BoundedHttpPostJson -Url ($ServerUrl + $script:HeartbeatPath) -Token $credential -JsonBody $envelope -MaxResponseBytes $script:MaxClaimResponseBytes
    $credential = $null

    if ($result.StatusCode -eq 410) {
        Add-JsonFieldRaw "ok" "true"
        Add-JsonField "step" "heartbeat"
        Add-JsonFieldRaw "retired" "true"
        Write-Info "agent is retired (HTTP 410)"
        Write-JsonSummary
        return
    }
    if ($result.StatusCode -ne 200) {
        Exit-Network "heartbeat failed with HTTP $($result.StatusCode)"
    }
    Add-JsonFieldRaw "ok" "true"
    Add-JsonField "step" "heartbeat"
    Write-Info "heartbeat accepted"
    Write-JsonSummary
}

# --- step: claim (and verify each job returned) -----------------------------
#
# ConvertFrom-Json's PSCustomObject unwraps a one-element JSON array back
# to a bare scalar the moment it crosses an `if`-expression assignment or
# a function `return` (confirmed empirically: `$x = if (...) { @(1) }`
# yields a scalar 1, not a one-element array, and `return @(1)` from a
# function has the same behavior on the caller's side), which would make
# `.jobs[0]` silently equivalent to `.jobs` whenever exactly one job comes
# back -- precisely the common case. The comma operator forces PowerShell
# to treat the return value as a single array argument rather than
# flattening it, which is the documented workaround for this behavior.
function Get-JobsArray {
    param($JobsProp)
    $list = New-Object 'System.Collections.Generic.List[object]'
    if ($null -ne $JobsProp) {
        foreach ($item in @($JobsProp.Value)) { $list.Add($item) }
    }
    return , $list
}

function Invoke-StepClaim {
    Assert-ServerUrlRequired
    if ([string]::IsNullOrEmpty($AgentId)) {
        Exit-Usage "-Step claim requires -AgentId"
    }
    if ([string]::IsNullOrEmpty($Pubkey)) {
        Exit-Usage "-Step claim requires -Pubkey to verify any returned job"
    }
    $credential = Resolve-AgentCredential $CredentialFile
    # supportedActions declares which wire actions this client can handle;
    # the server's claim matcher only returns jobs whose operation is in
    # this list (agentDispatch.js claimJobs). This client only ever
    # verifies/reports protocol_smoke, so that is the only action it may
    # declare -- "noop" is a real but unrelated wire action this client
    # never implements, and declaring it here meant claim always matched
    # zero jobs.
    $body = '{"maxJobs":1,"supportedActions":["protocol_smoke"]}'
    $envelope = New-OutboundEnvelope -MessageType "claim" -BodyJson $body -AgentIdValue $AgentId
    $result = Invoke-BoundedHttpPostJson -Url ($ServerUrl + $script:ClaimPath) -Token $credential -JsonBody $envelope -MaxResponseBytes $script:MaxClaimResponseBytes
    $credential = $null

    if ($result.StatusCode -ne 200) {
        Exit-Network "claim failed with HTTP $($result.StatusCode)"
    }
    $responseObj = ConvertFrom-SingleJsonValue $result.BodyBytes
    if ($null -eq $responseObj) {
        Exit-Pregate "claim response is not valid JSON"
    }
    $jobsProp = $responseObj.PSObject.Properties["jobs"]
    $jobs = Get-JobsArray $jobsProp
    Add-JsonField "step" "claim"
    Add-JsonFieldRaw "jobsReturned" $jobs.Count
    if ($jobs.Count -eq 0) {
        Add-JsonFieldRaw "ok" "true"
        Write-Info "no jobs available"
        Write-JsonSummary
        return
    }
    $envelopeJson = $jobs[0] | ConvertTo-Json -Compress -Depth 20
    Confirm-V2Envelope -EnvelopeJsonText $envelopeJson -PubkeyPath $Pubkey -VerifierExePath $script:ResolvedVerifierPath -ExpectedKeyId $SigningKeyId -ExpectedWorkspaceId $WorkspaceId -ExpectedAgentId $AgentId -ClockOffsetMs 0
    Write-ClaimState $ClaimStateFile
    Add-JsonFieldRaw "ok" "true"
    Add-JsonFieldRaw "verified" "true"
    Add-JsonField "jobId" $script:VerifiedJobId
    Write-Info "claimed and verified jobId=$($script:VerifiedJobId)"
    Write-JsonSummary
}

# --- step: verify (fully offline) -------------------------------------------

function Invoke-StepVerify {
    if ([string]::IsNullOrEmpty($Pubkey)) {
        Exit-Usage "-Step verify requires -Pubkey"
    }
    [byte[]]$envelopeBytes = $null
    if (-not [string]::IsNullOrEmpty($EnvelopeFile)) {
        if (-not (Test-Path -LiteralPath $EnvelopeFile -PathType Leaf)) {
            Exit-Usage "-EnvelopeFile not found: $EnvelopeFile"
        }
        $envelopeBytes = [System.IO.File]::ReadAllBytes($EnvelopeFile)
    } else {
        $stdinStream = [Console]::OpenStandardInput()
        $ms = New-Object System.IO.MemoryStream
        $stdinStream.CopyTo($ms)
        $envelopeBytes = $ms.ToArray()
    }
    $envelopeText = [System.Text.Encoding]::UTF8.GetString($envelopeBytes)
    Confirm-V2Envelope -EnvelopeJsonText $envelopeText -PubkeyPath $Pubkey -VerifierExePath $script:ResolvedVerifierPath -ExpectedKeyId $SigningKeyId -ExpectedWorkspaceId $WorkspaceId -ExpectedAgentId $AgentId -ClockOffsetMs 0
    Add-JsonFieldRaw "ok" "true"
    Add-JsonField "step" "verify"
    Add-JsonFieldRaw "verified" "true"
    Add-JsonField "jobId" $script:VerifiedJobId
    Write-Info "signature verified; jobId=$($script:VerifiedJobId)"
    Write-JsonSummary
}

# --- step: result ------------------------------------------------------------

function Invoke-StepResult {
    Assert-ServerUrlRequired
    if ([string]::IsNullOrEmpty($AgentId)) {
        Exit-Usage "-Step result requires -AgentId"
    }
    # A standalone `result` invocation is always a fresh process, so
    # $script:VerifiedJobId is never already populated here (that only
    # happens inside Invoke-StepAll, which never calls Invoke-StepResult
    # directly -- it inlines the same logic itself). -ClaimStateFile is
    # therefore mandatory: see Write-ClaimState/Read-ClaimState's header
    # comment for why there is deliberately no environment-variable
    # equivalent.
    if ([string]::IsNullOrEmpty($ClaimStateFile)) {
        Exit-Usage "-Step result requires -ClaimStateFile (the file -Step claim wrote), or use -Step all to claim and report in one run"
    }
    Read-ClaimState $ClaimStateFile
    $credential = Resolve-AgentCredential $CredentialFile
    $attemptIdOut = if (-not [string]::IsNullOrEmpty($script:VerifiedAttemptId)) { $script:VerifiedAttemptId } else { $script:VerifiedJobId }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('{"jobId":"' + (ConvertTo-JsonEscaped $script:VerifiedJobId) + '",')
    [void]$sb.Append('"attemptId":"' + (ConvertTo-JsonEscaped $attemptIdOut) + '",')
    [void]$sb.Append('"status":"dry_run_complete"')
    if (-not [string]::IsNullOrEmpty($script:VerifiedClaimId)) {
        [void]$sb.Append(',"claimId":"' + (ConvertTo-JsonEscaped $script:VerifiedClaimId) + '"')
    }
    if (-not [string]::IsNullOrEmpty($script:VerifiedNonce)) {
        [void]$sb.Append(',"nonce":"' + (ConvertTo-JsonEscaped $script:VerifiedNonce) + '"')
    }
    [void]$sb.Append('}')
    $body = $sb.ToString()
    $envelope = New-OutboundEnvelope -MessageType "result" -BodyJson $body -AgentIdValue $AgentId
    $result = Invoke-BoundedHttpPostJson -Url ($ServerUrl + $script:ResultsPath) -Token $credential -JsonBody $envelope -MaxResponseBytes $script:MaxClaimResponseBytes
    $credential = $null

    if ($result.StatusCode -ne 200 -and $result.StatusCode -ne 201) {
        Exit-Network "result report failed with HTTP $($result.StatusCode)"
    }
    Add-JsonFieldRaw "ok" "true"
    Add-JsonField "step" "result"
    Add-JsonField "jobId" $script:VerifiedJobId
    Write-Info "result reported for jobId=$($script:VerifiedJobId)"
    Write-JsonSummary
}

# --- step: all ---------------------------------------------------------------

function Invoke-StepAll {
    Assert-ServerUrlRequired
    if ([string]::IsNullOrEmpty($WorkspaceId)) {
        Exit-Usage "-Step all requires -WorkspaceId (the diagnostic-bootstrap route is scoped to one workspace)"
    }
    if ([string]::IsNullOrEmpty($Pubkey)) {
        Exit-Usage "-Step all requires -Pubkey"
    }

    $sessionCookie = Resolve-SessionCookie $SessionCookieFile
    $csrfToken = Resolve-CsrfToken $CsrfTokenFile
    $reqId = $RequestId
    if ([string]::IsNullOrEmpty($reqId)) { $reqId = New-RequestId }
    $registerBody = '{"requestId":"' + (ConvertTo-JsonEscaped $reqId) + '"}'
    $registerExtraHeaders = @{ "Cookie" = $sessionCookie; "X-CSRF-Token" = $csrfToken }
    $bootstrapPath = Get-DiagnosticBootstrapPath $WorkspaceId
    $registerResult = Invoke-BoundedHttpPostJson -Url ($ServerUrl + $bootstrapPath) -Token "" -JsonBody $registerBody -MaxResponseBytes $script:MaxClaimResponseBytes -ExtraHeaders $registerExtraHeaders
    $sessionCookie = $null
    $csrfToken = $null
    if ($registerResult.StatusCode -ne 200 -and $registerResult.StatusCode -ne 201) {
        Exit-Network "diagnostic bootstrap failed with HTTP $($registerResult.StatusCode)"
    }
    $registerResponseObj = ConvertFrom-SingleJsonValue $registerResult.BodyBytes
    if ($null -eq $registerResponseObj) {
        Exit-Pregate "diagnostic bootstrap response is not valid JSON"
    }
    $resolvedAgentId = Get-JsonStringField $registerResponseObj "agentId"
    $credential = Get-JsonStringField $registerResponseObj "credential"
    if ([string]::IsNullOrEmpty($resolvedAgentId) -or $resolvedAgentId -notmatch $script:IdPattern) {
        Exit-Pregate "diagnostic bootstrap response is missing a valid agentId"
    }
    if ([string]::IsNullOrEmpty($credential)) {
        Exit-Pregate "diagnostic bootstrap response is missing a credential"
    }
    Write-Info "diagnostic agent bootstrapped as agentId=$resolvedAgentId"

    # declaredCapabilities is advertised on heartbeat, not at bootstrap
    # (see Invoke-StepHeartbeat's comment): agent-id-binding-v1 asserts
    # this client's step-11 identity gate fails closed on an absent
    # agentId, not only a mismatched one.
    $heartbeatBody = '{"agentVersion":"' + (ConvertTo-JsonEscaped $AgentVersion) + '","declaredCapabilities":["signed-payload-b64-v1","agent-id-binding-v1"]}'
    $heartbeatEnvelope = New-OutboundEnvelope -MessageType "heartbeat" -BodyJson $heartbeatBody -AgentIdValue $resolvedAgentId
    $heartbeatResult = Invoke-BoundedHttpPostJson -Url ($ServerUrl + $script:HeartbeatPath) -Token $credential -JsonBody $heartbeatEnvelope -MaxResponseBytes $script:MaxClaimResponseBytes
    if ($heartbeatResult.StatusCode -ne 200) {
        $credential = $null
        Exit-Network "heartbeat failed with HTTP $($heartbeatResult.StatusCode)"
    }
    Write-Info "heartbeat accepted"

    $claimBody = '{"maxJobs":1,"supportedActions":["protocol_smoke"]}'
    $claimEnvelope = New-OutboundEnvelope -MessageType "claim" -BodyJson $claimBody -AgentIdValue $resolvedAgentId
    $claimResult = Invoke-BoundedHttpPostJson -Url ($ServerUrl + $script:ClaimPath) -Token $credential -JsonBody $claimEnvelope -MaxResponseBytes $script:MaxClaimResponseBytes
    if ($claimResult.StatusCode -ne 200) {
        $credential = $null
        Exit-Network "claim failed with HTTP $($claimResult.StatusCode)"
    }
    $claimResponseObj = ConvertFrom-SingleJsonValue $claimResult.BodyBytes
    if ($null -eq $claimResponseObj) {
        $credential = $null
        Exit-Pregate "claim response is not valid JSON"
    }
    $jobsProp = $claimResponseObj.PSObject.Properties["jobs"]
    $jobs = Get-JobsArray $jobsProp
    if ($jobs.Count -eq 0) {
        Add-JsonFieldRaw "ok" "true"
        Add-JsonField "step" "all"
        Add-JsonField "agentId" $resolvedAgentId
        Add-JsonFieldRaw "jobsReturned" "0"
        Write-Info "no protocol_smoke job was available to verify"
        $credential = $null
        Write-JsonSummary
        return
    }
    $envelopeJson = $jobs[0] | ConvertTo-Json -Compress -Depth 20
    Confirm-V2Envelope -EnvelopeJsonText $envelopeJson -PubkeyPath $Pubkey -VerifierExePath $script:ResolvedVerifierPath -ExpectedKeyId $SigningKeyId -ExpectedWorkspaceId $WorkspaceId -ExpectedAgentId $resolvedAgentId -ClockOffsetMs 0
    Write-Info "claimed and verified jobId=$($script:VerifiedJobId)"

    $attemptIdOut = if (-not [string]::IsNullOrEmpty($script:VerifiedAttemptId)) { $script:VerifiedAttemptId } else { $script:VerifiedJobId }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('{"jobId":"' + (ConvertTo-JsonEscaped $script:VerifiedJobId) + '",')
    [void]$sb.Append('"attemptId":"' + (ConvertTo-JsonEscaped $attemptIdOut) + '",')
    [void]$sb.Append('"status":"dry_run_complete"')
    if (-not [string]::IsNullOrEmpty($script:VerifiedClaimId)) {
        [void]$sb.Append(',"claimId":"' + (ConvertTo-JsonEscaped $script:VerifiedClaimId) + '"')
    }
    if (-not [string]::IsNullOrEmpty($script:VerifiedNonce)) {
        [void]$sb.Append(',"nonce":"' + (ConvertTo-JsonEscaped $script:VerifiedNonce) + '"')
    }
    [void]$sb.Append('}')
    $resultBody = $sb.ToString()
    $resultEnvelope = New-OutboundEnvelope -MessageType "result" -BodyJson $resultBody -AgentIdValue $resolvedAgentId
    $resultResult = Invoke-BoundedHttpPostJson -Url ($ServerUrl + $script:ResultsPath) -Token $credential -JsonBody $resultEnvelope -MaxResponseBytes $script:MaxClaimResponseBytes
    $credential = $null
    if ($resultResult.StatusCode -ne 200 -and $resultResult.StatusCode -ne 201) {
        Exit-Network "result report failed with HTTP $($resultResult.StatusCode)"
    }

    Add-JsonFieldRaw "ok" "true"
    Add-JsonField "step" "all"
    Add-JsonField "agentId" $resolvedAgentId
    Add-JsonField "jobId" $script:VerifiedJobId
    Add-JsonFieldRaw "verified" "true"
    Add-JsonFieldRaw "reported" "true"
    Write-Info "reported dry_run_complete for jobId=$($script:VerifiedJobId)"
    Write-JsonSummary
}

# --- main ----------------------------------------------------------------

Invoke-SelfCheckIfNeeded

switch ($Step) {
    "register" { Invoke-StepRegister }
    "heartbeat" { Invoke-StepHeartbeat }
    "claim" { Invoke-StepClaim }
    "verify" { Invoke-StepVerify }
    "result" { Invoke-StepResult }
    "all" { Invoke-StepAll }
}

exit $ExitOk


#requires -version 7
<#
.SYNOPSIS
  tokentimer-protocol.ps1 - PowerShell 7+ reference client for the CertOps
  agent protocol (ADR-0002/0003). Mirrors tokentimer-protocol.sh's flag
  contract exactly (-Mode, -Step, -Execute, -Json) so both scripts can
  be read/compared side by side. See docs/certops/agent.md and
  docs/adr/0002-certops-agent-protocol.md for the wire contract.

.DESCRIPTION
  Purpose: a portable, auditable reference implementation
  for Windows operators/integrators without a Bash environment. NOT a
  production agent replacement: no retry policy, no persistent
  claim/lease loop, no execution.

  Mandatory Ed25519 verification: this script never ships a switch that
  skips signature verification. PowerShell's native crypto surface
  (System.Security.Cryptography) does not yet reliably expose Ed25519
  across supported Windows PowerShell 7 runtimes, so -Step verify shells
  out to the pinned Node 22 helper (reference/lib/canonicalize.cjs, itself
  a thin wrapper around packages/agent/src/signing/index.js -- the SAME
  verifier the production agent uses) rather than reimplementing Ed25519
  verification in .NET. This is the "pinned Node 22 helper" this issue's
  scope calls for; the failure mode when Node is missing/too old is a
  clear, named, fail-closed error, never a silent weaker fallback.

.PARAMETER Mode
  "executor" or "agent". Required, no default.

.PARAMETER Step
  all | register | heartbeat | claim | result | verify. Required, no default.
  "verify" is local-only (no network call). "all" walks
  register -> heartbeat -> claim -> result in sequence, plus verify if
  -JobFile is also given.

.EXAMPLE
  ./tokentimer-protocol.ps1 -Mode agent -Step register -ApiUrl https://example.test -Json

.EXAMPLE
  ./tokentimer-protocol.ps1 -Mode agent -Step verify -JobFile job.json -PubKeyFile pub.pem -SigningKeyId signing-key-1

.EXAMPLE
  ./tokentimer-protocol.ps1 -Mode agent -Step all -ApiUrl https://example.test -JobFile job.json -PubKeyFile pub.pem -SigningKeyId signing-key-1
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("executor", "agent")]
  [string]$Mode,

  [Parameter(Mandatory = $true)]
  [ValidateSet("all", "register", "heartbeat", "claim", "result", "verify")]
  [string]$Step,

  [string]$ApiUrl,
  [string]$WorkspaceId,
  [string]$AgentId,
  [string]$ProtocolVersion = "1.0.0",
  [string]$BootstrapTokenFile,
  [string]$CredentialFile,
  [string]$JobFile,
  [string]$PubKeyFile,
  [string]$SigningKeyId,
  [string]$JobId,
  [string]$AttemptId,
  [ValidateSet("succeeded", "failed", "rejected", "dry_run_complete", "orphaned_unknown_effect")]
  [string]$ResultStatus,
  [string]$RejectionReason,
  [Nullable[bool]]$KeyRotated,
  [string]$ErrorMessageText,
  [string]$CaBundle,
  [switch]$Execute,
  [switch]$Json
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$script:LastVerifyAllowed = $false
$script:LastRequestOk = $false

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CanonicalizeJs = Join-Path $ScriptDir "lib/canonicalize.cjs"
# packages/agent/package.json engines.node ">=22.0.0 <25.0.0" (kept in sync
# manually with that file; both express the same "pinned Node 22" contract).
$RequiredNodeMajor = 22

function Write-Log {
  param([string]$Message)
  if (-not $Json) {
    Write-Host "tokentimer-protocol: $Message" -ForegroundColor DarkGray
  }
}

function Fail {
  param([string]$Message)
  Write-Error "tokentimer-protocol: ERROR: $Message" -ErrorAction Continue
  exit 1
}

function Assert-PinnedNode {
  $nodeCmd = Get-Command node -ErrorAction SilentlyContinue
  if (-not $nodeCmd) {
    Fail "node is required (pinned Node $RequiredNodeMajor+) for mandatory Ed25519 signature verification; none found on PATH"
  }
  $versionOutput = & node -v
  if ($versionOutput -notmatch '^v(\d+)\.') {
    Fail "could not parse Node version from 'node -v' output: $versionOutput"
  }
  $major = [int]$Matches[1]
  if ($major -lt $RequiredNodeMajor) {
    Fail "Node $versionOutput is too old; this script requires the pinned Node $RequiredNodeMajor+ helper (see packages/agent/package.json engines.node)"
  }
  Write-Log "Node check ok: $versionOutput"
}

function Read-SecretFile {
  param([string]$Path, [string]$Label)
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    Fail "$Label file not found: $Path"
  }
  # Windows ACLs, not POSIX mode bits: best-effort check that no principal
  # beyond the owner/Administrators/SYSTEM has explicit access, mirroring
  # (in spirit, not bytes) install-agent.sh's `chmod 600` gate on POSIX.
  $acl = Get-Acl -LiteralPath $Path
  $unexpected = $acl.Access | Where-Object {
    $_.IdentityReference.Value -notmatch '\\(Administrators|SYSTEM)$' -and
    $_.IdentityReference.Value -ne $acl.Owner
  }
  if ($unexpected) {
    $names = ($unexpected | ForEach-Object { $_.IdentityReference.Value }) -join ", "
    Write-Log "WARNING: $Label file $Path grants access to additional principals: $names (expected owner/Administrators/SYSTEM only)"
  }
  $value = (Get-Content -LiteralPath $Path -Raw).Trim()
  if ([string]::IsNullOrEmpty($value)) {
    Fail "$Label file $Path is empty"
  }
  return $value
}

function Resolve-BootstrapToken {
  if ($BootstrapTokenFile) { return Read-SecretFile -Path $BootstrapTokenFile -Label "bootstrap token" }
  if ($env:TOKENTIMER_AGENT_BOOTSTRAP_TOKEN) { return $env:TOKENTIMER_AGENT_BOOTSTRAP_TOKEN }
  if (-not $Execute) {
    Write-Log "no bootstrap token supplied; dry-run preview only (a real -Execute run requires `$env:TOKENTIMER_AGENT_BOOTSTRAP_TOKEN or -BootstrapTokenFile)"
    return "<no-bootstrap-token-dry-run-only>"
  }
  Fail "no bootstrap token: set `$env:TOKENTIMER_AGENT_BOOTSTRAP_TOKEN or pass -BootstrapTokenFile (never as a plain argument value)"
}

function Resolve-Credential {
  if ($CredentialFile) { return Read-SecretFile -Path $CredentialFile -Label "credential" }
  if ($env:TOKENTIMER_AGENT_CREDENTIAL) { return $env:TOKENTIMER_AGENT_CREDENTIAL }
  if (-not $Execute) {
    Write-Log "no credential supplied; dry-run preview only (a real -Execute run requires `$env:TOKENTIMER_AGENT_CREDENTIAL or -CredentialFile)"
    return "<no-credential-dry-run-only>"
  }
  Fail "no credential: set `$env:TOKENTIMER_AGENT_CREDENTIAL or pass -CredentialFile (never as a plain argument value)"
}

function New-RandomId {
  # 32 lowercase-hex chars; matches the Bash script's openssl-rand-based id
  # shape for reference-client demo purposes only, not a production nonce.
  -join ((1..16) | ForEach-Object { "{0:x2}" -f (Get-Random -Maximum 256) })
}

function Get-IsoNow {
  (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

function Get-RouteForStep {
  param([string]$StepName)
  switch ("$Mode`:$StepName") {
    "executor:register" { "/api/v1/certops/executor/observations" }
    "agent:register"     { "/api/v1/certops/agent/register" }
    "agent:heartbeat"    { "/api/v1/certops/agent/heartbeat" }
    "agent:claim"        { "/api/v1/certops/agent/jobs/claim" }
    "agent:result"       { "/api/v1/certops/agent/jobs/results" }
    default {
      Fail "no known route for -Mode $Mode -Step $StepName (executor mode only documents register/observations here; heartbeat/claim/result are agent-mode-only surfaces)"
    }
  }
}

<#
.SYNOPSIS
  Runs the "verify" step. Prints the {"allowed":...} JSON result and sets
  $script:LastVerifyAllowed rather than using `return`, because assigning
  a function's return value in PowerShell (`$x = Invoke-Verify`) captures
  EVERYTHING the function writes to the success/output stream -- including
  Write-Output calls made for -Json -- not just the explicit `return`
  value. Callers that need the result call this as a bare statement (so
  Write-Output reaches real stdout) and then read $script:LastVerifyAllowed.
#>
function Invoke-Verify {
  if (-not $JobFile) { Fail "-JobFile is required for -Step verify" }
  if (-not $PubKeyFile) { Fail "-PubKeyFile is required for -Step verify" }
  if (-not $SigningKeyId) { Fail "-SigningKeyId is required for -Step verify" }
  if (-not (Test-Path -LiteralPath $JobFile -PathType Leaf)) { Fail "job file not found: $JobFile" }
  if (-not (Test-Path -LiteralPath $PubKeyFile -PathType Leaf)) { Fail "public key file not found: $PubKeyFile" }
  Assert-PinnedNode

  $result = & node $CanonicalizeJs verify $JobFile $PubKeyFile $SigningKeyId 2>&1
  $exitCode = $LASTEXITCODE
  if ($exitCode -eq 2) {
    Fail "canonicalize.cjs verify failed: $result"
  }

  $parsed = $result | ConvertFrom-Json
  if ($Json) {
    Write-Output $result
  } elseif ($parsed.allowed) {
    Write-Log "Signature OK: job is signed by the pinned key ($SigningKeyId) and matches its canonical payload."
  } else {
    Write-Log "REJECTED: $($parsed.rejectionReason) -- $($parsed.detail)"
  }
  $script:LastVerifyAllowed = [bool]$parsed.allowed
}

function Build-ExecutorRegisterBody {
  [ordered]@{
    schemaVersion = 1
    workspaceId   = $WorkspaceId
    apiTokenId    = "reference-client-demo"
  }
}

function Build-AgentRegisterBody {
  $registrationId = "ref-$(New-RandomId)"
  $resolvedAgentId = if ($AgentId) { $AgentId } else { "ref-agent-$(New-RandomId)" }
  [ordered]@{
    schemaVersion   = 1
    protocolVersion = $ProtocolVersion
    messageType     = "register"
    agentId         = $resolvedAgentId
    sentAt          = Get-IsoNow
    body            = [ordered]@{
      bootstrapTokenId = "reference-client-demo"
      agentVersion     = "reference-client"
      registrationId   = $registrationId
    }
  }
}

function Build-AgentHeartbeatBody {
  if (-not $AgentId) { Fail "-AgentId is required for -Mode agent -Step heartbeat" }
  [ordered]@{
    schemaVersion   = 1
    protocolVersion = $ProtocolVersion
    messageType     = "heartbeat"
    agentId         = $AgentId
    sentAt          = Get-IsoNow
    body            = [ordered]@{ agentVersion = "reference-client" }
  }
}

function Build-AgentClaimBody {
  if (-not $AgentId) { Fail "-AgentId is required for -Mode agent -Step claim" }
  [ordered]@{
    schemaVersion   = 1
    protocolVersion = $ProtocolVersion
    messageType     = "claim"
    agentId         = $AgentId
    sentAt          = Get-IsoNow
    body            = [ordered]@{ maxJobs = 1 }
  }
}

function Build-AgentResultBody {
  if (-not $AgentId) { Fail "-AgentId is required for -Mode agent -Step result" }
  if (-not $JobId) { Fail "-JobId is required for -Mode agent -Step result (or pass -JobFile to source it)" }
  if (-not $AttemptId) { Fail "-AttemptId is required for -Mode agent -Step result" }
  if (-not $ResultStatus) { Fail "-ResultStatus is required for -Mode agent -Step result" }
  [ordered]@{
    schemaVersion   = 1
    protocolVersion = $ProtocolVersion
    messageType     = "result"
    agentId         = $AgentId
    sentAt          = Get-IsoNow
    body            = [ordered]@{
      jobId           = $JobId
      attemptId       = $AttemptId
      status          = $ResultStatus
      rejectionReason = if ($RejectionReason) { $RejectionReason } else { $null }
      keyRotated      = $KeyRotated
      errorMessage    = if ($ErrorMessageText) { $ErrorMessageText } else { $null }
    }
  }
}

function Invoke-ProtocolRequest {
  param([string]$StepName, [System.Collections.Specialized.OrderedDictionary]$Body, [string]$AuthHeader)

  $route = Get-RouteForStep -StepName $StepName
  $url = "$($ApiUrl.TrimEnd('/'))$route"
  $bodyJson = $Body | ConvertTo-Json -Depth 10 -Compress

  if (-not $Execute) {
    if ($Json) {
      $dryRun = [ordered]@{ dryRun = $true; method = "POST"; url = $url; body = $Body }
      Write-Output ($dryRun | ConvertTo-Json -Depth 10 -Compress)
    } else {
      Write-Log "[dry-run] POST $url"
      Write-Log "[dry-run] Authorization: Bearer <redacted>"
      Write-Log "[dry-run] body: $bodyJson"
    }
    $script:LastRequestOk = $true
    return
  }

  $headers = @{ Authorization = "Bearer $AuthHeader"; "Content-Type" = "application/json" }
  $invokeArgs = @{
    Uri                = $url
    Method              = "Post"
    Headers             = $headers
    Body                = $bodyJson
    ContentType         = "application/json"
    SkipHttpErrorCheck  = $true
    StatusCodeVariable  = "statusCode"
  }
  if ($CaBundle) {
    # Invoke-RestMethod has no direct --cacert equivalent; -SslProtocol/cert
    # pinning is out of scope for this reference client, so surface a clear
    # limitation instead of silently ignoring -CaBundle.
    Write-Log "WARNING: -CaBundle is not applied by this PowerShell client's HTTP call (Invoke-RestMethod has no direct CA-bundle override); use the Bash reference client's --ca-bundle, or trust the CA in the Windows certificate store, for a private-CA control plane."
  }

  $response = Invoke-RestMethod @invokeArgs
  if ($Json) {
    Write-Output ($response | ConvertTo-Json -Depth 10 -Compress)
  } else {
    Write-Log "HTTP $statusCode"
    Write-Log ($response | ConvertTo-Json -Depth 10 -Compress)
  }
  # See Invoke-Verify's doc comment: set a script-scoped variable instead
  # of `return`ing this, so callers can invoke this as a bare statement
  # (letting the Write-Output calls above reach real stdout) rather than
  # via `$ok = Invoke-ProtocolRequest ...`, which would swallow them.
  $script:LastRequestOk = ($statusCode -ge 200 -and $statusCode -lt 300)
}

function Invoke-Step {
  param([string]$StepName)

  $body = $null
  $authHeader = $null
  switch ("$Mode`:$StepName") {
    "executor:register" {
      if (-not $WorkspaceId) { Fail "-WorkspaceId is required for -Mode executor -Step register" }
      $authHeader = Resolve-BootstrapToken
      $body = Build-ExecutorRegisterBody
    }
    "agent:register" {
      $authHeader = Resolve-BootstrapToken
      $body = Build-AgentRegisterBody
    }
    "agent:heartbeat" {
      $authHeader = Resolve-Credential
      $body = Build-AgentHeartbeatBody
    }
    "agent:claim" {
      $authHeader = Resolve-Credential
      $body = Build-AgentClaimBody
    }
    "agent:result" {
      $authHeader = Resolve-Credential
      $body = Build-AgentResultBody
    }
    default {
      Fail "unsupported combination: -Mode $Mode -Step $StepName"
    }
  }

  Invoke-ProtocolRequest -StepName $StepName -Body $body -AuthHeader $authHeader
}

function Invoke-All {
  if ($Mode -ne "agent") {
    Fail "-Step all is only defined for -Mode agent (executor mode has a single register step; call it directly with -Step register)"
  }
  if (-not $AgentId) {
    $script:AgentId = "ref-agent-$(New-RandomId)"
    Write-Log "generated -AgentId $AgentId for this 'all' run (pass -AgentId explicitly to reuse an existing registration)"
  }
  # Source job-id/attempt-id/signing-key-id defaults from -JobFile when the
  # operator did not pass them explicitly, so "all -JobFile X" is a
  # complete, self-contained walkthrough.
  if ($JobFile -and (Test-Path -LiteralPath $JobFile -PathType Leaf)) {
    Assert-PinnedNode
    if (-not $JobId) {
      $script:JobId = & node $CanonicalizeJs extract-field $JobFile jobId 2>$null
    }
    if (-not $AttemptId) {
      $script:AttemptId = "ref-attempt-$(New-RandomId)"
    }
    if (-not $SigningKeyId) {
      $script:SigningKeyId = & node $CanonicalizeJs extract-field $JobFile signingKeyId 2>$null
    }
  }
  if (-not $JobId) { $script:JobId = "ref-job-$(New-RandomId)" }
  if (-not $AttemptId) { $script:AttemptId = "ref-attempt-$(New-RandomId)" }
  if (-not $ResultStatus) { $script:ResultStatus = "dry_run_complete" }

  Write-Log "=== step 1/4: register ==="
  Invoke-Step -StepName "register"

  Write-Log "=== step 2/4: heartbeat ==="
  Invoke-Step -StepName "heartbeat"

  Write-Log "=== step 3/4: claim ==="
  Invoke-Step -StepName "claim"

  if ($JobFile -and $PubKeyFile -and $SigningKeyId) {
    Write-Log "=== step (extra): verify ==="
    Invoke-Verify
    if (-not $script:LastVerifyAllowed) {
      Write-Log "verify rejected the job; continuing with the 'all' walkthrough anyway (this is a demo, not a real dispatch loop)"
    }
  }

  Write-Log "=== step 4/4: result ==="
  Invoke-Step -StepName "result"
}

function Main {
  if ($Step -eq "verify") {
    Invoke-Verify
    exit ([int](-not $script:LastVerifyAllowed))
  }

  if (-not $ApiUrl) { Fail "-ApiUrl is required for -Step $Step" }
  if ($ApiUrl -notmatch '^https?://') { Fail "-ApiUrl must start with http:// or https://" }
  if ($ApiUrl -like "http://*") {
    Write-Log "WARNING: -ApiUrl uses plain http://; only appropriate for local/loopback control planes"
  }

  if ($Step -eq "all") {
    Invoke-All
    return
  }

  Invoke-Step -StepName $Step
  if (-not $script:LastRequestOk) { exit 1 }
}

Main

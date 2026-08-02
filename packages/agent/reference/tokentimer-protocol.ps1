#requires -Version 7
<#
.SYNOPSIS
  tokentimer-protocol.ps1 - PowerShell 7+ reference client for the CertOps
  agent protocol (ADR-0002/0003). Mirrors tokentimer-protocol.sh flag
  contract for the agent surface (-Step, -Execute, -Json). See
  docs/certops/agent.md and docs/adr/0002-certops-agent-protocol.md.

.DESCRIPTION
  Portable, auditable reference implementation for Windows operators.
  NOT a production agent: no retry policy, no persistent claim/lease loop.

  Mandatory Ed25519 verification uses the pinned Node helper at
  reference/lib/canonicalize.cjs (self-contained; shells out for verify).

.PARAMETER Mode
  Must be "agent" (only supported mode).

.PARAMETER Step
  all | register | heartbeat | claim | result | verify. Required.
  verify is local-only. all walks register -> heartbeat -> claim ->
  verify (claimed jobs when -Execute; else optional -JobFile verify) ->
  result.

.EXAMPLE
  ./tokentimer-protocol.ps1 -Mode agent -Step register -ApiUrl https://example.test -Json

.EXAMPLE
  ./tokentimer-protocol.ps1 -Mode agent -Step verify -JobFile job.json -PubKeyFile pub.pem -SigningKeyId signing-key-1

.EXAMPLE
  ./tokentimer-protocol.ps1 -Mode agent -Step all -ApiUrl https://example.test -Execute -PubKeyFile pub.pem -SigningKeyId signing-key-1
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("agent")]
  [string]$Mode,

  [Parameter(Mandatory = $true)]
  [ValidateSet("all", "register", "heartbeat", "claim", "result", "verify")]
  [string]$Step,

  [string]$ApiUrl,
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
  [switch]$Json,
  [switch]$SkipTimeWindow
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$script:LastVerifyAllowed = $false
# Identity obtained from a register response during 'all -Execute'. The
# credential stays in this process's memory: never logged, never written to
# disk, never passed as an argv value to a child process.
$script:RegisteredAgentId = $null
$script:RegisteredCredential = $null
# Result-envelope fields copied out of the verified claimed job.
$script:JobNonce = $null
$script:JobClaimId = $null
$script:JobMode = $null
$script:LastRequestOk = $false
$script:LastResponse = $null

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CanonicalizeJs = Join-Path $ScriptDir "lib/canonicalize.cjs"

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
    Fail "node is required (>=22 and <25) for mandatory Ed25519 signature verification; none found on PATH"
  }
  $versionOutput = & node -v
  if ($versionOutput -notmatch '^v(\d+)\.') {
    Fail "could not parse Node version from 'node -v' output: $versionOutput"
  }
  $major = [int]$Matches[1]
  if ($major -lt 22 -or $major -ge 25) {
    Fail "Node $versionOutput is outside the required range >=22 and <25 (see packages/agent/package.json engines.node)"
  }
  Write-Log "Node check ok: $versionOutput"
}

function Read-SecretFile {
  param([string]$Path, [string]$Label)
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    Fail "$Label file not found: $Path"
  }
  try {
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
  } catch {
    Fail "could not inspect ACL for $Label file ${Path}: $($_.Exception.Message)"
  }
  $unexpected = @($acl.Access | Where-Object {
    $_.IdentityReference.Value -notmatch '\\(Administrators|SYSTEM)$' -and
    $_.IdentityReference.Value -ne $acl.Owner
  })
  if ($unexpected.Count -gt 0) {
    $names = ($unexpected | ForEach-Object { $_.IdentityReference.Value }) -join ", "
    Fail "$Label file $Path grants access to additional principals: $names (expected owner/Administrators/SYSTEM only)"
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
  # A credential minted by this run's own register step wins: 'all -Execute'
  # must speak as the identity it just enrolled, not as a separately supplied
  # one, or heartbeat/claim/result act on the wrong agent.
  if ($script:RegisteredCredential) { return $script:RegisteredCredential }
  if ($CredentialFile) { return Read-SecretFile -Path $CredentialFile -Label "credential" }
  if ($env:TOKENTIMER_AGENT_CREDENTIAL) { return $env:TOKENTIMER_AGENT_CREDENTIAL }
  if (-not $Execute) {
    Write-Log "no credential supplied; dry-run preview only (a real -Execute run requires `$env:TOKENTIMER_AGENT_CREDENTIAL or -CredentialFile)"
    return "<no-credential-dry-run-only>"
  }
  Fail "no credential: set `$env:TOKENTIMER_AGENT_CREDENTIAL or pass -CredentialFile (never as a plain argument value)"
}

function Assert-ApiUrl {
  if ($ApiUrl -notmatch '^https?://') {
    Fail "-ApiUrl must start with http:// or https://"
  }
  if ($ApiUrl -match '^https://') { return }
  try {
    $uri = [Uri]$ApiUrl
    $hostName = $uri.Host.ToLowerInvariant()
    if ($hostName -in @('localhost', '127.0.0.1', '::1')) {
      if (-not $Execute) {
        Write-Log "WARNING: -ApiUrl uses plain http:// against loopback; acceptable for local control planes only"
      }
      return
    }
  } catch {
    Fail "-ApiUrl is not a valid URI: $ApiUrl"
  }
  Fail "-ApiUrl uses plain http:// against a non-loopback host; use https:// or loopback (localhost, 127.0.0.1, ::1)"
}

function New-RandomId {
  -join ((1..16) | ForEach-Object { "{0:x2}" -f (Get-Random -Maximum 256) })
}

function Get-IsoNow {
  (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

function Get-RouteForStep {
  param([string]$StepName)
  switch ($StepName) {
    "register"  { return "/api/v1/certops/agent/register" }
    "heartbeat" { return "/api/v1/certops/agent/heartbeat" }
    "claim"     { return "/api/v1/certops/agent/jobs/claim" }
    "result"    { return "/api/v1/certops/agent/jobs/results" }
    default     { Fail "no known route for -Step $StepName" }
  }
}

function Get-ClaimJobsFromResponse {
  param($Response)
  if ($null -eq $Response) { return @() }
  $parsed = $Response
  if ($parsed -is [string]) {
    try {
      $parsed = $parsed | ConvertFrom-Json
    } catch {
      Fail "claim response is not valid JSON"
    }
  }
  if ($null -eq $parsed.jobs) { return @() }
  $jobs = $parsed.jobs
  if ($jobs -is [System.Collections.IEnumerable] -and -not ($jobs -is [string])) {
    return @($jobs)
  }
  return @($jobs)
}

function Invoke-Verify {
  param(
    [string]$JobPath
  )
  $jobPathToUse = if ($JobPath) { $JobPath } else { $JobFile }
  if (-not $jobPathToUse) { Fail "-JobFile is required for -Step verify" }
  if (-not $PubKeyFile) { Fail "-PubKeyFile is required for -Step verify" }
  if (-not $SigningKeyId) { Fail "-SigningKeyId is required for -Step verify" }
  if (-not (Test-Path -LiteralPath $jobPathToUse -PathType Leaf)) { Fail "job file not found: $jobPathToUse" }
  if (-not (Test-Path -LiteralPath $PubKeyFile -PathType Leaf)) { Fail "public key file not found: $PubKeyFile" }
  Assert-PinnedNode

  $verifyArgs = @($CanonicalizeJs, "verify", $jobPathToUse, $PubKeyFile, $SigningKeyId)
  if ($SkipTimeWindow) { $verifyArgs += "--skip-time-window" }

  $result = & node @verifyArgs 2>&1
  $exitCode = $LASTEXITCODE
  if ($exitCode -eq 2) {
    Fail "canonicalize.cjs verify failed: $result"
  }

  $resultText = ($result | Out-String).Trim()
  $parsed = $resultText | ConvertFrom-Json
  if ($Json) {
    Write-Output $resultText
  } elseif ($parsed.allowed) {
    Write-Log "Signature OK: job is signed by the pinned key ($SigningKeyId) and matches its canonical payload."
  } else {
    Write-Log "REJECTED: $($parsed.rejectionReason) -- $($parsed.detail)"
  }
  $script:LastVerifyAllowed = [bool]$parsed.allowed
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
  if (-not $AgentId) { Fail "-AgentId is required for -Step heartbeat" }
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
  if (-not $AgentId) { Fail "-AgentId is required for -Step claim" }
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
  if (-not $AgentId) { Fail "-AgentId is required for -Step result" }
  if (-not $JobId) { Fail "-JobId is required for -Step result (or derive from a verified claimed job)" }
  if (-not $AttemptId) { Fail "-AttemptId is required for -Step result (or derive from a verified claimed job)" }
  if (-not $ResultStatus) { Fail "-ResultStatus is required for -Step result" }
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
      # nonce and claimId come from the signed dispatch: the control plane
      # consumes the nonce in its replay ledger at result ingestion, so a real
      # submission without it is rejected. Null only on a dry-run walkthrough
      # that never claimed a signed job.
      claimId         = if ($script:JobClaimId) { $script:JobClaimId } else { $null }
      nonce           = if ($script:JobNonce) { $script:JobNonce } else { $null }
    }
  }
}

function Invoke-ProtocolRequest {
  param([string]$StepName, [System.Collections.Specialized.OrderedDictionary]$Body, [string]$AuthHeader)

  $route = Get-RouteForStep -StepName $StepName
  $url = "$($ApiUrl.TrimEnd('/'))$route"
  $bodyJson = $Body | ConvertTo-Json -Depth 20 -Compress

  $script:LastResponse = $null

  if (-not $Execute) {
    if ($Json) {
      $dryRun = [ordered]@{ dryRun = $true; method = "POST"; url = $url; body = $Body }
      Write-Output ($dryRun | ConvertTo-Json -Depth 20 -Compress)
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
    Uri               = $url
    Method            = "Post"
    Headers           = $headers
    Body              = $bodyJson
    ContentType       = "application/json"
    SkipHttpErrorCheck = $true
    StatusCodeVariable = "statusCode"
  }

  $response = Invoke-RestMethod @invokeArgs
  $script:LastResponse = $response
  if ($Json) {
    Write-Output ($response | ConvertTo-Json -Depth 20 -Compress)
  } else {
    Write-Log "HTTP $statusCode"
    Write-Log ($response | ConvertTo-Json -Depth 20 -Compress)
  }
  $script:LastRequestOk = ($statusCode -ge 200 -and $statusCode -lt 300)
}

function Invoke-Step {
  param([string]$StepName)

  $body = $null
  $authHeader = $null
  switch ($StepName) {
    "register" {
      $authHeader = Resolve-BootstrapToken
      $body = Build-AgentRegisterBody
    }
    "heartbeat" {
      $authHeader = Resolve-Credential
      $body = Build-AgentHeartbeatBody
    }
    "claim" {
      $authHeader = Resolve-Credential
      $body = Build-AgentClaimBody
    }
    "result" {
      $authHeader = Resolve-Credential
      $body = Build-AgentResultBody
    }
    default {
      Fail "unsupported -Step $StepName"
    }
  }

  Invoke-ProtocolRequest -StepName $StepName -Body $body -AuthHeader $authHeader
}

function Set-JobFieldsFromClaimedJob {
  param($Job)
  if ($null -eq $Job) { return }
  if ($Job.jobId) { $script:JobId = [string]$Job.jobId }
  if ($Job.attemptId) {
    $script:AttemptId = [string]$Job.attemptId
  } elseif ($Job.claimId) {
    $script:AttemptId = [string]$Job.claimId
  }
  if ($Job.claimId) { $script:JobClaimId = [string]$Job.claimId }
  if ($Job.nonce) { $script:JobNonce = [string]$Job.nonce }
  if ($Job.mode) { $script:JobMode = [string]$Job.mode }

  if (-not $script:JobId) { Fail "claimed job carries no jobId; cannot report a result" }
  if (-not $script:AttemptId) { Fail "claimed job carries neither attemptId nor claimId; cannot report a result" }

  # Status is decided by the job's immutable mode, not by a convenient default.
  # dry_run_complete is only legal for mode:"dry_run"; the control plane rejects
  # it for a real job. This client performs no certificate work at all, so it
  # must never claim a real job succeeded: it refuses the job outright and
  # leaves it to a real agent.
  if (-not $ResultStatus) {
    switch ($script:JobMode) {
      "dry_run" { $script:ResultStatus = "dry_run_complete" }
      "real" {
        Fail "claimed job $($script:JobId) has mode 'real' but this reference client performs no certificate operations; it will not report a terminal status for it. Pass -ResultStatus explicitly only if you are reporting on work done elsewhere, or claim with an agent that can execute."
      }
      default {
        Fail "claimed job $($script:JobId) carries no recognized execution mode ('$($script:JobMode)'); refusing to guess a terminal status"
      }
    }
  }
}

# Parses { agentId, credential, protocolVersion, signingKeyId?,
# signingPublicKeyPem? } out of a register response and adopts that identity
# for the rest of the run. Fails closed: a register response we cannot read
# means we do not know who we are, so continuing would report against the
# wrong agent id.
function Set-RegisteredIdentity {
  param($Response)
  if ($null -eq $Response) {
    Fail "register response was empty; cannot continue as the newly enrolled agent"
  }
  $agentId = $Response.agentId
  $credential = $Response.credential
  if ([string]::IsNullOrWhiteSpace([string]$agentId)) {
    Fail "register response did not carry a usable agentId; cannot continue as the newly enrolled agent"
  }
  if ([string]::IsNullOrWhiteSpace([string]$credential)) {
    Fail "register response did not carry a usable credential; cannot continue as the newly enrolled agent"
  }
  $script:RegisteredAgentId = [string]$agentId
  $script:RegisteredCredential = [string]$credential
  $script:AgentId = [string]$agentId
  Write-Log "adopted registered identity: agentId $($script:AgentId) (credential held in memory only)"
}

function Invoke-VerifyJobObject {
  param(
    [Parameter(Mandatory = $true)]
    $Job,
    [Parameter(Mandatory = $true)]
    [string]$TempPrefix,
    [Parameter(Mandatory = $true)]
    [bool]$FailOnReject
  )
  $tempJob = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "$TempPrefix-$(New-RandomId).json")
  try {
    $jobJson = $Job | ConvertTo-Json -Depth 30 -Compress
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($tempJob, $jobJson, $enc)
    Invoke-Verify -JobPath $tempJob
    if ($FailOnReject -and -not $script:LastVerifyAllowed) {
      Fail "verify rejected a claimed job; aborting before result"
    }
  } finally {
    if (Test-Path -LiteralPath $tempJob) {
      Remove-Item -LiteralPath $tempJob -Force -ErrorAction SilentlyContinue
    }
  }
}

function Invoke-All {
  if ($Execute) {
    if (-not $PubKeyFile) { Fail "-PubKeyFile is required for -Step all with -Execute" }
    if (-not $SigningKeyId) { Fail "-SigningKeyId is required for -Step all with -Execute" }
  }

  if (-not $AgentId) {
    $script:AgentId = "ref-agent-$(New-RandomId)"
    Write-Log "generated -AgentId $AgentId for this 'all' run (pass -AgentId explicitly to reuse an existing registration)"
  }

  if ($JobFile -and (Test-Path -LiteralPath $JobFile -PathType Leaf) -and -not $Execute) {
    Assert-PinnedNode
    if (-not $JobId) {
      $extracted = & node $CanonicalizeJs extract-field $JobFile jobId 2>$null
      if ($LASTEXITCODE -eq 0 -and $extracted) { $script:JobId = $extracted.Trim() }
    }
    if (-not $AttemptId) {
      $extracted = & node $CanonicalizeJs extract-field $JobFile attemptId 2>$null
      if ($LASTEXITCODE -eq 0 -and $extracted) {
        $script:AttemptId = $extracted.Trim()
      } else {
        $script:AttemptId = "ref-attempt-$(New-RandomId)"
      }
    }
    if (-not $SigningKeyId) {
      $extracted = & node $CanonicalizeJs extract-field $JobFile signingKeyId 2>$null
      if ($LASTEXITCODE -eq 0 -and $extracted) { $script:SigningKeyId = $extracted.Trim() }
    }
  }

  if (-not $JobId) { $script:JobId = "ref-job-$(New-RandomId)" }
  if (-not $AttemptId) { $script:AttemptId = "ref-attempt-$(New-RandomId)" }
  if (-not $ResultStatus) { $script:ResultStatus = "dry_run_complete" }

  Write-Log "=== step 1/4: register ==="
  Invoke-Step -StepName "register"
  if ($Execute -and -not $script:LastRequestOk) { exit 1 }
  if ($Execute) { Set-RegisteredIdentity -Response $script:LastResponse }

  Write-Log "=== step 2/4: heartbeat ==="
  Invoke-Step -StepName "heartbeat"
  if ($Execute -and -not $script:LastRequestOk) { exit 1 }

  Write-Log "=== step 3/4: claim ==="
  Invoke-Step -StepName "claim"
  if ($Execute -and -not $script:LastRequestOk) { exit 1 }

  if ($Execute) {
    Write-Log "=== step 4/5: verify claimed jobs ==="
    $claimedJobs = Get-ClaimJobsFromResponse -Response $script:LastResponse
    if ($claimedJobs.Count -eq 0) {
      Write-Log "claim returned zero jobs; nothing to verify or report"
      return
    }
    $index = 0
    foreach ($job in $claimedJobs) {
      $index++
      Write-Log "verify claimed job $index/$($claimedJobs.Count)"
      Invoke-VerifyJobObject -Job $job -TempPrefix "tokentimer-claimed-job" -FailOnReject $true
    }
    # Sets ids, nonce, claimId, and a mode-appropriate status (or fails closed).
    Set-JobFieldsFromClaimedJob -Job $claimedJobs[0]
    Write-Log "=== step 5/5: result ==="
    Invoke-Step -StepName "result"
    if (-not $script:LastRequestOk) { exit 1 }
    return
  }

  if ($JobFile -and $PubKeyFile -and $SigningKeyId) {
    Write-Log "=== step (extra): verify -JobFile ==="
    Invoke-Verify
    if (-not $script:LastVerifyAllowed) {
      Write-Log "verify rejected the job; continuing dry-run walkthrough (pass -Execute for fail-closed verify)"
    }
  }

  Write-Log "=== step 4/4: result ==="
  Invoke-Step -StepName "result"
}

function Main {
  if ($CaBundle) {
    Fail "-CaBundle is not supported by this PowerShell client; use the system trust store or the Bash reference client (--ca-bundle)"
  }

  if ($Step -eq "verify") {
    Invoke-Verify
    exit ([int](-not $script:LastVerifyAllowed))
  }

  if (-not $ApiUrl) { Fail "-ApiUrl is required for -Step $Step" }
  Assert-ApiUrl

  if ($Step -eq "all") {
    Invoke-All
    return
  }

  Invoke-Step -StepName $Step
  if ($Execute -and -not $script:LastRequestOk) { exit 1 }
}

Main
# Host path for owned bind-failure injection. A missing IIS, netsh, or
# appcmd capability exits 1. That result is not a pass. Commands come from
# the run manifest and are refused if they reset http.sys or name a binding
# this run does not own.
param([string]$PlanPath)

$ErrorActionPreference = 'Stop'

function Fail([string]$Reason, [string[]]$Missing) {
  @{ passed = $false; nativeQualified = $false; reason = $Reason; missing = @($Missing) } | ConvertTo-Json -Compress
  exit 1
}

$missing = @()
if ($env:CERTOPS_WINDOWS_BIND_FAILURE_REQUIRED -ne '1') {
  $missing += 'CERTOPS_WINDOWS_BIND_FAILURE_REQUIRED'
}
$netsh = Join-Path $env:SystemRoot 'System32\netsh.exe'
$appcmd = Join-Path $env:SystemRoot 'System32\inetsrv\appcmd.exe'
if (-not (Test-Path -LiteralPath $netsh)) { $missing += 'netsh' }
if (-not (Test-Path -LiteralPath $appcmd)) { $missing += 'appcmd' }
if (-not (Get-Module -ListAvailable WebAdministration)) { $missing += 'WebAdministration' }
if ($missing.Count -gt 0) { Fail 'host capability absent' $missing }
if ($env:CERTOPS_WINDOWS_BIND_FAILURE_EXECUTE -ne '1') { Fail 'host execution not requested' @() }
if (-not $PlanPath -or -not (Test-Path -LiteralPath $PlanPath)) { Fail 'plan absent' @() }

$node = Get-Command node.exe -ErrorAction SilentlyContinue
if (-not $node) { Fail 'host executor absent' @('node') }
& $node.Source (Join-Path $PSScriptRoot 'certops-windows-installed-bind-failure.js') '--check-plan' $PlanPath
if ($LASTEXITCODE -ne 0) { Fail 'plan refused' @() }

$plan = Get-Content -Raw -LiteralPath $PlanPath | ConvertFrom-Json
$allowed = @{
  'netsh.exe' = $netsh
  'appcmd.exe' = $appcmd
}
foreach ($step in @($plan.steps)) {
  $fileName = [string]$step.file
  if (-not $allowed.ContainsKey($fileName)) { Fail 'unexpected executable' @($fileName) }
  $joined = (@($step.args) -join ' ')
  if ($joined -match '(?i)reset|shutdown|reboot|0\.0\.0\.0|\[::\]') {
    Fail 'refusing blanket netsh reset' @()
  }
  & $allowed[$fileName] @($step.args)
  if ($step.step -eq 'inject-add') {
    if ($LASTEXITCODE -eq 0) { Fail 'bind-failure injection did not fail' @() }
  } elseif ($LASTEXITCODE -ne 0) {
    Fail 'owned command failed; fixture preserved' @([string]$step.step)
  }
}

# Cleanup runs only after the owned injection failed and the predecessor
# rollback command returned success. Selectors come from the manifest.
foreach ($site in @($plan.manifest.sites)) {
  $selector = [string]$site.binding.selector
  if ($selector -notmatch '^hostnameport=') { Fail 'refusing unowned selector' @($selector) }
  & $netsh 'http' 'delete' 'sslcert' $selector
  if ($LASTEXITCODE -ne 0) { Fail 'owned binding cleanup failed; fixture preserved' @($selector) }
  & $appcmd 'delete' 'site' "/name:$($site.name)"
  if ($LASTEXITCODE -ne 0) { Fail 'owned site cleanup failed; fixture preserved' @([string]$site.name) }
}

@{ passed = $false; nativeQualified = $false; reason = 'host commands finished; native qualification is not claimed' } | ConvertTo-Json -Compress
exit 1

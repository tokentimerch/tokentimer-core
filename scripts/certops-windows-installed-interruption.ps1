# Host path for a service stop or process kill at a recorded ledger or CNG
# point, followed by startup of that same owned target. A missing host exits
# 1 and is not a pass. This file does not reboot the machine and it does not
# delete an in-use key.
param([string]$PointPath)

$ErrorActionPreference = 'Stop'

function Fail([string]$Reason, [string[]]$Missing) {
  @{ passed = $false; nativeQualified = $false; reason = $Reason; missing = @($Missing) } | ConvertTo-Json -Compress
  exit 1
}

$missing = @()
if ($env:CERTOPS_WINDOWS_INTERRUPTION_REQUIRED -ne '1') {
  $missing += 'CERTOPS_WINDOWS_INTERRUPTION_REQUIRED'
}
$sc = Join-Path $env:SystemRoot 'System32\sc.exe'
$taskkill = Join-Path $env:SystemRoot 'System32\taskkill.exe'
if (-not (Test-Path -LiteralPath $sc)) { $missing += 'serviceControl' }
if (-not (Test-Path -LiteralPath $taskkill)) { $missing += 'processControl' }
if ($missing.Count -gt 0) { Fail 'host capability absent' $missing }
if ($env:CERTOPS_WINDOWS_INTERRUPTION_EXECUTE -ne '1') { Fail 'host execution not requested' @() }
if (-not $PointPath -or -not (Test-Path -LiteralPath $PointPath)) { Fail 'owned target absent' @() }

$node = Get-Command node.exe -ErrorAction SilentlyContinue
if (-not $node) { Fail 'host executor absent' @('node') }
& $node.Source (Join-Path $PSScriptRoot 'certops-windows-installed-interruption.js') '--check-point' $PointPath
if ($LASTEXITCODE -ne 0) { Fail 'interruption point refused' @() }

$saved = Get-Content -Raw -LiteralPath $PointPath | ConvertFrom-Json
$point = $saved.point
if ($point.key.inUse -ne $true) { Fail 'refusing a point that does not retain the in-use key' @() }
if ($point.serviceName -notmatch '^tt-int-[a-f0-9]{32}$') { Fail 'refusing unowned service' @([string]$point.serviceName) }
if ($point.mode -ne 'service-stop' -and $point.mode -ne 'process-kill') {
  Fail 'interruption mode must be service-stop or process-kill' @([string]$point.mode)
}

if ($point.mode -eq 'service-stop') {
  & $sc 'stop' ([string]$point.serviceName)
  if ($LASTEXITCODE -ne 0) { Fail 'owned service stop failed; point preserved' @() }
  & $sc 'start' ([string]$point.serviceName)
  if ($LASTEXITCODE -ne 0) { Fail 'owned service start failed; point preserved' @() }
} else {
  $pidValue = [int]$point.pid
  if ($pidValue -le 4) { Fail 'refusing an unowned process id' @() }
  $image = [string]$point.image
  $root = [string]$point.root
  if (-not $image.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
    Fail 'refusing a recovery image outside the run root' @()
  }
  & $taskkill '/PID' ([string]$pidValue) '/F'
  if ($LASTEXITCODE -ne 0) { Fail 'owned process kill failed; point preserved' @() }
  & $image '--recover' ([string]$point.runId) '--sequence' ([string]$point.sequence)
  if ($LASTEXITCODE -ne 0) { Fail 'startup recovery failed; point preserved' @() }
}

@{ passed = $false; nativeQualified = $false; reason = 'host-integration commands finished; native qualification is not claimed' } | ConvertTo-Json -Compress
exit 1

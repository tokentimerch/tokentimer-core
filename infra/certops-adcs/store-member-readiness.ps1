<# Read-only infrastructure check for the disposable AD CS store-only member.
It does not issue a certificate, prove the agent preflight, or qualify a build. #>
param(
  [string]$CaConfig = 'tt-ca.lab.certops.test\TTQualificationRoot',
  [string]$PreparedObservationRunId
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$prepared = $PSBoundParameters.ContainsKey('PreparedObservationRunId')
if ($prepared -and $PreparedObservationRunId -cnotmatch '^[a-f0-9]{32}\z') {
  throw 'A 32-character lowercase hexadecimal observation run ID is required'
}
if ($env:CERTOPS_ADCS_DISPOSABLE_LAB -ne '1') { throw 'Disposable lab marker required' }
if ($CaConfig -cnotmatch '^tt-ca\.lab\.certops\.test\\TTQualificationRoot$') { throw 'Owned lab CA required' }
$computer = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
if (-not $computer.PartOfDomain -or $computer.Domain -ine 'lab.certops.test' -or $os.ProductType -ne 3) {
  throw 'An isolated domain-joined Windows Server member is required'
}
if (-not (Test-ComputerSecureChannel)) { throw 'Domain trust unavailable' }
$role = Get-WindowsFeature -Name Web-Server -ErrorAction Stop
if ($null -eq $role -or $role.Installed) { throw 'A member without IIS is required' }
$service = Get-CimInstance Win32_Service -Filter "Name='TokenTimerAgent'"
$localSystem = $null -ne $service -and $service.StartName -in @('LocalSystem', 'NT AUTHORITY\SYSTEM')
if ($prepared) {
  if (-not $localSystem -or $service.State -ne 'Stopped' -or $service.StartMode -ne 'Disabled' -or $service.ProcessId -ne 0) {
    throw 'A stopped, disabled LocalSystem agent service with no process is required'
  }
  $expectedBinding = "TOKENTIMER_AGENT_HOST_OBSERVATION_RUN=$PreparedObservationRunId"
  try {
    $binding = @(Get-ItemPropertyValue -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\TokenTimerAgent' -Name Environment |
      Where-Object { $_ -match '^TOKENTIMER_AGENT_HOST_OBSERVATION_RUN=' })
  } catch {
    throw 'The prepared service observation run binding could not be read'
  }
  if ($binding.Count -ne 1 -or $binding[0] -cne $expectedBinding) {
    throw 'The prepared service does not bind the expected observation run'
  }
} else {
  if (-not $localSystem -or $service.State -ne 'Running') {
    throw 'A running LocalSystem agent service is required'
  }
  $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($service.ProcessId)"
  if ($null -eq $process -or (Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid).Sid -ne 'S-1-5-18') {
    throw 'The agent service process is not LocalSystem'
  }
}
$callerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$null = & certutil.exe -config $CaConfig -ping 2>&1
if ($LASTEXITCODE -ne 0) { throw 'CA RPC ping failed for the caller identity' }
@{
  domain = 'lab.certops.test'
  windowsBuild = [string]$os.BuildNumber
  iisInstalled = $false
  agentServiceRunning = -not $prepared
  agentServiceIdentity = 'LocalSystem'
  caRpcCallerSid = $callerSid
  caRpcPing = $true
  qualificationPassed = $false
} | ConvertTo-Json -Compress

<#
Exact owned disposable CA service outage with receipt-backed original service-state restoration.
Called by pending continuation tests; no production/domain host outside the qualification forest is
accepted.
#>
param(
  [Parameter(Mandatory)][ValidateSet('stop','restore','status')][string]$Action,
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{10}$')][string]$RunId
)
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'CA outage requires the isolated qualification forest'}
if(-not $env:CERTOPS_ADCS_OFFICER_PASSWORD){throw 'Isolated officer credential absent'}
$credential=[PSCredential]::new('TTQUAL\tt-lab-admin',(ConvertTo-SecureString $env:CERTOPS_ADCS_OFFICER_PASSWORD -AsPlainText -Force))
Invoke-Command -ComputerName 'tt-ca.lab.certops.test' -Credential $credential -ArgumentList $Action,$RunId -ScriptBlock {
  param([string]$Action,[string]$RunId)
  $ErrorActionPreference='Stop'
  $computer=Get-CimInstance Win32_ComputerSystem
  if($computer.Name -ine 'tt-ca' -or $computer.Domain -ne 'lab.certops.test'){throw 'Refusing service mutation on a foreign CA machine'}
  $activeNames=@((Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration').Active)
  if($activeNames.Count -ne 1 -or [string]$activeNames[0] -ne 'TTQualificationRoot'){throw 'Refusing mutation of a foreign or ambiguous active CA'}
  $active=[string]$activeNames[0]
  $directory='C:\ttqualification'
  $snapshot=Join-Path $directory "ca-service-$RunId.clixml"
  $service=Get-Service CertSvc -ErrorAction Stop
  if($Action -eq 'stop'){
    if(Test-Path -LiteralPath $snapshot){throw 'An owned CA outage snapshot already exists'}
    if($service.Status -ne 'Running'){throw 'Required isolated CA service is not running before the fault'}
    if(-not (Test-Path -LiteralPath $directory)){New-Item -ItemType Directory -Path $directory|Out-Null}
    @{runId=$RunId;machine=$computer.Name;domain=$computer.Domain;activeCa=$active;status=[string]$service.Status;startType=[string]$service.StartType}|Export-Clixml -LiteralPath $snapshot
    $service.Stop()
    $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(30))
    $service.Refresh()
    if($service.Status -ne 'Stopped'){throw 'Actual owned CA service did not stop'}
  }
  elseif($Action -eq 'restore'){
    if(-not (Test-Path -LiteralPath $snapshot)){throw 'Owned CA service snapshot absent'}
    $original=Import-Clixml -LiteralPath $snapshot
    if($original.runId -ne $RunId -or $original.machine -ine $computer.Name -or $original.domain -ne $computer.Domain -or $original.activeCa -ne $active -or $original.status -ne 'Running'){throw 'Refusing foreign or unsupported CA service recovery'}
    if([string]$service.StartType -ne $original.startType){throw 'CA service startup configuration changed during fault'}
    if($service.Status -ne 'Running'){$service.Start();$service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(30));$service.Refresh()}
    if($service.Status -ne 'Running'){throw 'Actual owned CA service did not recover'}
    Remove-Item -LiteralPath $snapshot
    if(Test-Path -LiteralPath $snapshot){throw 'Owned CA service snapshot remains after recovery'}
  }
  [pscustomobject]@{action=$Action;runId=$RunId;machine=$computer.Name;domain=$computer.Domain;activeCa=$active;service='CertSvc';status=[string]$service.Status;startType=[string]$service.StartType;snapshotPresent=[bool](Test-Path -LiteralPath $snapshot)}|ConvertTo-Json -Compress
}

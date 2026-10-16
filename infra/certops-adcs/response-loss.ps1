<#
Experimental actual-submit response-loss controller on the isolated forest. Observes a genuine CA
side effect, then interrupts only a verified owned certreq process tree; it never fabricates a
journal phase or request identifier.
#>
param([Parameter(Mandatory)][ValidatePattern('^certops-adcs-[a-f0-9]+-fault\.example\.test$')][string]$CommonName,
  [Parameter(Mandatory)][string]$OwnedDirectory)
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Response-loss controller requires isolated forest'}
if(-not $env:CERTOPS_ADCS_OFFICER_PASSWORD){throw 'Isolated CA observer credential absent'}
$resolved=[IO.Path]::GetFullPath($OwnedDirectory)
$temp=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\'
if(-not $resolved.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $resolved -Leaf) -notmatch '^certops-domain-adcs-'){throw 'Refusing a directory outside the owned native fixture'}
$service=Get-CimInstance Win32_Service -Filter "Name='TokenTimerAgent'"
if($service.State -ne 'Running' -or -not $service.ProcessId){throw 'Owned agent service must be running'}
$credential=[PSCredential]::new('TTQUAL\tt-lab-admin',(ConvertTo-SecureString $env:CERTOPS_ADCS_OFFICER_PASSWORD -AsPlainText -Force))
$requestId=Invoke-Command -ComputerName 'tt-ca.lab.certops.test' -Credential $credential -ArgumentList $CommonName -ScriptBlock {
  param([string]$CommonName)
  $ErrorActionPreference='Stop';$deadline=[DateTime]::UtcNow.AddSeconds(90)
  Write-Output 'CERTOPS_FAULT_READY'
  while([DateTime]::UtcNow -lt $deadline){
    $view=New-Object -ComObject CertificateAuthority.View
    $null=$view.OpenConnection('tt-ca.lab.certops.test\TTQualificationRoot')
    $view.SetResultColumnCount(2)
    $view.SetResultColumn($view.GetColumnIndex($false,'RequestID'))
    $view.SetResultColumn($view.GetColumnIndex($false,'RequesterName'))
    $view.SetRestriction($view.GetColumnIndex($false,'CommonName'),1,0,$CommonName)
    $rows=$view.OpenView()
    if($rows.Next() -ne -1){
      $columns=$rows.EnumCertViewColumn();$found=@()
      while($columns.Next() -ne -1){$found+=,$columns.GetValue(0)}
      if($found.Count -ne 2 -or $found[1] -ine 'TTQUAL\tt-agent$' -or $rows.Next() -ne -1){throw 'Foreign or ambiguous CA request'}
      return [long]$found[0]
    }
    Start-Sleep -Milliseconds 20
  }
  throw 'Independent CA submission observation did not occur inside the bounded fault window'
} | ForEach-Object {if($_ -eq 'CERTOPS_FAULT_READY'){[Console]::WriteLine('CERTOPS_FAULT_READY')}else{$_}}
if(-not $requestId){throw 'No actual CA request observed'}
$processes=@(Get-CimInstance Win32_Process)
$owned=@($processes | Where-Object {$_.Name -ieq 'certreq.exe' -and $_.CommandLine -match '(?i)(?:^|\s)-submit(?:\s|$)' -and $_.CommandLine.IndexOf($resolved,[StringComparison]::OrdinalIgnoreCase) -ge 0})
if($owned.Count -ne 1){throw 'Fault window missed: exactly one still-running owned certreq submit required'}
$candidate=$owned[0];$ancestor=$candidate; $ownedTree=$false
for($i=0;$i -lt 8;$i++){
  if($ancestor.ParentProcessId -eq $service.ProcessId){$ownedTree=$true;break}
  $ancestor=$processes | Where-Object ProcessId -eq $ancestor.ParentProcessId | Select-Object -First 1
  if(-not $ancestor){break}
}
if(-not $ownedTree){throw 'Refusing a certreq outside the owned agent service process tree'}
$fresh=Get-CimInstance Win32_Process -Filter "ProcessId=$($candidate.ProcessId)"
if(-not $fresh -or $fresh.CreationDate -ne $candidate.CreationDate -or $fresh.CommandLine -ne $candidate.CommandLine){throw 'Fault window missed or process identity changed'}
Stop-Process -Id $candidate.ProcessId -Force
@{requestId=[long]$requestId;killedProcessId=$candidate.ProcessId;caRequestObserved=$true;ownedServiceTree=$true;fault='real-native-certreq-termination-after-CA-observation'}|ConvertTo-Json -Compress

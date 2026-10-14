<#
Observed native phase fault for an explicitly selected experimental lab. Verifies run-owned
service/process/creation identity before interruption and snapshots SCM recovery configuration for
restoration; never rewrites enrollment journals.
#>
param([Parameter(Mandatory)][string]$OwnedDirectory,
  [Parameter(Mandatory)][string]$ConfigDirectory,
  [Parameter(Mandatory)][string]$RepositoryRoot,
  [Parameter(Mandatory)][string]$NodeExecutable,
  [Parameter(Mandatory)][ValidateSet('keygen_intent','prepared','submitting','installing')][string]$Phase)
$ErrorActionPreference='Stop'
if($env:CERTOPS_ADCS_DISPOSABLE_LAB -ne '1' -or (Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Fault requires disposable qualification forest'}
$owned=[IO.Path]::GetFullPath($OwnedDirectory).TrimEnd('\')
$temp=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\'
$config=[IO.Path]::GetFullPath($ConfigDirectory)
$repo=[IO.Path]::GetFullPath($RepositoryRoot)
if(-not $owned.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $owned -Leaf) -notmatch '^certops-domain-adcs-' -or $config -ine (Join-Path $owned 'agent')){throw 'Foreign fixture directory'}
$service=Get-CimInstance Win32_Service -Filter "Name='TokenTimerAgent'"
$hostProcess=Get-CimInstance Win32_Process -Filter "ProcessId=$($service.ProcessId)"
$expectedHost=Join-Path $repo 'packages\agent\bin\tokentimer-agent-host-amd64.exe'
if($service.State -ne 'Running' -or -not $hostProcess -or $hostProcess.ExecutablePath -ine $expectedHost){throw 'Foreign SCM host'}
$registry=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services\TokenTimerAgent')
try{$environment=@($registry.GetValue('Environment'));$owner=@($environment | Where-Object {$_ -like 'TOKENTIMER_AGENT_CONFIG_DIR=*'});if($owner.Count -ne 1 -or $owner[0].Substring('TOKENTIMER_AGENT_CONFIG_DIR='.Length) -ine $config){throw 'Foreign SCM configuration'}}finally{if($registry){$registry.Dispose()}}
$entry=Join-Path $repo 'packages\agent\bin\tokentimer-agent.js'
$nodes=@(Get-CimInstance Win32_Process | Where-Object {$_.ParentProcessId -eq $hostProcess.ProcessId -and $_.ExecutablePath -ieq $NodeExecutable -and $_.CommandLine.IndexOf($entry,[StringComparison]::OrdinalIgnoreCase) -ge 0})
if($nodes.Count -ne 1){throw 'Exactly one owned native agent child required'}
$node=$nodes[0];if((Invoke-CimMethod -InputObject $node -MethodName GetOwnerSid).Sid -ne 'S-1-5-18'){throw 'Native agent identity must be SYSTEM'}
$receipt=Join-Path $owned 'journal-phase-target.json'
if(Test-Path -LiteralPath $receipt){throw 'Fault receipt already exists'}
Write-Output 'CERTOPS_JOURNAL_FAULT_READY'
$deadline=[DateTime]::UtcNow.AddSeconds(180);$observed=$null;$target=$null
while([DateTime]::UtcNow -lt $deadline){
  if(-not $target -and (Test-Path -LiteralPath $receipt)){
    try{$candidate=Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json}catch{Start-Sleep -Milliseconds 10;continue}
    foreach($field in @('enrollmentId','jobId')){if($candidate.$field -notmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'){throw 'Malformed authoritative ownership receipt'}}
    if($candidate.snapshotSha256 -notmatch '^[a-f0-9]{64}$' -or $candidate.containerName -ne ('tokentimer-enr-'+$candidate.enrollmentId)){throw 'Malformed frozen identity receipt'}
    $target=$candidate
  }
  if($target){
    $artifact=if($Phase -eq 'keygen_intent'){'keygen-intent.json'}else{'journal.json'}
    $journal=Join-Path $config ('adcs-enrollments\'+$target.enrollmentId+'\'+$artifact)
    if(Test-Path -LiteralPath $journal){
      try{$candidate=Get-Content -LiteralPath $journal -Raw | ConvertFrom-Json}catch{Start-Sleep -Milliseconds 10;continue}
      if($Phase -eq 'keygen_intent'){$candidate|Add-Member NoteProperty state 'keygen_intent'}
      if($candidate.state -eq $Phase){
        if($candidate.enrollmentId -ne $target.enrollmentId -or $candidate.jobId -ne $target.jobId -or $candidate.snapshotSha256 -ne $target.snapshotSha256 -or $candidate.containerName -ne $target.containerName){throw 'Observed journal belongs to another attempt'}
        if($Phase -eq 'installing' -and $candidate.installStep -ne 'accept'){Start-Sleep -Milliseconds 5;continue}
        if($Phase -eq 'keygen_intent'){
          $newChildren=@(Get-CimInstance Win32_Process | Where-Object {$_.ParentProcessId -eq $node.ProcessId -and $_.ExecutablePath -ieq (Join-Path $env:SystemRoot 'System32\certreq.exe') -and $_.CommandLine -match '(?i)\s-new\s' -and $_.CommandLine.IndexOf($target.containerName,[StringComparison]::OrdinalIgnoreCase) -ge 0 -and $_.CommandLine.IndexOf((Join-Path $config 'windows-cert-store-work'),[StringComparison]::OrdinalIgnoreCase) -ge 0})
          if($newChildren.Count -ne 1){Start-Sleep -Milliseconds 5;continue}
          $key=$null;try{$key=[Security.Cryptography.CngKey]::Open($target.containerName,[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey);if($key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None){throw 'Native intent key is exportable'}}catch [Security.Cryptography.CryptographicException]{Start-Sleep -Milliseconds 5;continue}finally{if($key){$key.Dispose()}}
          $keygenProcess=$newChildren[0]
        }
        $observed=$candidate;break
      }
    }
  }
  Start-Sleep -Milliseconds 5
}
if(-not $observed){throw 'Experimental native durable phase window was missed'}
$processes=@(Get-CimInstance Win32_Process)
function IsOwnedDescendant($process){
  if($process.CreationDate -lt $node.CreationDate){return $false}
  $ancestor=$process
  for($i=0;$i -lt 16;$i++){
    if($ancestor.ParentProcessId -eq $node.ProcessId){return $true}
    $ancestor=$processes | Where-Object ProcessId -eq $ancestor.ParentProcessId | Select-Object -First 1
    if(-not $ancestor){return $false}
  }
  return $false
}
$descendants=@($processes | Where-Object {IsOwnedDescendant $_})
function KillUnchanged($process){
  $fresh=Get-CimInstance Win32_Process -Filter "ProcessId=$($process.ProcessId)"
  if(-not $fresh){return}
  if($fresh.CreationDate -ne $process.CreationDate -or $fresh.ParentProcessId -ne $process.ParentProcessId -or $fresh.ExecutablePath -ine $process.ExecutablePath){throw 'Refusing reused process identity'}
  Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
}
# Stop the verified Node first so child termination cannot trigger another
# callback/journal transition. Then stop only the captured owned descendants
# and the unchanged SCM host; no process-wide image-name kill is permitted.
KillUnchanged $node
foreach($process in $descendants){KillUnchanged $process}
KillUnchanged $hostProcess
$final=Get-Content -LiteralPath $journal -Raw | ConvertFrom-Json
if($Phase -eq 'keygen_intent'){$final|Add-Member NoteProperty state 'keygen_intent';if(Test-Path -LiteralPath (Join-Path (Split-Path $journal) 'csr.pem')){throw 'Durable CSR appeared during native interruption'}}
if($final.state -ne $observed.state -or $final.jobId -ne $observed.jobId -or $final.containerName -ne $observed.containerName -or $final.snapshotSha256 -ne $observed.snapshotSha256){throw 'Observed durable phase advanced before verified termination'}
if($Phase -eq 'installing' -and $final.installStep -ne 'accept'){throw 'Installation phase advanced before termination'}
@{phase=$Phase;observedDurablePhase=$true;unchangedAfterTermination=$true;ownedServiceTree=$true;nativeIdentity='LocalSystem';fault='verified-owned-native-agent-and-SCM-termination';actualCertreqNewObserved=($Phase -eq 'keygen_intent' -and $null -ne $keygenProcess);nonExportableOwnedKeyObserved=($Phase -eq 'keygen_intent');enrollmentId=$target.enrollmentId;jobId=$target.jobId;snapshotSha256=$target.snapshotSha256}|ConvertTo-Json -Compress

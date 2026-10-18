<# Experimental observed-window interruption AFTER real certreq acceptance and
BEFORE IIS cutover. This never edits a journal, a CA response or product code.
A missed window fails. Exact native custody and old binding are independently
checked after the complete owned process tree has drained. #>
param([Parameter(Mandatory)][string]$OwnedDirectory,[Parameter(Mandatory)][string]$ConfigDirectory,[Parameter(Mandatory)][string]$RepositoryRoot,[Parameter(Mandatory)][string]$NodeExecutable,[ValidateSet('accepted-before-bind','bound-before-complete')][string]$Phase='accepted-before-bind')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if($env:CERTOPS_ADCS_DISPOSABLE_LAB -ne '1' -or (Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Owned disposable forest required'}
$owned=[IO.Path]::GetFullPath($OwnedDirectory).TrimEnd('\');$config=[IO.Path]::GetFullPath($ConfigDirectory);$repo=[IO.Path]::GetFullPath($RepositoryRoot)
if(!$owned.StartsWith(([IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\'),[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $owned -Leaf) -notmatch '^certops-domain-adcs-' -or $config -ine (Join-Path $owned 'agent')){throw 'Foreign owned directory'}
foreach($file in @($owned,$config,$repo)){if(((Get-Item -LiteralPath $file -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Linked native fault root refused'}}
$service=Get-CimInstance Win32_Service -Filter "Name='TokenTimerAgent'"
$hostProcess=Get-CimInstance Win32_Process -Filter "ProcessId=$($service.ProcessId)"
if($service.State -ne 'Running' -or !$hostProcess -or $hostProcess.ExecutablePath -ine (Join-Path $repo 'packages\agent\bin\tokentimer-agent-host-amd64.exe')){throw 'Foreign native service host'}
$registry=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services\TokenTimerAgent')
try{$owner=@($registry.GetValue('Environment')|Where-Object {$_ -like 'TOKENTIMER_AGENT_CONFIG_DIR=*'});if($owner.Count -ne 1 -or $owner[0].Substring('TOKENTIMER_AGENT_CONFIG_DIR='.Length) -ine $config -or $null -ne $registry.GetValue('FailureActions')){throw 'Foreign configuration or automatic recovery policy'}}finally{$registry.Dispose()}
$entry=Join-Path $repo 'packages\agent\bin\tokentimer-agent.js'
$nodes=@(Get-CimInstance Win32_Process|Where-Object {$_.ParentProcessId -eq $hostProcess.ProcessId -and $_.ExecutablePath -ieq $NodeExecutable -and $_.CommandLine.IndexOf($entry,[StringComparison]::OrdinalIgnoreCase) -ge 0})
if($nodes.Count -ne 1 -or (Invoke-CimMethod -InputObject $nodes[0] -MethodName GetOwnerSid).Sid -ne 'S-1-5-18'){throw 'Exact SYSTEM native agent required'}
$node=$nodes[0];$receipt=Join-Path $owned 'accepted-install-target.json'
if(Test-Path -LiteralPath $receipt){throw 'Outstanding accepted-install receipt'}
if($Phase -eq 'bound-before-complete'){Import-Module WebAdministration}
Write-Output 'CERTOPS_ACCEPTED_INSTALL_READY'
$deadline=[DateTime]::UtcNow.AddSeconds(180);$target=$null;$observed=$null;$journalPath=$null
while([DateTime]::UtcNow -lt $deadline){
 if(!$target -and (Test-Path -LiteralPath $receipt)){
  try{$candidate=Get-Content -LiteralPath $receipt -Raw|ConvertFrom-Json}catch{Start-Sleep -Milliseconds 5;continue}
  foreach($field in @('enrollmentId','jobId')){if($candidate.$field -notmatch '^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$'){throw 'Malformed enrollment identity'}}
  if($candidate.snapshotSha256 -notmatch '^[a-f0-9]{64}$' -or $candidate.containerName -ne ('tokentimer-enr-'+$candidate.enrollmentId) -or $candidate.predecessorThumbprint -notmatch '^[A-F0-9]{40}$' -or $candidate.site -notmatch '^TTADCS-[a-f0-9]{10}-[a-z0-9-]+$' -or $candidate.domain -notmatch '^certops-adcs-[a-z0-9-]+\.example\.test$' -or $candidate.port -lt 1 -or $candidate.port -gt 65535){throw 'Malformed native ownership receipt'}
  $target=$candidate;$journalPath=Join-Path $config ('adcs-enrollments\'+$target.enrollmentId+'\journal.json')
 }
 if($target -and (Test-Path -LiteralPath $journalPath)){
  try{$candidate=Get-Content -LiteralPath $journalPath -Raw|ConvertFrom-Json}catch{Start-Sleep -Milliseconds 5;continue}
  if($candidate.state -eq 'installing' -and $candidate.installStep -eq 'bind'){
   if($candidate.enrollmentId -ne $target.enrollmentId -or $candidate.jobId -ne $target.jobId -or $candidate.snapshotSha256 -ne $target.snapshotSha256 -or $candidate.containerName -ne $target.containerName){throw 'Foreign durable installing phase'}
   if($Phase -eq 'bound-before-complete'){
    # Do not interrupt at the earlier accepted-only bind intent. The real
    # native binding must already select this actual journaled public leaf.
    $path=Join-Path (Split-Path $journalPath) 'leaf.pem'
    $body=[IO.File]::ReadAllText($path) -replace '-----BEGIN CERTIFICATE-----','' -replace '-----END CERTIFICATE-----','' -replace '\s',''
    $candidateLeaf=New-Object Security.Cryptography.X509Certificates.X509Certificate2(,[Convert]::FromBase64String($body))
    try{
     $bindings=@(Get-WebBinding -Name $target.site -Protocol https|Where-Object bindingInformation -eq "*:$($target.port):$($target.domain)")
     if($bindings.Count -ne 1){throw 'Owned native SNI binding missing or ambiguous'}
     $hash=$bindings[0].certificateHash;if($hash -is [byte[]]){$hash=([BitConverter]::ToString($hash)).Replace('-','')}
     $boundNow=[string]$hash -ieq $candidateLeaf.Thumbprint
    }finally{$candidateLeaf.Dispose()}
    if(!$boundNow){Start-Sleep -Milliseconds 5;continue}
   }
   $observed=$candidate;break
  }
 }
 Start-Sleep -Milliseconds 5
}
if(!$observed){throw 'Experimental accepted-before-bind window missed'}
function Stop-Exact($record){
 $fresh=Get-CimInstance Win32_Process -Filter "ProcessId=$($record.ProcessId)"
 if(!$fresh){return}
 if($fresh.CreationDate -ne $record.CreationDate -or $fresh.ParentProcessId -ne $record.ParentProcessId -or $fresh.ExecutablePath -ine $record.ExecutablePath -or $fresh.CommandLine -cne $record.CommandLine -or (Invoke-CimMethod -InputObject $fresh -MethodName GetOwnerSid).Sid -ne 'S-1-5-18'){throw 'Refuse changed native process identity'}
 Stop-Process -Id $record.ProcessId -Force -ErrorAction Stop
}
$before=@(Get-CimInstance Win32_Process)
# Capture the entire ownership frontier BEFORE termination. A later child or
# reused parent PID is ambiguous: never adopt or kill it from ParentProcessId.
$ownedProcesses=@{};$ownedProcesses[[int]$node.ProcessId]=$node;$ownedProcesses[[int]$hostProcess.ProcessId]=$hostProcess
for($pass=0;$pass -lt 16;$pass++){
 foreach($p in $before){
  if($ownedProcesses.ContainsKey([int]$p.ParentProcessId) -and !$ownedProcesses.ContainsKey([int]$p.ProcessId)){
   $parent=$ownedProcesses[[int]$p.ParentProcessId]
   if($p.CreationDate -lt $parent.CreationDate -or $p.CreationDate -lt $node.CreationDate -or !$p.ExecutablePath -or !$p.CommandLine -or (Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid).Sid -ne 'S-1-5-18'){throw 'Captured native child ownership is ambiguous'}
   $ownedProcesses[[int]$p.ProcessId]=$p
  }
 }
}
Stop-Exact $node
Stop-Exact $hostProcess
foreach($record in $ownedProcesses.Values){Stop-Exact $record}
$until=[DateTime]::UtcNow.AddSeconds(10);$emptyPasses=0
do{
 $all=@(Get-CimInstance Win32_Process)
 foreach($p in $all){if($ownedProcesses.ContainsKey([int]$p.ParentProcessId) -and $p.CreationDate -ge $node.CreationDate -and !$ownedProcesses.ContainsKey([int]$p.ProcessId)){throw 'Unexpected post-snapshot descendant: preserve native state without PID-based adoption'}}
 $live=@($ownedProcesses.Keys|ForEach-Object {Get-CimInstance Win32_Process -Filter "ProcessId=$_"})
 if(!$live.Count){$emptyPasses++}else{$emptyPasses=0}
 if($emptyPasses -ge 2){break};Start-Sleep -Milliseconds 20
}while([DateTime]::UtcNow -lt $until)
if($live.Count -or $emptyPasses -lt 2){throw 'Owned native process drainage unproven'}
if((Get-Service TokenTimerAgent).Status -ne 'Stopped'){throw 'Owned service did not stop'}
$final=Get-Content -LiteralPath $journalPath -Raw|ConvertFrom-Json
foreach($field in @('state','installStep','jobId','containerName','snapshotSha256','csrSha256','csrSpkiSha256','leafSha256','requestId')){if($final.$field -ne $observed.$field){throw 'Accepted-install journal advanced during termination'}}
if($final.predecessorThumbprint -ne $target.predecessorThumbprint){throw 'Wrong predecessor journal identity'}
$leafPath=Join-Path (Split-Path $journalPath) 'leaf.pem'
if((Get-FileHash -LiteralPath $leafPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $final.leafSha256){throw 'Issued leaf artifact hash mismatch'}
$pem=[IO.File]::ReadAllText($leafPath);$body=$pem -replace '-----BEGIN CERTIFICATE-----','' -replace '-----END CERTIFICATE-----','' -replace '\s',''
$leaf=New-Object Security.Cryptography.X509Certificates.X509Certificate2(,[Convert]::FromBase64String($body))
$cert=$null;$private=$null;$public=$null;$sha=[Security.Cryptography.SHA256]::Create()
try{
 $cert=Get-Item -LiteralPath ('Cert:\LocalMachine\My\'+$leaf.Thumbprint)
 if([Convert]::ToBase64String($cert.RawData) -ne [Convert]::ToBase64String($leaf.RawData) -or !$cert.HasPrivateKey){throw 'Exact accepted public leaf and private association missing'}
 $private=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
 if(!$private -or $private.Key.KeyName -ne $target.containerName -or $private.Key.Provider.Provider -ne 'Microsoft Software Key Storage Provider' -or !$private.Key.IsMachineKey -or $private.Key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None -or $private.KeySize -ne 2048){throw 'Exact accepted native CNG custody unproven'}
 $challenge=[Text.Encoding]::UTF8.GetBytes('CertOps accepted-key possession '+[guid]::NewGuid().ToString())
 $signature=$private.SignData($challenge,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
 $public=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($leaf)
 if(!$public.VerifyData($challenge,$signature,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)){throw 'Accepted container does not possess the actual leaf key'}
 $leafFingerprint=([BitConverter]::ToString($sha.ComputeHash($leaf.RawData))).Replace('-','').ToLowerInvariant()
 Import-Module WebAdministration
 $bindings=@(Get-WebBinding -Name $target.site -Protocol https|Where-Object bindingInformation -eq "*:$($target.port):$($target.domain)")
 if($bindings.Count -ne 1 -or [int]$bindings[0].sslFlags -ne 1){throw 'Owned SNI binding changed'}
 $hash=$bindings[0].certificateHash
 if($hash -is [byte[]]){$hash=([BitConverter]::ToString($hash)).Replace('-','')}
 $expectedBinding=if($Phase -eq 'bound-before-complete'){$leaf.Thumbprint}else{$target.predecessorThumbprint}
 if([string]$hash -ine $expectedBinding){throw 'Actual IIS cutover does not match the selected observed-window experiment'}
 $facts=@{phase=$Phase;observedDurablePhase=$true;unchangedAfterTermination=$true;ownedServiceTree=$true;ownedNativeChildrenAbsent=$true;nativeIdentity='LocalSystem';acceptedExactLeafAndCng=$true;enrollmentId=$target.enrollmentId;jobId=$target.jobId;snapshotSha256=$target.snapshotSha256;requestId=[string]$final.requestId;fingerprint=$leafFingerprint}
 if($Phase -eq 'bound-before-complete'){$facts.newIisLeafBound=$true}else{$facts.predecessorIisUnchanged=$true}
 $facts|ConvertTo-Json -Compress
}finally{if($public){$public.Dispose()};if($private){$private.Dispose()};if($cert){$cert.Dispose()};$leaf.Dispose();$sha.Dispose()}

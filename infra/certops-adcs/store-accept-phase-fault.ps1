<# Read-only observation and exact owned service-tree interruption on the
disposable member. A missed post-accept window is a failed experiment. #>
param([Parameter(Mandatory)][string]$OwnedDirectory,[Parameter(Mandatory)][string]$ConfigDirectory,[Parameter(Mandatory)][string]$RepositoryRoot,[Parameter(Mandatory)][string]$NodeExecutable)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if($env:CERTOPS_ADCS_DISPOSABLE_LAB -ne '1' -or (Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Owned disposable forest required'}
$feature=Get-WindowsFeature -Name Web-Server -ErrorAction Stop
if($feature.Installed){throw 'A member without IIS is required'}
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
$node=$nodes[0];$receipt=Join-Path $owned 'store-accept-target.json'
if(Test-Path -LiteralPath $receipt){throw 'Outstanding store-accept receipt'}
Write-Output 'CERTOPS_STORE_ACCEPT_READY'
$deadline=[DateTime]::UtcNow.AddSeconds(180);$target=$null;$observed=$null;$journalPath=$null;$acceptChild=$null
while([DateTime]::UtcNow -lt $deadline){
 $accepts=@()
 if($target){$workPath=[regex]::Escape((Join-Path $config 'windows-cert-store-work'));$accepts=@(Get-CimInstance Win32_Process|Where-Object {$_.ParentProcessId -eq $node.ProcessId -and $_.ExecutablePath -and (Split-Path $_.ExecutablePath -Leaf) -ieq 'certreq.exe' -and $_.CommandLine -match '(?i)(?:^|\s)-accept(?:\s|$)' -and $_.CommandLine -match "(?i)$workPath"})}
 if($accepts.Count -gt 1){throw 'Ambiguous native accept processes'}
 if($accepts.Count -eq 1){
  if($accepts[0].CreationDate -lt $node.CreationDate -or (Invoke-CimMethod -InputObject $accepts[0] -MethodName GetOwnerSid).Sid -ne 'S-1-5-18'){throw 'Foreign native accept process'}
  if($acceptChild -and ($acceptChild.ProcessId -ne $accepts[0].ProcessId -or $acceptChild.CreationDate -ne $accepts[0].CreationDate)){throw 'Multiple native accept invocations'}
  $acceptChild=$accepts[0]
 }
 if(!$target -and (Test-Path -LiteralPath $receipt)){
  try{$candidate=Get-Content -LiteralPath $receipt -Raw|ConvertFrom-Json}catch{Start-Sleep -Milliseconds 5;continue}
  foreach($field in @('enrollmentId','jobId')){if($candidate.$field -notmatch '^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$'){throw 'Malformed enrollment identity'}}
  if($candidate.snapshotSha256 -notmatch '^[a-f0-9]{64}$' -or $candidate.containerName -ne ('tokentimer-enr-'+$candidate.enrollmentId) -or $candidate.domain -notmatch '^certops-adcs-[a-f0-9]{16,32}-store\.example\.test$'){throw 'Malformed native ownership receipt'}
  $target=$candidate;$journalPath=Join-Path $config ('adcs-enrollments\'+$target.enrollmentId+'\journal.json')
 }
 if($target -and (Test-Path -LiteralPath $journalPath)){
  try{
   $candidate=Get-Content -LiteralPath $journalPath -Raw|ConvertFrom-Json
   if($candidate.state -eq 'installing' -and $candidate.installStep -eq 'accept'){
    if($candidate.enrollmentId -ne $target.enrollmentId -or $candidate.jobId -ne $target.jobId -or $candidate.snapshotSha256 -ne $target.snapshotSha256 -or $candidate.containerName -ne $target.containerName){throw 'Foreign installing phase'}
    $leafPath=Join-Path (Split-Path $journalPath) 'leaf.pem'
    $body=[IO.File]::ReadAllText($leafPath) -replace '-----BEGIN CERTIFICATE-----','' -replace '-----END CERTIFICATE-----','' -replace '\s',''
    $leaf=[Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($body))
    try{if($acceptChild -and !$accepts.Count -and (Test-Path -LiteralPath ('Cert:\LocalMachine\My\'+$leaf.Thumbprint))){$observed=$candidate;break}}finally{$leaf.Dispose()}
   }
  }catch{if($_.Exception.Message -eq 'Foreign installing phase'){throw}}
 }
 Start-Sleep -Milliseconds 5
}
if(!$observed){throw 'Native post-accept window missed'}
function Stop-Exact($record){
 $fresh=Get-CimInstance Win32_Process -Filter "ProcessId=$($record.ProcessId)"
 if(!$fresh){return}
 if($fresh.CreationDate -ne $record.CreationDate -or $fresh.ParentProcessId -ne $record.ParentProcessId -or $fresh.ExecutablePath -ine $record.ExecutablePath -or $fresh.CommandLine -cne $record.CommandLine -or (Invoke-CimMethod -InputObject $fresh -MethodName GetOwnerSid).Sid -ne 'S-1-5-18'){throw 'Refuse changed native process identity'}
 Stop-Process -Id $record.ProcessId -Force -ErrorAction Stop
}
$before=@(Get-CimInstance Win32_Process);$ownedProcesses=@{};$ownedProcesses[[int]$node.ProcessId]=$node;$ownedProcesses[[int]$hostProcess.ProcessId]=$hostProcess
for($pass=0;$pass -lt 16;$pass++){foreach($p in $before){if($ownedProcesses.ContainsKey([int]$p.ParentProcessId) -and !$ownedProcesses.ContainsKey([int]$p.ProcessId)){$parent=$ownedProcesses[[int]$p.ParentProcessId];if($p.CreationDate -lt $parent.CreationDate -or $p.CreationDate -lt $node.CreationDate -or !$p.ExecutablePath -or !$p.CommandLine -or (Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid).Sid -ne 'S-1-5-18'){throw 'Ambiguous child identity'};$ownedProcesses[[int]$p.ProcessId]=$p}}}
Stop-Exact $node;Stop-Exact $hostProcess;foreach($record in $ownedProcesses.Values){Stop-Exact $record}
$until=[DateTime]::UtcNow.AddSeconds(10);$emptyPasses=0
do{$all=@(Get-CimInstance Win32_Process);foreach($p in $all){if($ownedProcesses.ContainsKey([int]$p.ParentProcessId) -and $p.CreationDate -ge $node.CreationDate -and !$ownedProcesses.ContainsKey([int]$p.ProcessId)){throw 'Unexpected descendant; preserve native state'}};$live=@($ownedProcesses.Keys|ForEach-Object {Get-CimInstance Win32_Process -Filter "ProcessId=$_"});if(!$live.Count){$emptyPasses++}else{$emptyPasses=0};if($emptyPasses -ge 2){break};Start-Sleep -Milliseconds 20}while([DateTime]::UtcNow -lt $until)
if($live.Count -or $emptyPasses -lt 2 -or (Get-Service TokenTimerAgent).Status -ne 'Stopped'){throw 'Native process drainage unproven'}
$final=Get-Content -LiteralPath $journalPath -Raw|ConvertFrom-Json
foreach($field in @('state','installStep','jobId','containerName','snapshotSha256','csrSha256','csrSpkiSha256','leafSha256')){if($final.$field -ne $observed.$field){throw 'Journal advanced during interruption'}}
$leafPath=Join-Path (Split-Path $journalPath) 'leaf.pem'
if((Get-FileHash -LiteralPath $leafPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $final.leafSha256){throw 'Issued artifact hash mismatch'}
$body=[IO.File]::ReadAllText($leafPath) -replace '-----BEGIN CERTIFICATE-----','' -replace '-----END CERTIFICATE-----','' -replace '\s',''
$leaf=[Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($body));$cert=$null;$private=$null;$public=$null;$sha=[Security.Cryptography.SHA256]::Create()
try{
 $cert=Get-Item -LiteralPath ('Cert:\LocalMachine\My\'+$leaf.Thumbprint)
 if([Convert]::ToBase64String($cert.RawData) -ne [Convert]::ToBase64String($leaf.RawData) -or !$cert.HasPrivateKey){throw 'Exact leaf and key missing'}
 $private=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
 if(!$private -or $private.Key.KeyName -ne $target.containerName -or $private.Key.Provider.Provider -ne 'Microsoft Software Key Storage Provider' -or !$private.Key.IsMachineKey -or $private.Key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None){throw 'Protected native key unproven'}
 $challenge=[Text.Encoding]::UTF8.GetBytes('CertOps store-key possession '+[guid]::NewGuid().ToString());$signature=$private.SignData($challenge,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
 $public=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($leaf)
 if(!$public.VerifyData($challenge,$signature,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)){throw 'Native key does not match leaf'}
 $fingerprint=([BitConverter]::ToString($sha.ComputeHash($leaf.RawData))).Replace('-','').ToLowerInvariant()
 $requestId=if($final.PSObject.Properties['requestId']){$final.requestId}else{$null}
 @{nativeIdentity='LocalSystem';observedPostAccept=$true;nativeProcessDrained=$true;store='LocalMachine\My';iisBindingTouched=$false;hasPrivateKey=$true;nonExportable=$true;machineKey=$true;containerName=$target.containerName;fingerprintSha256=$fingerprint;csrSpkiSha256=$final.csrSpkiSha256;keyPossessionVerified=$true;requestId=$requestId;enrollmentId=$target.enrollmentId;jobId=$target.jobId;snapshotSha256=$target.snapshotSha256}|ConvertTo-Json -Compress
}finally{if($public){$public.Dispose()};if($private){$private.Dispose()};if($cert){$cert.Dispose()};$leaf.Dispose();$sha.Dispose()}

<#
Install/configure the enterprise CA on the freshly provisioned qualification domain server. Called
only by provision-lab.ps1 with a temporary forest credential; creates actual CA service/material,
not simulated certutil output.
#>
param([Parameter(Mandatory)][string]$DomainPassword,[ValidateSet('root','subordinate')][string]$HierarchyRole='root',[ValidateRange(60,900)][int]$StageTimeoutSeconds=600,[switch]$BootstrapWorker)
$ErrorActionPreference = 'Stop'
# Run the bounded bootstrap in an owned process. Stop-Job can itself block on
# stalled remoting/servicing; the parent must retain an enforceable deadline.
function Invoke-CaBootstrapProcess([string]$Script,[string]$Password,[string]$Role,[int]$Seconds,[int]$GraceSeconds=30){
 $start=[Diagnostics.ProcessStartInfo]::new()
 $start.FileName=Join-Path $PSHOME $(if($env:OS -eq 'Windows_NT'){'powershell.exe'}else{'pwsh'})
 $command='$ErrorActionPreference="Stop"; $phase="input"; try {$raw=[Console]::In.ReadToEnd(); $phase="json"; $p=$raw|ConvertFrom-Json; $raw=$null; $phase="worker"; & $p.Script -DomainPassword $p.Password -HierarchyRole $p.Role -StageTimeoutSeconds $p.Seconds -BootstrapWorker; exit 0} catch {$kind=$_.Exception.GetType().Name; if($kind -cnotmatch "^[A-Za-z][A-Za-z0-9]{0,79}$"){$kind="Exception"}; [Console]::Out.WriteLine("CERTOPS_CA_PROCESS_ERROR="+$phase+":"+$kind+":"+$_.Exception.HResult); exit 1}'
 $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
 $start.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '+$encoded
 $start.UseShellExecute=$false;$start.CreateNoWindow=$true
 $start.EnvironmentVariables.Remove('PSModulePath')
 $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
 $process=[Diagnostics.Process]::new();$process.StartInfo=$start;$started=$false
 try{
  $null=$process.Start();$started=$true
  $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
  # The temporary forest password goes through a pipe, never command arguments.
  $process.StandardInput.WriteLine((@{Script=$Script;Password=$Password;Role=$Role;Seconds=$Seconds}|ConvertTo-Json -Compress))
  $process.StandardInput.Close()
  if(-not $process.WaitForExit(($Seconds+$GraceSeconds)*1000)){
   $process.Kill();$null=$process.WaitForExit(5000)
   throw [TimeoutException]::new('Owned CA bootstrap process deadline exceeded')
  }
  $output=$stdout.GetAwaiter().GetResult()
  # Only fixed bootstrap receipts may cross the child-process boundary.
  foreach($line in ($output -split '\r?\n')){
   if($line -cmatch '^CERTOPS_STAGE=enterprise-(ca-service-running|subordinate-request-created)$' -or $line -cmatch '^CERTOPS_SUBORDINATE_REQUEST=[A-Za-z0-9+/=]+$'){Write-Output $line}
  }
  if($process.ExitCode -ne 0){
   $kind='Unknown'
   $match=[regex]::Match($output,'(?m)^CERTOPS_CA_PROCESS_ERROR=((?:input|json|worker):[A-Za-z][A-Za-z0-9]{0,79}:-?[0-9]{1,11})\r?$')
   if($match.Success){$kind=$match.Groups[1].Value}
   throw ('Owned CA bootstrap process failed: '+$kind+' (exit '+$process.ExitCode+')')
  }
 }finally{
  if($started -and -not $process.HasExited){$process.Kill()}
  $process.Dispose()
 }
}
if(-not $BootstrapWorker){
 try{Invoke-CaBootstrapProcess -Script $PSCommandPath -Password $DomainPassword -Role $HierarchyRole -Seconds $StageTimeoutSeconds}
 catch{
  $stage='membership'
  try{$r=Get-Content 'C:\ttqualification\domain-ca-stage.json' -Raw|ConvertFrom-Json;if($r.stage -in @('membership','directory-ready','remoting-setup','directory-officer','role-install','ca-configure','service-check')){$stage=$r.stage}}catch{}
  Write-Output ('CERTOPS_CA_FAILED_STAGE='+$stage)
  throw 'Owned CA bootstrap failed; inspect the bounded stage receipt'
 }finally{$DomainPassword=$null}
 return
}
$bootstrapClock=[Diagnostics.Stopwatch]::StartNew()
$stageFile='C:\ttqualification\domain-ca-stage.json'
function Invoke-CaBoundedLocalJob([scriptblock]$ScriptBlock,[object[]]$Arguments,[int]$TimeoutSeconds){
 $localJob=$null
 try{
  $localJob=Start-Job -ScriptBlock $ScriptBlock -ArgumentList $Arguments
  if(-not(Wait-Job -Job $localJob -Timeout $TimeoutSeconds)){throw [TimeoutException]::new('Owned CA preflight deadline exceeded')}
  Receive-Job -Job $localJob -ErrorAction Stop
  if($localJob.State -ne 'Completed'){throw 'Owned CA preflight did not complete'}
 }finally{
  if($localJob){if($localJob.State -notin @('Completed','Failed','Stopped')){Stop-Job -Job $localJob -ErrorAction SilentlyContinue};Remove-Job -Job $localJob -Force -ErrorAction SilentlyContinue}
 }
}
$job=$null
$credential=$null
try{
 # The owned lab's diagnostic directory is the only write before membership
 # verification; privileged directory/CA operations remain guarded below.
 New-Item -ItemType Directory -Path (Split-Path $stageFile) -Force|Out-Null
 @{stage='membership';status='running';updatedAt=[DateTimeOffset]::UtcNow.ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath $stageFile
 $prepare={
  param([string]$StageFile)
  $ErrorActionPreference='Stop'
  if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Expected isolated qualification forest'}
  New-Item -ItemType Directory -Path (Split-Path $StageFile) -Force|Out-Null
  @{stage='directory-ready';status='running';updatedAt=[DateTimeOffset]::UtcNow.ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath $StageFile
  Import-Module ActiveDirectory
  $ready=$false
  for($attempt=0;$attempt -lt 60;$attempt++){
   try{$null=Get-ADDomain -ErrorAction Stop;$ready=$true;break}catch{Start-Sleep -Seconds 2}
  }
  if(-not $ready){throw 'Directory was not ready after reboot'}
  @{stage='remoting-setup';status='running';updatedAt=[DateTimeOffset]::UtcNow.ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath $StageFile
  Enable-PSRemoting -Force
 }
 $remaining=[int][Math]::Floor($StageTimeoutSeconds-$bootstrapClock.Elapsed.TotalSeconds)
 if($remaining -lt 1){throw [TimeoutException]::new('Owned CA bootstrap deadline exceeded')}
 Invoke-CaBoundedLocalJob -ScriptBlock $prepare -Arguments @($stageFile) -TimeoutSeconds ([Math]::Min(120,$remaining))
$credential = [PSCredential]::new('TTQUAL\ttqualification', (ConvertTo-SecureString $DomainPassword -AsPlainText -Force))
$sessionOption=New-PSSessionOption -OpenTimeout 30000 -OperationTimeout 60000
$job=Invoke-Command -ComputerName localhost -Credential $credential -SessionOption $sessionOption -AsJob -ArgumentList $DomainPassword,$HierarchyRole,$stageFile -ScriptBlock {
  param([string]$DomainPassword,[string]$HierarchyRole,[string]$StageFile)
  $ErrorActionPreference = 'Stop'
  function Set-CaStage([string]$Stage){
    @{stage=$Stage;status='running';updatedAt=[DateTimeOffset]::UtcNow.ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath $StageFile
  }
Set-CaStage 'directory-officer'
Import-Module DnsServer
Set-DnsServerForwarder -IPAddress 168.63.129.16
Import-Module ActiveDirectory
New-ADUser -Name 'tt-lab-admin' -SamAccountName 'tt-lab-admin' -AccountPassword (ConvertTo-SecureString $DomainPassword -AsPlainText -Force) -Enabled $true
$domainSid=(Get-ADDomain).DomainSID.Value
Add-ADGroupMember -Identity "$domainSid-512" -Members 'tt-lab-admin'
Add-ADGroupMember -Identity "$domainSid-519" -Members 'tt-lab-admin'
$memberships=@(Get-ADPrincipalGroupMembership 'tt-lab-admin' | ForEach-Object {$_.SID.Value})
if($memberships -notcontains "$domainSid-512" -or $memberships -notcontains "$domainSid-519"){throw 'Owned officer privileged group membership missing'}
if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration') { throw 'Refusing to alter an existing CA' }
Set-CaStage 'role-install'
$role = Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools
if (-not $role.Success -or $role.RestartNeeded -ne 'No') { throw 'Enterprise CA role install failed or needs another reboot' }
Set-CaStage 'ca-configure'
if($HierarchyRole -eq 'subordinate'){
  New-Item -ItemType Directory -Path 'C:\ttqualification-hierarchy' -ErrorAction Stop | Out-Null
  Install-AdcsCertificationAuthority -CAType EnterpriseSubordinateCA -CACommonName 'TTQualificationRoot' -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -KeyLength 2048 -HashAlgorithmName SHA256 -OutputCertRequestFile 'C:\ttqualification-hierarchy\subordinate.req' -Force | Out-Null
  Write-Output ('CERTOPS_SUBORDINATE_REQUEST='+[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\ttqualification-hierarchy\subordinate.req')))
  Write-Output 'CERTOPS_STAGE=enterprise-subordinate-request-created'
  return
}
Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName 'TTQualificationRoot' -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -KeyLength 2048 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 1 -Force | Out-Null
Set-CaStage 'service-check'
if ((Get-Service CertSvc).Status -ne 'Running') { throw 'Enterprise CA service is not running' }
Write-Output 'CERTOPS_STAGE=enterprise-ca-service-running'

}
# Remoting's OperationTimeout is a transport heartbeat, not an execution limit.
# Bound the complete owned bootstrap job separately; never retry CA creation.
$remaining=[int][Math]::Floor($StageTimeoutSeconds-$bootstrapClock.Elapsed.TotalSeconds)
if($remaining -lt 1){throw [TimeoutException]::new('Owned CA bootstrap deadline exceeded')}
if(-not(Wait-Job -Job $job -Timeout $remaining)){throw [TimeoutException]::new('Owned CA bootstrap deadline exceeded')}
Receive-Job -Job $job -ErrorAction Stop
if($job.State -ne 'Completed'){throw 'Owned CA bootstrap did not complete'}
$receipt=Get-Content -LiteralPath $stageFile -Raw|ConvertFrom-Json
$receipt.status='completed';$receipt|ConvertTo-Json|Set-Content -LiteralPath $stageFile
}catch{
$timedOut=$_.Exception -is [TimeoutException]
$stage='membership'
try{$observed=Get-Content -LiteralPath $stageFile -Raw|ConvertFrom-Json;if($observed.stage -in @('membership','directory-ready','remoting-setup','directory-officer','role-install','ca-configure','service-check')){$stage=$observed.stage}}catch{}
if(Test-Path (Split-Path $stageFile)){@{stage=$stage;status='failed';timedOut=$timedOut;updatedAt=[DateTimeOffset]::UtcNow.ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath $stageFile}
Write-Output ('CERTOPS_CA_FAILED_STAGE='+$stage)
throw 'Owned CA bootstrap failed; inspect the bounded stage receipt'
}finally{
if($job){if($job.State -notin @('Completed','Failed','Stopped')){Stop-Job -Job $job -ErrorAction SilentlyContinue};Remove-Job -Job $job -Force -ErrorAction SilentlyContinue}
$credential=$null;$DomainPassword=$null
}

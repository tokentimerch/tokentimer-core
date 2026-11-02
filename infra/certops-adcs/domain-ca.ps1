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
 # A worker can leave a background job holding the output pipe open after exit.
 # Keep its entire process tree owned, including when this launcher is stopped.
 $ownedJob=$null
 if($env:OS -eq 'Windows_NT'){
  if(-not ('CertOpsCaOwnedJob' -as [type])){Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
public sealed class CertOpsCaOwnedJob : IDisposable {
 [StructLayout(LayoutKind.Sequential)] struct Limits {
  public long processTime,jobTime; public uint flags; public UIntPtr min,max;
  public uint processes; public UIntPtr affinity; public uint priority,scheduling;
 }
 [StructLayout(LayoutKind.Sequential)] struct Counters {public ulong a,b,c,d,e,f;}
 [StructLayout(LayoutKind.Sequential)] struct Extended {
  public Limits basic; public Counters io; public UIntPtr processMemory,jobMemory,peakProcess,peakJob;
 }
 [StructLayout(LayoutKind.Sequential)] struct Accounting {
  public long user,kernel,periodUser,periodKernel;
  public uint faults,total,active,terminated;
 }
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attrs,string name);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int kind,ref Extended limits,int size);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint code);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int kind,out Accounting info,int size,IntPtr returned);
 [DllImport("kernel32.dll",EntryPoint="QueryInformationJobObject",SetLastError=true)] static extern bool QueryProcesses(IntPtr job,int kind,IntPtr info,int size,IntPtr returned);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool IsProcessInJob(IntPtr process,IntPtr job,out bool member);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr process,uint milliseconds);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 IntPtr handle;
 public CertOpsCaOwnedJob() {
  handle=CreateJobObject(IntPtr.Zero,null);
  if(handle==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
  var limits=new Extended(); limits.basic.flags=0x2000;
  if(!SetInformationJobObject(handle,9,ref limits,Marshal.SizeOf(typeof(Extended)))) {
   int error=Marshal.GetLastWin32Error(); Dispose(); throw new Win32Exception(error);
  }
 }
 public void Add(IntPtr process) {if(!AssignProcessToJobObject(handle,process)) throw new Win32Exception(Marshal.GetLastWin32Error());}
 public bool Contains(IntPtr process) {
  bool member;
  if(!IsProcessInJob(process,handle,out member)) throw new Win32Exception(Marshal.GetLastWin32Error());
  return member;
 }
 List<IntPtr> CaptureMembers() {
  var members=new List<IntPtr>();
  int size=8+8192*IntPtr.Size;
  IntPtr buffer=Marshal.AllocHGlobal(size);
  try {
   if(!QueryProcesses(handle,3,buffer,size,IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
   int assigned=Marshal.ReadInt32(buffer),count=Marshal.ReadInt32(buffer,4);
   if(assigned<0 || assigned>8192 || count!=assigned) throw new InvalidOperationException("Owned CA process inventory exceeded its bound");
   for(int i=0;i<count;i++) {
    long pid=Marshal.ReadIntPtr(buffer,8+i*IntPtr.Size).ToInt64();
    if(pid<=0 || pid>UInt32.MaxValue) throw new InvalidOperationException("Invalid owned CA process identity");
    IntPtr process=OpenProcess(0x00101000,false,(uint)pid);
    if(process==IntPtr.Zero) {
     int error=Marshal.GetLastWin32Error();
     if(error==87) continue; // The process already exited before handle capture.
     throw new Win32Exception(error);
    }
    members.Add(process);
    if(!Contains(process)) throw new InvalidOperationException("Owned CA process identity changed");
   }
   return members;
  } catch {
   foreach(IntPtr process in members) CloseHandle(process);
   throw;
  } finally {Marshal.FreeHGlobal(buffer);}
 }
 public void StopAndDrain(int milliseconds) {
  var clock=System.Diagnostics.Stopwatch.StartNew();
  var members=CaptureMembers();
  try {
   if(!TerminateJobObject(handle,1)) throw new Win32Exception(Marshal.GetLastWin32Error());
   // Job accounting can reach zero before a terminated process is signaled.
   // Retain and wait on exact member handles; never reopen a PID to stop it.
   foreach(IntPtr process in members) {
    uint remaining=(uint)Math.Max(0,milliseconds-clock.ElapsedMilliseconds);
    if(WaitForSingleObject(process,remaining)!=0) throw new TimeoutException("Owned CA process handle did not drain");
   }
   do {
    Accounting value;
    if(!QueryInformationJobObject(handle,1,out value,Marshal.SizeOf(typeof(Accounting)),IntPtr.Zero))
     throw new Win32Exception(Marshal.GetLastWin32Error());
    if(value.active==0) return;
    System.Threading.Thread.Sleep(10);
   } while(clock.ElapsedMilliseconds<milliseconds);
   throw new TimeoutException("Owned CA bootstrap descendants did not drain");
  } finally {foreach(IntPtr process in members) CloseHandle(process);}
 }
 public void Dispose() {if(handle!=IntPtr.Zero){CloseHandle(handle);handle=IntPtr.Zero;}}
}
'@}
  $ownedJob=[CertOpsCaOwnedJob]::new()
 }
 $start=[Diagnostics.ProcessStartInfo]::new()
 $start.FileName=Join-Path $PSHOME $(if($env:OS -eq 'Windows_NT'){'powershell.exe'}else{'pwsh'})
 $command='$ErrorActionPreference="Stop"; $phase="input"; try {$reader=[IO.StreamReader]::new([Console]::OpenStandardInput(),[Text.Encoding]::UTF8,$true); $raw=$reader.ReadToEnd(); $phase="json"; $p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($raw))|ConvertFrom-Json; $raw=$null; $phase="worker"; & $p.Script -DomainPassword $p.Password -HierarchyRole $p.Role -StageTimeoutSeconds $p.Seconds -BootstrapWorker; exit 0} catch {$kind=$_.Exception.GetType().Name; if($kind -cnotmatch "^[A-Za-z][A-Za-z0-9]{0,79}$"){$kind="Exception"}; [Console]::Out.WriteLine("CERTOPS_CA_PROCESS_ERROR="+$phase+":"+$kind+":"+$_.Exception.HResult); exit 1}'
 $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
 $start.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '+$encoded
 $start.UseShellExecute=$false;$start.CreateNoWindow=$true
 $start.EnvironmentVariables.Remove('PSModulePath')
 $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
 $process=[Diagnostics.Process]::new();$process.StartInfo=$start;$started=$false
 try{
  $null=$process.Start();$started=$true
  # Assign before writing stdin: the worker cannot start CA work or children yet.
  if($ownedJob){$ownedJob.Add($process.Handle)}
  $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
  # The temporary forest password goes through a pipe, never command arguments.
  # ASCII framing survives OEM writers; the worker detects a UTF-8/UTF-16 BOM
  # on the binary pipe before decoding the UTF-8 JSON, including Unicode paths.
  $json=@{Script=$Script;Password=$Password;Role=$Role;Seconds=$Seconds}|ConvertTo-Json -Compress
  $process.StandardInput.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)))
  $json=$null
  $process.StandardInput.Close()
  if(-not $process.WaitForExit(($Seconds+$GraceSeconds)*1000)){
   if($ownedJob){$ownedJob.StopAndDrain(5000);$ownedJob.Dispose();$ownedJob=$null}else{$process.Kill($true)}
   $null=$process.WaitForExit(5000)
   throw [TimeoutException]::new('Owned CA bootstrap process deadline exceeded')
  }
  if($ownedJob){$ownedJob.StopAndDrain(5000);$ownedJob.Dispose();$ownedJob=$null}
  if(-not $stdout.Wait(5000)){throw [TimeoutException]::new('Owned CA bootstrap output deadline exceeded')}
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
  try{if($ownedJob){$ownedJob.StopAndDrain(5000)}}finally{
   if($ownedJob){$ownedJob.Dispose()}
   try{if($started -and -not $process.HasExited){$process.Kill();$null=$process.WaitForExit(5000)}}finally{$process.Dispose()}
  }
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

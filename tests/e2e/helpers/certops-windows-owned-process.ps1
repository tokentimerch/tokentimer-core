<# Existing-process interruption only, not retroactive atomic containment.
All native handles remain in this one process from capture through termination.
Unknown descendants or fixture-command survivors preserve the caller's guard. #>
param([Parameter(Mandatory)][string]$ContextFile,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ContextSha256,
 [Parameter(Mandatory)][int]$OwnerProcessId)
$ErrorActionPreference='Stop'
if([IntPtr]::Size -ne 8 -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw 'Actual64bit SYSTEM ownership required'}
$self=Get-CimInstance Win32_Process -Filter "ProcessId=$PID";$owner=Get-CimInstance Win32_Process -Filter "ProcessId=$OwnerProcessId"
if(!$owner -or $self.ParentProcessId -ne $OwnerProcessId){throw 'Native controller owner mismatch'}
$file=Get-Item -LiteralPath $ContextFile
if($file.PSIsContainer -or ($file.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Private process context refused'}
$bytes=[IO.File]::ReadAllBytes($ContextFile);$digest=[Security.Cryptography.SHA256]::Create();try{$actualHash=([BitConverter]::ToString($digest.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$digest.Dispose()};if($actualHash -cne $ContextSha256){throw 'Private process context digest mismatch'};$context=[Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json
if($owner.ExecutablePath -ine $context.ownerExecutable -or $owner.CreationDate -gt $self.CreationDate){throw 'Controller executable or chronology mismatch'}
if($context.schemaVersion -ne 1 -or $context.commandRoots.Count -lt 1 -or $context.commandRoots.Count -gt 8){throw 'Bounded owned context required'}
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
public sealed class RetainedFixtureProcess : IDisposable {
 [StructLayout(LayoutKind.Sequential)] struct FileTime {public uint Low,High;}
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr h,out FileTime c,out FileTime e,out FileTime k,out FileTime u);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr h,uint f,StringBuilder value,ref uint length);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr h,uint code);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr h,uint milliseconds);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr h);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr h,uint access,out IntPtr token);
 IntPtr handle;
 static void Require(bool value){if(!value)throw new Win32Exception(Marshal.GetLastWin32Error());}
 public RetainedFixtureProcess(uint pid){if(IntPtr.Size!=8 || Marshal.SizeOf(typeof(FileTime))!=8)throw new Exception("Unsupported ABI");handle=OpenProcess(0x00101001,false,pid);Require(handle!=IntPtr.Zero);}
 public string CreatedTicks {get{FileTime c,e,k,u;Require(GetProcessTimes(handle,out c,out e,out k,out u));return (((ulong)c.High<<32)|c.Low).ToString(System.Globalization.CultureInfo.InvariantCulture);}}
 public string CreatedMicroseconds {get{return DateTime.FromFileTimeUtc(Int64.Parse(CreatedTicks,System.Globalization.CultureInfo.InvariantCulture)).ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ",System.Globalization.CultureInfo.InvariantCulture);}}
 public string Image {get{uint size=32768;var b=new StringBuilder((int)size);Require(QueryFullProcessImageName(handle,0,b,ref size));return b.ToString();}}
 public string Sid {get{IntPtr t;Require(OpenProcessToken(handle,8,out t));try{using(var identity=new WindowsIdentity(t)){return identity.User.Value;}}finally{Require(CloseHandle(t));}}}
 public bool Exited {get{uint r=WaitForSingleObject(handle,0);if(r==0)return true;if(r==258)return false;throw new Win32Exception(Marshal.GetLastWin32Error());}}
 public void Terminate(string created,string image){if(Exited)return;if(CreatedTicks!=created || !String.Equals(Image,image,StringComparison.OrdinalIgnoreCase) || Sid!="S-1-5-18")throw new Exception("Retained identity changed");Require(TerminateProcess(handle,238));}
 public void Wait(){if(WaitForSingleObject(handle,30000)!=0)throw new Exception("Owned process did not drain");}
 public void Dispose(){if(handle!=IntPtr.Zero){IntPtr h=handle;handle=IntPtr.Zero;Require(CloseHandle(h));}}
}
'@
function Hash-Text([string]$value){$h=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($value)))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
function Identity($p){if(!$p -or !$p.ExecutablePath -or !$p.CommandLine){throw 'Complete process identity unavailable'};return @{pid=[int]$p.ProcessId;parentPid=[int]$p.ParentProcessId;createdAt=$p.CreationDate.ToUniversalTime().ToString('o');executable=[string]$p.ExecutablePath;commandSha256=(Hash-Text ([string]$p.CommandLine))}}
function Same($a,$b){return $a.pid -eq $b.pid -and $a.parentPid -eq $b.parentPid -and $a.createdAt -ceq $b.createdAt -and $a.executable -ieq $b.executable -and $a.commandSha256 -ceq $b.commandSha256}
function Inventory(){$rows=@(Get-CimInstance Win32_Process -ErrorAction Stop);if($rows.Count -lt 1 -or $rows.Count -gt 8192){throw 'Complete bounded native inventory required'};return $rows}
$handles=@();$root=$context.identity
try{
 $before=Inventory;$rootRows=@($before|Where-Object ProcessId -eq $root.pid)
 if($rootRows.Count -ne 1 -or !(Same (Identity $rootRows[0]) $root)){throw 'Original root identity mismatch'}
 $known=@{([int]$root.pid)=$true};$targets=@($rootRows[0])
 for($depth=0;$depth -lt 16;$depth++){
  $added=$false
  foreach($p in $before){if(!$known.ContainsKey([int]$p.ProcessId) -and $known.ContainsKey([int]$p.ParentProcessId)){
   $parents=@($targets|Where-Object ProcessId -eq $p.ParentProcessId);if($parents.Count -ne 1 -or $p.CreationDate -lt $parents[0].CreationDate){throw 'Immediate-parent ancestry creation mismatch'}
   $known[[int]$p.ProcessId]=$true;$targets+=,$p;$added=$true
   if($targets.Count -gt 128){throw 'Native descendant bound exceeded'}
  }}
  if(!$added){break}
 }
 # Retain every handle before any termination. No PID is used to kill.
 foreach($p in $targets){
  $identity=Identity $p;$handle=[RetainedFixtureProcess]::new([uint32]$p.ProcessId)
  $entry=@{identity=$identity;handle=$handle};$handles+=,$entry
  $fresh=Identity (Get-CimInstance Win32_Process -Filter "ProcessId=$($identity.pid)")
  if(!(Same $fresh $identity) -or $handle.Exited -or $handle.Image -ine $identity.executable -or $handle.Sid -cne 'S-1-5-18'){throw 'Native handle and caller identity disagree'}
  $entry.createdTicks=$handle.CreatedTicks
  # CIM exposes microseconds; only this presentation comparison truncates submicrosecond FILETIME precision.
  if($handle.CreatedMicroseconds -cne $p.CreationDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.ffffffZ')){throw 'Native creation time does not bind original CIM identity'}
 }
 $last=Inventory
 foreach($p in $last){if($known.ContainsKey([int]$p.ParentProcessId) -and !$known.ContainsKey([int]$p.ProcessId)){throw 'New descendant after capture; preserve state'}}
 foreach($entry in $handles){
  # A retained exited handle proves drainage; PID absence alone never does.
  if($entry.handle.Exited){continue}
  $fresh=Identity (Get-CimInstance Win32_Process -Filter "ProcessId=$($entry.identity.pid)")
  if(!(Same $fresh $entry.identity) -or $entry.handle.CreatedTicks -cne $entry.createdTicks){throw 'Captured identity changed before termination'}
 }
 # Root first prevents its completion callbacks from starting another operation.
 foreach($entry in $handles){if(!$entry.handle.Exited){
  $fresh=Identity (Get-CimInstance Win32_Process -Filter "ProcessId=$($entry.identity.pid)")
  if(!(Same $fresh $entry.identity)){throw 'Fresh process replacement at destructive boundary'}
  $entry.handle.Terminate($entry.createdTicks,$entry.identity.executable)
 }}
 foreach($entry in $handles){$entry.handle.Wait()}
 $clock=[Diagnostics.Stopwatch]::StartNew();$clear=$false
 do{
  $after=Inventory;$remaining=@()
  foreach($p in $after){
   if($p.ProcessId -eq $PID -or $p.ProcessId -eq $OwnerProcessId){continue}
   if($known.ContainsKey([int]$p.ProcessId) -or $known.ContainsKey([int]$p.ParentProcessId)){$remaining+=,$p;continue}
   foreach($prefix in $context.commandRoots){if(($p.CommandLine -and ([string]$p.CommandLine).IndexOf([string]$prefix,[StringComparison]::OrdinalIgnoreCase) -ge 0) -or ($p.ExecutablePath -and ([string]$p.ExecutablePath).Equals([string]$prefix,[StringComparison]::OrdinalIgnoreCase))){$remaining+=,$p;break}}
  }
  if($remaining.Count -eq 0){$clear=$true;break};Start-Sleep -Milliseconds 100
 }while($clock.ElapsedMilliseconds -lt 30000)
 if(!$clear){throw 'Surviving lineage or fixture command; preserve state'}
 @{scope='exact-owned-native-process-handle-termination';rootPid=[int]$root.pid;rootNativeCreatedTicks=[string]$handles[0].createdTicks;capturedProcessCount=$handles.Count;retainedNativeHandles=$true;freshIdentityReverified=$true;capturedHandlesExited=$true;capturedLineageAbsent=$true;fixtureCommandPathsAbsent=$true;atomicTreeContainmentQualified=$false}|ConvertTo-Json -Compress
}finally{$closeFailed=$false;foreach($entry in $handles){try{$entry.handle.Dispose()}catch{$closeFailed=$true}};if($closeFailed){throw 'Retained native handle release failed'}}

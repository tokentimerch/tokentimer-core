<# Read-only observer for an explicitly owned installed-service stop.
Retains query/synchronize handles before publishing readiness. This is not
atomic tree containment: unobserved fork/reparent races are not qualified.
It never stops,
signals or terminates any process. Unknown ancestry or missing evidence fails
closed; the caller must preserve its native and database ownership receipts. #>
param(
 [Parameter(Mandatory)][string]$ContextFile,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ContextSha256,
 [Parameter(Mandatory)][int]$OwnerProcessId,
 [Parameter(Mandatory)][string]$ReadyFile
)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if([IntPtr]::Size -ne 8 -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18'){throw 'Actual64bit SYSTEM observer required'}
$self=Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction Stop
$owner=Get-CimInstance Win32_Process -Filter "ProcessId=$OwnerProcessId" -ErrorAction Stop
if(!$self -or !$owner -or $self.ParentProcessId -ne $OwnerProcessId){throw 'Exact observer parent required'}
$contextItem=Get-Item -LiteralPath $ContextFile
if($contextItem.PSIsContainer -or ($contextItem.Attributes-band[IO.FileAttributes]::ReparsePoint) -or $contextItem.Length -lt 1 -or $contextItem.Length -gt 65536){throw 'Bounded regular observer context required'}
$contextStream=[IO.File]::Open($ContextFile,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
$handles=@();$ownerHandle=$null;$result=$null
try{
 $bytes=New-Object byte[] ([int]$contextStream.Length)
 if($contextStream.Read($bytes,0,$bytes.Length) -ne $bytes.Length -or $contextStream.ReadByte() -ne -1){throw 'Complete private observer context required'}
 $hasher=[Security.Cryptography.SHA256]::Create()
 try{$digest=([BitConverter]::ToString($hasher.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$hasher.Dispose()}
 if($digest -cne $ContextSha256){throw 'Observer context digest mismatch'}
 $context=[Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json
 if($context.schemaVersion -ne 1 -or $context.token -cnotmatch '^[a-f0-9]{64}$' -or $context.maxWaitMs -lt 1000 -or $context.maxWaitMs -gt 120000 -or $context.commandRoots.Count -lt 1 -or $context.commandRoots.Count -gt 8){throw 'Closed bounded observer context required'}
 if($owner.ExecutablePath -ine $context.ownerExecutable -or $owner.CreationDate.ToUniversalTime().ToString('o') -cne $context.ownerCreatedAt){throw 'Original observer owner changed'}
 Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
public sealed class StopObservationHandle : IDisposable {
 [StructLayout(LayoutKind.Sequential)] struct FileTime {public uint Low,High;}
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr h,out FileTime c,out FileTime e,out FileTime k,out FileTime u);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr h,uint f,StringBuilder b,ref uint n);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr h,uint ms);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr h,out uint code);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr h);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr h,uint access,out IntPtr token);
 IntPtr handle;
 static void Require(bool value){if(!value)throw new Win32Exception(Marshal.GetLastWin32Error());}
 public StopObservationHandle(uint pid){handle=OpenProcess(0x00101000,false,pid);Require(handle!=IntPtr.Zero);}
 public string CreatedTicks {get{FileTime c,e,k,u;Require(GetProcessTimes(handle,out c,out e,out k,out u));return (((ulong)c.High<<32)|c.Low).ToString(System.Globalization.CultureInfo.InvariantCulture);}}
 public string CreatedMicroseconds {get{return DateTime.FromFileTimeUtc(Int64.Parse(CreatedTicks,System.Globalization.CultureInfo.InvariantCulture)).ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ",System.Globalization.CultureInfo.InvariantCulture);}}
 public string Image {get{uint n=32768;var b=new StringBuilder((int)n);Require(QueryFullProcessImageName(handle,0,b,ref n));return b.ToString();}}
 public string Sid {get{IntPtr token;Require(OpenProcessToken(handle,8,out token));try{using(var identity=new WindowsIdentity(token)){return identity.User.Value;}}finally{Require(CloseHandle(token));}}}
 public bool Exited {get{uint r=WaitForSingleObject(handle,0);if(r==0)return true;if(r==258)return false;throw new Win32Exception(Marshal.GetLastWin32Error());}}
 public uint ExitCode {get{if(!Exited)throw new Exception("Original handle still live");uint code;Require(GetExitCodeProcess(handle,out code));return code;}}
 public void Dispose(){if(handle!=IntPtr.Zero){IntPtr h=handle;handle=IntPtr.Zero;Require(CloseHandle(h));}}
}
'@
 function Hash-Text([string]$value){$h=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($value)))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
 function Identity($p){if(!$p -or !$p.ExecutablePath -or !$p.CommandLine){throw 'Complete observed identity required'};return @{pid=[int]$p.ProcessId;parentPid=[int]$p.ParentProcessId;createdAt=$p.CreationDate.ToUniversalTime().ToString('o');executable=[string]$p.ExecutablePath;commandSha256=(Hash-Text ([string]$p.CommandLine))}}
 function Same($a,$b){return $a.pid -eq $b.pid -and $a.parentPid -eq $b.parentPid -and $a.createdAt -ceq $b.createdAt -and $a.executable -ieq $b.executable -and $a.commandSha256 -ceq $b.commandSha256}
 function Inventory(){$rows=@(Get-CimInstance Win32_Process -ErrorAction Stop);if($rows.Count -lt 1 -or $rows.Count -gt 8192){throw 'Complete bounded process inventory required'};return $rows}
 $ownerHandle=[StopObservationHandle]::new([uint32]$OwnerProcessId)
 if($ownerHandle.Exited -or $ownerHandle.Image -ine $owner.ExecutablePath -or $ownerHandle.Sid -cne 'S-1-5-18' -or $ownerHandle.CreatedMicroseconds -cne $owner.CreationDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.ffffffZ')){throw 'Native observer owner binding failed'}
 $before=Inventory;$roots=@($before|Where-Object ProcessId -eq $context.identity.pid)
 if($roots.Count -ne 1 -or !(Same (Identity $roots[0]) $context.identity)){throw 'Original installed host identity mismatch'}
 $known=@{([int]$roots[0].ProcessId)=$true};$targets=@($roots[0])
 for($depth=0;$depth -lt 16;$depth++){
  $added=$false
  foreach($p in $before){if(!$known.ContainsKey([int]$p.ProcessId) -and $known.ContainsKey([int]$p.ParentProcessId)){
   $parents=@($targets|Where-Object ProcessId -eq $p.ParentProcessId)
   if($parents.Count -ne 1 -or $p.CreationDate -lt $parents[0].CreationDate){throw 'Native immediate-parent chronology changed'}
   $known[[int]$p.ProcessId]=$true;$targets+=,$p;$added=$true
   if($targets.Count -gt 128){throw 'Observer descendant bound exceeded'}
  }}
  if(!$added){break}
 }
 if($targets.Count -lt 2){throw 'Installed host and actual Node required'}
 $nodeTargets=@($targets|Where-Object ProcessId -eq $context.nodeIdentity.pid)
 if($nodeTargets.Count -ne 1 -or $context.nodeIdentity.parentPid -ne $context.identity.pid -or !(Same (Identity $nodeTargets[0]) $context.nodeIdentity)){throw 'Original installed Node identity mismatch'}
 foreach($p in $targets){
  $identity=Identity $p;$handle=[StopObservationHandle]::new([uint32]$p.ProcessId)
  $entry=@{identity=$identity;handle=$handle};$handles+=,$entry
  $fresh=Identity (Get-CimInstance Win32_Process -Filter "ProcessId=$($identity.pid)" -ErrorAction Stop)
  if(!(Same $identity $fresh) -or $handle.Exited -or $handle.Image -ine $identity.executable -or $handle.Sid -cne 'S-1-5-18' -or $handle.CreatedMicroseconds -cne $p.CreationDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.ffffffZ')){throw 'Captured native handle identity mismatch'}
 }
 # A new descendant after capture is never adopted by PID or terminated.
 foreach($p in (Inventory)){if($known.ContainsKey([int]$p.ParentProcessId) -and !$known.ContainsKey([int]$p.ProcessId)){throw 'Uncaptured descendant; preserve fixture'}}
 $ready=@{schemaVersion=1;token=$context.token;observerPid=$PID;capturedProcessCount=$handles.Count;retainedReadOnlyHandles=$true}|ConvertTo-Json -Compress
 $readyBytes=[Text.UTF8Encoding]::new($false).GetBytes($ready)
 $readyStream=[IO.File]::Open($ReadyFile,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$readyStream.Write($readyBytes,0,$readyBytes.Length);$readyStream.Flush($true)}finally{$readyStream.Dispose()}
 $clock=[Diagnostics.Stopwatch]::StartNew()
 while(@($handles|Where-Object {!$_.handle.Exited}).Count -gt 0){
  if($ownerHandle.Exited){throw 'Original owner exited before observed stop'}
  foreach($p in (Inventory)){if($known.ContainsKey([int]$p.ParentProcessId) -and !$known.ContainsKey([int]$p.ProcessId)){throw 'New descendant during stop; preserve fixture'}}
  if($clock.ElapsedMilliseconds -ge $context.maxWaitMs){throw 'Original native handles did not exit within bounded stop observation'}
  Start-Sleep -Milliseconds 100
 }
 foreach($p in (Inventory)){
  if($p.ProcessId -eq $PID -or $p.ProcessId -eq $OwnerProcessId){continue}
  if($known.ContainsKey([int]$p.ProcessId) -or $known.ContainsKey([int]$p.ParentProcessId)){throw 'Unresolved captured lineage after stop'}
  foreach($root in $context.commandRoots){if(($p.CommandLine -and ([string]$p.CommandLine).IndexOf([string]$root,[StringComparison]::OrdinalIgnoreCase) -ge 0) -or ($p.ExecutablePath -and ([string]$p.ExecutablePath).Equals([string]$root,[StringComparison]::OrdinalIgnoreCase))){throw 'Owned fixture command remains live'}}
 }
 $nodeHandles=@($handles|Where-Object {$_.identity.pid -eq $context.nodeIdentity.pid})
 if($nodeHandles.Count -ne 1){throw 'Original Node retained handle missing'}
 $result=@{schemaVersion=1;token=$context.token;capturedProcessCount=$handles.Count;rootExitCode=$handles[0].handle.ExitCode;nodeExitCode=$nodeHandles[0].handle.ExitCode;allCapturedHandlesExited=$true;capturedLineageAbsent=$true;fixtureCommandPathsAbsent=$true;readOnlyObservation=$true;atomicTreeContainmentQualified=$false}
}finally{
 $closeFailed=$false
 foreach($entry in $handles){try{$entry.handle.Dispose()}catch{$closeFailed=$true}}
 if($ownerHandle){try{$ownerHandle.Dispose()}catch{$closeFailed=$true}}
 try{$contextStream.Dispose()}catch{$closeFailed=$true}
 if($closeFailed){throw 'Read-only observer handle release failed'}
}
if(!$result){throw 'No completed native stop observation'}
$result.nativeHandlesClosed=$true
$result|ConvertTo-Json -Compress

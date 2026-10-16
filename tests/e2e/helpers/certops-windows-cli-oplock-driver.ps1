<#
External synchronization for an owned installer CLI second-rename fault.
An exclusive source-file oplock holds the real Copy-Item open until this driver
has acquired a native staging-directory handle without delete sharing. The
installer itself is never rewritten, instrumented, paused or hooked.
See Microsoft FSCTL_REQUEST_OPLOCK_LEVEL_1 and Breaking Oplocks documentation.
Only private process/file identity receipts are written; public reports project
bounded facts elsewhere. Missing native capability fails rather than skipping.
#>
param(
 [Parameter(Mandatory)][string]$SourceFile,
 [Parameter(Mandatory)][string]$InstallRoot,
 [Parameter(Mandatory)][string]$ProtocolDirectory,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$Token,
 [Parameter(Mandatory)][int]$OwnerProcessId
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$protocol=[IO.Path]::GetFullPath($ProtocolDirectory).TrimEnd('\')
$root=[IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
$source=[IO.Path]::GetFullPath($SourceFile)
if(-not [IO.Path]::IsPathRooted($SourceFile) -or -not [IO.Path]::IsPathRooted($InstallRoot) -or -not [IO.Path]::IsPathRooted($ProtocolDirectory)){throw 'Absolute owned paths required'}
if([IO.Path]::GetFileName($protocol) -notmatch '^certops-cli-oplock-'){throw 'Refuse unowned protocol directory'}
if(-not $root.Equals('C:\ProgramData\TokenTimerAgent',[StringComparison]::OrdinalIgnoreCase) -and [IO.Path]::GetFileName($root) -notmatch '^certops-cli-oplock-support-'){throw 'Refuse unsupported install root'}
$self=Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
$owner=Get-CimInstance Win32_Process -Filter "ProcessId=$OwnerProcessId"
if(!$owner -or $self.ParentProcessId -ne $OwnerProcessId){throw 'Oplock driver parent mismatch'}
$ownerCreated=$owner.CreationDate.ToUniversalTime().ToString('o')
function Assert-Owner {
 $current=Get-CimInstance Win32_Process -Filter "ProcessId=$OwnerProcessId"
 if(!$current -or $current.CreationDate.ToUniversalTime().ToString('o') -ne $ownerCreated){throw 'Oplock owner is gone'}
}
function Signal([string]$Name,[int]$Seconds=30){
 $file=Join-Path $protocol $Name;$until=[DateTime]::UtcNow.AddSeconds($Seconds)
 while(!(Test-Path -LiteralPath $file)){
  Assert-Owner
  if(Test-Path -LiteralPath (Join-Path $protocol 'cancel')){throw 'Owned oplock protocol cancelled'}
  if([DateTime]::UtcNow -ge $until){throw "Owned oplock signal deadline: $Name"}
  Start-Sleep -Milliseconds 20
 }
 if([IO.File]::ReadAllText($file) -ne $Token){throw 'Owned oplock signal token mismatch'}
}
function Receipt([string]$Name,$Value){
 $target=Join-Path $protocol $Name;$temp=$target+'.tmp'
 $bytes=[Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Depth 6 -Compress))
 $stream=[IO.File]::Open($temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
 [IO.File]::Move($temp,$target)
}
Add-Type @'
using System;
using System.IO;
using System.Threading;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class CliOplockNative {
 [StructLayout(LayoutKind.Sequential)] public struct Info { public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Created,Accessed,Written; public uint Volume,High,Low,Links,IndexHigh,IndexLow; }
 [StructLayout(LayoutKind.Sequential)] public struct Overlap { public UIntPtr Internal,InternalHigh; public uint Offset,OffsetHigh; public IntPtr Event; }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetFileInformationByHandle(SafeFileHandle file,out Info info);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool DeviceIoControl(SafeFileHandle file,uint code,IntPtr input,uint inputSize,IntPtr output,uint outputSize,out uint bytes,IntPtr overlap);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool CancelIoEx(SafeFileHandle file,IntPtr overlap);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetOverlappedResult(SafeFileHandle file,IntPtr overlap,out uint bytes,bool wait);
 public static string Identity(string path) { using(var h=CreateFile(path,0x80000000,7,IntPtr.Zero,3,0x02000000,IntPtr.Zero)){Info i;if(h.IsInvalid||!GetFileInformationByHandle(h,out i))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());return i.Volume.ToString("x8")+":"+i.IndexHigh.ToString("x8")+i.IndexLow.ToString("x8");} }
}
public sealed class CliSourceOplock:IDisposable {
 private SafeFileHandle file; private IntPtr overlap; private ManualResetEvent signal;
 public CliSourceOplock(string path) {
  try {
   signal=new ManualResetEvent(false);
   file=CliOplockNative.CreateFile(path,0x80000000,7,IntPtr.Zero,3,0x40000000,IntPtr.Zero);
   if(file.IsInvalid)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
   var value=new CliOplockNative.Overlap();value.Event=signal.SafeWaitHandle.DangerousGetHandle();
   overlap=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(CliOplockNative.Overlap)));Marshal.StructureToPtr(value,overlap,false);
   uint bytes;bool completed=CliOplockNative.DeviceIoControl(file,0x00090000,IntPtr.Zero,0,IntPtr.Zero,0,out bytes,overlap);
   int error=Marshal.GetLastWin32Error();
   if(completed||error!=997)throw new InvalidOperationException("OPLOCK_CAPABILITY_UNAVAILABLE:"+error);
  } catch { Dispose();throw; }
 }
 public bool Broken(int milliseconds){return signal.WaitOne(milliseconds);}
 public void Dispose(){
  if(file!=null){if(!file.IsInvalid&&overlap!=IntPtr.Zero){CliOplockNative.CancelIoEx(file,overlap);uint bytes;CliOplockNative.GetOverlappedResult(file,overlap,out bytes,true);}file.Dispose();file=null;}
  if(overlap!=IntPtr.Zero){Marshal.FreeHGlobal(overlap);overlap=IntPtr.Zero;}
  if(signal!=null){signal.Dispose();signal=null;}
 }
}
public sealed class CliRenameObserver:IDisposable {
 private FileSystemWatcher watcher; public readonly ConcurrentQueue<string[]> Events=new ConcurrentQueue<string[]>(); public volatile bool Failed;
 public CliRenameObserver(string root){watcher=new FileSystemWatcher(root);watcher.NotifyFilter=NotifyFilters.DirectoryName;watcher.IncludeSubdirectories=false;watcher.InternalBufferSize=16384;watcher.Renamed+=(s,e)=>Events.Enqueue(new[]{e.OldName,e.Name});watcher.Error+=(s,e)=>Failed=true;watcher.EnableRaisingEvents=true;}
 public void Dispose(){watcher.Dispose();}
}
'@
$oplock=$null;$held=$null;$observer=$null;$restored=$false;$staging=$null;$installerProcess=$null
try {
 Signal 'identity-confirmed'
 foreach($target in @($root,(Join-Path $root 'app'),$protocol,$source)){
  $item=Get-Item -LiteralPath $target -Force
  if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Linked oplock target refused'}
 }
 $originalId=[CliOplockNative]::Identity((Join-Path $root 'app'))
 $oplock=New-Object CliSourceOplock($source)
 Receipt 'ready.json' @{token=$Token;pid=$PID;parentPid=$OwnerProcessId;created=$self.CreationDate.ToUniversalTime().ToString('o');phase='source-oplock-granted';originalId=$originalId}
 # The external launcher waits without invoking any product code until this
 # driver independently registers its exact identity and retains its handle.
 Signal 'installer-identity-confirmed'
 $identity=Get-Content -LiteralPath (Join-Path $protocol 'installer.json') -Raw|ConvertFrom-Json
 if($identity.token -ne $Token -or $identity.parentPid -ne $OwnerProcessId){throw 'Installer identity receipt mismatch'}
 $installer=Get-CimInstance Win32_Process -Filter "ProcessId=$($identity.pid)"
 if(!$installer -or $installer.ParentProcessId -ne $OwnerProcessId -or $installer.CreationDate.ToUniversalTime().ToString('o') -ne $identity.created -or $installer.ExecutablePath -ne $identity.executable -or $installer.CommandLine -ne $identity.command){throw 'Actual installer identity changed before staging hold'}
 $candidateProcess=[Diagnostics.Process]::GetProcessById([int]$identity.pid)
 try{
  $null=$candidateProcess.Handle
  # CIM creation dates have microsecond precision; the retained process handle
  # has 100ns ticks. Truncate only that sub-microsecond digit, never a time range.
  $handleTicks=$candidateProcess.StartTime.ToUniversalTime().Ticks
  if(($handleTicks-($handleTicks%10)) -ne ([DateTime]::Parse($identity.created)).ToUniversalTime().Ticks){throw 'Retained installer handle identity mismatch'}
  $installerProcess=$candidateProcess;$candidateProcess=$null
 }finally{if($candidateProcess){$candidateProcess.Dispose()}}
 Receipt 'registered.json' @{token=$Token;installerPid=$identity.pid;phase='registered-before-product-invocation'}
 $until=[DateTime]::UtcNow.AddSeconds(60)
 while(!$oplock.Broken(50)){Assert-Owner;if(Test-Path -LiteralPath (Join-Path $protocol 'cancel')){throw 'Oplock cancelled'};if([DateTime]::UtcNow -ge $until){throw 'Actual source-file open never broke the granted oplock'}}
 $staging=Join-Path $root "app.staging.$($identity.pid)";$previous=Join-Path $root "app.previous.$($identity.pid)"
 if(!(Test-Path -LiteralPath $staging) -or (Test-Path -LiteralPath $previous)){throw 'Oplock broke outside actual staging copy; refusing race-based qualification'}
 if(((Get-Item -LiteralPath $staging -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Linked actual staging directory refused'}
 $stagingId=[CliOplockNative]::Identity($staging)
 $held=[CliOplockNative]::CreateFile($staging,[uint32]2147483648,3,[IntPtr]::Zero,3,33554432,[IntPtr]::Zero)
 if($held.IsInvalid){throw 'Actual staging directory handle unavailable'}
 $observer=New-Object CliRenameObserver($root)
 Receipt 'held.json' @{token=$Token;installerPid=$identity.pid;phase='copy-blocked-staging-held';originalId=$originalId;stagingId=$stagingId;shareMask=3}
 Signal 'resume-copy'
 $oplock.Dispose();$oplock=$null
 $until=[DateTime]::UtcNow.AddSeconds(60)
 while($observer.Events.Count -lt 2 -and [DateTime]::UtcNow -lt $until){Assert-Owner;Start-Sleep -Milliseconds 20}
 $events=@($observer.Events.ToArray());$previousLeaf="app.previous.$($identity.pid)"
 if($observer.Failed -or $events.Count -ne 2 -or $events[0][0] -ne 'app' -or $events[0][1] -ne $previousLeaf -or $events[1][0] -ne $previousLeaf -or $events[1][1] -ne 'app'){throw 'Actual CLI did not emit exact ordered predecessor move/restoration'}
 if((Test-Path -LiteralPath $previous) -or [CliOplockNative]::Identity((Join-Path $root 'app')) -ne $originalId -or [CliOplockNative]::Identity($staging) -ne $stagingId){throw 'Actual CLI restoration identity mismatch'}
 $restored=$true
 Receipt 'restored.json' @{token=$Token;installerPid=$identity.pid;phase='restored';originalId=$originalId;stagingId=$stagingId;shareMask=3;renameEvents=$events}
 Signal 'release-staging' 90
} finally {
 # On parent death, cancellation or an unexpected phase, stop the retained
 # exact installer process BEFORE releasing any handle that could resume it.
 # A failed stop preserves the holder and active cleanup guards. The ordinary
 # 10-second drain budget is reported, then this safety custodian keeps its
 # handles until that exact process exits; it never releases on a timeout.
 if($installerProcess -and !$installerProcess.HasExited){
  try{$installerProcess.Kill()}catch{}
  if(!$installerProcess.WaitForExit(10000)){
   Receipt 'drain-blocked.json' @{token=$Token;installerPid=$identity.pid;phase='installer-drain-unproven-handles-retained'}
   while(!$installerProcess.HasExited){Start-Sleep -Milliseconds 250}
  }
 }
 if($oplock){$oplock.Dispose()}
 if($observer){$observer.Dispose()}
 if($held){$held.Dispose()}
 if($installerProcess){$installerProcess.Dispose()}
 if($restored){
  if((Test-Path -LiteralPath $previous) -or [CliOplockNative]::Identity((Join-Path $root 'app')) -ne $originalId -or [CliOplockNative]::Identity($staging) -ne $stagingId){throw 'Refuse staging cleanup after identity changed'}
  if(-not $staging.Equals((Join-Path $root "app.staging.$($identity.pid)"),[StringComparison]::OrdinalIgnoreCase)){throw 'Refuse unexpected staging cleanup path'}
  Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction Stop
  if(Test-Path -LiteralPath $staging){throw 'Owned actual CLI staging remains'}
  Receipt 'closed.json' @{token=$Token;installerPid=$identity.pid;phase='closed';originalId=$originalId;stagingId=$stagingId;stagingAbsent=$true}
 }
}

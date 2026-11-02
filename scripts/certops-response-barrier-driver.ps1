# Supporting file-level input/output delivery barriers, not an AD CS qualifier.
# Uses the same acknowledged level-1 oplock primitive as the owned installer
# controls. Directory change notifications are never treated as a barrier.
# Private immutable identity receipts survive every failure. Never release an
# output holder while the exact registered temporary writer can still resume.
param([Parameter(Mandatory)][string]$Root,
      [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$Token,
      [Parameter(Mandatory)][int]$OwnerPid,
      [Parameter(Mandatory)][ValidateRange(0,2)][int]$OutputIndex)
$ErrorActionPreference='Stop'
function Public-Hash([string]$File) {
  $sha=[Security.Cryptography.SHA256]::Create();$stream=[IO.File]::OpenRead($File)
  try{return [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','').ToLowerInvariant()}finally{$stream.Dispose();$sha.Dispose()}
}
Set-StrictMode -Version Latest
$rootPath=[IO.Path]::GetFullPath($Root).TrimEnd('\')
$temporary=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')
if((Split-Path $rootPath -Parent) -ine $temporary -or [IO.Path]::GetFileName($rootPath) -notmatch '^certops-response-barrier-support-[a-f0-9-]{36}$'){throw 'Owned temporary supporting root required'}
if([IO.File]::ReadAllText((Join-Path $rootPath '.owner')) -cne $Token){throw 'Root owner mismatch'}
$self=Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
$owner=Get-CimInstance Win32_Process -Filter "ProcessId=$OwnerPid"
if(-not $owner -or $self.ParentProcessId -ne $OwnerPid){throw 'Exact parent owner unavailable'}
$ownerCreated=$owner.CreationDate.ToUniversalTime().ToString('o')
$driverCreated=$self.CreationDate.ToUniversalTime().ToString('o')
function Assert-Owner {
  $current=Get-CimInstance Win32_Process -Filter "ProcessId=$OwnerPid"
  if(-not $current -or $current.CreationDate.ToUniversalTime().ToString('o') -cne $ownerCreated){throw 'Supporting parent ownership lost'}
  if(Test-Path -LiteralPath (Join-Path $rootPath '.cancel')){throw 'Supporting cancellation requested'}
}
function Receipt([string]$Name,$Value) {
  $target=Join-Path $rootPath $Name
  $bytes=[Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Depth 8 -Compress))
  $stream=[IO.File]::Open($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
  try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
Add-Type @'
using System;
using System.IO;
using System.Threading;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class ResponseBarrierNative {
 [StructLayout(LayoutKind.Sequential)] public struct Info { public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Created,Accessed,Written; public uint Volume,High,Low,Links,IndexHigh,IndexLow; }
 [StructLayout(LayoutKind.Sequential)] public struct Overlap { public UIntPtr Internal,InternalHigh; public uint Offset,OffsetHigh; public IntPtr Event; }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetFileInformationByHandle(SafeFileHandle file,out Info info);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool DeviceIoControl(SafeFileHandle file,uint code,IntPtr input,uint inputSize,IntPtr output,uint outputSize,out uint bytes,IntPtr overlap);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool CancelIoEx(SafeFileHandle file,IntPtr overlap);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetOverlappedResult(SafeFileHandle file,IntPtr overlap,out uint bytes,bool wait);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool TerminateProcess(IntPtr process,uint code);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
 public static string Identity(string path) { using(var h=CreateFile(path,0x80000000,7,IntPtr.Zero,3,0x02000000,IntPtr.Zero)){Info i;if(h.IsInvalid||!GetFileInformationByHandle(h,out i))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());return i.Volume.ToString("x8")+":"+i.IndexHigh.ToString("x8")+i.IndexLow.ToString("x8");} }
}
public sealed class ResponseFileOplock:IDisposable {
 private SafeFileHandle file; private IntPtr overlap; private ManualResetEvent signal;
 public ResponseFileOplock(string path) {
  try {
   signal=new ManualResetEvent(false);
   file=ResponseBarrierNative.CreateFile(path,0x80000000,7,IntPtr.Zero,3,0x40000000,IntPtr.Zero);
   if(file.IsInvalid)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
   var value=new ResponseBarrierNative.Overlap();value.Event=signal.SafeWaitHandle.DangerousGetHandle();
   overlap=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ResponseBarrierNative.Overlap)));Marshal.StructureToPtr(value,overlap,false);
   uint bytes;bool completed=ResponseBarrierNative.DeviceIoControl(file,0x00090000,IntPtr.Zero,0,IntPtr.Zero,0,out bytes,overlap);
   int error=Marshal.GetLastWin32Error();if(completed||error!=997)throw new InvalidOperationException("LEVEL1_OPLOCK_NOT_GRANTED:"+error);
  } catch { Dispose();throw; }
 }
 public bool Broken(int milliseconds){return signal.WaitOne(milliseconds);}
 public string State(){ResponseBarrierNative.Info i;if(!ResponseBarrierNative.GetFileInformationByHandle(file,out i))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());return i.Volume.ToString("x8")+":"+i.IndexHigh.ToString("x8")+i.IndexLow.ToString("x8")+":"+i.High.ToString()+":"+i.Low.ToString()+":"+i.Attributes.ToString();}
 public void Dispose(){
  if(file!=null){if(!file.IsInvalid&&overlap!=IntPtr.Zero){ResponseBarrierNative.CancelIoEx(file,overlap);uint bytes;ResponseBarrierNative.GetOverlappedResult(file,overlap,out bytes,true);}file.Dispose();file=null;}
  if(overlap!=IntPtr.Zero){Marshal.FreeHGlobal(overlap);overlap=IntPtr.Zero;}
  if(signal!=null){signal.Dispose();signal=null;}
 }
}
'@
$inputHolder=$null;$outputs=@();$worker=$null;$workerHandle=[IntPtr]::Zero;$workerCreated=$null;$workerExe=$null;$drained=$false;$passed=$false;$failure=$null;$stage="initial"
function Assert-ExactWorker {
  $current=Get-CimInstance Win32_Process -Filter "ProcessId=$($worker.Id)"
  if(-not $current -or $current.ParentProcessId -ne $PID -or $current.CreationDate.ToUniversalTime().ToString('o') -cne $workerCreated -or $current.ExecutablePath -ine $workerExe -or $current.CommandLine.IndexOf($rootPath,[StringComparison]::OrdinalIgnoreCase) -lt 0){throw 'Exact supporting reader identity unavailable'}
}
function Stop-ExactWorker {
  if(-not $worker){return $true}
  if([ResponseBarrierNative]::WaitForSingleObject($workerHandle,0) -ne 0){
    Assert-ExactWorker
    if(-not [ResponseBarrierNative]::TerminateProcess($workerHandle,73)){throw 'Exact retained supporting child termination failed'}
  }
  if([ResponseBarrierNative]::WaitForSingleObject($workerHandle,10000) -ne 0){throw 'Supporting child termination unproven'}
  if(Get-CimInstance Win32_Process -Filter "ProcessId=$($worker.Id)"){throw 'Supporting child PID absence unproven'}
  return $true
}
try {
  $stage="owned-files";Assert-Owner
  foreach($name in @('.owner','request.req','issued.cer','chain.p7b','submit-response.rsp')) {
    $item=Get-Item -LiteralPath (Join-Path $rootPath $name)
    if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Linked supporting file refused'}
  }
  $stage="native-root-identity";$rootIdentity=[ResponseBarrierNative]::Identity($rootPath)
  $requestFile=Join-Path $rootPath 'request.req'
  $inputIdentity=[ResponseBarrierNative]::Identity($requestFile)
  $inputHash=(Public-Hash $requestFile)
  $stage="arm-output-barriers";$states=@();foreach($name in @('issued.cer','chain.p7b','submit-response.rsp')) {
    $file=Join-Path $rootPath $name
    if((Get-Item -LiteralPath $file).Length -ne 0){throw 'Supporting output already contains bytes'}
    $holder=New-Object ResponseFileOplock($file);$outputs+=,$holder;$states+=,$holder.State()
  }
  $stage="arm-input-barrier";$inputHolder=New-Object ResponseFileOplock($requestFile)
  $guard=@{token=$Token;root=$rootPath;rootIdentity=$rootIdentity;inputIdentity=$inputIdentity;inputHash=$inputHash;outputStates=$states;driverPid=$PID;driverCreated=$driverCreated;scope='supporting-temporary-file-barriers-not-certreq'}
  Receipt '.active-guard.json' $guard
  $guardHash=(Public-Hash (Join-Path $rootPath '.active-guard.json'))
  $guardIdentity=[ResponseBarrierNative]::Identity((Join-Path $rootPath '.active-guard.json'))
  $workerScript=Join-Path $PSScriptRoot 'certops-response-barrier-worker.ps1'
  $workerHash=(Public-Hash $workerScript)
  $exe=(Get-Process -Id $PID).Path
  $worker=Start-Process -FilePath $exe -ArgumentList @('-NoProfile','-NonInteractive','-File',('"'+$workerScript+'"'),'-Root',('"'+$rootPath+'"'),'-Token',$Token,'-DriverPid',"$PID",'-DriverCreated',$driverCreated,'-OutputIndex',"$OutputIndex") -WindowStyle Hidden -PassThru
  $workerHandle=$worker.Handle
  $until=[DateTime]::UtcNow.AddSeconds(30)
  while(-not(Test-Path -LiteralPath (Join-Path $rootPath '.worker-ready.json'))) { Assert-Owner;if($worker.HasExited -or [DateTime]::UtcNow -ge $until){throw 'Supporting worker startup deadline'};Start-Sleep -Milliseconds 10 }
  $ready=Get-Content -LiteralPath (Join-Path $rootPath '.worker-ready.json') -Raw|ConvertFrom-Json
  $workerCreated=$ready.created;$workerExe=$ready.exe
  if($ready.token -cne $Token -or $ready.pid -ne $worker.Id -or $ready.parentPid -ne $PID -or $ready.scriptHash -cne $workerHash){throw 'Supporting startup receipt mismatch'}
  Assert-ExactWorker
  Receipt '.registered-worker.json' @{token=$Token;pid=$worker.Id;created=$workerCreated;exe=$workerExe;parentPid=$PID;scriptHash=$workerHash}
  [IO.File]::WriteAllText((Join-Path $rootPath '.allow-access'),$Token)
  $until=[DateTime]::UtcNow.AddSeconds(30)
  while(-not $inputHolder.Broken(20)){Assert-Owner;Assert-ExactWorker;if([DateTime]::UtcNow -ge $until){throw 'Actual input read never broke its granted oplock'}}
  Assert-ExactWorker
  foreach($holder in $outputs){if($holder.Broken(0)){throw 'Output attempted before input acknowledgment'}}
  # All output file barriers were armed before this one input acknowledgment.
  $inputHolder.Dispose();$inputHolder=$null
  $until=[DateTime]::UtcNow.AddSeconds(30)
  while(-not $outputs[$OutputIndex].Broken(20)){Assert-Owner;Assert-ExactWorker;if([DateTime]::UtcNow -ge $until){throw 'Actual selected output open never broke its granted oplock'}}
  Assert-ExactWorker
  $read=Get-Content -LiteralPath (Join-Path $rootPath '.input-read.json') -Raw|ConvertFrom-Json
  if($read.token -cne $Token -or $read.pid -ne $worker.Id -or $read.sha256 -cne $inputHash){throw 'Actual supporting input bytes mismatch'}
  for($i=0;$i -lt 3;$i++){if($outputs[$i].State() -cne $states[$i]){throw 'Output identity/length changed before loss'}}
  if(Test-Path -LiteralPath (Join-Path $rootPath '.write-completed.json')){throw 'Writer completed before intended response loss'}
  $drained=Stop-ExactWorker
  # Exact process exit + PID absence precede every output holder release.
  for($i=0;$i -lt 3;$i++){if($outputs[$i].State() -cne $states[$i]){throw 'Output changed during child termination'}}
  if((Public-Hash (Join-Path $rootPath '.active-guard.json')) -cne $guardHash -or [ResponseBarrierNative]::Identity((Join-Path $rootPath '.active-guard.json')) -cne $guardIdentity){throw 'Active guard identity/bytes changed'}
  if([ResponseBarrierNative]::Identity($rootPath) -cne $rootIdentity -or [ResponseBarrierNative]::Identity($requestFile) -cne $inputIdentity -or (Public-Hash $requestFile) -cne $inputHash){throw 'Supporting ancestry/input identity changed'}
  foreach($holder in $outputs){$holder.Dispose()};$outputs=@()
  for($i=0;$i -lt 3;$i++){if((Get-Item -LiteralPath (Join-Path $rootPath (@('issued.cer','chain.p7b','submit-response.rsp')[$i]))).Length -ne 0){throw 'Output wrote after holder release'}}
  Receipt '.drained.json' @{token=$Token;root=$rootPath;guardHash=$guardHash;guardIdentity=$guardIdentity;workerPid=$worker.Id;workerCreated=$workerCreated;childExited=$true;childPidAbsent=$true;holdersReleasedAfterDrain=$true}
  $passed=$true
} catch {$failure=$_.Exception;try{Receipt ".failure.json" @{stage=$stage;errorType=$failure.GetType().FullName;hresult=$failure.HResult;message=$failure.Message.Substring(0,[Math]::Min(300,$failure.Message.Length))}}catch{}}
finally {
  if(-not $drained){try{$drained=Stop-ExactWorker}catch{}}
  # A failure to prove termination retains all holders in this custodian. A
  # parent/caller must preserve the private root and never kill this holder to
  # make cleanup look successful. No whole-process-tree termination is used.
  while(-not $drained -and $worker){Start-Sleep -Milliseconds 250;try{$drained=Stop-ExactWorker}catch{}}
  if($drained -or -not $worker){if($inputHolder){$inputHolder.Dispose()};foreach($holder in $outputs){$holder.Dispose()};if($worker){$worker.Dispose()}}
}
if(-not $passed){[Console]::Error.WriteLine('Supporting response barrier failed; preserve private owned receipts');exit 1}
@{outputIndex=$OutputIndex;inputLevelOneGranted=$true;actualInputReadBreak=$true;threeOutputLevelOneGranted=$true;outputsArmedBeforeReadRelease=$true;actualSelectedOutputOpenBreak=$true;readerIdentityBoundBeforeAccess=$true;inputBytesVerified=$true;allOutputsZeroBeforeLoss=$true;exactChildExitAndAbsence=$true;holdersReleasedAfterExactDrain=$true;allOutputsZeroAfterRelease=$true;inputAndGuardIdentityUnchanged=$true}|ConvertTo-Json -Compress

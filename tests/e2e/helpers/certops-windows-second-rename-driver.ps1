<#
Deterministic activation-function fault driver for owned qualification files.
Only the actual Copy-PackageTree and Activate-StagedPackage functions are parsed
from the candidate installer; its top-level service/registry code never runs.
A native staging-directory handle causes the second rename and staging cleanup
to fail. Native rename notifications and file IDs prove predecessor restoration.
The verified parent releases the handle before exact staging cleanup. Never run
against an installation outside an explicitly owned disposable test directory.
#>
param(
 [Parameter(Mandatory)][string]$Installer,
 [Parameter(Mandatory)][string]$PackageDirectory,
 [Parameter(Mandatory)][string]$OwnedRoot,
 [Parameter(Mandatory)][string]$ReceiptPrefix,
 [Parameter(Mandatory)][string]$GoPath,
 [Parameter(Mandatory)][string]$ReleasePath,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$Token,
 [Parameter(Mandatory)][int]$OwnerProcessId
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=[IO.Path]::GetFullPath($OwnedRoot).TrimEnd('\')
if(-not [IO.Path]::IsPathRooted($OwnedRoot) -or [IO.Path]::GetFileName($root) -notmatch '^certops-(windows-journey|second-rename-support)-'){throw 'Refuse an unowned activation root'}
foreach($file in @($ReceiptPrefix,$GoPath,$ReleasePath)){
 if(-not [IO.Path]::GetFullPath($file).StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Protocol file outside owned root'}
}
$self=Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
$owner=Get-CimInstance Win32_Process -Filter "ProcessId=$OwnerProcessId"
if(!$owner -or $self.ParentProcessId -ne $OwnerProcessId){throw 'Driver parent identity mismatch'}
$ownerCreated=$owner.CreationDate.ToUniversalTime().ToString('o')
function Assert-Owner {
 $current=Get-CimInstance Win32_Process -Filter "ProcessId=$OwnerProcessId"
 if(!$current -or $current.CreationDate.ToUniversalTime().ToString('o') -ne $ownerCreated){throw 'Owned driver parent is gone'}
}
function Wait-OwnedSignal([string]$Signal,[int]$Seconds){
 $deadline=[DateTime]::UtcNow.AddSeconds($Seconds)
 while(!(Test-Path -LiteralPath $Signal)){
  Assert-Owner
  if([DateTime]::UtcNow -ge $deadline){throw 'Owned activation signal deadline exceeded'}
  if($Signal -eq $GoPath -and (Test-Path -LiteralPath $ReleasePath)){throw 'Activation cancelled before ownership confirmation'}
  Start-Sleep -Milliseconds 50
 }
 if([IO.File]::ReadAllText($Signal) -ne $Token){throw 'Owned activation signal mismatch'}
}
function Write-Receipt([string]$Path,$Value){
 $bytes=[Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Depth 5 -Compress))
 $temporary=$Path+'.tmp'
 $stream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
 [IO.File]::Move($temporary,$Path)
}
# No package copy or rename is allowed until the parent has independently
# measured this exact PID, executable, arguments, creation time and parent.
Wait-OwnedSignal $GoPath 30
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $Installer).Path,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw 'Candidate installer parse failed'}
foreach($name in @('Copy-PackageTree','Activate-StagedPackage')){
 $definition=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true))
 if($definition.Count -ne 1){throw 'Missing unique production activation function'}
 Invoke-Expression $definition[0].Extent.Text
}
Add-Type @'
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class SecondRenameNative {
 [StructLayout(LayoutKind.Sequential)] public struct Information { public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Created,Accessed,Written; public uint Volume,High,Low,Links,IndexHigh,IndexLow; }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetFileInformationByHandle(SafeFileHandle handle,out Information info);
 public static string Identity(string path) { using(var h=CreateFile(path,0x80000000,7,IntPtr.Zero,3,0x02000000,IntPtr.Zero)){Information i;if(h.IsInvalid||!GetFileInformationByHandle(h,out i))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());return i.Volume.ToString("x8")+":"+i.IndexHigh.ToString("x8")+i.IndexLow.ToString("x8");} }
}
public sealed class SecondRenameObserver:IDisposable {
 private readonly FileSystemWatcher watcher;
 public readonly ConcurrentQueue<string[]> Events=new ConcurrentQueue<string[]>();
 public volatile bool Failed;
 public SecondRenameObserver(string root){watcher=new FileSystemWatcher(root);watcher.NotifyFilter=NotifyFilters.DirectoryName;watcher.IncludeSubdirectories=false;watcher.InternalBufferSize=16384;watcher.Renamed+=(s,e)=>Events.Enqueue(new[]{e.OldName,e.Name});watcher.Error+=(s,e)=>Failed=true;watcher.EnableRaisingEvents=true;}
 public void Dispose(){watcher.Dispose();}
}
'@
$app=Join-Path $root 'app'
$staging="$app.staging.$PID"
$previous="$app.previous.$PID"
if(!(Test-Path -LiteralPath $app) -or (Test-Path -LiteralPath $staging) -or (Test-Path -LiteralPath $previous)){throw 'Activation fixture directory collision'}
foreach($directory in @($root,$app,$PackageDirectory)){
 if(((Get-Item -LiteralPath $directory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Linked activation fixture refused'}
}
$originalId=[SecondRenameNative]::Identity($app)
$handle=$null;$observer=$null;$restored=$false
try{
 Copy-PackageTree -Source $PackageDirectory -Destination $staging
 $stagingId=[SecondRenameNative]::Identity($staging)
 $handle=[SecondRenameNative]::CreateFile($staging,[uint32]2147483648,3,[IntPtr]::Zero,3,33554432,[IntPtr]::Zero)
 if($handle.IsInvalid){throw 'Native staging handle unavailable'}
 $observer=New-Object SecondRenameObserver($root)
 $failure=$null
 try{Activate-StagedPackage -AppDirectory $app -StagingDirectory $staging -PreviousDirectory $previous}catch{$failure=$_.Exception.Message}
 if(!$failure -or $failure -notmatch 'recovery incomplete \(staging cleanup failed\)' -or $failure -match 'previous installation restoration failed'){throw 'Expected second-rename refusal and explicit held-staging cleanup failure'}
 $deadline=[DateTime]::UtcNow.AddSeconds(5)
 while($observer.Events.Count -lt 2 -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 20}
 $events=@($observer.Events.ToArray())
 if($observer.Failed -or $events.Count -ne 2 -or $events[0][0] -ne 'app' -or $events[0][1] -ne "app.previous.$PID" -or $events[1][0] -ne "app.previous.$PID" -or $events[1][1] -ne 'app'){throw 'Native notifications did not prove ordered predecessor move and restoration'}
 if((Test-Path -LiteralPath $previous) -or !(Test-Path -LiteralPath $staging) -or [SecondRenameNative]::Identity($app) -ne $originalId -or [SecondRenameNative]::Identity($staging) -ne $stagingId){throw 'Independent restored directory identity mismatch'}
 $receipt=@{token=$Token;pid=$PID;parentPid=$OwnerProcessId;created=$self.CreationDate.ToUniversalTime().ToString('o');phase='restored';originalId=$originalId;restoredId=[SecondRenameNative]::Identity($app);stagingId=$stagingId;shareMask=3;renameEvents=$events;errorKind='staging-cleanup-blocked-after-restoration';previousAbsent=$true;stagingPresent=$true}
 Write-Receipt ($ReceiptPrefix+'.restored.json') $receipt
 $restored=$true
 Wait-OwnedSignal $ReleasePath 90
}finally{
 if($observer){$observer.Dispose()}
 if($handle){$handle.Dispose()}
 # The exact current-PID staging directory is removed only after its native
 # handle is released. Unknown recovery state retains evidence and fails.
 if($restored){
  if([SecondRenameNative]::Identity($app) -ne $originalId -or (Test-Path -LiteralPath $previous) -or [SecondRenameNative]::Identity($staging) -ne $stagingId){throw 'Refuse cleanup after an unexpected activation state change'}
  Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction Stop
  if(Test-Path -LiteralPath $staging){throw 'Owned staging cleanup incomplete'}
  $receipt.phase='closed';$receipt.stagingPresent=$false
  Write-Receipt ($ReceiptPrefix+'.closed.json') $receipt
 }
}

<#
Hold only the installed journey's owned app directory with a genuine native
handle excluding FILE_SHARE_DELETE. Public file identity/process receipts prove
the fault before the real installer runs; release closes the handle in finally.
Never invokes an installer, service mutation or certificate command itself.
#>
param(
  [Parameter(Mandatory)][string]$Directory,
  [Parameter(Mandatory)][string]$ReceiptPrefix,
  [Parameter(Mandatory)][string]$ReleasePath,
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$Token,
  [Parameter(Mandatory)][int]$OwnerProcessId
)
$ErrorActionPreference='Stop'
$directoryPath=[IO.Path]::GetFullPath($Directory).TrimEnd('\')
if([IO.Path]::GetFileName($directoryPath) -ne 'app'){throw 'Only the owned app directory may be held'}
$ownedRoot=[IO.Directory]::GetParent($directoryPath).FullName
foreach($file in @($ReceiptPrefix,$ReleasePath)){
  if(-not [IO.Path]::GetFullPath($file).StartsWith($ownedRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Receipt must remain under the owned root'}
}
$process=Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
if($process.ParentProcessId -ne $OwnerProcessId){throw 'Native handle child parent mismatch'}
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class QualificationDirectoryHandle {
 [StructLayout(LayoutKind.Sequential)] public struct FileInformation {
  public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
  public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
 }
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetFileInformationByHandle(SafeFileHandle handle,out FileInformation information);
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern uint GetFinalPathNameByHandle(SafeFileHandle handle,StringBuilder path,uint count,uint flags);
}
'@
function Write-PublicReceipt([string]$Path,$Value){
 $bytes=[Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Compress))
 $temporary=$Path+'.tmp'
 $stream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
 [IO.File]::Move($temporary,$Path)
}
$handle=$null;$held=$false
try{
 # GENERIC_READ; share READ|WRITE only; OPEN_EXISTING; BACKUP_SEMANTICS.
 # Attribute-only/zero access does not reliably prevent the directory rename.
 $handle=[QualificationDirectoryHandle]::CreateFile($directoryPath,[uint32]2147483648,3,[IntPtr]::Zero,3,33554432,[IntPtr]::Zero)
 if($handle.IsInvalid){throw 'Owned directory native handle could not be opened'}
 $info=New-Object QualificationDirectoryHandle+FileInformation
 if(-not [QualificationDirectoryHandle]::GetFileInformationByHandle($handle,[ref]$info) -or ($info.Attributes -band 16) -eq 0){throw 'Held object is not a native directory'}
 $buffer=New-Object Text.StringBuilder 32768
 $length=[QualificationDirectoryHandle]::GetFinalPathNameByHandle($handle,$buffer,$buffer.Capacity,0)
 if($length -lt 1 -or $length -ge $buffer.Capacity){throw 'Held directory final path unavailable'}
 $final=$buffer.ToString();if($final.StartsWith('\\?\')){$final=$final.Substring(4)}
 if(-not $final.Equals($directoryPath,[StringComparison]::OrdinalIgnoreCase)){throw 'Held directory target differs from the owned app'}
 $identity=@{token=$Token;pid=$PID;parentPid=$OwnerProcessId;created=$process.CreationDate.ToUniversalTime().ToString('o');directory=$final;volume=$info.Volume;fileId=('{0:x8}{1:x8}' -f $info.IndexHigh,$info.IndexLow);shareMask=3;phase='held'}
 Write-PublicReceipt ($ReceiptPrefix+'.held.json') $identity
 $held=$true;$deadline=[DateTime]::UtcNow.AddMinutes(5)
 while(-not (Test-Path -LiteralPath $ReleasePath)){
  if([DateTime]::UtcNow -ge $deadline){throw 'Owned handle release deadline exceeded'}
  Start-Sleep -Milliseconds 100
 }
 if((Get-Content -LiteralPath $ReleasePath -Raw).Trim() -ne $Token){throw 'Owned handle release token mismatch'}
}finally{
 if($handle){$handle.Dispose()}
 if($held){$identity.phase='closed';Write-PublicReceipt ($ReceiptPrefix+'.closed.json') $identity}
}

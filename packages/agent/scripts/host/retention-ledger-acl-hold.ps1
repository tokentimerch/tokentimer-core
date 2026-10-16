<#
Owned temporary ledger ACL holder. The handle grants only ACL/metadata access,
excludes delete sharing, and survives the deny probe. Both mutation and exact
restoration use that retained handle, never a reopened filename. No CNG/CA/SCM.
#>
param([Parameter(Mandatory)][string]$ContextPath,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ContextSha256)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$contextItem=Get-Item -LiteralPath $ContextPath -Force
if($contextItem.PSIsContainer -or ($contextItem.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Regular owned context required'}
$stream=[IO.File]::Open($ContextPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
try{
 $currentItem=Get-Item -LiteralPath $ContextPath -Force
 if($currentItem.PSIsContainer -or ($currentItem.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Context changed to reparse/nonregular path'}
 if($stream.Length -le 0 -or $stream.Length -gt 16384){throw 'Bounded context required'}
 $buffer=[byte[]]::new(16385);$length=0
 while($length -lt $buffer.Length){$count=$stream.Read($buffer,$length,$buffer.Length-$length);if($count -eq 0){break};$length+=$count}
 if($length -le 0 -or $length -gt 16384 -or $stream.Length -ne $length){throw 'Context length changed'}
 $bytes=[byte[]]::new($length);[Array]::Copy($buffer,$bytes,$length)
}finally{$stream.Dispose()}
$hash=[Security.Cryptography.SHA256]::Create()
try{$actual=[BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
if($actual -cne $ContextSha256 -or $bytes.Length -gt 16384){throw 'Owned ACL protocol changed'}
$c=[Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json
if($c.schemaVersion -ne 1 -or $c.nonce -cnotmatch '^[a-f0-9]{64}$' -or $c.targetInode -cnotmatch '^[1-9][0-9]{0,24}$' -or $c.targetVolume -cnotmatch '^[1-9][0-9]{0,9}$'){throw 'Invalid ACL ownership protocol'}
$protocol=[IO.Path]::GetFullPath((Split-Path $ContextPath))
foreach($name in @('ready','release','restored')){if([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($c.$name)) -cne $protocol){throw 'Protocol path escape'}}
foreach($name in @('ready','restored')){if(Test-Path -LiteralPath $c.$name){throw 'Never adopt existing ACL receipt'}}
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
public sealed class OwnedLedgerAclHandle : IDisposable {
 [StructLayout(LayoutKind.Sequential)] struct Info {
  public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh;
  public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
 }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string name,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle,out Info info);
 [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(SafeFileHandle handle,int objectType,uint information,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
 [DllImport("advapi32.dll")] static extern uint SetSecurityInfo(SafeFileHandle handle,int objectType,uint information,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetSecurityDescriptorDacl(IntPtr descriptor,out bool present,out IntPtr dacl,out bool defaulted);
 [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
 [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr value);
 readonly SafeFileHandle handle; readonly byte[] original; readonly bool directory; bool attempted;
 public string FileId {get;private set;}
 public OwnedLedgerAclHandle(string path,string expectedVolume,string expectedInode,bool isDirectory) {
  directory=isDirectory;
  if(Marshal.SizeOf(typeof(Info))!=52 || Marshal.OffsetOf(typeof(Info),"IndexHigh").ToInt32()!=44)throw new InvalidOperationException("Native file-information ABI mismatch");
  handle=CreateFileW(path,0x00060080,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
  if(handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
  try {
   Info info;if(!GetFileInformationByHandle(handle,out info))throw new Win32Exception(Marshal.GetLastWin32Error());
   ulong index=((ulong)info.IndexHigh<<32)|info.IndexLow;
   if(index==0 || index.ToString()!=expectedInode || info.Volume.ToString()!=expectedVolume || ((info.Attributes&0x10)!=0)!=directory || (info.Attributes&0x400)!=0)throw new InvalidOperationException("Exact retained file identity required");
   FileId=info.Volume.ToString()+":"+index.ToString();IntPtr owner,group,dacl,sacl,descriptor;
   uint error=GetSecurityInfo(handle,1,4,out owner,out group,out dacl,out sacl,out descriptor);
   if(error!=0)throw new Win32Exception((int)error);
   try{uint length=GetSecurityDescriptorLength(descriptor);if(length<20 || length>65536)throw new InvalidOperationException("Bounded native security descriptor required");original=new byte[length];Marshal.Copy(descriptor,original,0,(int)length);}
   finally{LocalFree(descriptor);}
  }catch{handle.Dispose();throw;}
 }
 uint Flags(byte[] descriptor) {
  var raw=new RawSecurityDescriptor(descriptor,0);
  return 4u|((raw.ControlFlags&ControlFlags.DiscretionaryAclProtected)!=0?0x80000000u:0x20000000u);
 }
 public string OriginalDacl {get{return new RawSecurityDescriptor(original,0).GetSddlForm(AccessControlSections.Access);}}
 void Apply(byte[] descriptor) {
  var pinned=GCHandle.Alloc(descriptor,GCHandleType.Pinned);
  try{bool present,defaulted;IntPtr dacl;
   if(!GetSecurityDescriptorDacl(pinned.AddrOfPinnedObject(),out present,out dacl,out defaulted) || !present)throw new InvalidOperationException("Explicit native DACL required");
   uint error=SetSecurityInfo(handle,1,Flags(descriptor),IntPtr.Zero,IntPtr.Zero,dacl,IntPtr.Zero);
   if(error!=0)throw new Win32Exception((int)error);
  }finally{pinned.Free();}
 }
 public void DenyCurrentPrincipal() {
  FileSystemSecurity security=directory?(FileSystemSecurity)new DirectorySecurity():new FileSecurity();
  security.SetSecurityDescriptorBinaryForm(original,AccessControlSections.Access);
  var sid=WindowsIdentity.GetCurrent().User;
  security.AddAccessRule(new FileSystemAccessRule(sid,directory?FileSystemRights.ListDirectory:FileSystemRights.ReadData,AccessControlType.Deny));
  byte[] denied=security.GetSecurityDescriptorBinaryForm();attempted=true;
  Apply(denied);
 }
 public void Restore() {
  if(attempted){Apply(original);attempted=false;}
 }
 public void Dispose(){try{Restore();}finally{handle.Dispose();}}
}
'@
$holder=$null;$restored=$false
function Write-NewReceipt([string]$File,[string]$Text){
 $data=[Text.Encoding]::UTF8.GetBytes($Text)
 if($data.Length -gt 16384){throw 'Receipt exceeds bound'}
 $temporary=$File+'.writing'
 $output=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$output.Write($data,0,$data.Length);$output.Flush($true)}finally{$output.Dispose()}
 [IO.File]::Move($temporary,$File)
}
try{
 $holder=[OwnedLedgerAclHandle]::new([string]$c.target,[string]$c.targetVolume,[string]$c.targetInode,[bool]$c.directory)
 $sddl=$holder.OriginalDacl
 $holder.DenyCurrentPrincipal()
 $self=Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
 $ready=@{schemaVersion=1;nonce=$c.nonce;fileId=$holder.FileId;principalSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;processId=$PID;processCreatedAt=$self.CreationDate.ToUniversalTime().ToString('o');denied=$true}
 Write-NewReceipt $c.ready ($ready|ConvertTo-Json -Compress)
 $deadline=[DateTime]::UtcNow.AddSeconds(120)
 while(!(Test-Path -LiteralPath $c.release)){
  if([DateTime]::UtcNow -ge $deadline){throw 'Owned ACL holder release deadline'}
  Start-Sleep -Milliseconds 50
 }
 $release=Get-Item -LiteralPath $c.release
 if($release.Attributes -band [IO.FileAttributes]::ReparsePoint -or $release.Length -ne 64 -or [IO.File]::ReadAllText($c.release) -cne $c.nonce){throw 'Owned ACL release identity mismatch'}
 $holder.Restore();$restored=$true
 Write-NewReceipt $c.restored (@{schemaVersion=1;nonce=$c.nonce;fileId=$holder.FileId;restored=$true;originalDacl=$sddl}|ConvertTo-Json -Compress)
}finally{if($holder){$holder.Dispose()}}
if(!$restored){throw 'Exact owned ACL restoration unproven'}

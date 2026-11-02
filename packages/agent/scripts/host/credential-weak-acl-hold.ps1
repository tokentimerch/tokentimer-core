<# Supporting public-control credential ACL fault. All DACL changes/restoration
use one original native file handle without delete sharing. No SCM, key or CA.
The caller must contain this process before execution and preserve unknown state. #>
param([Parameter(Mandatory)][string]$ContextPath,[Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ContextSha256)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$inputFile=[IO.File]::Open($ContextPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
try {
 if($inputFile.Length -lt 1 -or $inputFile.Length -gt 8192){throw 'Bounded owned context required'}
 $bytes=[byte[]]::new([int]$inputFile.Length);$n=$inputFile.Read($bytes,0,$bytes.Length)
 if($n -ne $bytes.Length -or $inputFile.ReadByte() -ne -1){throw 'Context changed'}
 $sha=[Security.Cryptography.SHA256]::Create()
 try{if([BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLowerInvariant() -cne $ContextSha256){throw 'Context digest mismatch'}}finally{$sha.Dispose()}
 $c=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json
 $fields=@('schemaVersion','targetKind','nonce','target','volume','inode','originalDacl','ready','release','restored')
 if(@($c.PSObject.Properties).Count -ne $fields.Count -or @($c.PSObject.Properties|Where-Object {$_.Name -cnotin $fields}).Count -or $c.schemaVersion -ne 1 -or $c.nonce -cnotmatch '^[a-f0-9]{64}$' -or $c.volume -cnotmatch '^[1-9][0-9]{0,9}$' -or $c.inode -cnotmatch '^[1-9][0-9]{0,24}$'){throw 'Closed owned ACL context required'}
 if($c.originalDacl -isnot [string] -or $c.originalDacl.Length -lt 1 -or $c.originalDacl.Length -gt 4096){throw 'Bounded original DACL required'}
 $directory=[IO.Path]::GetFullPath((Split-Path $ContextPath))
 foreach($name in @('ready','release','restored')){if([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($c.$name)) -cne $directory){throw 'Context path escape'}}
 if($c.targetKind -ceq 'public-control') {if([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($c.target)) -cne $directory){throw 'Public target path escape'}}
 elseif($c.targetKind -ceq 'installed-owned-credential') {
  $expectedTarget=Join-Path (Split-Path -Parent $directory) 'state\credential'
  if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18' -or [IO.Path]::GetFullPath($c.target) -cne [IO.Path]::GetFullPath($expectedTarget)){throw 'Installed owned SYSTEM credential required'}
 } else {throw 'Unknown credential target kind'}
 foreach($name in @('ready','release','restored')){if(Test-Path -LiteralPath $c.$name){throw 'Never adopt an existing ACL protocol file'}}
 Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
public sealed class OwnedPublicCredentialAcl : IDisposable {
 [StructLayout(LayoutKind.Sequential)] struct Info { public uint Attributes,CreationLow,CreationHigh,AccessLow,AccessHigh,WriteLow,WriteHigh,Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow; }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info info);
 [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(SafeFileHandle h,int type,uint flags,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
 [DllImport("advapi32.dll")] static extern uint SetSecurityInfo(SafeFileHandle h,int type,uint flags,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetSecurityDescriptorDacl(IntPtr descriptor,out bool present,out IntPtr dacl,out bool defaulted);
 [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
 [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
 readonly SafeFileHandle handle; readonly byte[] original; readonly string identity; bool attempted; string appliedSddl;
 public string FileId {get{return identity;}}
 public string OriginalDacl {get{return new RawSecurityDescriptor(original,0).GetSddlForm(AccessControlSections.Access);}}
 public OwnedPublicCredentialAcl(string path,string volume,string inode,string expectedDacl){
  if(Marshal.SizeOf(typeof(Info))!=52||Marshal.OffsetOf(typeof(Info),"IndexHigh").ToInt32()!=44)throw new InvalidOperationException("File information ABI mismatch");
  handle=CreateFileW(path,0x00060080,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
  if(handle.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());
  try{Info i;if(!GetFileInformationByHandle(handle,out i))throw new Win32Exception(Marshal.GetLastWin32Error());ulong id=((ulong)i.IndexHigh<<32)|i.IndexLow;identity=i.Volume+":"+id;if(id==0||i.Volume.ToString()!=volume||id.ToString()!=inode||(i.Attributes&0x410)!=0)throw new InvalidOperationException("Exact original regular file required");original=Read();if(OriginalDacl!=new RawSecurityDescriptor(expectedDacl).GetSddlForm(AccessControlSections.Access))throw new InvalidOperationException("Original DACL changed before mutation");}catch{handle.Dispose();throw;}
 }
 byte[] Read(){IntPtr o,g,d,s,p;uint e=GetSecurityInfo(handle,1,4,out o,out g,out d,out s,out p);if(e!=0)throw new Win32Exception((int)e);try{uint n=GetSecurityDescriptorLength(p);if(n<20||n>65536)throw new InvalidOperationException("Bounded descriptor required");var b=new byte[n];Marshal.Copy(p,b,0,(int)n);return b;}finally{LocalFree(p);}}
 void Apply(byte[] bytes){var p=GCHandle.Alloc(bytes,GCHandleType.Pinned);try{IntPtr d;bool present,def;if(!GetSecurityDescriptorDacl(p.AddrOfPinnedObject(),out present,out d,out def)||!present)throw new InvalidOperationException("DACL required");var raw=new RawSecurityDescriptor(bytes,0);uint flags=4u|((raw.ControlFlags&ControlFlags.DiscretionaryAclProtected)!=0?0x80000000u:0x20000000u);uint e=SetSecurityInfo(handle,1,flags,IntPtr.Zero,IntPtr.Zero,d,IntPtr.Zero);if(e!=0)throw new Win32Exception((int)e);}finally{p.Free();}}
 public string GrantPublicRead(){var raw=new RawSecurityDescriptor(original,0);if(raw.DiscretionaryAcl==null||(raw.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0)throw new InvalidOperationException("Original protected DACL required");raw.DiscretionaryAcl.InsertAce(raw.DiscretionaryAcl.Count,new CommonAce(AceFlags.None,AceQualifier.AccessAllowed,1,new SecurityIdentifier("S-1-1-0"),false,null));var bytes=new byte[raw.BinaryLength];raw.GetBinaryForm(bytes,0);appliedSddl=raw.GetSddlForm(AccessControlSections.Access);attempted=true;Apply(bytes);if(new RawSecurityDescriptor(Read(),0).GetSddlForm(AccessControlSections.Access)!=appliedSddl)throw new InvalidOperationException("Applied DACL readback mismatch");return appliedSddl;}
 public static int RestorationAction(string current,string original,string applied){if(current==original)return 0;if(applied!=null&&current==applied)return 1;throw new InvalidOperationException("Unknown foreign DACL preserved");}
 public void Restore(){if(attempted){string current=new RawSecurityDescriptor(Read(),0).GetSddlForm(AccessControlSections.Access);if(RestorationAction(current,OriginalDacl,appliedSddl)==1){Apply(original);if(new RawSecurityDescriptor(Read(),0).GetSddlForm(AccessControlSections.Access)!=OriginalDacl)throw new InvalidOperationException("Exact original DACL not restored");}attempted=false;}}
 public void Dispose(){try{Restore();}finally{handle.Dispose();}}
}
'@
 # Pure managed policy checks run before any native file handle is opened.
 if([OwnedPublicCredentialAcl]::RestorationAction('original','original','applied') -ne 0 -or [OwnedPublicCredentialAcl]::RestorationAction('applied','original','applied') -ne 1){throw 'Restoration policy mismatch'}
 $foreignRefused=$false;try{[void][OwnedPublicCredentialAcl]::RestorationAction('foreign','original','applied')}catch{$foreignRefused=$true};if(!$foreignRefused){throw 'Foreign DACL restoration must refuse'}
 function Write-ExclusiveReceipt($file,$value){$data=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Compress));if($data.Length -gt 16384){throw 'Receipt too large'};$temp=$file+'.writing';$out=[IO.File]::Open($temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$out.Write($data,0,$data.Length);$out.Flush($true)}finally{$out.Dispose()};[IO.File]::Move($temp,$file)}
 $holder=$null
 try {
  $holder=[OwnedPublicCredentialAcl]::new([string]$c.target,[string]$c.volume,[string]$c.inode,[string]$c.originalDacl)
  $original=$holder.OriginalDacl;$applied=$holder.GrantPublicRead()
  Write-ExclusiveReceipt $c.ready @{schemaVersion=1;nonce=$c.nonce;fileId=$holder.FileId;originalDacl=$original;appliedDacl=$applied;untrustedSid='S-1-1-0';readMask=1;retainedOriginalHandle=$true}
  $clock=[Diagnostics.Stopwatch]::StartNew()
  while(!(Test-Path -LiteralPath $c.release)){if($clock.Elapsed.TotalSeconds -gt 90){throw 'Owned ACL release timed out'};Start-Sleep -Milliseconds 25}
  $release=Get-Item -LiteralPath $c.release -Force
  if($release.PSIsContainer -or ($release.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $release.Length -ne 64 -or [IO.File]::ReadAllText($c.release) -cne $c.nonce){throw 'Owned release receipt mismatch'}
  $holder.Restore()
  Write-ExclusiveReceipt $c.restored @{schemaVersion=1;nonce=$c.nonce;fileId=$holder.FileId;originalDacl=$original;restored=$true}
 } finally {if($holder){$holder.Dispose()}}
} finally {$inputFile.Dispose()}

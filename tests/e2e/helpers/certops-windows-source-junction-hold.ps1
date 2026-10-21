<# Fixture-only source junction custody. The contained parent supplies a hashed
closed context. The original reparse handle pins identity/target across installer
execution and removes only that junction through its handle; never traverses it. #>
param([Parameter(Mandatory)][string]$ContextPath,[Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ContextSha256)
$ErrorActionPreference='Stop'
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18'){throw 'Disposable SYSTEM fixture required'}
$input=[IO.File]::Open($ContextPath,'Open','Read','Read')
try {
 if($input.Length -lt 1 -or $input.Length -gt 8192){throw 'Bounded context required'}
 $bytes=[byte[]]::new([int]$input.Length);if($input.Read($bytes,0,$bytes.Length) -ne $bytes.Length -or $input.ReadByte() -ne -1){throw 'Context changed'}
 $sha=[Security.Cryptography.SHA256]::Create();try{if([BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLowerInvariant() -cne $ContextSha256){throw 'Context hash differs'}}finally{$sha.Dispose()}
 $c=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json
 $keys=@('schemaVersion','token','link','target','linkId','targetId','ready','release','removed')
 if(@($c.PSObject.Properties).Count -ne $keys.Count -or @($c.PSObject.Properties|Where-Object {$_.Name -cnotin $keys}).Count -or $c.schemaVersion -ne 1 -or $c.token -cnotmatch '^[a-f0-9]{32}$'){throw 'Closed context required'}
 $directory=[IO.Path]::GetFullPath((Split-Path $ContextPath));$root=Split-Path $directory
 if((Split-Path $directory -Leaf) -cne ('.source-junction-'+$c.token)){throw 'Owned protocol root required'}
 $expectedLink=Join-Path $root ('candidate-package\package\qualification-source-junction-'+$c.token)
 if([IO.Path]::GetFullPath($c.link) -cne [IO.Path]::GetFullPath($expectedLink) -or [IO.Path]::GetFullPath($c.target) -cne (Join-Path $directory 'target')){throw 'Owned link and target required'}
 foreach($name in @('ready','release','removed')){if([IO.Path]::GetFullPath($c.$name) -cne (Join-Path $directory $name) -or (Test-Path -LiteralPath $c.$name)){throw 'Private protocol path refused'}}
 Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public sealed class OwnedSourceJunction : IDisposable {
 [StructLayout(LayoutKind.Sequential)] struct Info {public uint Attributes,CreatedLow,CreatedHigh,AccessLow,AccessHigh,WrittenLow,WrittenHigh,Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string p,uint a,uint s,IntPtr x,uint d,uint f,IntPtr t);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info i);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool DeviceIoControl(SafeFileHandle h,uint c,IntPtr i,uint n,byte[] o,uint z,out uint r,IntPtr v);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle h,int c,byte[] b,uint n);
 readonly SafeFileHandle link,target;readonly string destination;public readonly string LinkId,TargetId;bool removed;
 static void Require(bool v){if(!v)throw new Win32Exception(Marshal.GetLastWin32Error());}
 static string Id(SafeFileHandle h,bool junction){Info i;Require(GetFileInformationByHandle(h,out i));if((i.Attributes&16)==0||((i.Attributes&1024)!=0)!=junction)throw new InvalidOperationException("Original directory type differs");return i.Volume+":"+(((ulong)i.IndexHigh<<32)|i.IndexLow);}
 public static string ParseTarget(byte[] b,int n){if(n<16||n>b.Length||BitConverter.ToUInt32(b,0)!=0xa0000003u||BitConverter.ToUInt16(b,4)+8!=n)throw new InvalidOperationException("Exact mount point data required");int o=BitConverter.ToUInt16(b,8),l=BitConverter.ToUInt16(b,10),po=BitConverter.ToUInt16(b,12),pl=BitConverter.ToUInt16(b,14);if((o&1)!=0||(l&1)!=0||(po&1)!=0||(pl&1)!=0||l<2||16+o+l>n||16+po+pl>n)throw new InvalidOperationException("Bounded substitute name required");string value=Encoding.Unicode.GetString(b,16+o,l);if(!value.StartsWith(@"\??\")||value.IndexOf('\0')>=0)throw new InvalidOperationException("Absolute local mount point required");value=value.Substring(4);if(value.Length<3||!Char.IsLetter(value[0])||value[1]!=':'||value[2]!='\\')throw new InvalidOperationException("Local drive target required");return System.IO.Path.GetFullPath(value).TrimEnd('\\');}
 string ReadTarget(){var b=new byte[16384];uint n;Require(DeviceIoControl(link,0x900a8,IntPtr.Zero,0,b,(uint)b.Length,out n,IntPtr.Zero));return ParseTarget(b,(int)n);}
 public OwnedSourceJunction(string path,string destination,string expectedLink,string expectedTarget){
  this.destination=System.IO.Path.GetFullPath(destination).TrimEnd('\\');
  if(Marshal.SizeOf(typeof(Info))!=52)throw new InvalidOperationException("File identity ABI differs");
  target=CreateFileW(destination,0x80000000,1,IntPtr.Zero,3,0x02200000,IntPtr.Zero);if(target.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());
  try{TargetId=Id(target,false);if(TargetId!=expectedTarget)throw new InvalidOperationException("Target replaced");link=CreateFileW(path,0x80010000,1,IntPtr.Zero,3,0x02200000,IntPtr.Zero);if(link.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());LinkId=Id(link,true);if(LinkId!=expectedLink||!String.Equals(ReadTarget(),System.IO.Path.GetFullPath(destination).TrimEnd('\\'),StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Junction identity or target differs");}catch{if(link!=null)link.Dispose();target.Dispose();throw;}
 }
 public void Remove(){if(removed)throw new InvalidOperationException("Already removed");if(Id(link,true)!=LinkId||Id(target,false)!=TargetId||!String.Equals(ReadTarget(),destination,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Retained object changed");Require(SetFileInformationByHandle(link,4,new byte[]{1},1));link.Dispose();removed=true;target.Dispose();}
 public void Dispose(){if(link!=null)link.Dispose();if(target!=null)target.Dispose();}
}
'@
 function Publish($file,$value){$data=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Compress));$temp=$file+'.writing';$stream=[IO.File]::Open($temp,'CreateNew','Write','None');try{$stream.Write($data,0,$data.Length);$stream.Flush($true)}finally{$stream.Dispose()};[IO.File]::Move($temp,$file)}
 $holder=$null
 try {
  $holder=[OwnedSourceJunction]::new($c.link,$c.target,$c.linkId,$c.targetId)
  Publish $c.ready @{schemaVersion=1;token=$c.token;linkId=$holder.LinkId;targetId=$holder.TargetId;reparseTag=2684354563;exactTarget=$true;originalHandlesHeld=$true}
  $clock=[Diagnostics.Stopwatch]::StartNew();while(!(Test-Path -LiteralPath $c.release)){if($clock.Elapsed.TotalSeconds -gt 120){throw 'Release deadline exceeded'};Start-Sleep -Milliseconds 25}
  $item=Get-Item -LiteralPath $c.release -Force;if($item.PSIsContainer -or ($item.Attributes-band[IO.FileAttributes]::ReparsePoint) -or $item.Length-ne32 -or [IO.File]::ReadAllText($c.release)-cne$c.token){throw 'Release token differs'}
  $holder.Remove()
  Publish $c.removed @{schemaVersion=1;token=$c.token;linkId=$holder.LinkId;targetId=$holder.TargetId;originalJunctionRemoved=$true;targetHandleClosed=$true}
 }finally{if($holder){$holder.Dispose()}}
}finally{$input.Dispose()}

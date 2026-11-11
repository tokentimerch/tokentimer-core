# Qualification-only retained public-certificate context. No key export, deletion,
# recreation, ACL change, service control or child process occurs in this holder.
# A shared retained JobObject owns this process before execution. An uncertain
# phase deliberately preserves the fixture instead of guessing restoration.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ContextPath,[Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ContextSha256)
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public sealed class CertOpsPredecessorDirectory : IDisposable {
 [StructLayout(LayoutKind.Sequential)] struct Info {public uint Attr;public System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write;public uint Volume,SizeHigh,SizeLow,Links,High,Low;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle,out Info info);
 SafeFileHandle handle; readonly string volume,id;
 static Info Read(SafeFileHandle h){Info x;if(h.IsInvalid||!GetFileInformationByHandle(h,out x))throw new InvalidOperationException("Owned directory observation failed");if((x.Attr&16)==0||(x.Attr&1024)!=0)throw new InvalidOperationException("Original non-reparse directory required");return x;}
 static string Id(Info x){return (((ulong)x.High<<32)|x.Low).ToString(CultureInfo.InvariantCulture);}
 public CertOpsPredecessorDirectory(string path,string expectedVolume,string expectedId){handle=CreateFileW(path,128,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);try{Info x=Read(handle);volume=x.Volume.ToString(CultureInfo.InvariantCulture);id=Id(x);if(volume!=expectedVolume||id!=expectedId)throw new InvalidOperationException("Original directory identity required");}catch{handle.Dispose();throw;}}
 public void Check(string path){Info held=Read(handle);using(SafeFileHandle fresh=CreateFileW(path,128,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero)){Info x=Read(fresh);if(x.Volume.ToString(CultureInfo.InvariantCulture)!=volume||Id(x)!=id||Id(held)!=id)throw new InvalidOperationException("Changed owned directory preserved");}}
 public void Dispose(){if(handle!=null)handle.Dispose();}
}
"@
$inputFile=$null;$rootPin=$null;$directoryPin=$null;$store=$null;$certificate=$null;$key=$null;$public=$null
function Digest([byte[]]$Bytes){$sha=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}}
function Check-Namespace {$rootPin.Check($ctx.root);$directoryPin.Check($ctx.directory)}
function Publish([string]$Name,$Value){Check-Namespace;$target=Join-Path $ctx.directory $Name;$temporary=Join-Path $ctx.directory ($Name+'.pending');$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Compress));$f=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()};[IO.File]::Move($temporary,$target);Check-Namespace}
function Wait-Control([string]$Name){$deadline=[DateTime]::UtcNow.AddMinutes(12);$path=Join-Path $ctx.directory $Name;while(!(Test-Path -LiteralPath $path)){Check-Namespace;if([DateTime]::UtcNow-ge$deadline){throw 'Owned predecessor phase deadline exceeded'};Start-Sleep -Milliseconds 25};Check-Namespace;$f=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);try{if($f.Length-ne 64){throw 'Exact owned predecessor control required'};$bytes=New-Object byte[] 65;$length=$f.Read($bytes,0,65);if($length-ne 64-or[Text.Encoding]::ASCII.GetString($bytes,0,64)-cne$ctx.token){throw 'Exact owned predecessor token required'}}finally{$f.Dispose()};Check-Namespace}
function Native-Signature {if(!$key.Key.IsMachineKey-or[int]$key.Key.ExportPolicy-ne 0-or$key.KeySize-ne 2048-or$key.Key.Provider.Provider-cne'Microsoft Software Key Storage Provider'-or$key.Key.KeyName-cne$ctx.containerName-or$key.Key.UniqueName-cne$ctx.uniqueName){throw 'Original protected CNG identity changed'};$sig=$key.SignData($challenge,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1);if(!$public.VerifyData($challenge,$sig,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)){throw 'Original protected CNG possession required'};[Convert]::ToBase64String($sig)}
function Store-Matches {@($store.Certificates|Where-Object {$_.Thumbprint-ceq$ctx.thumbprint})}
try {
 if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value-cne'S-1-5-18'){throw 'Original SYSTEM holder required'}
 $inputFile=[IO.File]::Open($ContextPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 if($inputFile.Length-lt 1-or$inputFile.Length-gt 65536){throw 'Bounded original context required'}
 $bytes=New-Object byte[] ([int]$inputFile.Length);$position=0;while($position-lt$bytes.Length){$n=$inputFile.Read($bytes,$position,$bytes.Length-$position);if($n-lt 1){throw 'Complete original context required'};$position+=$n}
 if((Digest $bytes)-cne$ContextSha256){throw 'Exact original context digest required'}
 $ctx=[Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json
 $fields=@('schemaVersion','token','root','rootDev','rootIno','directory','directoryDev','directoryIno','thumbprint','derBase64','containerName','uniqueName','challengeBase64')
 if((@($ctx.PSObject.Properties.Name|Sort-Object)-join',')-cne(@($fields|Sort-Object)-join',')-or($ctx.schemaVersion-isnot[int])-or$ctx.schemaVersion-ne 1-or$ctx.token-cnotmatch'^[a-f0-9]{64}$'-or$ctx.thumbprint-cnotmatch'^[A-F0-9]{40}$'){throw 'Closed original predecessor context required'}
 if([IO.Path]::GetFullPath($ContextPath)-cne(Join-Path $ctx.directory 'context.json')-or[IO.Path]::GetFullPath($ctx.directory)-cne(Join-Path $ctx.root ('.failed-rollback-holder-'+$ctx.token))){throw 'Exact owned predecessor namespace required'}
 foreach($name in @('rootDev','rootIno','directoryDev','directoryIno')){if($ctx.$name-cnotmatch'^[1-9][0-9]{0,19}$'){throw 'Positive original directory identity required'}}
 foreach($name in @('containerName','uniqueName')){if($ctx.$name-isnot[string]-or$ctx.$name.Length-lt 1-or$ctx.$name.Length-gt 1024-or$ctx.$name-match'[\x00-\x1f]'){throw 'Bounded original protected key identity required'}}
 $rootPin=[CertOpsPredecessorDirectory]::new($ctx.root,$ctx.rootDev,$ctx.rootIno);$directoryPin=[CertOpsPredecessorDirectory]::new($ctx.directory,$ctx.directoryDev,$ctx.directoryIno)
 Check-Namespace;$challenge=[Convert]::FromBase64String($ctx.challengeBase64);if($challenge.Length-ne 32){throw 'Original possession challenge required'}
 $store=[Security.Cryptography.X509Certificates.X509Store]::new('My','LocalMachine');$store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
 $matches=Store-Matches;if($matches.Count-ne 1){throw 'One original public certificate required'};$certificate=$matches[0]
 if(!$certificate.HasPrivateKey-or[Convert]::ToBase64String($certificate.RawData)-cne$ctx.derBase64){throw 'Original associated public certificate required'}
 $key=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate);$public=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($certificate)
 Publish 'ready.json' @{token=$ctx.token;phase='ready';fingerprint=(Digest $certificate.RawData);signature=(Native-Signature)}
 Wait-Control 'remove';Check-Namespace;$matches=Store-Matches;if($matches.Count-ne 1-or[Convert]::ToBase64String($matches[0].RawData)-cne$ctx.derBase64){throw 'Changed predecessor public copy preserved'}
 $store.Remove($certificate);if((Store-Matches).Count-ne 0){throw 'Original public entry must be absent'}
 Publish 'removed.json' @{token=$ctx.token;phase='removed';publicEntryAbsent=$true;fingerprint=(Digest $certificate.RawData);signature=(Native-Signature)}
 Wait-Control 'restore';Check-Namespace;if((Store-Matches).Count-ne 0){throw 'Unexpected predecessor public copy preserved'}
 $null=Native-Signature;$store.Add($certificate);$restored=Store-Matches
 if($restored.Count-ne 1-or!$restored[0].HasPrivateKey-or[Convert]::ToBase64String($restored[0].RawData)-cne$ctx.derBase64){throw 'Exact original public association restoration required'}
 $fresh=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($restored[0]);try{if($fresh.Key.KeyName-cne$ctx.containerName-or$fresh.Key.UniqueName-cne$ctx.uniqueName-or!$fresh.Key.IsMachineKey-or[int]$fresh.Key.ExportPolicy-ne 0-or$fresh.Key.Provider.Provider-cne'Microsoft Software Key Storage Provider'){throw 'Restored original protected key association required'}}finally{if($fresh){$fresh.Dispose()};$restored[0].Dispose()}
 Publish 'restored.json' @{token=$ctx.token;phase='restored';originalPublicAssociationRestored=$true;fingerprint=(Digest $certificate.RawData);signature=(Native-Signature)}
} catch {throw 'Owned predecessor context phase failed; preserve fixture'}
finally {if($public){$public.Dispose()};if($key){$key.Dispose()};if($certificate){$certificate.Dispose()};if($store){$store.Dispose()};if($inputFile){$inputFile.Dispose()};if($directoryPin){$directoryPin.Dispose()};if($rootPin){$rootPin.Dispose()}}

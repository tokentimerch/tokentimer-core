<#
Native Microsoft Online Responder admission for the disposable issuing CA.
Importing this file defines functions only. The enclosing fixture must persist
the returned baseline in its restrictive, identity-bound receipt BEFORE any
role, directory, template, publication, service or key mutation.
Historical revoked-status phases are hooks for the separate proof. Native lab
execution is still pending. This file does not qualify revoked status.

This deliberately refuses an existing responder or IIS installation. It does
not adopt a shared native service and does not offer broad feature teardown.
#>
function Initialize-OcspReceiptReader {
 if('TTQualificationOcspReceipt' -as [type]) { return }
 Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
public static class TTQualificationOcspReceipt {
 [StructLayout(LayoutKind.Sequential)] struct Info {
  public uint Attributes;
  public System.Runtime.InteropServices.ComTypes.FILETIME Created,Accessed,Written;
  public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
 }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
 static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)]
 static extern bool GetFileInformationByHandle(SafeFileHandle handle,out Info info);
 static Info Identity(SafeFileHandle handle,bool allowEmpty=false) {
  Info value;
  if(handle.IsInvalid || !GetFileInformationByHandle(handle,out value) ||
     (value.Attributes & (0x10u|0x400u))!=0 || value.Links!=1 ||
     value.SizeHigh!=0 || (!allowEmpty && value.SizeLow<1) || value.SizeLow>65536 ||
     (value.IndexHigh==0 && value.IndexLow==0))
   throw new IOException("Exact bounded regular private OCSP receipt required");
  return value;
 }
 static bool Same(Info a,Info b) {
  return a.Volume==b.Volume && a.IndexHigh==b.IndexHigh && a.IndexLow==b.IndexLow &&
   a.SizeLow==b.SizeLow && a.Written.dwHighDateTime==b.Written.dwHighDateTime &&
   a.Written.dwLowDateTime==b.Written.dwLowDateTime;
 }
 public static void AssertAbi() {
  if(Marshal.SizeOf(typeof(Info))!=52 || Marshal.OffsetOf(typeof(Info),"Volume").ToInt32()!=28 ||
     Marshal.OffsetOf(typeof(Info),"IndexHigh").ToInt32()!=44)
   throw new IOException("Native OCSP receipt identity ABI unproven");
 }
 static void PrivateAcl(string path) {
  var acl=File.GetAccessControl(path);
  if(!acl.AreAccessRulesProtected) throw new IOException("OCSP receipt inherits access");
  string owner=WindowsIdentity.GetCurrent().User.Value; bool system=false;
  foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier))) {
   string sid=rule.IdentityReference.Value;
   if(rule.IsInherited || (rule.AccessControlType==AccessControlType.Allow &&
      sid!=owner && sid!="S-1-5-18" && sid!="S-1-5-32-544"))
    throw new IOException("OCSP receipt grants foreign access");
   if(sid=="S-1-5-18" && rule.AccessControlType==AccessControlType.Allow &&
      (rule.FileSystemRights & FileSystemRights.FullControl)==FileSystemRights.FullControl) system=true;
  }
  if(!system) throw new IOException("OCSP receipt lacks explicit SYSTEM custody");
 }
 public static string DirectoryIdentity(string path) {
  AssertAbi();
  using(var handle=CreateFile(path,0x80u,3u,IntPtr.Zero,3u,0x02200000u,IntPtr.Zero)) {
   Info value;
   if(handle.IsInvalid || !GetFileInformationByHandle(handle,out value) ||
      (value.Attributes & 0x10u)==0 || (value.Attributes & 0x400u)!=0 ||
      (value.IndexHigh==0 && value.IndexLow==0))
    throw new IOException("Original regular OCSP directory identity required");
   return value.Volume.ToString("x8")+":"+value.IndexHigh.ToString("x8")+value.IndexLow.ToString("x8");
  }
 }
 public static SafeFileHandle PinDirectory(string path,string expected) {
  AssertAbi();
  var handle=CreateFile(path,0x80u,3u,IntPtr.Zero,3u,0x02200000u,IntPtr.Zero);
  try {
   Info value;
   if(handle.IsInvalid || !GetFileInformationByHandle(handle,out value) ||
      (value.Attributes & 0x10u)==0 || (value.Attributes & 0x400u)!=0 ||
      (value.IndexHigh==0 && value.IndexLow==0) ||
      value.Volume.ToString("x8")+":"+value.IndexHigh.ToString("x8")+value.IndexLow.ToString("x8")!=expected)
    throw new IOException("Original native OCSP directory pin refused");
   // No FILE_SHARE_DELETE: callers retain this exact handle across every
   // private-namespace write, so the directory cannot be swapped for an alias.
   return handle;
  } catch { handle.Dispose();throw; }
 }
 public static byte[] Read(string path) { return ReadFile(path,true); }
 public static byte[] ReadPublic(string path) { return ReadFile(path,false); }
 static byte[] ReadFile(string path,bool privateReceipt) {
  AssertAbi();
  // Open the alias itself, deny write/delete sharing, and retain this exact
  // native file while checking its private ACL and bounded bytes.
  using(var handle=CreateFile(path,0x80000000u,1u,IntPtr.Zero,3u,0x00200000u,IntPtr.Zero)) {
   var before=Identity(handle); if(privateReceipt) PrivateAcl(path);
   using(var stream=new FileStream(handle,FileAccess.Read)) {
    var buffer=new byte[65537]; int length=0,count;
    while(length<buffer.Length && (count=stream.Read(buffer,length,buffer.Length-length))>0) length+=count;
    var after=Identity(handle);
    using(var fresh=CreateFile(path,0x80000000u,1u,IntPtr.Zero,3u,0x00200000u,IntPtr.Zero)) {
     if(length!=before.SizeLow || !Same(before,after) || !Same(before,Identity(fresh)))
      throw new IOException("OCSP receipt changed while reading");
    }
    if(privateReceipt) PrivateAcl(path);
    var result=new byte[length]; Array.Copy(buffer,result,length); return result;
   }
  }
 }
 public static FileStream PinRead(string path) {
  AssertAbi();
  var handle=CreateFile(path,0x80000000u,1u,IntPtr.Zero,3u,0x00200000u,IntPtr.Zero);
  try {
   Identity(handle);PrivateAcl(path);
   return new FileStream(handle,FileAccess.Read);
  } catch { handle.Dispose();throw; }
 }
 // Certreq output files are created and ACL-bound BEFORE launch. Certreq may
 // require exclusive sharing, so do not retain a writer handle while it runs.
 // After the contained command has drained, reopen the alias itself and bind
 // volume, file ID AND native creation time before reading any output bytes.
 // A delete/recreate output is refused; no replacement's ACL is ever repaired.
 public sealed class Output : IDisposable {
  readonly string path;
  readonly Info original;
  public Output(string path,FileSecurity security) {
   AssertAbi();
   this.path=path;
   using(var handle=CreateFile(path,0xc0060000u,3u,IntPtr.Zero,1u,0x00200000u,IntPtr.Zero)) {
    original=Identity(handle,true);
    using(var stream=new FileStream(handle,FileAccess.ReadWrite)) {
     stream.SetAccessControl(security);
     PrivateAcl(path);
    }
   }
  }
  public byte[] ReadCompleted() {
   using(var handle=CreateFile(path,0x80000000u,1u,IntPtr.Zero,3u,0x00200000u,IntPtr.Zero)) {
    var before=Identity(handle);
    if(before.Volume!=original.Volume || before.IndexHigh!=original.IndexHigh ||
       before.IndexLow!=original.IndexLow ||
       before.Created.dwHighDateTime!=original.Created.dwHighDateTime ||
       before.Created.dwLowDateTime!=original.Created.dwLowDateTime)
     throw new IOException("Owned certreq output identity changed");
    PrivateAcl(path);
    using(var stream=new FileStream(handle,FileAccess.Read)) {
     var buffer=new byte[65537];int length=0,count;
     while(length<buffer.Length && (count=stream.Read(buffer,length,buffer.Length-length))>0) length+=count;
     var after=Identity(handle);
     using(var fresh=CreateFile(path,0x80000000u,1u,IntPtr.Zero,3u,0x00200000u,IntPtr.Zero)) {
      if(length!=before.SizeLow || !Same(before,after) || !Same(before,Identity(fresh)))
       throw new IOException("Owned certreq output changed while reading");
     }
     PrivateAcl(path);
     var bytes=new byte[length];Array.Copy(buffer,bytes,length);return bytes;
    }
   }
  }
  public void Dispose() { }
 }
}
'@
}

function Assert-OcspPrivateDirectory([string]$Path) {
 $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
 if(!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
  throw 'Regular nonreparse OCSP receipt directory required'
 }
 $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
 if(!$acl.AreAccessRulesProtected) { throw 'OCSP receipt directory inherits access' }
 $allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
 $system=$false
 foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
  if($rule.IsInherited -or ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -cnotin $allowed)) {
   throw 'OCSP receipt directory grants foreign access'
  }
  if($rule.IdentityReference.Value -ceq 'S-1-5-18' -and $rule.AccessControlType -eq 'Allow' -and
     ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl) {
   $system=$true
  }
 }
 if(!$system) { throw 'OCSP receipt directory lacks explicit SYSTEM custody' }
}

function Assert-OcspFixtureIdentifier([string]$Value) {
 if($Value -cnotmatch '^TTQualificationOcsp[a-f0-9]{16}$') {
  throw 'Exact owned OCSP template identifier required'
 }
}

function Initialize-OcspContainedCommand([string]$DriverPath,[string]$ExpectedSha256) {
 if($ExpectedSha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'Exact candidate native driver digest required' }
 Initialize-OcspReceiptReader
 # The public driver is copied into the protected fixture directory as a
 # previously absent regular file, then receives a private explicit DACL.
 $bytes=[TTQualificationOcspReceipt]::Read($DriverPath)
 $hash=[Security.Cryptography.SHA256]::Create()
 try { $actual=[BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-','').ToLowerInvariant() }
 finally { $hash.Dispose() }
 if($actual -cne $ExpectedSha256) { throw 'Candidate native driver digest mismatch' }
 if('ContainedNativeJob' -as [type]) {
  if($script:OcspContainedSourceHash -cne $ExpectedSha256) { throw 'Native driver type provenance is unknown' }
  [ContainedNativeJob]::AssertAbi()
  return
 }
 $text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)
 $tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors)
 if($errors.Count) { throw 'Candidate native driver parse failed' }
 $literals=@($ast.FindAll({param($node)
  $node -is [Management.Automation.Language.StringConstantExpressionAst] -and
  $node.StringConstantType -eq [Management.Automation.Language.StringConstantType]::SingleQuotedHereString -and
  $node.Value.TrimStart().StartsWith('using System;')
 },$true))
 if($literals.Count -ne 1) { throw 'Exact candidate native driver definition required' }
 # Compile only the reviewed driver definition, never execute its top-level
 # Node/wrapper protocol. The same original source digest binds both uses.
 Add-Type -TypeDefinition $literals[0].Value -ErrorAction Stop
 [ContainedNativeJob]::AssertAbi()
 $script:OcspContainedSourceHash=$ExpectedSha256
}

function Initialize-OcspRetainedProcessWait([string]$DriverPath,[string]$ExpectedSha256) {
 if($ExpectedSha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'Exact candidate process waiter digest required' }
 Initialize-OcspReceiptReader
 $bytes=[TTQualificationOcspReceipt]::Read($DriverPath)
 $hash=[Security.Cryptography.SHA256]::Create()
 try { $actual=[BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-','').ToLowerInvariant() }
 finally { $hash.Dispose() }
 if($actual -cne $ExpectedSha256) { throw 'Candidate process waiter digest mismatch' }
 if('RetainedFixtureProcess' -as [type]) {
  if($script:OcspWaitSourceHash -cne $ExpectedSha256) { throw 'Process waiter type provenance is unknown' }
  return
 }
 $tokens=$null;$errors=$null
 $text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)
 $ast=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors)
 if($errors.Count) { throw 'Candidate process waiter parse failed' }
 $literals=@($ast.FindAll({param($node)
  $node -is [Management.Automation.Language.StringConstantExpressionAst] -and
  $node.StringConstantType -eq [Management.Automation.Language.StringConstantType]::SingleQuotedHereString -and
  $node.Value.TrimStart().StartsWith('using System;')
 },$true))
 if($literals.Count -ne 1) { throw 'Exact candidate retained process definition required' }
 Add-Type -TypeDefinition $literals[0].Value -ErrorAction Stop
 $script:OcspWaitSourceHash=$ExpectedSha256
}

function Invoke-OcspContainedCommand(
 [ValidateSet('certreq.exe','certutil.exe','powershell.exe')][string]$Command,
 [string[]]$Arguments,
 [string]$WorkingDirectory,
 [ValidateRange(1,180)][int]$TimeoutSeconds=120
) {
 if(!$script:OcspContainedSourceHash -or !('ContainedNativeJob' -as [type])) {
  throw 'Candidate native command containment is not initialized'
 }
 Assert-OcspPrivateDirectory $WorkingDirectory
 if($Arguments.Count -lt 1 -or $Arguments.Count -gt 16 -or
    @($Arguments|Where-Object {$_ -isnot [string] -or $_.Length -gt 4096 -or $_ -match '[\x00-\x1f\x7f]'}).Count) {
  throw 'Bounded public native command arguments required'
 }
 $executable=if($Command -ceq 'powershell.exe'){
  Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
 }else{
  Join-Path $env:SystemRoot ('System32\'+$Command)
 }
 $file=Get-Item -LiteralPath $executable -Force -ErrorAction Stop
 if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
  throw 'Original system native executable required'
 }
 $job=$null;$closed=$false
 try {
  $rendered=[ContainedNativeJob]::Render($executable,$Arguments)
  if($rendered.Length -gt 16384) { throw 'Native command line exceeds bound' }
  $job=[ContainedNativeJob]::new($executable,$rendered,$WorkingDirectory)
  # The retained Job Object already contains the suspended process. Native
  # image/token observation precedes Resume; no PID is ever a kill target.
  $identity=[ContainedNativeIdentity]::Observe([int]$job.ProcessId)
  if($identity.pid -ne $job.ProcessId -or $identity.executablePath -ine $executable -or
     $identity.sid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -or
     $job.RootExited -or $job.Active -ne 1) {
   throw 'Suspended native command identity mismatch'
  }
  $job.Resume()
  $watch=[Diagnostics.Stopwatch]::StartNew()
  while(!$job.RootExited -or $job.Active -ne 0) {
   if($watch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
    throw 'Owned native command timed out; phase remains unresolved'
   }
   Start-Sleep -Milliseconds 20
  }
  $exitCode=$job.Drain()
  if($exitCode -ne 0) { throw 'Owned native command failed; phase remains unresolved' }
  $job.CloseVerified();$closed=$true
  return @{rootExitCode=0;activeNativeProcesses=0;retainedHandlesClosed=$true}
 } finally {
  if($null -ne $job) {
   if(!$closed) {
    # Emergency drainage protects the machine but never turns a failed native
    # phase into successful fixture evidence. Durable receipts stay unresolved.
    try { [void]$job.Drain();$job.CloseVerified() }
    finally { $job.Dispose() }
   } else { $job.Dispose() }
  }
 }
}

function Invoke-OwnedOcspSurvivorCapture($Owner,[string]$HelperSha256,[string]$ScriptSha256) {
 if($HelperSha256 -cnotmatch '^[a-f0-9]{64}$' -or $ScriptSha256 -cnotmatch '^[a-f0-9]{64}$') {
  throw 'Exact native helper and wrapper candidate digests required'
 }
 $Owner=Read-OwnedOcspOwnershipReceipt $Owner.ownership.runId $Owner.ownership.token $Owner.ownership.baseline.issuingCaThumbprint $Owner.ownership.baseline.signingTemplateName
 $scriptPath=Join-Path $Owner.directory 'ocsp-native-survivors.ps1'
 $sourceHandle=[IO.File]::Open($scriptPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try {
 # Hold the exact script against write/replacement through execution, not just
 # a hash check followed by a later path-based interpreter open.
 $source=[TTQualificationOcspReceipt]::Read($scriptPath)
 $hash=[Security.Cryptography.SHA256]::Create()
 try { $actual=[BitConverter]::ToString($hash.ComputeHash($source)).Replace('-','').ToLowerInvariant() }
 finally { $hash.Dispose() }
 if($actual -cne $ScriptSha256) { throw 'Candidate survivor-wrapper digest mismatch' }
 $arguments=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$scriptPath,'-HelperSha256',$HelperSha256,'-Token',$Owner.ownership.token)
 $native=Invoke-OcspContainedCommand 'powershell.exe' $arguments $Owner.directory 120
 # Both wrapper and Go descendants are now proven absent by the retained Job.
 # Never authorize key deletion merely because a result filename appeared.
 $resultPath=Join-Path $Owner.directory ('survivors-'+$Owner.ownership.token+'.json')
 $bytes=[TTQualificationOcspReceipt]::Read($resultPath)
 if($bytes.Length -gt 4096) { throw 'Native survivor receipt exceeds production bound' }
 $result=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json -ErrorAction Stop
 Assert-OcspClosedObject $result @('complete','shared','storesScanned','certificatesScanned','matches')
 if($result.complete -isnot [bool] -or $result.complete -ne $true -or
    $result.shared -isnot [bool] -or $result.shared -ne $false -or $result.matches -ne 0) {
  throw 'Native unshared signer key inventory required'
 }
 foreach($name in @('storesScanned','certificatesScanned','matches')) {
  $number=$result.$name
  $maximum=if($name -ceq 'storesScanned'){512}else{100000}
  if(($number -isnot [int] -and $number -isnot [long]) -or $number -lt 0 -or $number -gt $maximum) {
   throw 'Bounded native signer inventory counts required'
  }
 }
 if($result.storesScanned -lt 1) { throw 'Native machine-store inventory is empty' }
 return @{native=$native;result=$result;bytes=$bytes}
 } finally { $sourceHandle.Dispose() }
}

function New-OcspPrivateAcl([bool]$Directory) {
 $acl=if($Directory){[Security.AccessControl.DirectorySecurity]::new()}else{[Security.AccessControl.FileSecurity]::new()}
 $acl.SetAccessRuleProtection($true,$false)
 foreach($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')|Select-Object -Unique) {
  $principal=[Security.Principal.SecurityIdentifier]::new($sid)
  $rule=if($Directory){
   [Security.AccessControl.FileSystemAccessRule]::new($principal,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
  }else{
   [Security.AccessControl.FileSystemAccessRule]::new($principal,'FullControl','Allow')
  }
  $acl.AddAccessRule($rule)
 }
 return $acl
}

function New-OcspOwnershipReceipt([string]$RunId,[string]$Token,[string]$ExpectedCaThumbprint,[string]$TemplateName) {
 if($RunId -cnotmatch '^[a-f0-9]{10}$' -or
    $Token -cnotmatch '^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$') {
  throw 'Exact owned OCSP run and token required'
 }
 # Admission is repeated immediately before durable ownership publication.
 # No native role, directory template, CA publication or key is changed here.
 $baseline=Get-OcspResponderAdmission $TemplateName $ExpectedCaThumbprint
 $programData=[Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
 $parent=Get-Item -LiteralPath $programData -Force -ErrorAction Stop
 if(!$parent.PSIsContainer -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
  throw 'Original regular ProgramData required'
 }
 # Use a dedicated protected root rather than repairing permissions on another
 # qualification fixture's preexisting shared directory.
 $directory=Join-Path $programData 'TokenTimerOcspQualification'
 if(!(Test-Path -LiteralPath $directory)) {
  [void][IO.Directory]::CreateDirectory($directory,(New-OcspPrivateAcl $true))
 }
 Assert-OcspPrivateDirectory $directory
 if(@(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop|Select-Object -First 1).Count) {
  throw 'Never adopt a nonempty OCSP fixture directory'
 }
 $receipt=Join-Path $directory ($ExpectedCaThumbprint+'.json')
 if(Test-Path -LiteralPath $receipt) { throw 'Never adopt an existing OCSP ownership receipt' }
 $caPath='SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\TTQualificationRoot'
 $registry=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($caPath,$false)
 if(!$registry) { throw 'Original issuing CA publication key missing' }
 try {
  $publication=@{}
  foreach($name in @('CRLPublicationURLs','CACertPublicationURLs')) {
   if($registry.GetValueKind($name) -ne [Microsoft.Win32.RegistryValueKind]::MultiString) {
    throw 'Original issuing CA publication type mismatch'
   }
   $values=[string[]]$registry.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
   if($values.Count -lt 1 -or $values.Count -gt 32 -or
      @($values|Where-Object {$_.Length -lt 1 -or $_.Length -gt 4096}).Count) {
    throw 'Bounded original CA publication values required'
   }
   $publication[$name]=@($values)
  }
 } finally { $registry.Dispose() }
 $root=[ADSI]'LDAP://RootDSE'
 $configurationDn=[string]$root.configurationNamingContext
 $servicePath='LDAP://CN=TTQualificationRoot,CN=Enrollment Services,CN=Public Key Services,CN=Services,'+$configurationDn
 $enrollmentService=[ADSI]$servicePath
 if([string]$enrollmentService.Properties['cn'].Value -cne 'TTQualificationRoot') {
  throw 'Original issuing CA enrollment-service object missing'
 }
 $published=@($enrollmentService.Properties['certificateTemplates']|ForEach-Object {[string]$_})
 if($published.Count -lt 1 -or $published.Count -gt 512 -or $published -ccontains $TemplateName) {
  throw 'Original native publication inventory mismatch'
 }
 Initialize-OcspReceiptReader
 $directoryIdentity=[TTQualificationOcspReceipt]::DirectoryIdentity($directory)
 $proof=@{
  schemaVersion=1;runId=$RunId;token=$Token;baseline=$baseline
  originalPublication=$publication;originalPublishedTemplates=$published
  enrollmentServiceGuid=([Guid]$enrollmentService.Guid).ToString('D')
  plannedContainer=('tokentimer-enr-'+$Token)
  directoryIdentity=$directoryIdentity
 }
 $bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes(($proof|ConvertTo-Json -Depth 8 -Compress))
 if($bytes.Length -lt 1 -or $bytes.Length -gt 65536) { throw 'OCSP ownership receipt exceeds bound' }
 $directoryPin=[TTQualificationOcspReceipt]::PinDirectory($directory,$directoryIdentity)
 try {
 $stream=[IO.File]::Open($receipt,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try {
  $stream.SetAccessControl((New-OcspPrivateAcl $false))
  $stream.Write($bytes,0,$bytes.Length)
  $stream.Flush($true)
 } finally { $stream.Dispose() }
 Initialize-OcspReceiptReader
 $readback=[TTQualificationOcspReceipt]::Read($receipt)
 if([Convert]::ToBase64String($readback) -cne [Convert]::ToBase64String($bytes) -or
    [TTQualificationOcspReceipt]::DirectoryIdentity($directory) -cne $directoryIdentity) {
  throw 'Immutable OCSP ownership receipt readback mismatch'
 }
 # These private coordinates never enter the public qualification projection.
 return @{path=$receipt;directory=$directory;bytes=$bytes;ownership=$proof}
 } finally { $directoryPin.Dispose() }
}

function Assert-OwnedOcspDirectory($Owner) {
 Assert-OcspPrivateDirectory $Owner.directory
 Initialize-OcspReceiptReader
 if([TTQualificationOcspReceipt]::DirectoryIdentity($Owner.directory) -cne $Owner.ownership.directoryIdentity) {
  throw 'Original native OCSP directory was replaced'
 }
}

function Assert-OcspClosedObject($Value,[string[]]$Fields) {
 if($null -eq $Value -or @($Value.PSObject.Properties).Count -ne $Fields.Count -or
    @($Value.PSObject.Properties|Where-Object {$_.Name -cnotin $Fields}).Count) {
  throw 'Closed native OCSP ownership object required'
 }
}

function Read-OwnedOcspOwnershipReceipt([string]$RunId,[string]$Token,[string]$ExpectedCaThumbprint,[string]$TemplateName) {
 Assert-OcspFixtureIdentifier $TemplateName
 if($RunId -cnotmatch '^[a-f0-9]{10}$' -or $ExpectedCaThumbprint -cnotmatch '^[A-F0-9]{40}$' -or
    $Token -cnotmatch '^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$') {
  throw 'Exact original OCSP owner coordinates required'
 }
 $programData=[Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
 $parent=Get-Item -LiteralPath $programData -Force -ErrorAction Stop
 if(!$parent.PSIsContainer -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
  throw 'Original regular ProgramData required'
 }
 $directory=Join-Path $programData 'TokenTimerOcspQualification'
 Assert-OcspPrivateDirectory $directory
 Initialize-OcspReceiptReader
 $receipt=Join-Path $directory ($ExpectedCaThumbprint+'.json')
 $directoryIdentity=[TTQualificationOcspReceipt]::DirectoryIdentity($directory)
 $bytes=[TTQualificationOcspReceipt]::Read($receipt)
 $proof=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json -ErrorAction Stop
 Assert-OcspClosedObject $proof @('schemaVersion','runId','token','baseline','originalPublication','originalPublishedTemplates','enrollmentServiceGuid','plannedContainer','directoryIdentity')
 Assert-OcspClosedObject $proof.baseline @('schemaVersion','machineName','domain','ownerSid','installedFeatures','issuingCaThumbprint','caDerSha256','signingTemplateName','responderInitiallyAbsent','iisInitiallyAbsent','httpPortInitiallyUnbound')
 Assert-OcspClosedObject $proof.originalPublication @('CRLPublicationURLs','CACertPublicationURLs')
 if($proof.directoryIdentity -cnotmatch '^[a-f0-9]{8}:[a-f0-9]{16}$' -or
    $proof.directoryIdentity -cne $directoryIdentity -or
    [TTQualificationOcspReceipt]::DirectoryIdentity($directory) -cne $directoryIdentity -or
    $proof.schemaVersion -isnot [int] -or $proof.schemaVersion -ne 1 -or $proof.runId -cne $RunId -or $proof.token -cne $Token -or
    $proof.plannedContainer -cne ('tokentimer-enr-'+$Token) -or $proof.baseline.schemaVersion -isnot [int] -or $proof.baseline.schemaVersion -ne 1 -or
    $proof.baseline.machineName -ine 'tt-ca' -or $proof.baseline.domain -ine 'lab.certops.test' -or
    $proof.baseline.ownerSid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -or
    $proof.baseline.issuingCaThumbprint -cne $ExpectedCaThumbprint -or
    $proof.baseline.signingTemplateName -cne $TemplateName) {
  throw 'Original native OCSP receipt ownership mismatch'
 }
 if($proof.baseline.caDerSha256 -cnotmatch '^[a-f0-9]{64}$') {
  throw 'Original issuing CA DER digest required'
 }
 if($proof.enrollmentServiceGuid -isnot [string] -or
    $proof.enrollmentServiceGuid -cnotmatch '^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$' -or
    $proof.enrollmentServiceGuid -ceq '00000000-0000-0000-0000-000000000000') {
  throw 'Original enrollment-service object identity required'
 }
 foreach($name in @('responderInitiallyAbsent','iisInitiallyAbsent','httpPortInitiallyUnbound')) {
  if($proof.baseline.$name -isnot [bool] -or $proof.baseline.$name -ne $true) {
   throw 'Original OCSP ownership prerequisite missing'
  }
 }
 foreach($name in @('CRLPublicationURLs','CACertPublicationURLs')) {
  $values=@($proof.originalPublication.$name)
  if($values.Count -lt 1 -or $values.Count -gt 32 -or
     @($values|Where-Object {$_ -isnot [string] -or $_.Length -lt 1 -or $_.Length -gt 4096}).Count) {
   throw 'Original native publication receipt is invalid'
  }
 }
 foreach($name in @('installedFeatures','originalPublishedTemplates')) {
  $values=if($name -ceq 'installedFeatures'){@($proof.baseline.installedFeatures)}else{@($proof.originalPublishedTemplates)}
  $maximum=if($name -ceq 'installedFeatures'){2048}else{512}
  if($values.Count -lt 1 -or $values.Count -gt $maximum -or
     @($values|Where-Object {$_ -isnot [string] -or $_.Length -lt 1 -or $_.Length -gt 256 -or $_ -match '[\x00-\x1f\x7f]'}).Count -or
     @($values|Sort-Object -Unique).Count -ne $values.Count) {
   throw 'Original native role or template inventory is invalid'
  }
 }
 if($proof.baseline.installedFeatures -notcontains 'ADCS-Cert-Authority' -or
    $proof.baseline.installedFeatures -contains 'Web-Server' -or
    $proof.baseline.installedFeatures -contains 'ADCS-Online-Cert' -or
    $proof.originalPublishedTemplates -ccontains $TemplateName) {
  throw 'Original OCSP role or template absence receipt mismatch'
 }
 return @{path=$receipt;directory=$directory;bytes=$bytes;ownership=$proof}
}

function Write-OwnedOcspPhase($Owner,[ValidateSet('roles-installed','responder-installed','template-intent','template-created','template-published','signer-intent','signer-key-created','signer-issued','signer-accept-intent','signer-accepted','configuration-intent','configured','publication-intent','publication-applied','publication-restored','template-restored','configuration-removed','responder-stop-intent','responder-stopped','iis-captured','iis-stopped','signer-removed','historical-revoke-intent','historical-revoked','revocation-refresh-intent','revocation-refreshed')][string]$Phase,$Facts) {
 # Every phase is immutable and exclusive. A failed/uncertain native operation
 # cannot be silently repeated by overwriting the evidence of its first try.
 Assert-OwnedOcspDirectory $Owner
 Initialize-OcspReceiptReader
 if([Convert]::ToBase64String([TTQualificationOcspReceipt]::Read($Owner.path)) -cne [Convert]::ToBase64String($Owner.bytes)) {
  throw 'Original OCSP ownership changed before native phase publication'
 }
 $path=Join-Path $Owner.directory ($Owner.ownership.baseline.issuingCaThumbprint+'-'+$Phase+'.json')
 $value=@{schemaVersion=1;runId=$Owner.ownership.runId;token=$Owner.ownership.token;phase=$Phase;facts=$Facts}
 $bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes(($value|ConvertTo-Json -Depth 12 -Compress))
 if($bytes.Length -lt 1 -or $bytes.Length -gt 65536) { throw 'Native OCSP phase exceeds bound' }
 $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try {
  [IO.File]::SetAccessControl($path,(New-OcspPrivateAcl $false))
  $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)
 } finally { $stream.Dispose() }
 if([Convert]::ToBase64String([TTQualificationOcspReceipt]::Read($path)) -cne [Convert]::ToBase64String($bytes)) {
  throw 'Native OCSP phase readback mismatch'
 }
 return @{path=$path;bytes=$bytes;phase=$value}
}

function Read-OwnedOcspPhase($Owner,[ValidateSet('roles-installed','responder-installed','template-intent','template-created','template-published','signer-intent','signer-key-created','signer-issued','signer-accept-intent','signer-accepted','configuration-intent','configured','publication-intent','publication-applied','publication-restored','template-restored','configuration-removed','responder-stop-intent','responder-stopped','iis-captured','iis-stopped','signer-removed','historical-revoke-intent','historical-revoked','revocation-refresh-intent','revocation-refreshed')][string]$Phase,[string[]]$FactFields) {
 Assert-OwnedOcspDirectory $Owner
 Initialize-OcspReceiptReader
 if([Convert]::ToBase64String([TTQualificationOcspReceipt]::Read($Owner.path)) -cne [Convert]::ToBase64String($Owner.bytes)) {
  throw 'Original native OCSP ownership changed'
 }
 $path=Join-Path $Owner.directory ($Owner.ownership.baseline.issuingCaThumbprint+'-'+$Phase+'.json')
 $bytes=[TTQualificationOcspReceipt]::Read($path)
 $value=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json -ErrorAction Stop
 Assert-OcspClosedObject $value @('schemaVersion','runId','token','phase','facts')
 Assert-OcspClosedObject $value.facts $FactFields
 if($value.schemaVersion -isnot [int] -or $value.schemaVersion -ne 1 -or $value.runId -cne $Owner.ownership.runId -or
    $value.token -cne $Owner.ownership.token -or $value.phase -cne $Phase) {
  throw 'Native OCSP phase ownership mismatch'
 }
 return @{path=$path;bytes=$bytes;phase=$value}
}

function Install-OwnedOcspRoles([string]$RunId,[string]$Token,[string]$ExpectedCaThumbprint,[string]$TemplateName) {
 $owner=Read-OwnedOcspOwnershipReceipt $RunId $Token $ExpectedCaThumbprint $TemplateName
 $mutex=[Threading.Mutex]::new($false,('Global\TokenTimerQualification-Ocsp-'+$ExpectedCaThumbprint))
 $held=$false
 try {
  try { $held=$mutex.WaitOne(0) }
  catch [Threading.AbandonedMutexException] {
   $held=$true
   throw 'Abandoned OCSP mutation requires explicit owned restoration'
  }
  if(!$held) { throw 'Another owned OCSP mutation remains active' }
  $fresh=Get-OcspResponderAdmission $TemplateName $ExpectedCaThumbprint
  if(@(Compare-Object @($owner.ownership.baseline.installedFeatures) @($fresh.installedFeatures)).Count) {
   throw 'Original role inventory changed before OCSP installation'
  }
  $phasePath=Join-Path $owner.directory ($ExpectedCaThumbprint+'-roles-installed.json')
  if(Test-Path -LiteralPath $phasePath) { throw 'Never repeat an installed OCSP role phase' }
  # The original absence/feature inventory is already durable. If this native
  # operation fails before a complete phase receipt, preserve the whole lab;
  # do not infer a safely removable partial role tree.
  # CA management cmdlets already belong to the original CA installation.
  # Do not add another management-tool bundle or later remove a shared one.
  $result=Install-WindowsFeature -Name @('ADCS-Online-Cert','Web-Server','Web-Http-Logging','Web-ISAPI-Ext','Web-Scripting-Tools') -ErrorAction Stop
  if(!$result.Success -or [string]$result.RestartNeeded -cne 'No') {
   throw 'Online Responder role installation incomplete or restart required'
  }
  $installed=@(Get-WindowsFeature -ErrorAction Stop|Where-Object Installed|ForEach-Object Name|Sort-Object)
  $original=@($owner.ownership.baseline.installedFeatures)
  if($installed.Count -gt 2048 -or $installed -notcontains 'ADCS-Online-Cert' -or
     $installed -notcontains 'Web-Server' -or @($original|Where-Object {$_ -notin $installed}).Count) {
   throw 'Native OCSP role installation inventory mismatch'
  }
  $added=@($installed|Where-Object {$_ -notin $original})
  if($added.Count -lt 1 -or
     @($added|Where-Object {$_ -cnotmatch '^(?:ADCS-Online-Cert|Web-[A-Za-z0-9-]+|WAS(?:-[A-Za-z0-9-]+)?)$'}).Count) {
   throw 'Unexpected native feature delta; preserve without adopting it'
  }
  [void](Write-OwnedOcspPhase $owner 'roles-installed' @{installedFeatures=$installed;newFeatures=$added})
  Install-AdcsOnlineResponder -Force -Confirm:$false -ErrorAction Stop|Out-Null
  $service=Get-OwnedOcspServiceIdentity
  $state=Get-Service -Name OCSPSvc -ErrorAction Stop
  $state.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(60))
  # Capture the running identity after native setup, not the possibly stopped
  # service's earlier ProcessId. Only this observed account receives key read.
  $running=Get-OwnedOcspServiceIdentity
  if($running.account -cne $service.account -or $running.path -cne $service.path -or $running.processId -lt 1) {
   throw 'Native responder setup identity mismatch'
  }
  [void](Write-OwnedOcspPhase $owner 'responder-installed' @{serviceIdentity=$running})
  return @{owner=$owner;serviceIdentity=$running;installedFeatures=$installed;newFeatures=$added}
 } finally {
  if($held) { $mutex.ReleaseMutex() }
  $mutex.Dispose()
 }
}

function New-OwnedOcspSigningTemplate($Owner) {
 $Owner=Read-OwnedOcspOwnershipReceipt $Owner.ownership.runId $Owner.ownership.token $Owner.ownership.baseline.issuingCaThumbprint $Owner.ownership.baseline.signingTemplateName
 $mutex=[Threading.Mutex]::new($false,('Global\TokenTimerQualification-Ocsp-'+$Owner.ownership.baseline.issuingCaThumbprint))
 $held=$false
 try {
 try { $held=$mutex.WaitOne(0) }
 catch [Threading.AbandonedMutexException] {
  $held=$true
  throw 'Abandoned OCSP template mutation requires owned restoration'
 }
 if(!$held) { throw 'Another owned OCSP mutation remains active' }
 # This is a signer-only fixture. It is never offered to the product issuer
 # preflight or general Domain Computers enrollment population.
 $name=[string]$Owner.ownership.baseline.signingTemplateName
 Assert-OcspFixtureIdentifier $name
 $domain=Get-ADDomain -ErrorAction Stop
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 $principal=[Security.Principal.WindowsPrincipal]::new($identity)
 $officer=Get-ADUser -Identity 'tt-lab-admin' -ErrorAction Stop
 if($domain.DNSRoot -ine 'lab.certops.test' -or $identity.User.Value -cne $officer.SID.Value -or
    $identity.User.Value -cne $Owner.ownership.baseline.ownerSid) {
  throw 'Original directory officer required for owned signing template'
 }
 foreach($rid in @(512,519)) {
  if(!$principal.IsInRole([Security.Principal.SecurityIdentifier]::new($domain.DomainSID.Value+'-'+$rid))) {
   throw 'Actual directory administration token required'
  }
 }
 $computer=Get-ADComputer -Identity 'tt-ca' -ErrorAction Stop
 if($computer.DNSHostName -ine 'tt-ca.lab.certops.test') { throw 'Exact responder machine SID required' }
 $configurationDn=[string]([ADSI]'LDAP://RootDSE').configurationNamingContext
 $services='CN=Public Key Services,CN=Services,'+$configurationDn
 $container=[ADSI]('LDAP://CN=Certificate Templates,'+$services)
 $oids=[ADSI]('LDAP://CN=OID,'+$services)
 $source=[ADSI]('LDAP://CN=OCSPResponseSigning,CN=Certificate Templates,'+$services)
 $targetDn='CN='+$name+',CN=Certificate Templates,'+$services
 $oidCn=([Guid]$Owner.ownership.token).ToString('N')
 $oidDn='CN='+$oidCn+',CN=OID,'+$services
 if([DirectoryServices.DirectoryEntry]::Exists('LDAP://'+$targetDn) -or
    [DirectoryServices.DirectoryEntry]::Exists('LDAP://'+$oidDn)) {
  throw 'Never adopt an existing signing template or template OID object'
 }
 $forestOid=[string]$oids.Properties['msPKI-Cert-Template-OID'].Value
 if($forestOid -cnotmatch '^1\.3\.6\.1\.4\.1\.311\.21\.8(?:\.[0-9]+)+$' -or
    [string]$source.Properties['cn'].Value -cne 'OCSPResponseSigning') {
  throw 'Original native OCSP signing-template source unavailable'
 }
 $oid=$forestOid+'.'+(Get-Random -Minimum 1000000 -Maximum 99999999)+'.'+(Get-Random -Minimum 1000000 -Maximum 99999999)
 $oidSearch=[DirectoryServices.DirectorySearcher]::new($oids)
 try {
  $oidSearch.Filter='(&(objectClass=msPKI-Enterprise-Oid)(msPKI-Cert-Template-OID='+$oid+'))'
  $oidSearch.SizeLimit=2
  $oidSearch.ServerTimeLimit=[TimeSpan]::FromSeconds(10)
  $oidSearch.ClientTimeout=[TimeSpan]::FromSeconds(10)
  $existing=$oidSearch.FindAll()
  try { if($existing.Count -ne 0) { throw 'Never reuse a published template OID value' } }
  finally { $existing.Dispose() }
 } finally { $oidSearch.Dispose() }
 [void](Write-OwnedOcspPhase $Owner 'template-intent' @{
  templateDn=$targetDn;oidDn=$oidDn;templateOid=$oid
  sourceGuid=([Guid]$source.Guid).ToString('D')
  responderMachineSid=$computer.SID.Value
 })
 # Unknown interruption after either creation deliberately leaves the durable
 # intent unresolved. Restoration cannot guess or adopt an object by CN alone.
 $oidObject=$oids.Create('msPKI-Enterprise-Oid',('CN='+$oidCn))
 $oidObject.Put('msPKI-Cert-Template-OID',$oid)
 $oidObject.Put('displayName',$name)
 $oidObject.Put('flags',1)
 $oidObject.SetInfo()
 $oidObject.Options.SecurityMasks=[DirectoryServices.SecurityMasks]::Dacl
 $oidObject.RefreshCache()
 $oidDacl=$oidObject.ObjectSecurity.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
 $oidSearch=[DirectoryServices.DirectorySearcher]::new($oids)
 try {
  $oidSearch.Filter='(&(objectClass=msPKI-Enterprise-Oid)(msPKI-Cert-Template-OID='+$oid+'))'
  $oidSearch.SizeLimit=2
  $oidSearch.ServerTimeLimit=[TimeSpan]::FromSeconds(10)
  $oidSearch.ClientTimeout=[TimeSpan]::FromSeconds(10)
  $created=$oidSearch.FindAll()
  try {
   if($created.Count -ne 1 -or
      ([Guid]::new([byte[]]$created[0].Properties['objectguid'][0])) -ne [Guid]$oidObject.Guid) {
    throw 'New template OID identity is not unique'
   }
  } finally { $created.Dispose() }
 } finally { $oidSearch.Dispose() }
 $template=$container.Create('pKICertificateTemplate',('CN='+$name))
 foreach($attribute in @('flags','pKIExpirationPeriod','pKIOverlapPeriod')) {
  $template.Put($attribute,$source.Properties[$attribute].Value)
 }
 $values=@{
  displayName=$name;revision=100;pKIDefaultKeySpec=1;pKIMaxIssuingDepth=0
  # MS-CRTD 2.26: ADD_OCSP_NOCHECK is 0x1000. 0x4000 only suppresses
  # revocation information and does not request the signer no-check extension.
  'msPKI-RA-Signature'=0;'msPKI-Enrollment-Flag'=0x1000
  'msPKI-Private-Key-Flag'=0;'msPKI-Certificate-Name-Flag'=1
  'msPKI-Minimal-Key-Size'=2048;'msPKI-Template-Schema-Version'=3
  'msPKI-Template-Minor-Revision'=1;'msPKI-Cert-Template-OID'=$oid
 }
 foreach($attribute in $values.Keys) { $template.Put($attribute,$values[$attribute]) }
 $template.Put('pKIKeyUsage',[byte[]](0x80,0x00))
 $template.Put('pKICriticalExtensions',[object[]]@('2.5.29.15'))
 $template.Put('pKIExtendedKeyUsage',[object[]]@('1.3.6.1.5.5.7.3.9'))
 $template.Put('msPKI-Certificate-Application-Policy',[object[]]@('1.3.6.1.5.5.7.3.9'))
 $template.Put('pKIDefaultCSPs',[object[]]@('1,Microsoft Software Key Storage Provider'))
 $template.Put('msPKI-RA-Application-Policies',"msPKI-Asymmetric-Algorithm``PZPWSTR``RSA``msPKI-Hash-Algorithm``PZPWSTR``SHA256``msPKI-Key-Usage``DWORD``16777215``msPKI-Symmetric-Algorithm``PZPWSTR``3DES``msPKI-Symmetric-Key-Length``DWORD``168``")
 $template.SetInfo()
 $security=[DirectoryServices.ActiveDirectorySecurity]::new()
 $security.SetAccessRuleProtection($true,$false)
 foreach($sid in @($identity.User.Value,'S-1-5-18',($domain.DomainSID.Value+'-512'),($domain.DomainSID.Value+'-519'))) {
  $security.AddAccessRule([DirectoryServices.ActiveDirectoryAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'GenericAll','Allow'))
 }
 $security.AddAccessRule([DirectoryServices.ActiveDirectoryAccessRule]::new($computer.SID,'GenericRead','Allow'))
 $security.AddAccessRule([DirectoryServices.ActiveDirectoryAccessRule]::new($computer.SID,'ExtendedRight','Allow',[Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'))
 $template.Options.SecurityMasks=[DirectoryServices.SecurityMasks]::Dacl
 $template.ObjectSecurity=$security
 $template.CommitChanges()
 $template.RefreshCache()
 $actualDacl=$template.ObjectSecurity.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
 $expectedDacl=$security.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
 if($actualDacl -cne $expectedDacl -or
    [string]$template.Properties['msPKI-Cert-Template-OID'].Value -cne $oid) {
  throw 'Owned signer-only template readback mismatch'
 }
 $facts=@{
  templateDn=$targetDn;templateGuid=([Guid]$template.Guid).ToString('D');templateOid=$oid
  oidDn=$oidDn;oidGuid=([Guid]$oidObject.Guid).ToString('D');templateDacl=$actualDacl;oidDacl=$oidDacl
  responderMachineSid=$computer.SID.Value
 }
 [void](Write-OwnedOcspPhase $Owner 'template-created' $facts)
 return $facts
 } finally {
  if($held) { $mutex.ReleaseMutex() }
  $mutex.Dispose()
 }
}

function Publish-OwnedOcspSigningTemplate($Owner) {
 $Owner=Read-OwnedOcspOwnershipReceipt $Owner.ownership.runId $Owner.ownership.token $Owner.ownership.baseline.issuingCaThumbprint $Owner.ownership.baseline.signingTemplateName
 $created=Read-OwnedOcspPhase $Owner 'template-created' @('templateDn','templateGuid','templateOid','oidDn','oidGuid','templateDacl','oidDacl','responderMachineSid')
 $mutex=[Threading.Mutex]::new($false,('Global\TokenTimerQualification-Ocsp-'+$Owner.ownership.baseline.issuingCaThumbprint))
 $held=$false
 try {
  try { $held=$mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] {
   $held=$true
   throw 'Abandoned OCSP owner requires explicit restoration'
  }
  if(!$held) { throw 'Another owned OCSP mutation is active' }
  $template=[ADSI]('LDAP://'+$created.phase.facts.templateDn)
  $template.Options.SecurityMasks=[DirectoryServices.SecurityMasks]::Dacl
  $template.RefreshCache()
  if(([Guid]$template.Guid).ToString('D') -cne $created.phase.facts.templateGuid -or
     [string]$template.Properties['msPKI-Cert-Template-OID'].Value -cne $created.phase.facts.templateOid -or
     $template.ObjectSecurity.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access) -cne $created.phase.facts.templateDacl) {
   throw 'Owned signing template changed before publication'
  }
  $root=[ADSI]'LDAP://RootDSE'
  $service=[ADSI]('LDAP://CN=TTQualificationRoot,CN=Enrollment Services,CN=Public Key Services,CN=Services,'+[string]$root.configurationNamingContext)
  $service.RefreshCache()
  if(([Guid]$service.Guid).ToString('D') -cne $Owner.ownership.enrollmentServiceGuid) {
   throw 'Original CA enrollment service identity changed'
  }
  $before=@($service.Properties['certificateTemplates'] | ForEach-Object { [string]$_ } | Sort-Object)
  $original=@($Owner.ownership.originalPublishedTemplates | Sort-Object)
  if(!(Test-OcspExactValues $before $original)) {
   throw 'Original published template inventory changed'
  }
  $pin=Open-OwnedOcspCaRegistry $Owner $false
  $pin.Dispose()
  Import-Module ADCSAdministration -ErrorAction Stop
  # The role cmdlet adds exactly the new signer template. Never replace the
  # complete publication list, which would erase a concurrent foreign change.
  Add-CATemplate -Name $Owner.ownership.baseline.signingTemplateName -Force -ErrorAction Stop | Out-Null
  $service.RefreshCache()
  $after=@($service.Properties['certificateTemplates'] | ForEach-Object { [string]$_ } | Sort-Object)
  $expected=@(@($original)+@($Owner.ownership.baseline.signingTemplateName) | Sort-Object)
  if(!(Test-OcspExactValues $after $expected)) {
   throw 'Exact owned signing template publication readback failed'
  }
  $facts=@{enrollmentServiceGuid=$Owner.ownership.enrollmentServiceGuid;publishedTemplates=$after;templateGuid=$created.phase.facts.templateGuid}
  [void](Write-OwnedOcspPhase $Owner 'template-published' $facts)
  return $facts
 } finally {
  if($held) { $mutex.ReleaseMutex() }
  $mutex.Dispose()
 }
}

function Restore-OwnedOcspSigningTemplate($Owner) {
 $Owner=Read-OwnedOcspOwnershipReceipt $Owner.ownership.runId $Owner.ownership.token $Owner.ownership.baseline.issuingCaThumbprint $Owner.ownership.baseline.signingTemplateName
 $created=Read-OwnedOcspPhase $Owner 'template-created' @('templateDn','templateGuid','templateOid','oidDn','oidGuid','templateDacl','oidDacl','responderMachineSid')
 $facts=$created.phase.facts
 $mutex=[Threading.Mutex]::new($false,('Global\TokenTimerQualification-Ocsp-'+$Owner.ownership.baseline.issuingCaThumbprint))
 $held=$false
 try {
  try { $held=$mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $held=$true }
  if(!$held) { throw 'Another owned OCSP mutation is active' }
  $pin=Open-OwnedOcspCaRegistry $Owner $false
  $pin.Dispose()
  $root=[ADSI]'LDAP://RootDSE'
  $service=[ADSI]('LDAP://CN=TTQualificationRoot,CN=Enrollment Services,CN=Public Key Services,CN=Services,'+[string]$root.configurationNamingContext)
  $service.RefreshCache()
  if(([Guid]$service.Guid).ToString('D') -cne $Owner.ownership.enrollmentServiceGuid) {
   throw 'Original CA enrollment service changed before template restoration'
  }
  $actual=@($service.Properties['certificateTemplates'] | ForEach-Object { [string]$_ } | Sort-Object)
  $original=@($Owner.ownership.originalPublishedTemplates | Sort-Object)
  $applied=@(@($original)+@($Owner.ownership.baseline.signingTemplateName) | Sort-Object)
  if(!(Test-OcspExactValues $actual $original) -and !(Test-OcspExactValues $actual $applied)) {
   throw 'Foreign published template change prevents exact restoration'
  }
  # Check BOTH exact AD objects before the first removal. A matching name or
  # OID alone never establishes ownership of a replacement directory object.
  $template=[ADSI]('LDAP://'+$facts.templateDn)
  $template.Options.SecurityMasks=[DirectoryServices.SecurityMasks]::Dacl
  $template.RefreshCache()
  $oid=[ADSI]('LDAP://'+$facts.oidDn)
  $oid.Options.SecurityMasks=[DirectoryServices.SecurityMasks]::Dacl
  $oid.RefreshCache()
  if(([Guid]$template.Guid).ToString('D') -cne $facts.templateGuid -or
     [string]$template.Properties['msPKI-Cert-Template-OID'].Value -cne $facts.templateOid -or
     $template.ObjectSecurity.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access) -cne $facts.templateDacl -or
     ([Guid]$oid.Guid).ToString('D') -cne $facts.oidGuid -or
     [string]$oid.Properties['msPKI-Cert-Template-OID'].Value -cne $facts.templateOid -or
     $oid.ObjectSecurity.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access) -cne $facts.oidDacl -or
     @($template.Children).Count -ne 0 -or @($oid.Children).Count -ne 0) {
   throw 'Owned signer template or OID changed before removal'
  }
  if(Test-OcspExactValues $actual $applied) {
   Import-Module ADCSAdministration -ErrorAction Stop
   Remove-CATemplate -Name $Owner.ownership.baseline.signingTemplateName -Force -ErrorAction Stop | Out-Null
  }
  $service.RefreshCache()
  $restored=@($service.Properties['certificateTemplates'] | ForEach-Object { [string]$_ } | Sort-Object)
  if(!(Test-OcspExactValues $restored $original)) {
   throw 'Original published template inventory restoration failed'
  }
  $templateParent=$template.psbase.Parent
  try { $templateParent.Children.Remove($template) } finally { $templateParent.Dispose() }
  if([DirectoryServices.DirectoryEntry]::Exists('LDAP://'+$facts.templateDn)) {
   throw 'Owned signer template absence unproven'
  }
  $oidParent=$oid.psbase.Parent
  try { $oidParent.Children.Remove($oid) } finally { $oidParent.Dispose() }
  if([DirectoryServices.DirectoryEntry]::Exists('LDAP://'+$facts.oidDn)) {
   throw 'Owned signer OID absence unproven'
  }
  $completion=@{
   originalPublishedTemplatesRestored=$true;ownedTemplateAbsent=$true;ownedOidAbsent=$true
  }
  [void](Write-OwnedOcspPhase $Owner 'template-restored' $completion)
  return $completion
 } finally {
  if($held) { $mutex.ReleaseMutex() }
  $mutex.Dispose()
 }
}

function Get-OwnedOcspSignerRequest($Owner,[string]$CertificateSha256) {
 if($CertificateSha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'Exact signer certificate digest required' }
 $subject='certops-adcs-'+$Owner.ownership.runId+'-ocspsigner.example.test'
 $view=$null
 try {
  $view=New-Object -ComObject CertificateAuthority.View
  [void]$view.OpenConnection('tt-ca.lab.certops.test\TTQualificationRoot')
  $columns=@()
  foreach($aliases in @(
   @('RequestID'),@('CommonName'),@('RequesterName'),
   @('Request.Disposition','Disposition'),@('RawCertificate')
  )) {
   $indices=[Collections.Generic.HashSet[int]]::new()
   foreach($alias in $aliases) {
    try {
     $index=[int]$view.GetColumnIndex($false,[string]$alias)
     if($index -ge 0) { [void]$indices.Add($index) }
    } catch { }
   }
   if($indices.Count -ne 1) { throw 'Unique native signer request column required' }
   $columns+=@($indices)[0]
  }
  $view.SetResultColumnCount(5)
  foreach($index in $columns) { $view.SetResultColumn($index) }
  $view.SetRestriction($columns[1],1,0,$subject)
  $rows=$view.OpenView()
  if($rows.Next() -eq -1) { throw 'Actual signer CA request row missing' }
  $enumerator=$rows.EnumCertViewColumn()
  $values=@()
  while($enumerator.Next() -ne -1) {
   $encoding=if($values.Count -eq 4){1}else{0}
   $values+=,$enumerator.GetValue($encoding)
   if($values.Count -gt 5) { throw 'Malformed native signer request row' }
  }
  if($values.Count -ne 5 -or [string]$values[1] -cne $subject -or
     [string]$values[2] -ine 'TTQUAL\tt-lab-admin' -or [int]$values[3] -ne 20 -or
     [long]$values[0] -lt 1 -or [long]$values[0] -gt 4294967295 -or
     $values[4] -isnot [string] -or $values[4].Length -gt 32768) {
   throw 'Exact issued signer CA request identity mismatch'
  }
  $der=[Convert]::FromBase64String($values[4])
  if((Get-OcspPublicDigest $der) -cne $CertificateSha256 -or $rows.Next() -ne -1) {
   throw 'Actual signer CA leaf/request association mismatch'
  }
  return [long]$values[0]
 } finally {
  if($view -and [Runtime.InteropServices.Marshal]::IsComObject($view)) {
   [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
  }
 }
}

function Request-OwnedOcspSigner($Owner) {
 $Owner=Read-OwnedOcspOwnershipReceipt $Owner.ownership.runId $Owner.ownership.token $Owner.ownership.baseline.issuingCaThumbprint $Owner.ownership.baseline.signingTemplateName
 $published=Read-OwnedOcspPhase $Owner 'template-published' @('enrollmentServiceGuid','publishedTemplates','templateGuid')
 if($published.phase.facts.enrollmentServiceGuid -cne $Owner.ownership.enrollmentServiceGuid -or
    @($published.phase.facts.publishedTemplates) -cnotcontains $Owner.ownership.baseline.signingTemplateName) {
  throw 'Exact owned signing template publication required'
 }
 $subject='certops-adcs-'+$Owner.ownership.runId+'-ocspsigner.example.test'
 # Original ownership already names this canonical container. This exclusive
 # phase makes any partial key creation/submission non-repeatable: restoration
 # must inspect its exact native identity instead of submitting a second CSR.
 [void](Write-OwnedOcspPhase $Owner 'signer-intent' @{container=$Owner.ownership.plannedContainer;subject=$subject})
 $owned=$null;$request=$null;$certificate=$null;$chain=$null;$response=$null
 try {
  $owned=New-OwnedOcspKey $Owner.ownership.plannedContainer
  [void](Write-OwnedOcspPhase $Owner 'signer-key-created' @{
   keyIdentity=$owned.identity;originalDacl=[Convert]::ToBase64String($owned.originalDacl)
  })
  $input=Write-OwnedOcspRequestInput $Owner 'signer.inf' (New-OwnedOcspSignerRequestText $Owner.ownership.plannedContainer $subject)
  $requestPath=Join-Path $Owner.directory 'signer.req'
  $certificatePath=Join-Path $Owner.directory 'signer.cer'
  $chainPath=Join-Path $Owner.directory 'signer-chain.p7b'
  $responsePath=Join-Path $Owner.directory 'signer-response.rsp'
  $request=[TTQualificationOcspReceipt+Output]::new($requestPath,(New-OcspPrivateAcl $false))
  $certificate=[TTQualificationOcspReceipt+Output]::new($certificatePath,(New-OcspPrivateAcl $false))
  $chain=[TTQualificationOcspReceipt+Output]::new($chainPath,(New-OcspPrivateAcl $false))
  $response=[TTQualificationOcspReceipt+Output]::new($responsePath,(New-OcspPrivateAcl $false))
  [void](Invoke-OcspContainedCommand 'certreq.exe' @('-q','-f','-new',$input,$requestPath) $Owner.directory 120)
  $csr=$request.ReadCompleted()
  Assert-OwnedOcspKeyIdentity $owned.key $owned.identity
  $pin=Open-OwnedOcspCaRegistry $Owner $false
  $pin.Dispose()
  # Public CSR submission deliberately uses the actual provisioned officer,
  # whose signer-only template rights were established above. -machine belongs
  # to existing-key generation/acceptance, not to the RPC submission identity.
  $requestPin=[TTQualificationOcspReceipt]::PinRead($requestPath)
  try {
   if([Convert]::ToBase64String($request.ReadCompleted()) -cne [Convert]::ToBase64String($csr)) {
    throw 'Original signer CSR changed before submission'
   }
   [void](Invoke-OcspContainedCommand 'certreq.exe' @(
    '-q','-f','-submit','-config','tt-ca.lab.certops.test\TTQualificationRoot',
    '-attrib',('CertificateTemplate:'+$Owner.ownership.baseline.signingTemplateName),
    $requestPath,$certificatePath,$chainPath,$responsePath
   ) $Owner.directory 180)
  } finally { $requestPin.Dispose() }
  $bytes=$certificate.ReadCompleted()
  $issued=[Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
  try {
   if($issued.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) -cne $subject -or
      $issued.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or
      $issued.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow.AddHours(1)) {
    throw 'Actual owned signer certificate identity or validity mismatch'
   }
   $rsa=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($issued)
   try {
    if(!$rsa -or $rsa.KeySize -ne 2048) { throw 'Actual signer RSA2048 public key required' }
    $public=$rsa.ExportParameters($false)
    if([Convert]::ToBase64String($public.Modulus) -cne $owned.identity.modulus -or
       [Convert]::ToBase64String($public.Exponent) -cne $owned.identity.exponent) {
     throw 'Actual signer certificate does not match the original owned key'
    }
   } finally { if($rsa) { $rsa.Dispose() } }
   Assert-OwnedOcspKeyIdentity $owned.key $owned.identity
   $digest=[Security.Cryptography.SHA256]::Create()
   try { $requestDigest=[Convert]::ToBase64String($digest.ComputeHash($csr)) }
   finally { $digest.Dispose() }
   $facts=@{
    certificateSha256=(Get-OcspPublicDigest $issued.RawData)
    fingerprint=$issued.Thumbprint;subject=$subject;keyIdentity=$owned.identity
    requestSha256=$requestDigest
    nativeRequestId=(Get-OwnedOcspSignerRequest $Owner (Get-OcspPublicDigest $issued.RawData))
   }
   [void](Write-OwnedOcspPhase $Owner 'signer-issued' $facts)
   # This is issued public material only. Acceptance, service access and OCSP
   # configuration remain forbidden until the caller independently validates
   # its actual CA signature, OCSP-only EKU/KU and mandatory no-check extension.
   return @{facts=$facts;certificateBase64=[Convert]::ToBase64String($issued.RawData)}
  } finally { $issued.Dispose() }
 } finally {
  foreach($resource in @($request,$certificate,$chain,$response)) {
   if($resource) { $resource.Dispose() }
  }
  if($owned) { $owned.key.Dispose() }
 }
}

function Accept-OwnedOcspSigner($Owner,[string]$VerifiedCertificateSha256) {
 if($VerifiedCertificateSha256 -cnotmatch '^[a-f0-9]{64}$') {
  throw 'Independently verified signer DER digest required'
 }
 $Owner=Read-OwnedOcspOwnershipReceipt $Owner.ownership.runId $Owner.ownership.token $Owner.ownership.baseline.issuingCaThumbprint $Owner.ownership.baseline.signingTemplateName
 $issued=Read-OwnedOcspPhase $Owner 'signer-issued' @('certificateSha256','fingerprint','subject','keyIdentity','requestSha256','nativeRequestId')
 $keyReceipt=Read-OwnedOcspPhase $Owner 'signer-key-created' @('keyIdentity','originalDacl')
 if($issued.phase.facts.certificateSha256 -cne $VerifiedCertificateSha256) {
  throw 'Independent signer verification does not bind issued certificate'
 }
 $path=Join-Path $Owner.directory 'signer.cer'
 $certificatePin=[TTQualificationOcspReceipt]::PinRead($path)
 try {
 $bytes=[TTQualificationOcspReceipt]::Read($path)
 if((Get-OcspPublicDigest $bytes) -cne $VerifiedCertificateSha256) {
  throw 'Issued signer DER changed before machine acceptance'
 }
 $fingerprint=[string]$issued.phase.facts.fingerprint
 if($fingerprint -cnotmatch '^[A-F0-9]{40}$' -or
    (Test-Path -LiteralPath ('Cert:\LocalMachine\My\'+$fingerprint))) {
  throw 'Never adopt an existing signer certificate entry'
 }
 $key=[Security.Cryptography.CngKey]::Open($Owner.ownership.plannedContainer,[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)
 try {
  Assert-OwnedOcspKeyIdentity $key $keyReceipt.phase.facts.keyIdentity
  foreach($name in @('container','unique','provider','modulus','exponent')) {
   if($issued.phase.facts.keyIdentity.$name -cne $keyReceipt.phase.facts.keyIdentity.$name) {
    throw 'Original signer key receipts disagree'
   }
  }
  $service=Get-OwnedOcspServiceIdentity
  if($service.processId -lt 1) { throw 'Actual running responder required before signer acceptance' }
  [void](Write-OwnedOcspPhase $Owner 'signer-accept-intent' @{
   certificateSha256=$VerifiedCertificateSha256;fingerprint=$fingerprint;serviceIdentity=$service
  })
  [void](Invoke-OcspContainedCommand 'certreq.exe' @('-q','-machine','-accept',$path) $Owner.directory 120)
  $installed=Get-Item -LiteralPath ('Cert:\LocalMachine\My\'+$fingerprint) -ErrorAction Stop
  try {
   if(!$installed.HasPrivateKey -or (Get-OcspPublicDigest $installed.RawData) -cne $VerifiedCertificateSha256) {
    throw 'Exact signer certificate machine association missing'
   }
   $private=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($installed)
   try {
    if($private -isnot [Security.Cryptography.RSACng]) { throw 'Native signer requires original CNG private association' }
    Assert-OwnedOcspKeyIdentity $private.Key $keyReceipt.phase.facts.keyIdentity
   } finally { if($private) { $private.Dispose() } }
  } finally { $installed.Dispose() }
  $original=[Convert]::FromBase64String($keyReceipt.phase.facts.originalDacl)
  $applied=Grant-OwnedOcspServiceRead $key $keyReceipt.phase.facts.keyIdentity $original $service
  $facts=@{
   certificateSha256=$VerifiedCertificateSha256;fingerprint=$fingerprint;serviceIdentity=$service
   appliedDacl=[Convert]::ToBase64String($applied)
  }
  [void](Write-OwnedOcspPhase $Owner 'signer-accepted' $facts)
  return $facts
 } finally { $key.Dispose() }
 } finally { $certificatePin.Dispose() }
}

function Write-OwnedOcspRequestInput($Owner,[string]$Name,[string]$Text) {
 if($Name -cne 'signer.inf' -or !$Text -or $Text.Length -gt 8192) {
  throw 'Bounded fixed OCSP signer request input required'
 }
 Assert-OwnedOcspDirectory $Owner
 $path=Join-Path $Owner.directory $Name
 $bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes($Text)
 $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try {
  [IO.File]::SetAccessControl($path,(New-OcspPrivateAcl $false))
  $stream.Write($bytes,0,$bytes.Length)
  $stream.Flush($true)
 } finally { $stream.Dispose() }
 if([Convert]::ToBase64String([TTQualificationOcspReceipt]::Read($path)) -cne [Convert]::ToBase64String($bytes)) {
  throw 'Owned signer input readback failed'
 }
 return $path
}

function Invoke-OwnedOcspPinnedOperation($Owner,[scriptblock]$Operation) {
 # This is an in-process boundary for the fixed operation dispatcher, never a
 # serialized handle or a caller-supplied remote command. Holding the directory
 # without delete sharing prevents namespace replacement across native writes.
 if($null -eq $Operation) { throw 'Fixed owned OCSP operation required' }
 Assert-OwnedOcspDirectory $Owner
 Initialize-OcspReceiptReader
 $pin=[TTQualificationOcspReceipt]::PinDirectory($Owner.directory,$Owner.ownership.directoryIdentity)
 try {
  Assert-OwnedOcspDirectory $Owner
  if([Convert]::ToBase64String([TTQualificationOcspReceipt]::Read($Owner.path)) -cne
     [Convert]::ToBase64String($Owner.bytes)) {
   throw 'Original OCSP receipt changed before pinned operation'
  }
  # Do not publish a successful result until the post-operation identity and
  # immutable receipt checks have also completed.
  $result=& $Operation $Owner
  Assert-OwnedOcspDirectory $Owner
  if([Convert]::ToBase64String([TTQualificationOcspReceipt]::Read($Owner.path)) -cne
     [Convert]::ToBase64String($Owner.bytes)) {
   throw 'Original OCSP receipt changed during pinned operation'
  }
  return $result
 } finally { $pin.Dispose() }
}

function Write-OwnedOcspPublicTool($Owner,[string]$Name,[byte[]]$Bytes,[string]$ExpectedSha256) {
 # Only candidate tools needed by the fixed remote dispatcher may cross this
 # boundary. No officer credential, private key, arbitrary path or executable
 # argument is accepted. The private directory is pinned for the entire write.
 $allowed=@('chain-helper.exe','ocsp-native-survivors.ps1','certops-windows-contained-process.ps1','certops-windows-owned-process.ps1')
 if($Name -cnotin $allowed -or $ExpectedSha256 -cnotmatch '^[a-f0-9]{64}$' -or
    !$Bytes -or $Bytes.Length -lt 1 -or $Bytes.Length -gt 6291456 -or
    ($Name -cne 'chain-helper.exe' -and $Bytes.Length -gt 65536)) {
  throw 'Bounded exact candidate OCSP tool required'
 }
 $hash=[Security.Cryptography.SHA256]::Create()
 try {
  $actual=[BitConverter]::ToString($hash.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant()
 } finally { $hash.Dispose() }
 if($actual -cne $ExpectedSha256) { throw 'Candidate OCSP tool digest mismatch' }
 Invoke-OwnedOcspPinnedOperation $Owner {
  param($PinnedOwner)
  $path=Join-Path $PinnedOwner.directory $Name
  # CreateNew refuses every existing object. Applying the ACL to the retained
  # new stream avoids a path-based security-descriptor replacement race.
  $stream=[IO.FileStream]::new($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
  try {
   $stream.SetAccessControl((New-OcspPrivateAcl $false))
   $stream.Write($Bytes,0,$Bytes.Length)
   $stream.Flush($true)
   if($stream.Length -ne $Bytes.Length) { throw 'Candidate OCSP tool write length mismatch' }
   $stream.Position=0
   $readHash=[Security.Cryptography.SHA256]::Create()
   try {
    $readback=[BitConverter]::ToString($readHash.ComputeHash($stream)).Replace('-','').ToLowerInvariant()
   } finally { $readHash.Dispose() }
   if($stream.Length -ne $Bytes.Length -or $readback -cne $ExpectedSha256) {
    throw 'Candidate OCSP tool retained-handle readback mismatch'
   }
   return @{name=$Name;sha256=$readback;bytes=$Bytes.Length}
  } finally { $stream.Dispose() }
 }
}

function Get-OcspPublicDigest([byte[]]$Bytes) {
 if(!$Bytes -or $Bytes.Length -lt 100 -or $Bytes.Length -gt 1048576) {
  throw 'Bounded public native certificate or CRL bytes required'
 }
 $hash=[Security.Cryptography.SHA256]::Create()
 try { return [BitConverter]::ToString($hash.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant() }
 finally { $hash.Dispose() }
}

function Open-OwnedOcspCaRegistry($Owner,[bool]$Writable) {
 $base='SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
 $root=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($base,$false)
 if(!$root) { throw 'Original issuing CA configuration missing' }
 try {
  if([string]$root.GetValue('Active') -cne 'TTQualificationRoot') { throw 'Original active issuing CA changed' }
 } finally { $root.Dispose() }
 $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(($base+'\TTQualificationRoot'),$Writable)
 if(!$key) { throw 'Original issuing CA key missing' }
 try {
  $hashes=@($key.GetValue('CACertHash'))
  $thumb=[string]$Owner.ownership.baseline.issuingCaThumbprint
  if($hashes.Count -ne 1 -or ([string]$hashes[0]).Replace(' ','').ToUpperInvariant() -cne $thumb) {
   throw 'Original issuing CA generation changed'
  }
  $certificate=Get-Item -LiteralPath ('Cert:\LocalMachine\My\'+$thumb) -ErrorAction Stop
  try {
   if(!$certificate.HasPrivateKey -or $certificate.Thumbprint -cne $thumb -or
      (Get-OcspPublicDigest $certificate.RawData) -cne $Owner.ownership.baseline.caDerSha256) {
    throw 'Original issuing CA certificate changed'
   }
  } finally { $certificate.Dispose() }
  return $key
 } catch { $key.Dispose();throw }
}

function Get-OwnedOcspPublication($Key) {
 $result=@{}
 foreach($name in @('CRLPublicationURLs','CACertPublicationURLs')) {
  if($Key.GetValueKind($name) -ne [Microsoft.Win32.RegistryValueKind]::MultiString) {
   throw 'Original CA publication value kind changed'
  }
  $values=[string[]]$Key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
  if($values.Count -lt 1 -or $values.Count -gt 32 -or
     @($values|Where-Object {$_.Length -lt 1 -or $_.Length -gt 4096}).Count) {
   throw 'Bounded actual CA publication required'
  }
  $result[$name]=@($values)
 }
 return $result
}

function Test-OcspExactValues([string[]]$First,[string[]]$Second) {
 if($First.Count -ne $Second.Count) { return $false }
 for($index=0;$index -lt $First.Count;$index++) {
  if($First[$index] -cne $Second[$index]) { return $false }
 }
 return $true
}

function Restart-OwnedOcspIssuingCa($Owner) {
 $key=Open-OwnedOcspCaRegistry $Owner $false
 $key.Dispose()
 Restart-Service CertSvc -ErrorAction Stop
 (Get-Service CertSvc -ErrorAction Stop).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(60))
 [void](Invoke-OcspContainedCommand 'certutil.exe' @('-config','tt-ca.lab.certops.test\TTQualificationRoot','-ping') $Owner.directory 60)
 [void](Invoke-OcspContainedCommand 'certutil.exe' @('-crl') $Owner.directory 120)
 $key=Open-OwnedOcspCaRegistry $Owner $false
 $key.Dispose()
}

function Set-OwnedOcspOnlyPublication($Owner) {
 $Owner=Read-OwnedOcspOwnershipReceipt $Owner.ownership.runId $Owner.ownership.token $Owner.ownership.baseline.issuingCaThumbprint $Owner.ownership.baseline.signingTemplateName
 $mutex=[Threading.Mutex]::new($false,('Global\TokenTimerQualification-Ocsp-'+$Owner.ownership.baseline.issuingCaThumbprint))
 $held=$false;$key=$null
 try {
  try { $held=$mutex.WaitOne(0) }
  catch [Threading.AbandonedMutexException] {
   $held=$true
   throw 'Abandoned OCSP publication mutation requires owned restoration'
  }
  if(!$held) { throw 'Another owned OCSP mutation remains active' }
  $key=Open-OwnedOcspCaRegistry $Owner $true
  $before=Get-OwnedOcspPublication $key
  foreach($name in @('CRLPublicationURLs','CACertPublicationURLs')) {
   if(!(Test-OcspExactValues $before[$name] ([string[]]$Owner.ownership.originalPublication.$name))) {
    throw 'Original CA publication changed before owned OCSP fixture'
   }
  }
  Import-Module ADCSAdministration -ErrorAction Stop
  $existing=@(Get-CAAuthorityInformationAccess -ErrorAction Stop|Where-Object AddToCertificateOcsp)
  if($existing.Count -ne 0) { throw 'Never adopt an existing OCSP authority URL' }
  $url='http://10.64.0.4/ocsp'
  $crl=[string[]]@('1:'+$env:SystemRoot+'\System32\CertSrv\CertEnroll\%3%8%9.crl')
  [void](Write-OwnedOcspPhase $Owner 'publication-intent' @{ocspUrl=$url;appliedCrlPublication=$crl})
  # Keep genuine local base-CRL publication for the responder, but include no
  # CRL or delta-CRL retrieval URL in the new leaf. Native DER must prove this.
  $key.SetValue('CRLPublicationURLs',$crl,[Microsoft.Win32.RegistryValueKind]::MultiString)
  Add-CAAuthorityInformationAccess -Uri $url -AddToCertificateOcsp -Force -Confirm:$false -ErrorAction Stop|Out-Null
  $after=Get-OwnedOcspPublication $key
  $actual=@(Get-CAAuthorityInformationAccess -ErrorAction Stop|Where-Object AddToCertificateOcsp)
  if(!(Test-OcspExactValues $after.CRLPublicationURLs $crl) -or $actual.Count -ne 1 -or
     [string]$actual[0].Uri -cne $url -or $actual[0].AddToCertificateAia -or
     $after.CACertPublicationURLs.Count -ne ($before.CACertPublicationURLs.Count+1) -or
     @($before.CACertPublicationURLs|Where-Object {$_ -cnotin $after.CACertPublicationURLs}).Count) {
   throw 'Actual OCSP-only publication readback mismatch'
  }
  $key.Flush()
  [void](Write-OwnedOcspPhase $Owner 'publication-applied' @{ocspUrl=$url;appliedPublication=$after})
  $key.Dispose();$key=$null
  Restart-OwnedOcspIssuingCa $Owner
  return @{ocspUrl=$url;appliedPublication=$after}
 } finally {
  if($null -ne $key) { $key.Dispose() }
  if($held) { $mutex.ReleaseMutex() }
  $mutex.Dispose()
 }
}

function Restore-OwnedOcspPublication($Owner) {
 $Owner=Read-OwnedOcspOwnershipReceipt $Owner.ownership.runId $Owner.ownership.token $Owner.ownership.baseline.issuingCaThumbprint $Owner.ownership.baseline.signingTemplateName
 $applied=Read-OwnedOcspPhase $Owner 'publication-applied' @('ocspUrl','appliedPublication')
 Assert-OcspClosedObject $applied.phase.facts.appliedPublication @('CRLPublicationURLs','CACertPublicationURLs')
 if($applied.phase.facts.ocspUrl -cne 'http://10.64.0.4/ocsp') { throw 'Owned OCSP endpoint changed' }
 $mutex=[Threading.Mutex]::new($false,('Global\TokenTimerQualification-Ocsp-'+$Owner.ownership.baseline.issuingCaThumbprint))
 $held=$false;$key=$null
 try {
  try { $held=$mutex.WaitOne(0) }
  catch [Threading.AbandonedMutexException] { $held=$true }
  if(!$held) { throw 'Another owned OCSP mutation remains active' }
  $key=Open-OwnedOcspCaRegistry $Owner $true
  $current=Get-OwnedOcspPublication $key
  foreach($name in @('CRLPublicationURLs','CACertPublicationURLs')) {
   $original=[string[]]$Owner.ownership.originalPublication.$name
   $expected=[string[]]$applied.phase.facts.appliedPublication.$name
   if(!(Test-OcspExactValues $current[$name] $expected) -and !(Test-OcspExactValues $current[$name] $original)) {
    throw 'Foreign CA publication change prevents restoration'
   }
  }
  foreach($name in @('CRLPublicationURLs','CACertPublicationURLs')) {
   $key.SetValue($name,[string[]]$Owner.ownership.originalPublication.$name,[Microsoft.Win32.RegistryValueKind]::MultiString)
  }
  $key.Flush()
  $restored=Get-OwnedOcspPublication $key
  foreach($name in @('CRLPublicationURLs','CACertPublicationURLs')) {
   if(!(Test-OcspExactValues $restored[$name] ([string[]]$Owner.ownership.originalPublication.$name))) {
    throw 'Exact original CA publication restoration unproven'
   }
  }
  $key.Dispose();$key=$null
  Restart-OwnedOcspIssuingCa $Owner
  $path=Join-Path $Owner.directory ($Owner.ownership.baseline.issuingCaThumbprint+'-publication-restored.json')
  if(Test-Path -LiteralPath $path) {
   $prior=Read-OwnedOcspPhase $Owner 'publication-restored' @('originalPublicationRestored')
   if($prior.phase.facts.originalPublicationRestored -isnot [bool] -or $prior.phase.facts.originalPublicationRestored -ne $true) {
    throw 'Original publication restoration receipt invalid'
   }
  } else {
   [void](Write-OwnedOcspPhase $Owner 'publication-restored' @{originalPublicationRestored=$true})
  }
  return @{originalPublicationRestored=$true}
 } finally {
  if($null -ne $key) { $key.Dispose() }
  if($held) { $mutex.ReleaseMutex() }
  $mutex.Dispose()
 }
}

function Capture-OwnedOcspIis($Owner) {
 $Owner=Read-OwnedOcspOwnershipReceipt $Owner.ownership.runId $Owner.ownership.token $Owner.ownership.baseline.issuingCaThumbprint $Owner.ownership.baseline.signingTemplateName
 $snapshot=Get-OwnedOcspIisSnapshot $Owner
 [void](Write-OwnedOcspPhase $Owner 'iis-captured' $snapshot)
 return $snapshot
}

function Stop-AndRecordOwnedOcspIis($Owner) {
 $Owner=Read-OwnedOcspOwnershipReceipt $Owner.ownership.runId $Owner.ownership.token $Owner.ownership.baseline.issuingCaThumbprint $Owner.ownership.baseline.signingTemplateName
 $original=Read-OwnedOcspPhase $Owner 'iis-captured' @('siteName','siteId','protocol','bindingInformation','applicationPath','virtualDirectoryPath','applicationPool','physicalPath','physicalDirectoryIdentity')
 $facts=Stop-OwnedOcspIis $Owner $original.phase.facts
 # The helper's finally has closed every retained worker handle before it
 # returns. Only then may this durable phase authorize signer key cleanup.
 [void](Write-OwnedOcspPhase $Owner 'iis-stopped' $facts)
 return $facts
}

function Assert-OwnedOcspStoppedConsumers($OriginalResponderIdentity) {
 foreach($name in @('OCSPSvc','W3SVC','WAS')) {
  $rows=@(Get-CimInstance Win32_Service -Filter ("Name='"+$name+"'") -ErrorAction Stop)
  if($rows.Count -ne 1 -or $rows[0].State -cne 'Stopped' -or
     $rows[0].StartMode -cne 'Disabled' -or $rows[0].ProcessId -ne 0) {
   throw 'Fresh stopped and disabled native consumer services required'
  }
  if($name -ceq 'OCSPSvc' -and
     ($rows[0].StartName -cne $OriginalResponderIdentity.account -or
      $rows[0].PathName -cne $OriginalResponderIdentity.path)) {
   throw 'Original disabled responder service identity changed'
  }
 }
 $processes=@(Get-CimInstance Win32_Process -Filter "Name='w3wp.exe' OR Name='ocspsvc.exe'" -ErrorAction Stop)
 if($processes.Count -ne 0) { throw 'Unexpected native responder or IIS worker prevents cleanup' }
 $listeners=@(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object LocalPort -EQ 80)
 if($listeners.Count -ne 0) { throw 'Native responder HTTP endpoint became active again' }
}

function Remove-OwnedOcspSigner($Owner,[string]$HelperSha256,[string]$SurvivorScriptSha256) {
 $Owner=Read-OwnedOcspOwnershipReceipt $Owner.ownership.runId $Owner.ownership.token $Owner.ownership.baseline.issuingCaThumbprint $Owner.ownership.baseline.signingTemplateName
 $stopped=Read-OwnedOcspPhase $Owner 'responder-stopped' @('exactOriginalProcessExited','nativeServiceStopped','ownedServiceDisabled')
 foreach($name in @('exactOriginalProcessExited','nativeServiceStopped','ownedServiceDisabled')) {
  if($stopped.phase.facts.$name -isnot [bool] -or !$stopped.phase.facts.$name) {
   throw 'Exact responder process/service drainage required before signer cleanup'
  }
 }
 $iis=Read-OwnedOcspPhase $Owner 'iis-stopped' @('actualWorkersDrained','ownedIisServicesStopped','sharedServiceHostTerminationQualified','nativeHttpEndpointAbsent')
 foreach($name in @('actualWorkersDrained','ownedIisServicesStopped','nativeHttpEndpointAbsent')) {
  if($iis.phase.facts.$name -isnot [bool] -or !$iis.phase.facts.$name) {
   throw 'Exact IIS worker/endpoint drainage required before signer cleanup'
  }
 }
 if($iis.phase.facts.sharedServiceHostTerminationQualified -isnot [bool] -or
    $iis.phase.facts.sharedServiceHostTerminationQualified -ne $false) {
  throw 'Shared service host termination cannot authorize cleanup'
 }
 $keyReceipt=Read-OwnedOcspPhase $Owner 'signer-key-created' @('keyIdentity','originalDacl')
 $accepted=Read-OwnedOcspPhase $Owner 'signer-accepted' @('certificateSha256','fingerprint','serviceIdentity','appliedDacl')
 $container=$Owner.ownership.plannedContainer
 $key=[Security.Cryptography.CngKey]::Open($container,[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)
 try {
  Assert-OwnedOcspKeyIdentity $key $keyReceipt.phase.facts.keyIdentity
  $service=Get-OwnedOcspServiceIdentity
  if($service.processId -ne 0 -or $service.account -cne $accepted.phase.facts.serviceIdentity.account -or
     $service.path -cne $accepted.phase.facts.serviceIdentity.path -or $service.sid -cne $accepted.phase.facts.serviceIdentity.sid) {
   throw 'Owned responder service changed after stop'
  }
  Assert-OwnedOcspStoppedConsumers $accepted.phase.facts.serviceIdentity
  Restore-OwnedOcspKeyDacl $key $keyReceipt.phase.facts.keyIdentity ([Convert]::FromBase64String($keyReceipt.phase.facts.originalDacl)) ([Convert]::FromBase64String($accepted.phase.facts.appliedDacl))
  $fingerprint=[string]$accepted.phase.facts.fingerprint
  if($fingerprint -cnotmatch '^[A-F0-9]{40}$') { throw 'Exact owned signer certificate fingerprint required' }
  $certificatePath='Cert:\LocalMachine\My\'+$fingerprint
  $certificate=Get-Item -LiteralPath $certificatePath -ErrorAction Stop
  try {
   if(!$certificate.HasPrivateKey -or (Get-OcspPublicDigest $certificate.RawData) -cne $accepted.phase.facts.certificateSha256) {
    throw 'Original signer public entry changed before removal'
   }
   $private=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
   try {
    if($private -isnot [Security.Cryptography.RSACng]) { throw 'Exact signer CNG association required' }
    Assert-OwnedOcspKeyIdentity $private.Key $keyReceipt.phase.facts.keyIdentity
   } finally { if($private) { $private.Dispose() } }
  } finally { $certificate.Dispose() }
  # Remove only the exact owned PUBLIC entry, never -DeleteKey. A complete
  # shipped native all-store scan must independently prove no surviving key
  # consumer (including Request or a foreign mirror) before the next step.
  Remove-Item -LiteralPath $certificatePath -ErrorAction Stop
  if(Test-Path -LiteralPath $certificatePath) { throw 'Owned signer public entry absence unproven' }
  $scan=Invoke-OwnedOcspSurvivorCapture $Owner $HelperSha256 $SurvivorScriptSha256
  Assert-OwnedOcspStoppedConsumers $accepted.phase.facts.serviceIdentity
  Assert-OwnedOcspKeyIdentity $key $keyReceipt.phase.facts.keyIdentity
  $key.Delete()
 } finally { $key.Dispose() }
 if([Security.Cryptography.CngKey]::Exists($container,[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)) {
  throw 'Exact owned signer key absence unproven'
 }
 $facts=@{
  originalSignerDaclRestored=$true;exactOwnedSignerPublicEntryAbsent=$true
  completeNativeSurvivorScanVerified=$true;exactOwnedSignerKeyAbsent=$true
  nativeScanRootExitCode=$scan.native.rootExitCode;nativeScanActiveProcesses=$scan.native.activeNativeProcesses
  nativeScanHandlesClosed=$scan.native.retainedHandlesClosed
 }
 [void](Write-OwnedOcspPhase $Owner 'signer-removed' $facts)
 return $facts
}

function Remove-OwnedOcspConfiguration($Owner,[byte[]]$OriginalCaDer,[byte[]]$SignerDer,[byte[]]$CurrentSignedCrlDer) {
 $Owner=Read-OwnedOcspOwnershipReceipt $Owner.ownership.runId $Owner.ownership.token $Owner.ownership.baseline.issuingCaThumbprint $Owner.ownership.baseline.signingTemplateName
 $restored=Read-OwnedOcspPhase $Owner 'publication-restored' @('originalPublicationRestored')
 if($restored.phase.facts.originalPublicationRestored -isnot [bool] -or
    !$restored.phase.facts.originalPublicationRestored) {
  throw 'Exact original publication restoration required before responder removal'
 }
 $configured=Read-OwnedOcspPhase $Owner 'configured' @('identifier','caDerSha256','signerDerSha256','signedCrlSha256','signingFlags','hashAlgorithm','nativeSignerError','nativeRevocationError')
 $identifier=$Owner.ownership.baseline.signingTemplateName
 if($configured.phase.facts.identifier -cne $identifier -or
    (Get-OcspPublicDigest $OriginalCaDer) -cne $Owner.ownership.baseline.caDerSha256 -or
    (Get-OcspPublicDigest $SignerDer) -cne $configured.phase.facts.signerDerSha256) {
  throw 'Original native responder CA/signer binding changed before removal'
 }
 [void](Get-OwnedOcspConfigurationObservation $identifier $OriginalCaDer $SignerDer $CurrentSignedCrlDer)
 $admin=$null;$collection=$null;$entry=$null
 try {
  $admin=New-Object -ComObject 'CertAdm.OCSPAdmin'
  [void]$admin.GetConfiguration('tt-ca.lab.certops.test',$false)
  $collection=$admin.OCSPCAConfigurationCollection
  if($collection.Count -ne 1) { throw 'Unexpected responder configuration prevents removal' }
  $entry=$collection.ItemByName($identifier)
  if($entry.Identifier -cne $identifier -or
     (Get-OcspPublicDigest ([byte[]]$entry.CACertificate)) -cne $Owner.ownership.baseline.caDerSha256 -or
     (Get-OcspPublicDigest ([byte[]]$entry.SigningCertificate)) -cne $configured.phase.facts.signerDerSha256 -or
     [int]$entry.SigningFlags -ne 0x69 -or $entry.HashAlgorithm -cne 'SHA256' -or
     ([string]$entry.ProviderCLSID).ToLowerInvariant() -cne '{4956d17f-88fd-4198-b287-1e6e65883b19}' -or
     [int]$entry.ErrorCode -ne 0) {
   throw 'Owned responder configuration changed immediately before removal'
  }
  $properties=$entry.ProviderProperties
  if($properties -isnot [Array] -or $properties.Rank -ne 2 -or
     $properties.GetLength(1) -ne 2 -or $properties.GetLength(0) -lt 1 -or
     $properties.GetLength(0) -gt 32 -or $properties.GetLowerBound(0) -ne 0 -or
     $properties.GetLowerBound(1) -ne 0) {
   throw 'Bounded native revocation properties required immediately before removal'
  }
  $names=@{};$actualCrl=$null;$revocationError=$null
  for($index=0;$index -lt $properties.GetLength(0);$index++) {
   $name=$properties[$index,0]
   if($name -isnot [string] -or $name.Length -lt 1 -or $name.Length -gt 128 -or $names.ContainsKey($name)) {
    throw 'Ambiguous native revocation properties before removal'
   }
   $names[$name]=$true
   if($name -ceq 'BaseCrl') { $actualCrl=[byte[]]$properties[$index,1] }
   if($name -ceq 'RevocationErrorCode') { $revocationError=$properties[$index,1] }
  }
  if($null -eq $revocationError -or [int]$revocationError -ne 0 -or
     (Get-OcspPublicDigest $actualCrl) -cne (Get-OcspPublicDigest $CurrentSignedCrlDer)) {
   throw 'Native signed revocation state changed before removal'
  }
  # The preceding independent native observation pins every configured value.
  # Deletion is by the exact owned identifier, never by collection position.
  $collection.DeleteCAConfiguration($identifier)
  [void]$admin.SetConfiguration('tt-ca.lab.certops.test',$false)
 } finally {
  foreach($resource in @($entry,$collection,$admin)) {
   if($null -ne $resource -and [Runtime.InteropServices.Marshal]::IsComObject($resource)) {
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($resource)
   }
  }
 }
 $admin=$null;$collection=$null
 try {
  $admin=New-Object -ComObject 'CertAdm.OCSPAdmin'
  [void]$admin.GetConfiguration('tt-ca.lab.certops.test',$false)
  $collection=$admin.OCSPCAConfigurationCollection
  if($collection.Count -ne 0) { throw 'Native responder configuration absence unproven' }
 } finally {
  foreach($resource in @($collection,$admin)) {
   if($null -ne $resource -and [Runtime.InteropServices.Marshal]::IsComObject($resource)) {
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($resource)
   }
  }
 }
 $completion=@{
  identifier=$identifier;nativeConfigurationAbsent=$true
 }
 [void](Write-OwnedOcspPhase $Owner 'configuration-removed' $completion)
 return $completion
}

function Stop-OwnedOcspResponder($Owner) {
 $Owner=Read-OwnedOcspOwnershipReceipt $Owner.ownership.runId $Owner.ownership.token $Owner.ownership.baseline.issuingCaThumbprint $Owner.ownership.baseline.signingTemplateName
 $removed=Read-OwnedOcspPhase $Owner 'configuration-removed' @('identifier','nativeConfigurationAbsent')
 if($removed.phase.facts.nativeConfigurationAbsent -isnot [bool] -or
    !$removed.phase.facts.nativeConfigurationAbsent -or
    $removed.phase.facts.identifier -cne $Owner.ownership.baseline.signingTemplateName) {
  throw 'Exact owned revocation configuration removal required before service stop'
 }
 $accepted=Read-OwnedOcspPhase $Owner 'signer-accepted' @('certificateSha256','fingerprint','serviceIdentity','appliedDacl')
 $observed=Get-OwnedOcspServiceIdentity
 foreach($name in @('name','account','sid','path','processId','processCreatedAt','executablePath','processSid')) {
  if($observed[$name] -cne $accepted.phase.facts.serviceIdentity.$name) {
   throw 'Original responder service identity changed before stop'
  }
 }
 if(!('RetainedFixtureProcess' -as [type]) -or !$script:OcspWaitSourceHash) {
  throw 'Candidate-bound native retained process waiter required'
 }
 $retained=[RetainedFixtureProcess]::new([uint32]$observed.processId)
 try {
  $created=[DateTime]::Parse($observed.processCreatedAt,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.ffffffZ',[Globalization.CultureInfo]::InvariantCulture)
  if($retained.Exited -or $retained.CreatedMicroseconds -cne $created -or
     $retained.Image -ine $observed.executablePath -or $retained.Sid -cne $observed.sid) {
   throw 'Retained native responder identity does not match original service'
  }
  $fresh=Get-OwnedOcspServiceIdentity
  foreach($name in @('name','account','sid','path','processId','processCreatedAt','executablePath','processSid')) {
   if($fresh[$name] -cne $observed[$name]) { throw 'Responder changed during retained handle capture' }
  }
  [void](Write-OwnedOcspPhase $Owner 'responder-stop-intent' @{
   serviceIdentity=$observed;nativeCreationTicks=$retained.CreatedTicks
  })
  # This is an ordinary SCM stop of the originally absent, owned service.
  # Never terminate by PID, and never reuse the SYSTEM-only emergency kill
  # operation exposed by the shared class for another fixture's purpose.
  Stop-Service -Name OCSPSvc -ErrorAction Stop
  $retained.Wait()
  if(!$retained.Exited) { throw 'Exact retained responder process did not exit' }
  $stopped=@(Get-CimInstance Win32_Service -Filter "Name='OCSPSvc'" -ErrorAction Stop)
  $survivors=@(Get-CimInstance Win32_Process -Filter "Name='ocspsvc.exe'" -ErrorAction Stop)
  if($stopped.Count -ne 1 -or $stopped[0].State -cne 'Stopped' -or
     $stopped[0].ProcessId -ne 0 -or $stopped[0].StartName -cne $observed.account -or
     $stopped[0].PathName -cne $observed.path -or $survivors.Count -ne 0) {
   throw 'Native responder service/process absence unproven'
  }
  Set-Service -Name OCSPSvc -StartupType Disabled -ErrorAction Stop
  $disabled=@(Get-CimInstance Win32_Service -Filter "Name='OCSPSvc'" -ErrorAction Stop)
  if($disabled.Count -ne 1 -or $disabled[0].StartMode -cne 'Disabled' -or
     $disabled[0].State -cne 'Stopped' -or $disabled[0].ProcessId -ne 0) {
   throw 'Owned responder disable readback failed'
  }
  $completion=@{
   exactOriginalProcessExited=$true;nativeServiceStopped=$true;ownedServiceDisabled=$true
  }
  [void](Write-OwnedOcspPhase $Owner 'responder-stopped' $completion)
  return $completion
 } finally { $retained.Dispose() }
}

function Set-OwnedOcspConfiguration($Owner,[byte[]]$VerifiedSignedCrlDer) {
 $Owner=Read-OwnedOcspOwnershipReceipt $Owner.ownership.runId $Owner.ownership.token $Owner.ownership.baseline.issuingCaThumbprint $Owner.ownership.baseline.signingTemplateName
 $accepted=Read-OwnedOcspPhase $Owner 'signer-accepted' @('certificateSha256','fingerprint','serviceIdentity','appliedDacl')
 $service=Get-OwnedOcspServiceIdentity
 foreach($name in @('name','account','sid','path','processId','processCreatedAt','executablePath','processSid')) {
  if($service[$name] -cne $accepted.phase.facts.serviceIdentity.$name) {
   throw 'Original responder service changed before configuration'
  }
 }
 $signer=[TTQualificationOcspReceipt]::Read((Join-Path $Owner.directory 'signer.cer'))
 if((Get-OcspPublicDigest $signer) -cne $accepted.phase.facts.certificateSha256) {
  throw 'Accepted signer certificate changed before responder configuration'
 }
 $crlDigest=Get-OcspPublicDigest $VerifiedSignedCrlDer
 $pin=Open-OwnedOcspCaRegistry $Owner $false
 $pin.Dispose()
 $ca=Get-Item -LiteralPath ('Cert:\LocalMachine\My\'+$Owner.ownership.baseline.issuingCaThumbprint) -ErrorAction Stop
 try { $caBytes=$ca.RawData } finally { $ca.Dispose() }
 $admin=$null;$collection=$null;$entry=$null
 try {
  $admin=New-Object -ComObject 'CertAdm.OCSPAdmin'
  [void]$admin.GetConfiguration('tt-ca.lab.certops.test',$false)
  $collection=$admin.OCSPCAConfigurationCollection
  if($collection.Count -ne 0) { throw 'Never adopt an existing responder revocation configuration' }
  $identifier=$Owner.ownership.baseline.signingTemplateName
  [void](Write-OwnedOcspPhase $Owner 'configuration-intent' @{
   identifier=$identifier;caDerSha256=$Owner.ownership.baseline.caDerSha256
   signerDerSha256=$accepted.phase.facts.certificateSha256;signedCrlSha256=$crlDigest
  })
  $entry=$collection.CreateCAConfiguration($identifier,[byte[]]$caBytes)
  $entry.SigningFlags=[int]0x69
  $entry.SigningCertificate=[byte[]]$signer
  $entry.HashAlgorithm='SHA256'
  $entry.ProviderCLSID='{4956d17f-88fd-4198-b287-1e6e65883b19}'
  # Explicit actual signed CRL bytes avoid an unrelated network dependency or
  # a responder using a stale publication cache. The caller independently
  # verifies this exact DER against the original issuing key before this call.
  $properties=[Array]::CreateInstance([object],1,2)
  $properties[0,0]='BaseCrl'
  $properties[0,1]=[byte[]]$VerifiedSignedCrlDer
  $entry.ProviderProperties=$properties
  [void]$admin.SetConfiguration('tt-ca.lab.certops.test',$false)
 } finally {
  foreach($resource in @($entry,$collection,$admin)) {
   if($null -ne $resource -and [Runtime.InteropServices.Marshal]::IsComObject($resource)) {
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($resource)
   }
  }
 }
 $observation=Get-OwnedOcspConfigurationObservation $identifier $caBytes $signer $VerifiedSignedCrlDer
 [void](Write-OwnedOcspPhase $Owner 'configured' $observation)
 return $observation
}

function Get-OwnedOcspConfigurationObservation(
 [string]$Identifier,
 [byte[]]$OriginalCaDer,
 [byte[]]$OwnedSignerDer,
 [byte[]]$CurrentSignedCrlDer
) {
 Assert-OcspFixtureIdentifier $Identifier
 $caDigest=Get-OcspPublicDigest $OriginalCaDer
 $signerDigest=Get-OcspPublicDigest $OwnedSignerDer
 $crlDigest=Get-OcspPublicDigest $CurrentSignedCrlDer
 $admin=$null;$collection=$null;$entry=$null
 try {
  # Read the running native service only. Registry fallback could conceal an
  # unavailable responder and is intentionally disabled for qualification.
  $admin=New-Object -ComObject 'CertAdm.OCSPAdmin'
  [void]$admin.GetConfiguration('tt-ca.lab.certops.test',$false)
  $collection=$admin.OCSPCAConfigurationCollection
  if($collection.Count -ne 1) { throw 'Exact sole owned revocation configuration required' }
  $entry=$collection.ItemByName($Identifier)
  if($entry.Identifier -cne $Identifier -or
     (Get-OcspPublicDigest ([byte[]]$entry.CACertificate)) -cne $caDigest -or
     (Get-OcspPublicDigest ([byte[]]$entry.SigningCertificate)) -cne $signerDigest) {
   throw 'Native responder CA or delegated signer changed'
  }
  # Silent key access, same-CA-key signer validation, manual certificate and
  # byKey responder identity. No CA-key
  # signing, discovery, automatic renewal or autoenrollment is accepted.
  if([int]$entry.SigningFlags -ne 0x69 -or $entry.HashAlgorithm -cne 'SHA256' -or
     ([string]$entry.ProviderCLSID).ToLowerInvariant() -cne '{4956d17f-88fd-4198-b287-1e6e65883b19}' -or
     [int]$entry.ErrorCode -ne 0) {
   throw 'Native manual delegated responder configuration is not ready'
  }
  $properties=$entry.ProviderProperties
  if($properties -isnot [Array] -or $properties.Rank -ne 2 -or
     $properties.GetLength(1) -ne 2 -or $properties.GetLength(0) -lt 1 -or
     $properties.GetLength(0) -gt 32 -or $properties.GetLowerBound(0) -ne 0 -or
     $properties.GetLowerBound(1) -ne 0) {
   throw 'Bounded native revocation provider properties required'
  }
  $names=@{};$baseCrl=$null;$revocationError=$null
  for($index=0;$index -lt $properties.GetLength(0);$index++) {
   $name=$properties[$index,0]
   if($name -isnot [string] -or $name.Length -lt 1 -or $name.Length -gt 128 -or $names.ContainsKey($name)) {
    throw 'Ambiguous native revocation provider properties'
   }
   $names[$name]=$true
   if($name -ceq 'BaseCrl') { $baseCrl=[byte[]]$properties[$index,1] }
   if($name -ceq 'RevocationErrorCode') { $revocationError=$properties[$index,1] }
  }
  if($null -eq $revocationError -or [int]$revocationError -ne 0 -or
     (Get-OcspPublicDigest $baseCrl) -cne $crlDigest) {
   throw 'Actual signed native revocation provider is not ready'
  }
  return @{
   identifier=$Identifier
   caDerSha256=$caDigest
   signerDerSha256=$signerDigest
   signedCrlSha256=$crlDigest
   signingFlags=0x69
   hashAlgorithm='SHA256'
   nativeSignerError=0
   nativeRevocationError=0
  }
 } finally {
  foreach($owned in @($entry,$collection,$admin)) {
   if($null -ne $owned -and [Runtime.InteropServices.Marshal]::IsComObject($owned)) {
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($owned)
   }
  }
 }
}

function Get-OcspResponderAdmission([string]$TemplateName,[string]$ExpectedCaThumbprint) {
 Assert-OcspFixtureIdentifier $TemplateName
 if($ExpectedCaThumbprint -cnotmatch '^[A-F0-9]{40}$') {
  throw 'Exact original issuing CA thumbprint required'
 }
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 $principal=[Security.Principal.WindowsPrincipal]::new($identity)
 if(!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Owned CA administrative context required'
 }
 $machine=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
 if(!$machine.PartOfDomain -or $machine.Name -ine 'tt-ca' -or $machine.Domain -ine 'lab.certops.test') {
  throw 'Exact disposable issuing CA host required'
 }
 # Local Administrator/SYSTEM is insufficient evidence of directory authority.
 # Use only the lab's independently provisioned officer and require both
 # privileged domain groups to be enabled in this actual impersonation token.
 Import-Module ActiveDirectory -ErrorAction Stop
 $domain=Get-ADDomain -ErrorAction Stop
 $officer=Get-ADUser -Identity 'tt-lab-admin' -ErrorAction Stop
 if($domain.DNSRoot -ine 'lab.certops.test' -or $officer.SID.Value -cne $identity.User.Value) {
  throw 'Exact provisioned directory officer context required'
 }
 foreach($rid in @(512,519)) {
  $groupSid=[Security.Principal.SecurityIdentifier]::new($domain.DomainSID.Value+'-'+$rid)
  if(!$principal.IsInRole($groupSid)) {
   throw 'Enabled domain and enterprise administration authority required'
  }
 }

 # Snapshot all originally installed features. A later restore may remove only
 # features proven newly installed by this exact fixture, never this baseline.
 $features=@(Get-WindowsFeature -ErrorAction Stop)
 if($features.Count -lt 1 -or $features.Count -gt 2048) {
  throw 'Bounded native role inventory required'
 }
 $installed=@($features | Where-Object Installed | ForEach-Object Name | Sort-Object)
 if($installed -notcontains 'ADCS-Cert-Authority') {
  throw 'Original issuing CA role missing'
 }
 foreach($name in @('Web-Server','ADCS-Online-Cert','WAS')) {
  $rows=@($features | Where-Object Name -CEQ $name)
  if($rows.Count -ne 1 -or $rows[0].Installed) {
   throw 'Never adopt an existing IIS, activation or Online Responder role'
  }
 }
 $services=@(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object Name -CEQ 'OCSPSvc')
 if($services.Count -ne 0) { throw 'Never adopt an existing responder service' }
 $listeners=@(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object LocalPort -EQ 80)
 if($listeners.Count -ne 0) { throw 'Responder HTTP port is already owned' }
 $iisConfig=Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
 if(Test-Path -LiteralPath $iisConfig) {
  throw 'Preexisting IIS configuration cannot be adopted'
 }
 # An absent IIS role does not prove that its default physical namespace is
 # disposable. Refuse an existing directory, file or dangling reparse point;
 # feature installation must never overwrite foreign content under inetpub.
 $inetpub=Join-Path $env:SystemDrive 'inetpub'
 $physicalNamespace=@(Get-ChildItem -LiteralPath ($env:SystemDrive+'\') -Force -ErrorAction Stop |
  Where-Object Name -IEQ 'inetpub')
 if($physicalNamespace.Count -ne 0 -or (Test-Path -LiteralPath $inetpub)) {
  throw 'Preexisting IIS physical namespace cannot be adopted'
 }

 $configuration='HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
 $active=(Get-ItemProperty -LiteralPath $configuration -Name Active -ErrorAction Stop).Active
 if($active -cne 'TTQualificationRoot') { throw 'Original issuing CA configuration mismatch' }
 $caRegistry=Get-ItemProperty -LiteralPath (Join-Path $configuration $active) -ErrorAction Stop
 $hashes=@($caRegistry.CACertHash)
 if($hashes.Count -ne 1 -or ([string]$hashes[0]).Replace(' ','').ToUpperInvariant() -cne $ExpectedCaThumbprint) {
  throw 'Single original issuing CA generation required'
 }
 $certificate=Get-Item -LiteralPath ('Cert:\LocalMachine\My\'+$ExpectedCaThumbprint) -ErrorAction Stop
 try {
  if($certificate.Thumbprint -cne $ExpectedCaThumbprint -or !$certificate.HasPrivateKey -or
     $certificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) -cne 'TTQualificationRoot') {
   throw 'Pinned native issuing CA certificate mismatch'
  }
  $caDerSha256=Get-OcspPublicDigest $certificate.RawData
 } finally { $certificate.Dispose() }

 $root=[ADSI]'LDAP://RootDSE'
 $configurationDn=[string]$root.configurationNamingContext
 if(!$configurationDn) { throw 'Native directory configuration context unavailable' }
 $templates='CN=Certificate Templates,CN=Public Key Services,CN=Services,'+$configurationDn
 $templatePath='LDAP://CN='+$TemplateName+','+$templates
 if([DirectoryServices.DirectoryEntry]::Exists($templatePath)) {
  throw 'Never adopt an existing responder signing template'
 }
 $signingSource=[ADSI]('LDAP://CN=OCSPResponseSigning,'+$templates)
 if([string]$signingSource.Properties['cn'].Value -cne 'OCSPResponseSigning') {
  throw 'Native OCSP signing template source unavailable'
 }
 # Baseline contains no password, private key, template SDDL or raw registry
 # values. Exact publication values belong in the separate private receipt.
 return @{
  schemaVersion=1
  machineName=[string]$machine.Name
  domain=[string]$machine.Domain
  ownerSid=$identity.User.Value
  installedFeatures=$installed
  issuingCaThumbprint=$ExpectedCaThumbprint
  caDerSha256=$caDerSha256
  signingTemplateName=$TemplateName
  responderInitiallyAbsent=$true
  iisInitiallyAbsent=$true
  httpPortInitiallyUnbound=$true
 }
}

<#
Temporarily publish an HTTP-only leaf CDP on the exact disposable issuing CA.
The public CRL is served by the owned member fixture, not arbitrary CA files.
A fixed CA mutex and immutable private original/applied receipt precede registry
mutation. Restore compares the actual value before writing; foreign changes
refuse. This script is never invoked by supporting source/AST tests.
#>
param(
 [Parameter(Mandatory)][ValidateSet('Apply','Restore')][string]$Action,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{10}$')][string]$RunId,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$')][string]$OwnershipToken,
 [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{40}$')][string]$ExpectedCaThumbprint,
 [Parameter(Mandatory)][ValidateRange(1024,65535)][int]$HttpPort
)
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test' -or !$env:CERTOPS_ADCS_OFFICER_PASSWORD){throw 'Owned isolated forest officer context required'}
$credential=[PSCredential]::new('TTQUAL\tt-lab-admin',(ConvertTo-SecureString $env:CERTOPS_ADCS_OFFICER_PASSWORD -AsPlainText -Force))
Invoke-Command -ComputerName 'tt-ca.lab.certops.test' -Credential $credential -ArgumentList $Action,$RunId,$OwnershipToken,$ExpectedCaThumbprint,$HttpPort -ScriptBlock {
 param($Action,$RunId,$OwnershipToken,$ExpectedCaThumbprint,$HttpPort)
 $ErrorActionPreference='Stop'
 if($env:COMPUTERNAME -ine 'tt-ca' -or (Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Exact owned CA host required'}
 $configuration='SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
 $root=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($configuration)
 try{if([string]$root.GetValue('Active') -cne 'TTQualificationRoot'){throw 'Unexpected active CA configuration'}}finally{$root.Dispose()}
 $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$configuration\TTQualificationRoot",$true)
 if(!$key){throw 'Owned CA registry key absent'}
 $mutex=$null;$held=$false;$ca=$null
 # Open the actual alias itself, and deny replacement while reading. Public
 # CRLs and private receipts use the same bounded, native-identity reader.
 Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class HttpLeafCrlFile {
 [StructLayout(LayoutKind.Sequential)] struct Info {
  public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Created,Accessed,Written;
  public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
 }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
 static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle,out Info info);
 static Info Identity(SafeFileHandle handle,int maximum) {
  Info value;
  if(handle.IsInvalid || !GetFileInformationByHandle(handle,out value)) throw new IOException("Native file identity unavailable");
  if((value.Attributes & (0x10u|0x400u)) != 0 || value.SizeHigh != 0 || value.SizeLow < 1 || value.SizeLow > maximum || (value.IndexHigh == 0 && value.IndexLow == 0)) throw new IOException("Bounded regular native file required");
  return value;
 }
 static bool Same(Info a,Info b) {
  return a.Volume==b.Volume && a.IndexHigh==b.IndexHigh && a.IndexLow==b.IndexLow && a.SizeHigh==b.SizeHigh && a.SizeLow==b.SizeLow && a.Written.dwHighDateTime==b.Written.dwHighDateTime && a.Written.dwLowDateTime==b.Written.dwLowDateTime;
 }
 public static byte[] Read(string path,int maximum,bool privateReceipt) {
  using(var handle=CreateFile(path,0x80000000u,1u,IntPtr.Zero,3u,0x00200000u,IntPtr.Zero)) {
   var before=Identity(handle,maximum);
   if(privateReceipt && before.Links!=1) throw new IOException("Private receipt alias refused");
   if(privateReceipt) CheckAcl(path);
   using(var stream=new FileStream(handle,FileAccess.Read)) {
    var buffer=new byte[maximum+1]; int length=0,count;
    while(length<buffer.Length && (count=stream.Read(buffer,length,buffer.Length-length))>0) length+=count;
    var after=Identity(handle,maximum);
    using(var fresh=CreateFile(path,0x80000000u,1u,IntPtr.Zero,3u,0x00200000u,IntPtr.Zero)) {
     if(length!=before.SizeLow || !Same(before,after) || !Same(before,Identity(fresh,maximum))) throw new IOException("Native file changed while reading");
    }
    if(privateReceipt) CheckAcl(path);
    var result=new byte[length]; Array.Copy(buffer,result,length); return result;
   }
  }
 }
 static void CheckAcl(string path) {
  var acl=File.GetAccessControl(path);
  if(!acl.AreAccessRulesProtected) throw new IOException("Receipt inherits access");
  var owner=System.Security.Principal.WindowsIdentity.GetCurrent().User.Value; bool system=false;
  foreach(System.Security.AccessControl.FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(System.Security.Principal.SecurityIdentifier))) {
   string sid=rule.IdentityReference.Value;
   if(rule.IsInherited || (rule.AccessControlType==System.Security.AccessControl.AccessControlType.Allow && sid!=owner && sid!="S-1-5-18" && sid!="S-1-5-32-544")) throw new IOException("Receipt grants unowned access");
   if(sid=="S-1-5-18" && rule.AccessControlType==System.Security.AccessControl.AccessControlType.Allow && (rule.FileSystemRights & System.Security.AccessControl.FileSystemRights.FullControl)==System.Security.AccessControl.FileSystemRights.FullControl) system=true;
  }
  if(!system) throw new IOException("Receipt lacks explicit SYSTEM custody");
 }
}
'@
 function Sha([byte[]]$Bytes){$hash=[Security.Cryptography.SHA256]::Create();try{return [BitConverter]::ToString($hash.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}}
 function Encoded([string[]]$Values){return [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject @($Values) -Compress))}
 function Same([string[]]$First,[string[]]$Second){return [Convert]::ToBase64String((Encoded $First)) -ceq [Convert]::ToBase64String((Encoded $Second))}
 function Current {
  if($key.GetValueKind('CRLPublicationURLs') -ne [Microsoft.Win32.RegistryValueKind]::MultiString){throw 'Original publication kind must remain MultiString'}
  $values=[string[]]$key.GetValue('CRLPublicationURLs')
  if($values.Count -lt 1 -or $values.Count -gt 16 -or @($values|Where-Object {$_.Length -lt 1 -or $_.Length -gt 4096}).Count){throw 'Bounded actual publication values required'}
  return ,$values
 }
 function CheckCa {
  $hashes=@($key.GetValue('CACertHash'))
  if($hashes.Count -ne 1 -or ([string]$hashes[0]).Replace(' ','').ToUpperInvariant() -cne $ExpectedCaThumbprint){throw 'Current original CA certificate identity changed'}
  $certificate=Get-Item -LiteralPath "Cert:\LocalMachine\My\$ExpectedCaThumbprint"
  if(!$certificate.HasPrivateKey -or $certificate.Thumbprint.Replace(' ','').ToUpperInvariant() -cne $ExpectedCaThumbprint -or $certificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) -cne 'TTQualificationRoot'){if($certificate){$certificate.Dispose()};throw 'Exact original native CA custody required'}
  return $certificate
 }
 function PrivateAcl([string]$Path,[bool]$Directory){
  $acl=if($Directory){[Security.AccessControl.DirectorySecurity]::new()}else{[Security.AccessControl.FileSecurity]::new()}
  $acl.SetAccessRuleProtection($true,$false)
  foreach($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')|Select-Object -Unique){
   $principal=[Security.Principal.SecurityIdentifier]::new($sid)
   $rule=if($Directory){[Security.AccessControl.FileSystemAccessRule]::new($principal,'FullControl','ContainerInherit,ObjectInherit','None','Allow')}else{[Security.AccessControl.FileSystemAccessRule]::new($principal,'FullControl','Allow')}
   $acl.AddAccessRule($rule)
  }
  if($Directory){[IO.Directory]::SetAccessControl($Path,$acl)}else{[IO.File]::SetAccessControl($Path,$acl)}
 }
 function RegularDirectory([string]$Path){$item=Get-Item -LiteralPath $Path -Force;if(!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Receipt ancestor must be regular and nonreparse'}}
 function PrivateDirectory([string]$Path){
  RegularDirectory $Path
  $acl=Get-Acl -LiteralPath $Path
  if(!$acl.AreAccessRulesProtected){throw 'Existing receipt directory inherits access'}
  $allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
  $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
  foreach($rule in $rules){if($rule.IsInherited -or ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -cnotin $allowed)){throw 'Receipt directory grants unowned access'}}
  if(!@($rules|Where-Object {$_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -ceq 'S-1-5-18' -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl}).Count){throw 'Receipt lacks explicit SYSTEM custody'}
 }
 function ReadBounded([string]$Path,[int]$Maximum,[bool]$PrivateReceipt=$false){return ,[HttpLeafCrlFile]::Read($Path,$Maximum,$PrivateReceipt)}
 try{
  $ca=CheckCa
  # Fixed by the exact shared CA, never the nonce of one contender.
  $mutex=[Threading.Mutex]::new($false,"Global\TokenTimerQualification-HttpLeafCrl-$ExpectedCaThumbprint")
  try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true;if($Action -ne 'Restore'){throw 'Abandoned publication mutation requires exact restore'}}
  if(!$held){throw 'Another owned publication operation remains active'}
  RegularDirectory $env:ProgramData
  $parent=Join-Path $env:ProgramData 'TokenTimerQualification'
  if(!(Test-Path -LiteralPath $parent)){$null=New-Item -Path $parent -ItemType Directory}
  RegularDirectory $parent
  $directory=Join-Path $parent 'http-leaf-crl'
  if(!(Test-Path -LiteralPath $directory)){$null=New-Item -Path $directory -ItemType Directory;PrivateAcl $directory $true}
  PrivateDirectory $directory
  $receipt=Join-Path $directory "$ExpectedCaThumbprint.json"
  $httpUrl="http://10.64.0.6:$HttpPort/TTQualificationRoot.crl"
  $applied=[string[]]@("1:$env:SystemRoot\System32\CertSrv\CertEnroll\%3%8%9.crl","2:$httpUrl")
  if($Action -eq 'Apply'){
   if(Test-Path -LiteralPath $receipt){throw 'Never adopt an existing CA publication receipt'}
   $original=Current
   if(Same $original $applied){throw 'Publication was already changed outside this owner'}
   $proof=@{schemaVersion=1;runId=$RunId;token=$OwnershipToken;caThumbprint=$ExpectedCaThumbprint;httpPort=$HttpPort;original=@($original);applied=@($applied)}
   $bytes=[Text.Encoding]::UTF8.GetBytes(($proof|ConvertTo-Json -Depth 5 -Compress))
   if($bytes.Length -gt 32768){throw 'Publication receipt exceeds bound'}
   $file=[IO.File]::Open($receipt,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
   try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
   PrivateAcl $receipt $false
   $key.SetValue('CRLPublicationURLs',$applied,[Microsoft.Win32.RegistryValueKind]::MultiString)
   if(!(Same (Current) $applied)){throw 'Applied publication readback mismatch'}
  }else{
   $proof=[Text.Encoding]::UTF8.GetString((ReadBounded $receipt 32768 $true))|ConvertFrom-Json
   $fields=@('schemaVersion','runId','token','caThumbprint','httpPort','original','applied')
   if(@($proof.PSObject.Properties).Count -ne $fields.Count -or @($proof.PSObject.Properties|Where-Object {$_.Name -cnotin $fields}).Count){throw 'Closed publication receipt required'}
   if($proof.schemaVersion -ne 1 -or $proof.runId -cne $RunId -or $proof.token -cne $OwnershipToken -or $proof.caThumbprint -cne $ExpectedCaThumbprint -or $proof.httpPort -ne $HttpPort -or !(Same ([string[]]$proof.applied) $applied)){throw 'Original publication ownership mismatch'}
   $original=[string[]]$proof.original
   if($original.Count -lt 1 -or $original.Count -gt 16 -or @($original|Where-Object {$_.Length -lt 1 -or $_.Length -gt 4096}).Count){throw 'Original publication receipt invalid'}
   $current=Current
   if(!(Same $current $applied) -and !(Same $current $original)){throw 'Foreign CA publication change prevents restoration'}
   $key.SetValue('CRLPublicationURLs',$original,[Microsoft.Win32.RegistryValueKind]::MultiString)
   if(!(Same (Current) $original)){throw 'Original CA publication restoration unproven'}
  }
  $key.Flush()
  Restart-Service CertSvc -ErrorAction Stop
  (Get-Service CertSvc).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(60))
  & certutil.exe -config 'tt-ca.lab.certops.test\TTQualificationRoot' -ping | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Owned CA did not become ready after publication change'}
  & certutil.exe -crl | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Actual issuing CA CRL publication failed'}
  $check=CheckCa;$check.Dispose()
  $result=@{scope='owned-enterprise-ca-http-leaf-publication';action=$Action;runId=$RunId;token=$OwnershipToken;caThumbprint=$ExpectedCaThumbprint;httpUrl=$httpUrl;originalSha256=(Sha (Encoded $original));appliedSha256=(Sha (Encoded $applied));caReady=$true;publicationRestored=($Action -eq 'Restore')}
  if($Action -eq 'Apply'){
   # Only the fixed original CA's public base CRL leaves the server. The
   # member additionally checks its actual signature, issuer and pinned key.
   $crlDirectory=Join-Path $env:SystemRoot 'System32\CertSrv\CertEnroll';RegularDirectory $crlDirectory
   $crl=ReadBounded (Join-Path $crlDirectory 'TTQualificationRoot.crl') 1048576
   $result.crlBase64=[Convert]::ToBase64String($crl);$result.caCertificateBase64=[Convert]::ToBase64String($ca.RawData)
  }
  # Keep original private ownership until disposable-lab teardown. Re-apply
  # cannot overwrite the receipt, and exact-token Restore remains retryable.
  $result|ConvertTo-Json -Depth 5 -Compress
 }finally{if($held){$mutex.ReleaseMutex()};if($mutex){$mutex.Dispose()};if($ca){$ca.Dispose()};$key.Dispose()}
}

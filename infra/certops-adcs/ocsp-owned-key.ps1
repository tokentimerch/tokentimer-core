<#
Functions for a delegated OCSP signer in the disposable CA fixture only.
Import defines functions; it does not create a key, change permissions or load
native code. The enclosing fixture must persist ownership BEFORE New-OwnedKey,
and must stop its exact owned responder and obtain the shipped complete native
survivor scan before deleting the new key. This file offers NO delete shortcut.
#>
function Initialize-OcspKeySecurity {
 if('TTQualificationOcspKeySecurity' -as [type]){return}
 Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class TTQualificationOcspKeySecurity {
 [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)]
 static extern int NCryptGetProperty(SafeNCryptKeyHandle key,string name,byte[] output,int size,out int required,uint flags);
 [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)]
 static extern int NCryptSetProperty(SafeNCryptKeyHandle key,string name,byte[] input,int size,uint flags);
 public static byte[] ReadDacl(SafeNCryptKeyHandle key) {
  int required;
  if(key==null || key.IsInvalid || key.IsClosed || NCryptGetProperty(key,"Security Descr",null,0,out required,0x44u)!=0 || required<20 || required>16384) throw new IOException("Owned signer DACL size unavailable");
  var bytes=new byte[required]; int actual;
  if(NCryptGetProperty(key,"Security Descr",bytes,bytes.Length,out actual,0x44u)!=0 || actual!=bytes.Length) throw new IOException("Owned signer DACL unavailable");
  return bytes;
 }
 public static void WriteDacl(SafeNCryptKeyHandle key,byte[] bytes) {
  if(key==null || key.IsInvalid || key.IsClosed || bytes==null || bytes.Length<20 || bytes.Length>16384) throw new IOException("Owned signer DACL input refused");
  // DACL_SECURITY_INFORMATION | NCRYPT_SILENT_FLAG | NCRYPT_PERSIST_FLAG.
  // No owner, primary group or SACL mutation is requested.
  if(NCryptSetProperty(key,"Security Descr",bytes,bytes.Length,0x80000044u)!=0) throw new IOException("Owned signer DACL write failed");
 }
}
'@
}

function Get-OcspDaclText([byte[]]$Bytes){
 if(!$Bytes -or $Bytes.Length -lt 20 -or $Bytes.Length -gt 16384){throw 'Bounded signer security descriptor required'}
 $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($Bytes,0)
 if(!$descriptor.DiscretionaryAcl -or !($descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent)){throw 'Signer requires an actual DACL'}
 return $descriptor.GetSddlForm([Security.AccessControl.AccessControlSections]::Access)
}

function Get-OwnedOcspKeyIdentity([Security.Cryptography.CngKey]$Key){
 if(!$Key -or !$Key.IsMachineKey -or $Key.Provider.Provider -cne 'Microsoft Software Key Storage Provider' -or $Key.Algorithm.Algorithm -cne 'RSA' -or $Key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None){throw 'Owned nonexportable machine RSA signer required'}
 if($Key.KeyName -cnotmatch '^tokentimer-enr-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$' -or !$Key.UniqueName){throw 'Canonical exact signer identity required'}
 $rsa=[Security.Cryptography.RSACng]::new($Key)
 try{
  if($rsa.KeySize -ne 2048){throw 'Owned signer requires RSA2048'}
  $public=$rsa.ExportParameters($false)
  # Public modulus/exponent only; no private key material is exported.
  return @{container=$Key.KeyName;unique=$Key.UniqueName;provider=$Key.Provider.Provider;modulus=[Convert]::ToBase64String($public.Modulus);exponent=[Convert]::ToBase64String($public.Exponent)}
 }finally{$rsa.Dispose()}
}

function Assert-OwnedOcspKeyIdentity([Security.Cryptography.CngKey]$Key,$Expected){
 $actual=Get-OwnedOcspKeyIdentity $Key
 foreach($name in @('container','unique','provider','modulus','exponent')){if($actual[$name] -cne $Expected[$name]){throw 'Native signer key identity changed'}}
}

function New-OwnedOcspSignerRequestText([string]$Container,[string]$CommonName) {
 if($Container -cnotmatch '^tokentimer-enr-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$' -or
    $CommonName -cnotmatch '^certops-adcs-[a-f0-9]{8,32}-ocspsigner\.example\.test$') {
  throw 'Exact owned signer request coordinates required'
 }
 # The fixture creates and durably records the nonexportable native CNG key
 # first. Certreq must reuse that exact key and must not generate a second key.
 # Exportable is intentionally absent: certreq forbids it with an existing key.
 # Submit carries the owned signing-template attribute, never the CSR INF.
 return (@(
  '[Version]',
  'Signature="$Windows NT$"',
  '',
  '[NewRequest]',
  ('Subject = "CN='+$CommonName+'"'),
  'MachineKeySet = TRUE',
  'UseExistingKeySet = TRUE',
  ('KeyContainer = "'+$Container+'"'),
  'ProviderName = "Microsoft Software Key Storage Provider"',
  'ProviderType = 0',
  'KeyAlgorithm = RSA',
  'KeyUsage = 0x80',
  'Silent = TRUE',
  'RequestType = PKCS10',
  'HashAlgorithm = SHA256',
  ''
 ) -join "`r`n")
}

function New-OwnedOcspKey([string]$Container){
 if($Container -cnotmatch '^tokentimer-enr-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$'){throw 'Canonical owned signer container required'}
 Initialize-OcspKeySecurity
 $provider=[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
 if([Security.Cryptography.CngKey]::Exists($Container,$provider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)){throw 'Never adopt an existing signer key'}
 $parameters=[Security.Cryptography.CngKeyCreationParameters]::new()
 $parameters.Provider=$provider
 $parameters.KeyCreationOptions=[Security.Cryptography.CngKeyCreationOptions]::MachineKey
 $parameters.ExportPolicy=[Security.Cryptography.CngExportPolicies]::None
 $parameters.KeyUsage=[Security.Cryptography.CngKeyUsages]::Signing
 $parameters.Parameters.Add([Security.Cryptography.CngProperty]::new('Length',[BitConverter]::GetBytes([int]2048),[Security.Cryptography.CngPropertyOptions]::None))
 $key=[Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::Rsa,$Container,$parameters)
 try{
  # Apply only to the key just created after the caller's durable receipt.
  # Existing keys are never repaired or permission-normalized by this helper.
  $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;$sid)")
  $bytes=[byte[]]::new($descriptor.BinaryLength);$descriptor.GetBinaryForm($bytes,0)
  [TTQualificationOcspKeySecurity]::WriteDacl($key.Handle,$bytes)
  $original=[TTQualificationOcspKeySecurity]::ReadDacl($key.Handle)
  if((Get-OcspDaclText $original) -cne (Get-OcspDaclText $bytes)){throw 'New signer private DACL readback mismatch'}
  return @{key=$key;identity=(Get-OwnedOcspKeyIdentity $key);originalDacl=$original}
 }catch{
  # Do not delete an unknown partially created key. The enclosing receipt is
  # deliberately still unresolved and must preserve the disposable fixture.
  $key.Dispose();throw
 }
}

function Get-OwnedOcspServiceIdentity {
 # Observe the native service twice; never derive its account from an expected
 # default alone. An unexpected account is a fixture prerequisite failure.
 $rows=@(Get-CimInstance Win32_Service -Filter "Name='OCSPSvc'" -ErrorAction Stop)
 if($rows.Count -ne 1){throw 'Exact native responder service required'}
 $service=$rows[0]
 if($service.Name -cne 'OCSPSvc' -or $service.StartName -isnot [string] -or
    $service.StartName.Length -lt 1 -or $service.StartName.Length -gt 256 -or
    $service.StartName -match '[\x00-\x1f\x7f]'){throw 'Unexpected responder service account'}
 $account=[Security.Principal.NTAccount]::new($service.StartName)
 $sid=$account.Translate([Security.Principal.SecurityIdentifier]).Value
 if($sid -cne 'S-1-5-20'){throw 'Observed responder account SID mismatch'}
 $created=$null;$image=$null;$processSid=$null
 if($service.ProcessId -gt 0){
  $processRows=@(Get-CimInstance Win32_Process -Filter ('ProcessId='+[uint32]$service.ProcessId) -ErrorAction Stop)
  if($processRows.Count -ne 1 -or !$processRows[0].CreationDate){throw 'Exact responder process creation identity required'}
  $process=$processRows[0]
  $image=[string]$process.ExecutablePath
  if($image -ine (Join-Path $env:SystemRoot 'System32\ocspsvc.exe')){throw 'Original native responder image required'}
  $nativeOwner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop
  if($nativeOwner.ReturnValue -ne 0 -or $nativeOwner.Sid -cne $sid){throw 'Responder process account does not match service'}
  $created=$process.CreationDate.ToUniversalTime().ToString('o')
  $processSid=$nativeOwner.Sid
 }
 $fresh=@(Get-CimInstance Win32_Service -Filter "Name='OCSPSvc'" -ErrorAction Stop)
 if($fresh.Count -ne 1 -or $fresh[0].StartName -cne $service.StartName -or $fresh[0].PathName -cne $service.PathName -or $fresh[0].ProcessId -ne $service.ProcessId){throw 'Responder service identity changed'}
 return @{name=$service.Name;account=$service.StartName;sid=$sid;path=$service.PathName;processId=[uint32]$service.ProcessId;processCreatedAt=$created;executablePath=$image;processSid=$processSid}
}

function Grant-OwnedOcspServiceRead([Security.Cryptography.CngKey]$Key,$Expected,[byte[]]$OriginalDacl,$ServiceIdentity){
 $observed=Get-OwnedOcspServiceIdentity
 if($observed.processId -lt 1){throw 'Actual running responder process required before key grant'}
 foreach($name in @('name','account','sid','path','processId','processCreatedAt','executablePath','processSid')){
  if($null -eq $ServiceIdentity -or $observed[$name] -cne $ServiceIdentity[$name]){throw 'Exact observed responder service identity required'}
 }
 Initialize-OcspKeySecurity
 Assert-OwnedOcspKeyIdentity $Key $Expected
 $before=[TTQualificationOcspKeySecurity]::ReadDacl($Key.Handle)
 if((Get-OcspDaclText $before) -cne (Get-OcspDaclText $OriginalDacl)){throw 'Signer DACL changed before owned service grant'}
 $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($OriginalDacl,0)
 $sid=[Security.Principal.SecurityIdentifier]::new($observed.sid)
 foreach($ace in $descriptor.DiscretionaryAcl){if($ace.SecurityIdentifier -eq $sid){throw 'Never adopt a preexisting responder key grant'}}
 $descriptor.DiscretionaryAcl.InsertAce($descriptor.DiscretionaryAcl.Count,[Security.AccessControl.CommonAce]::new([Security.AccessControl.AceFlags]::None,[Security.AccessControl.AceQualifier]::AccessAllowed,[int]::MinValue,$sid,$false,$null))
 $applied=[byte[]]::new($descriptor.BinaryLength);$descriptor.GetBinaryForm($applied,0)
 [TTQualificationOcspKeySecurity]::WriteDacl($Key.Handle,$applied)
 $actual=[TTQualificationOcspKeySecurity]::ReadDacl($Key.Handle)
 if((Get-OcspDaclText $actual) -cne (Get-OcspDaclText $applied)){throw 'Exact responder key access grant unproven'}
 return ,$actual
}

function Restore-OwnedOcspKeyDacl([Security.Cryptography.CngKey]$Key,$Expected,[byte[]]$OriginalDacl,[byte[]]$AppliedDacl){
 Initialize-OcspKeySecurity
 Assert-OwnedOcspKeyIdentity $Key $Expected
 $actual=[TTQualificationOcspKeySecurity]::ReadDacl($Key.Handle)
 if((Get-OcspDaclText $actual) -cne (Get-OcspDaclText $AppliedDacl)){throw 'Foreign signer key ACL change prevents restoration'}
 [TTQualificationOcspKeySecurity]::WriteDacl($Key.Handle,$OriginalDacl)
 $restored=[TTQualificationOcspKeySecurity]::ReadDacl($Key.Handle)
 if((Get-OcspDaclText $restored) -cne (Get-OcspDaclText $OriginalDacl)){throw 'Original signer key ACL restoration unproven'}
 Assert-OwnedOcspKeyIdentity $Key $Expected
}

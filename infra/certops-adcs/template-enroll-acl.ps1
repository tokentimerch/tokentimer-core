<#
Live exact-machine Enroll denial on the already confirmed owned template.
Only its DACL changes. A durable private original/applied receipt precedes the
LDAP commit; fixed template-GUID serialization and exact compare-before-restore
prevent a second owner from adopting or overwriting another mutation.
#>
param([Parameter(Mandatory)][ValidateSet('Apply','Restore')][string]$Action,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{10}$')][string]$RunId,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$')][string]$OwnershipToken,
 [Parameter(Mandatory)][ValidatePattern('^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$')][string]$MachineSid)
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test' -or !$env:CERTOPS_ADCS_OFFICER_PASSWORD){throw 'Owned isolated qualification forest required'}
$credential=[PSCredential]::new('TTQUAL\tt-lab-admin',(ConvertTo-SecureString $env:CERTOPS_ADCS_OFFICER_PASSWORD -AsPlainText -Force))
Invoke-Command -ComputerName 'tt-ca.lab.certops.test' -Credential $credential -ArgumentList $Action,$RunId,$OwnershipToken,$MachineSid -ScriptBlock {
 param($Action,$RunId,$OwnershipToken,$MachineSid)
 $ErrorActionPreference='Stop'
 if($env:COMPUTERNAME -ine 'tt-ca' -or (Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Exact owned CA host required'}
 Import-Module ActiveDirectory
 $computer=Get-ADComputer -Identity 'tt-agent' -Properties objectSid
 if($computer.SID.Value -cne $MachineSid -or $computer.ObjectClass -ne 'computer'){throw 'Actual member machine SID mismatch'}
 $root=[ADSI]'LDAP://RootDSE'
 $configuration=[string]$root.configurationNamingContext
 $entry=[DirectoryServices.DirectoryEntry]::new("LDAP://CN=TTQualificationRSAShort,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configuration")
 $entry.Options.SecurityMasks=[DirectoryServices.SecurityMasks]::Dacl
 $mutex=$null;$held=$false
 function Sha([byte[]]$Bytes){$h=[Security.Cryptography.SHA256]::Create();try{return [BitConverter]::ToString($h.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
 function TemplateIdentity {
  $entry.RefreshCache()
  if([string]$entry.Properties['cn'].Value -cne 'TTQualificationRSAShort' -or [int]$entry.Properties['revision'].Value -ne 100 -or [int]$entry.Properties['msPKI-Template-Schema-Version'].Value -ne 2 -or [int]$entry.Properties['msPKI-Minimal-Key-Size'].Value -ne 2048){throw 'Owned RSA template identity changed'}
  $guid=[Guid]::new([byte[]]$entry.Properties['objectGUID'].Value).ToString('D').ToLowerInvariant()
  $oid=[string]$entry.Properties['msPKI-Cert-Template-OID'].Value
  if($oid -cnotmatch '^1(?:\.[0-9]+)+$'){throw 'Owned template OID missing'}
  return @{guid=$guid;oid=$oid;revision=100}
 }
 function CurrentDacl {return $entry.ObjectSecurity.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)}
 function PrivateAcl([string]$Path,[bool]$Directory){
  $acl=if($Directory){[Security.AccessControl.DirectorySecurity]::new()}else{[Security.AccessControl.FileSecurity]::new()}
  $acl.SetAccessRuleProtection($true,$false)
  foreach($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')|Select-Object -Unique){
   $principal=[Security.Principal.SecurityIdentifier]::new($sid)
   if($Directory){$rule=[Security.AccessControl.FileSystemAccessRule]::new($principal,'FullControl','ContainerInherit,ObjectInherit','None','Allow')}else{$rule=[Security.AccessControl.FileSystemAccessRule]::new($principal,'FullControl','Allow')}
   $acl.AddAccessRule($rule)
  }
  # Windows PowerShell 5 native filesystem API writes only modified sections;
  # Set-Acl can unnecessarily request SACL privilege for an Access-only object.
  if($Directory){[IO.Directory]::SetAccessControl($Path,$acl)}else{[IO.File]::SetAccessControl($Path,$acl)}
 }
 function AssertRegularDirectory([string]$Path){
  $item=Get-Item -LiteralPath $Path -Force
  if(!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Receipt ancestor must be an existing regular directory'}
 }
 function AssertPrivateDirectory([string]$Path){
  AssertRegularDirectory $Path
  $acl=Get-Acl -LiteralPath $Path
  $allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
  if(!$acl.AreAccessRulesProtected){throw 'Existing receipt directory inherits permissions'}
  $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
  foreach($rule in $rules){
   if($rule.IsInherited -or ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -cnotin $allowed)){throw 'Existing receipt directory grants unowned access'}
  }
  if(!@($rules|Where-Object {$_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -ceq 'S-1-5-18' -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl}).Count){throw 'Receipt directory lacks explicit SYSTEM custody'}
 }
 try{
  $identity=TemplateIdentity
  # Fixed by the shared template, never the caller nonce: independent callers
  # must serialize against the same mutable LDAP object.
  $mutex=[Threading.Mutex]::new($false,"Global\TokenTimerQualification-TemplateEnrollAcl-$($identity.guid)")
  try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true;if($Action -ne 'Restore'){throw 'Abandoned apply ownership requires exact restore'}}
  if(!$held){throw 'Another owned template ACL operation remains active'}
  # Never repair or weaken a preexisting directory's ACL. Every existing
  # ancestor is inspected before creating the isolated protected leaf.
  AssertRegularDirectory $env:ProgramData
  $parent=Join-Path $env:ProgramData 'TokenTimerQualification'
  if(!(Test-Path -LiteralPath $parent)){$null=New-Item -Path $parent -ItemType Directory}
  AssertRegularDirectory $parent
  $directory=Join-Path $parent 'template-enroll-acl'
  if(!(Test-Path -LiteralPath $directory)){$null=New-Item -Path $directory -ItemType Directory;PrivateAcl $directory $true}
  AssertPrivateDirectory $directory
  $receipt=Join-Path $directory "$($identity.guid).json"
  if($Action -eq 'Apply'){
   if(Test-Path -LiteralPath $receipt){throw 'Never adopt an existing template ACL receipt'}
   $security=$entry.ObjectSecurity
   $original=$security.GetSecurityDescriptorBinaryForm()
   $originalSddl=$security.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
   $enroll=[Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
   $sid=[Security.Principal.SecurityIdentifier]::new($MachineSid)
   foreach($rule in $security.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier])){if($rule.IdentityReference.Value -ceq $MachineSid -and $rule.AccessControlType -eq 'Deny' -and $rule.ObjectType -eq $enroll){throw 'Existing same-machine Enroll deny is not fixture-owned'}}
   $security.AddAccessRule([DirectoryServices.ActiveDirectoryAccessRule]::new($sid,[DirectoryServices.ActiveDirectoryRights]::ExtendedRight,[Security.AccessControl.AccessControlType]::Deny,$enroll,[DirectoryServices.ActiveDirectorySecurityInheritance]::None))
   $appliedSddl=$security.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
   if($appliedSddl -ceq $originalSddl){throw 'Exact machine deny was not added'}
   $proof=@{schemaVersion=1;runId=$RunId;token=$OwnershipToken;machineSid=$MachineSid;templateGuid=$identity.guid;templateOid=$identity.oid;revision=100;originalBase64=[Convert]::ToBase64String($original);originalSddl=$originalSddl;appliedSddl=$appliedSddl}
   $bytes=[Text.Encoding]::UTF8.GetBytes(($proof|ConvertTo-Json -Compress))
   if($bytes.Length -gt 32768){throw 'Private DACL receipt exceeds bound'}
   $file=[IO.File]::Open($receipt,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
   try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
   PrivateAcl $receipt $false
   # Only the DACL is requested/written; owner, group and SACL are untouched.
   $entry.ObjectSecurity=$security;$entry.CommitChanges();$current=TemplateIdentity
   if($current.guid -cne $identity.guid -or $current.oid -cne $identity.oid -or (CurrentDacl) -cne $appliedSddl){throw 'Applied owned template DACL readback mismatch'}
  }else{
   $item=Get-Item -LiteralPath $receipt
   if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 32768){throw 'Private DACL receipt is not regular/bounded'}
   $file=[IO.File]::Open($receipt,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
   try{$buffer=[byte[]]::new(32769);$length=0;while($length -lt $buffer.Length){$read=$file.Read($buffer,$length,$buffer.Length-$length);if(!$read){break};$length+=$read};if($length -le 0 -or $length -gt 32768){throw 'Private DACL receipt bound'};$proof=[Text.Encoding]::UTF8.GetString($buffer,0,$length)|ConvertFrom-Json}finally{$file.Dispose()}
   if($proof.schemaVersion -ne 1 -or $proof.runId -cne $RunId -or $proof.token -cne $OwnershipToken -or $proof.machineSid -cne $MachineSid -or $proof.templateGuid -cne $identity.guid -or $proof.templateOid -cne $identity.oid -or $proof.revision -ne 100){throw 'Original template ACL owner mismatch'}
   $originalSddl=[string]$proof.originalSddl;$appliedSddl=[string]$proof.appliedSddl
   $currentSddl=CurrentDacl
   if($currentSddl -cne $appliedSddl -and $currentSddl -cne $originalSddl){throw 'Current template ACL is not the exact owned mutation'}
   $security=[DirectoryServices.ActiveDirectorySecurity]::new();$security.SetSecurityDescriptorBinaryForm([Convert]::FromBase64String($proof.originalBase64),[Security.AccessControl.AccessControlSections]::Access)
   if($security.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access) -cne $originalSddl){throw 'Original template DACL receipt mismatch'}
   $entry.ObjectSecurity=$security;$entry.CommitChanges();$current=TemplateIdentity
   if($current.guid -cne $identity.guid -or $current.oid -cne $identity.oid -or (CurrentDacl) -cne $originalSddl){throw 'Exact template DACL restoration failed'}
  }
  Restart-Service CertSvc -ErrorAction Stop
  (Get-Service CertSvc).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(60))
  & certutil.exe -config 'tt-ca.lab.certops.test\TTQualificationRoot' -ping | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Actual owned CA did not recover after template cache flush'}
  # Keep the immutable private receipt until whole-lab teardown. Restoration
  # does not need to unlink a pathname after releasing its read handle, and a
  # second Apply must never adopt this original owner or silently overwrite it.
  @{scope='actual-live-same-template-current-machine-enroll-dacl';action=$Action;templateGuid=$identity.guid;templateOid=$identity.oid;machineSid=$MachineSid;originalDaclSha256=(Sha ([Text.Encoding]::UTF8.GetBytes($originalSddl)));appliedDaclSha256=(Sha ([Text.Encoding]::UTF8.GetBytes($appliedSddl)));applied=($Action -eq 'Apply');restored=($Action -eq 'Restore');actualCaReady=$true}|ConvertTo-Json -Compress
 }finally{if($held){$mutex.ReleaseMutex()};if($mutex){$mutex.Dispose()};$entry.Dispose();$root.Dispose()}
}

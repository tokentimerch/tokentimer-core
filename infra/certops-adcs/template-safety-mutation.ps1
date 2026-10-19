<#
Live owned LDAP template safety mutation oracle. Records exact attribute presence/values before
mutation and verifies all values after restoration; used by genuine candidate preflight/signed
enrollment refusal cases, not simulated native output.
#>
param([Parameter(Mandatory)][ValidateSet('apply','restore')][string]$Action,
 [Parameter(Mandatory)][ValidateSet('schema-one','application-policy-absent','subject-client-auth','schema-three-algorithm-absent','eku-absent','subject-any-purpose','subject-enrollment-agent','subject-smartcard','subject-pkinit','application-policy-any-purpose','application-policy-client-mixed','minimum-key-absent','template-oid-absent','schema-out-of-range','minimum-key-zero','subject-name-flag-absent')][string]$CaseId,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{10}$')][string]$RunId,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9-]{36}$')][string]$OwnershipToken)
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test' -or -not $env:CERTOPS_ADCS_OFFICER_PASSWORD){throw 'Template mutation requires isolated qualification forest'}
$credential=[PSCredential]::new('TTQUAL\tt-lab-admin',(ConvertTo-SecureString $env:CERTOPS_ADCS_OFFICER_PASSWORD -AsPlainText -Force))
Invoke-Command -ComputerName 'tt-ca.lab.certops.test' -Credential $credential -ArgumentList $Action,$CaseId,$RunId,$OwnershipToken -ScriptBlock {
 param($Action,$CaseId,$RunId,$OwnershipToken)
 $ErrorActionPreference='Stop'
 if($env:COMPUTERNAME -ine 'tt-ca'){throw 'Unexpected template mutation host'}
 $root=[ADSI]'LDAP://RootDSE';$configuration=[string]$root.configurationNamingContext
 $entry=[ADSI]"LDAP://CN=TTQualificationRSAShort,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configuration"
 if([string]$entry.Properties['cn'].Value -ne 'TTQualificationRSAShort' -or [int]$entry.Properties['revision'].Value -ne 100){throw 'Refusing non-fixture template'}
 $receipt=Join-Path $env:TEMP "tokentimer-template-$RunId-$CaseId.xml"
 $attributes=@('pKIExtendedKeyUsage','msPKI-Certificate-Application-Policy','msPKI-Template-Schema-Version','msPKI-Certificate-Name-Flag','msPKI-RA-Application-Policies','msPKI-Minimal-Key-Size','msPKI-Cert-Template-OID')
 try{
  if($Action -eq 'apply'){
   if(Test-Path -LiteralPath $receipt){throw 'Refusing existing template ownership receipt'}
   $values=@{};foreach($name in $attributes){$values[$name]=[object[]]@($entry.Properties[$name])}
   $proof=@{ownershipToken=$OwnershipToken;template='TTQualificationRSAShort';caseId=$CaseId;values=$values}
   $stream=[IO.File]::Open($receipt,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
   try{$serialized=[Management.Automation.PSSerializer]::Serialize($proof);$bytes=[Text.Encoding]::UTF8.GetBytes($serialized);$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
   switch($CaseId){
    'schema-one' {$entry.Properties['msPKI-Template-Schema-Version'].Value=1}
    'application-policy-absent' {$entry.Properties['msPKI-Certificate-Application-Policy'].Clear()}
    'subject-client-auth' {$entry.Properties['msPKI-Certificate-Name-Flag'].Value=1;$entry.Properties['pKIExtendedKeyUsage'].Value='1.3.6.1.5.5.7.3.2'}
    'schema-three-algorithm-absent' {$entry.Properties['msPKI-Template-Schema-Version'].Value=3;$entry.Properties['msPKI-RA-Application-Policies'].Clear()}
    'minimum-key-absent' {$entry.Properties['msPKI-Minimal-Key-Size'].Clear()}
    'minimum-key-zero' {$entry.Properties['msPKI-Minimal-Key-Size'].Value=0}
    'subject-name-flag-absent' {$entry.Properties['msPKI-Certificate-Name-Flag'].Clear()}
    'template-oid-absent' {$entry.Properties['msPKI-Cert-Template-OID'].Clear()}
    'schema-out-of-range' {$entry.Properties['msPKI-Template-Schema-Version'].Value=17}
    'eku-absent' {$entry.Properties['pKIExtendedKeyUsage'].Clear()}
    'subject-any-purpose' {$entry.Properties['msPKI-Certificate-Name-Flag'].Value=1;$entry.Properties['pKIExtendedKeyUsage'].Value='2.5.29.37.0'}
    'subject-enrollment-agent' {$entry.Properties['msPKI-Certificate-Name-Flag'].Value=1;$entry.Properties['pKIExtendedKeyUsage'].Value='1.3.6.1.4.1.311.20.2.1'}
    'subject-smartcard' {$entry.Properties['msPKI-Certificate-Name-Flag'].Value=1;$entry.Properties['pKIExtendedKeyUsage'].Value='1.3.6.1.4.1.311.20.2.2'}
    'subject-pkinit' {$entry.Properties['msPKI-Certificate-Name-Flag'].Value=1;$entry.Properties['pKIExtendedKeyUsage'].Value='1.3.6.1.5.2.3.4'}
    'application-policy-any-purpose' {$entry.Properties['msPKI-Certificate-Application-Policy'].Value='2.5.29.37.0'}
    'application-policy-client-mixed' {$entry.Properties['msPKI-Certificate-Application-Policy'].Clear();$null=$entry.Properties['msPKI-Certificate-Application-Policy'].Add('1.3.6.1.5.5.7.3.1');$null=$entry.Properties['msPKI-Certificate-Application-Policy'].Add('1.3.6.1.5.5.7.3.2')}

   }
   $entry.CommitChanges();$entry.RefreshCache();@{caseId=$CaseId;template='TTQualificationRSAShort';applied=$true}|ConvertTo-Json -Compress
  }else{
   if(-not(Test-Path -LiteralPath $receipt)){@{caseId=$CaseId;absent=$true}|ConvertTo-Json -Compress;return}
   $item=Get-Item -LiteralPath $receipt;if($item.PSIsContainer -or $item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Unsafe template ownership receipt'}
   $proof=Import-Clixml -LiteralPath $receipt
   if($proof.ownershipToken -ne $OwnershipToken -or $proof.template -ne 'TTQualificationRSAShort' -or $proof.caseId -ne $CaseId){throw 'Template ownership receipt mismatch'}
   foreach($name in $attributes){$entry.Properties[$name].Clear();foreach($value in @($proof.values[$name])){$null=$entry.Properties[$name].Add($value)}}
   $entry.CommitChanges();$entry.RefreshCache()
   foreach($name in $attributes){$actual=@($entry.Properties[$name]|ForEach-Object {[string]$_}|Sort-Object);$expected=@($proof.values[$name]|ForEach-Object {[string]$_}|Sort-Object);if(($actual -join [char]0) -cne ($expected -join [char]0)){throw "Template attribute restoration mismatch: $name"}}
   Remove-Item -LiteralPath $receipt;@{caseId=$CaseId;restored=$true;exactPublicAttributesVerified=$true}|ConvertTo-Json -Compress
  }
 }finally{$entry.Dispose();$root.Dispose()}
}

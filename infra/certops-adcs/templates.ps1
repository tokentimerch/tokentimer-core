<#
Publish the real isolated safe/pending/unsafe AD CS template matrix with qualification-only
enrollment ACLs. Provisioner passes committed matrix bytes; native public preflight/enrollment cases
must independently observe these actual LDAP values.
#>
param([Parameter(Mandatory)][string]$DomainPassword,[Parameter(Mandatory)][string]$SafetyCasesBase64)
$ErrorActionPreference = 'Stop'
$safetyCases=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($SafetyCasesBase64)) | ConvertFrom-Json
if($safetyCases.schemaVersion -ne 1 -or $safetyCases.templateCases.Count -lt 14 -or $safetyCases.caFlagCases.Count -lt 3){throw 'Complete public template safety fixture descriptor required'}
if ((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test') { throw 'Template fixtures require isolated qualification forest' }
$credential = [PSCredential]::new('TTQUAL\tt-lab-admin', (ConvertTo-SecureString $DomainPassword -AsPlainText -Force))
Invoke-Command -ComputerName localhost -Credential $credential -ArgumentList $safetyCases -ScriptBlock {
  param($SafetyCases)
  $ErrorActionPreference = 'Stop'
  $serverAuth='1.3.6.1.5.5.7.3.1'
  $definitions=@(
    @{Name='TTQualificationRSA';Bits=2048;Schema=2;Pending=0;Eku=@($serverAuth)},
    @{Name='TTQualificationRSAShort';Bits=2048;Schema=2;Pending=0;Eku=@($serverAuth);ValidityDays=6},
    @{Name='TTQualificationRSA3072';Bits=3072;Schema=2;Pending=0;Eku=@($serverAuth)},
    @{Name='TTQualificationRSA4096';Bits=4096;Schema=2;Pending=0;Eku=@($serverAuth)},
    @{Name='TTQualificationPending';Bits=2048;Schema=2;Pending=2;Eku=@($serverAuth);ValidityDays=6},
    @{Name='TTQualificationPendingOlder';Bits=2048;Schema=2;Pending=2;Eku=@($serverAuth);ValidityDays=2},
    @{Name='TTQualificationEC256';Bits=256;Schema=4;Pending=0;Eku=@($serverAuth);Algorithm='ECDSA_P256'},
    @{Name='TTQualificationEC384';Bits=384;Schema=4;Pending=0;Eku=@($serverAuth);Algorithm='ECDSA_P384'},
    @{Name='TTQualificationEC256Schema3';Bits=256;Schema=3;Pending=0;Eku=@($serverAuth);Algorithm='ECDSA_P256'},
    @{Name='TTQualificationEC384Schema3';Bits=384;Schema=3;Pending=0;Eku=@($serverAuth);Algorithm='ECDSA_P384'},
    @{Name='TTQualificationNoEnroll';Bits=2048;Schema=2;Pending=0;Eku=@($serverAuth);NoEnroll=$true},
    @{Name='TTQualificationUnpublished';Bits=2048;Schema=2;Pending=0;Eku=@($serverAuth);Unpublished=$true}
  )
  foreach($case in $SafetyCases.templateCases){$definitions+=@{Name=$case.name;Bits=2048;Schema=[int]$case.schema;Pending=0;Eku=@($case.eku);ApplicationPolicies=@($case.applicationPolicies)}}
  foreach($case in $SafetyCases.caFlagCases){$definitions+=@{Name=$case.template;Bits=2048;Schema=2;Pending=0;Eku=@($serverAuth)}}
  if(@($definitions.Name | Select-Object -Unique).Count -ne $definitions.Count){throw 'Duplicate owned template safety fixture'}
  $config=([ADSI]'LDAP://RootDSE').configurationNamingContext
  $services="CN=Public Key Services,CN=Services,$config"
  $container=[ADSI]"LDAP://CN=Certificate Templates,$services"
  $oids=[ADSI]"LDAP://CN=OID,$services"
  $source=[ADSI]"LDAP://CN=WebServer,CN=Certificate Templates,$services"
  $forestOid=[string]$oids.Properties['msPKI-Cert-Template-OID'].Value
  if (-not $forestOid) { throw 'Forest template OID unavailable' }
  Import-Module ActiveDirectory
  $computerSid=[Security.Principal.SecurityIdentifier]::new("$((Get-ADDomain).DomainSID.Value)-515")
  if(-not(Get-ADGroup -Identity $computerSid.Value)){throw 'Owned domain computer group missing'}
  $computers=$computerSid
  foreach ($definition in $definitions) {
    if ($container.Children | Where-Object { $_.Properties['cn'].Value -eq $definition.Name }) { throw "Existing fixture template $($definition.Name)" }
    $oid="$forestOid.$(Get-Random -Minimum 1000000 -Maximum 99999999).$(Get-Random -Minimum 1000000 -Maximum 99999999)"
    $oidObject=$oids.Create('msPKI-Enterprise-Oid',"CN=$([Guid]::NewGuid().ToString('N'))")
    $oidObject.Put('msPKI-Cert-Template-OID',$oid)
    $oidObject.Put('displayName',$definition.Name)
    $oidObject.Put('flags',1)
    $oidObject.SetInfo()
    $template=$container.Create('pKICertificateTemplate',"CN=$($definition.Name)")
    foreach ($attribute in @('flags','pKIKeyUsage','pKIExpirationPeriod','pKIOverlapPeriod')) { $template.Put($attribute,$source.Properties[$attribute].Value) }
    if($definition.ValidityDays){
      $template.Put('pKIExpirationPeriod',[BitConverter]::GetBytes([long](-[TimeSpan]::FromDays($definition.ValidityDays).Ticks)))
      $template.Put('pKIOverlapPeriod',[BitConverter]::GetBytes([long](-[TimeSpan]::FromDays(1).Ticks)))
    }
    $values=@{'displayName'=$definition.Name;'revision'=100;'pKIDefaultKeySpec'=1;'pKIMaxIssuingDepth'=0;'msPKI-RA-Signature'=0;'msPKI-Enrollment-Flag'=$definition.Pending;'msPKI-Private-Key-Flag'=0;'msPKI-Certificate-Name-Flag'=1;'msPKI-Minimal-Key-Size'=$definition.Bits;'msPKI-Template-Schema-Version'=$definition.Schema;'msPKI-Template-Minor-Revision'=1;'msPKI-Cert-Template-OID'=$oid}
    foreach ($attribute in $values.Keys) { $template.Put($attribute,$values[$attribute]) }
    $template.Put('pKICriticalExtensions',[object[]]@('2.5.29.15'))
    if($definition.Eku.Count -gt 0){$template.Put('pKIExtendedKeyUsage',[object[]]$definition.Eku)}
    $applicationPolicies=if($definition.ContainsKey('ApplicationPolicies')){$definition.ApplicationPolicies}else{$definition.Eku}
    if($applicationPolicies.Count -gt 0){$template.Put('msPKI-Certificate-Application-Policy',[object[]]$applicationPolicies)}
    if ($definition.Algorithm) {
      $template.Put('pKIKeyUsage',[byte[]](0x80,0x00))
      $template.Put('pKIDefaultCSPs',[object[]]@('1,Microsoft Software Key Storage Provider'))
      $algorithm=$definition.Algorithm
      $template.Put('msPKI-RA-Application-Policies',"msPKI-Asymmetric-Algorithm``PZPWSTR``$algorithm``msPKI-Hash-Algorithm``PZPWSTR``SHA256``msPKI-Key-Usage``DWORD``16777215``msPKI-Symmetric-Algorithm``PZPWSTR``3DES``msPKI-Symmetric-Key-Length``DWORD``168``")
    }
    $template.SetInfo()
    $template.ObjectSecurity.AddAccessRule([DirectoryServices.ActiveDirectoryAccessRule]::new($computers,'GenericRead','Allow'))
    $enrollmentAccess=if($definition.NoEnroll){'Deny'}else{'Allow'}
    $template.ObjectSecurity.AddAccessRule([DirectoryServices.ActiveDirectoryAccessRule]::new($computers,'ExtendedRight',$enrollmentAccess,[Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'))
    $template.CommitChanges()
    if (-not $definition.Unpublished) {
      $published=$false
      for($attempt=0;$attempt -lt 6;$attempt++){
        & certutil.exe -SetCATemplates "+$($definition.Name)" | Out-Null
        if($LASTEXITCODE -eq 0){$published=$true;break}
        Start-Sleep -Seconds 10
      }
      if(-not $published){throw "Fixture template publication failed: $($definition.Name)"}
    }
  }
  & certutil.exe -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'CA encrypted request enforcement failed' }
  & certutil.exe -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'CA SAN attribute hardening failed' }
  $caPath='HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\TTQualificationRoot'
  $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new((Get-ItemProperty -LiteralPath $caPath -Name Security).Security,0)
  $descriptor.DiscretionaryAcl.InsertAce($descriptor.DiscretionaryAcl.Count,[Security.AccessControl.CommonAce]::new('None','AccessAllowed',0x100,$computerSid,$false,$null))
  $encoded=[byte[]]::new($descriptor.BinaryLength)
  $descriptor.GetBinaryForm($encoded,0)
  Set-ItemProperty -LiteralPath $caPath -Name Security -Value $encoded
  Restart-Service CertSvc
  Write-Output 'CERTOPS_STAGE=isolated-template-matrix-published'
}

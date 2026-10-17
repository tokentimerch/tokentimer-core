<# Optional fourth-VM bootstrap for a genuine two-issuer campaign. Invoked only
   in the owned disposable forest; never installs a CA on the agent or offline root.
   Every resource and CA key dies with the same leased resource group. #>
param([Parameter(Mandatory)][ValidateSet('join','install','trust')][string]$Action,
  [Parameter(Mandatory)][string]$DomainPassword)
$ErrorActionPreference='Stop'
$machine=Get-CimInstance Win32_ComputerSystem
if($Action -eq 'join'){
  if($machine.Name -ine 'tt-ca-switch' -or $machine.PartOfDomain){throw 'Destination CA must be a fresh isolated VM'}
  Get-NetAdapter | Where-Object Status -eq 'Up' | Set-DnsClientServerAddress -ServerAddresses '10.64.0.4'
  Resolve-DnsName '_ldap._tcp.dc._msdcs.lab.certops.test' -Type SRV -ErrorAction Stop | Out-Null
  $credential=[PSCredential]::new('TTQUAL\tt-lab-admin',(ConvertTo-SecureString $DomainPassword -AsPlainText -Force))
  Add-Computer -DomainName 'lab.certops.test' -Credential $credential -Force
  Write-Output 'CERTOPS_STAGE=destination-ca-joined-reboot-required'
  return
}
if($machine.Domain -ne 'lab.certops.test' -or -not $machine.PartOfDomain){throw 'Expected isolated qualification forest'}
$config='tt-ca-switch.lab.certops.test\TTQualificationDestination'
if($Action -eq 'trust'){
  if($machine.Name -ine 'tt-agent'){throw 'Only the qualification member may install destination trust'}
  $file=Join-Path $env:TEMP ('tt-destination-'+[Guid]::NewGuid().ToString('N')+'.cer')
  try{
    & certutil.exe -f -config $config -ca.cert $file | Out-Null
    if($LASTEXITCODE){throw 'Destination public CA certificate retrieval failed'}
    $certificate=[Security.Cryptography.X509Certificates.X509Certificate2]::new($file)
    try{if($certificate.Subject -ne 'CN=TTQualificationDestination' -or $certificate.Issuer -ne $certificate.Subject){throw 'Unexpected destination authority'}}finally{$certificate.Dispose()}
    & certutil.exe -addstore Root $file | Out-Null
    if($LASTEXITCODE){throw 'Destination root trust installation failed'}
  }finally{Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue}
  Write-Output 'CERTOPS_STAGE=destination-ca-trusted-by-member'
  return
}
if($machine.Name -ine 'tt-ca-switch' -or (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration')){throw 'Refusing existing or foreign destination CA'}
Enable-PSRemoting -Force
$credential=[PSCredential]::new('TTQUAL\tt-lab-admin',(ConvertTo-SecureString $DomainPassword -AsPlainText -Force))
Invoke-Command -ComputerName localhost -Credential $credential -ScriptBlock {
  $ErrorActionPreference='Stop'
  $role=Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools
  if(-not $role.Success -or [string]$role.RestartNeeded -ne 'No'){throw 'Destination role requires an unsupported reboot'}
  Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName 'TTQualificationDestination' -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -KeyLength 2048 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 1 -Force | Out-Null
  & certutil.exe -SetCATemplates 'TTQualificationRSAShort' | Out-Null
  if($LASTEXITCODE){throw 'Existing safe directory template publication failed'}
  & certutil.exe -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST | Out-Null
  if($LASTEXITCODE){throw 'Destination encrypted request enforcement failed'}
  & certutil.exe -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2 | Out-Null
  if($LASTEXITCODE){throw 'Destination SAN attribute hardening failed'}
  $computer=([ADSI]'LDAP://CN=tt-agent,CN=Computers,DC=lab,DC=certops,DC=test').objectSid
  $sid=[Security.Principal.SecurityIdentifier]::new([byte[]]$computer[0],0)
  $key='HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\TTQualificationDestination'
  $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new((Get-ItemProperty -LiteralPath $key -Name Security).Security,0)
  $descriptor.DiscretionaryAcl.InsertAce($descriptor.DiscretionaryAcl.Count,[Security.AccessControl.CommonAce]::new('None','AccessAllowed',0x100,$sid,$false,$null))
  $bytes=[byte[]]::new($descriptor.BinaryLength);$descriptor.GetBinaryForm($bytes,0)
  Set-ItemProperty -LiteralPath $key -Name Security -Value $bytes
  Restart-Service CertSvc
  if((Get-Service CertSvc).Status -ne 'Running'){throw 'Destination CA did not start'}
}
Write-Output 'CERTOPS_STAGE=destination-enterprise-ca-running'

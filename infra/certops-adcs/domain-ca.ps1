<#
Install/configure the enterprise CA on the freshly provisioned qualification domain server. Called
only by provision-lab.ps1 with a temporary forest credential; creates actual CA service/material,
not simulated certutil output.
#>
param([Parameter(Mandatory)][string]$DomainPassword,[ValidateSet('root','subordinate')][string]$HierarchyRole='root')
$ErrorActionPreference = 'Stop'
if ((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test') { throw 'Expected isolated qualification forest' }
Import-Module ActiveDirectory
$directoryReady=$false
for($attempt=0;$attempt -lt 60;$attempt++){
  try{$null=Get-ADDomain -ErrorAction Stop;$directoryReady=$true;break}catch{Start-Sleep -Seconds 2}
}
if(-not $directoryReady){throw 'New qualification directory did not become ready after reboot'}
Enable-PSRemoting -Force
$credential = [PSCredential]::new('TTQUAL\ttqualification', (ConvertTo-SecureString $DomainPassword -AsPlainText -Force))
Invoke-Command -ComputerName localhost -Credential $credential -ArgumentList $DomainPassword,$HierarchyRole -ScriptBlock {
  param([string]$DomainPassword,[string]$HierarchyRole)
  $ErrorActionPreference = 'Stop'
Import-Module DnsServer
Set-DnsServerForwarder -IPAddress 168.63.129.16
Import-Module ActiveDirectory
New-ADUser -Name 'tt-lab-admin' -SamAccountName 'tt-lab-admin' -AccountPassword (ConvertTo-SecureString $DomainPassword -AsPlainText -Force) -Enabled $true
$domainSid=(Get-ADDomain).DomainSID.Value
Add-ADGroupMember -Identity "$domainSid-512" -Members 'tt-lab-admin'
Add-ADGroupMember -Identity "$domainSid-519" -Members 'tt-lab-admin'
$memberships=@(Get-ADPrincipalGroupMembership 'tt-lab-admin' | ForEach-Object {$_.SID.Value})
if($memberships -notcontains "$domainSid-512" -or $memberships -notcontains "$domainSid-519"){throw 'Owned officer privileged group membership missing'}
if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration') { throw 'Refusing to alter an existing CA' }
$role = Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools
if (-not $role.Success -or $role.RestartNeeded -ne 'No') { throw 'Enterprise CA role install failed or needs another reboot' }
if($HierarchyRole -eq 'subordinate'){
  New-Item -ItemType Directory -Path 'C:\ttqualification-hierarchy' -ErrorAction Stop | Out-Null
  Install-AdcsCertificationAuthority -CAType EnterpriseSubordinateCA -CACommonName 'TTQualificationRoot' -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -KeyLength 2048 -HashAlgorithmName SHA256 -OutputCertRequestFile 'C:\ttqualification-hierarchy\subordinate.req' -Force | Out-Null
  Write-Output ('CERTOPS_SUBORDINATE_REQUEST='+[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\ttqualification-hierarchy\subordinate.req')))
  Write-Output 'CERTOPS_STAGE=enterprise-subordinate-request-created'
  return
}
Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName 'TTQualificationRoot' -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -KeyLength 2048 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 1 -Force | Out-Null
if ((Get-Service CertSvc).Status -ne 'Running') { throw 'Enterprise CA service is not running' }
Write-Output 'CERTOPS_STAGE=enterprise-ca-service-running'

}

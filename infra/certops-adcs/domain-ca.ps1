<#
Install/configure the enterprise CA on the freshly provisioned qualification domain server. Called
only by provision-lab.ps1 with a temporary forest credential; creates actual CA service/material,
not simulated certutil output.
#>
param([Parameter(Mandatory)][string]$DomainPassword,[ValidateSet('root','subordinate')][string]$HierarchyRole='root',[ValidateRange(60,900)][int]$StageTimeoutSeconds=600)
$ErrorActionPreference = 'Stop'
if ((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test') { throw 'Expected isolated qualification forest' }
Import-Module ActiveDirectory
$directoryReady=$false
for($attempt=0;$attempt -lt 60;$attempt++){
  try{$null=Get-ADDomain -ErrorAction Stop;$directoryReady=$true;break}catch{Start-Sleep -Seconds 2}
}
if(-not $directoryReady){throw 'New qualification directory did not become ready after reboot'}
$stageDirectory='C:\ttqualification'
New-Item -ItemType Directory -Path $stageDirectory -Force|Out-Null
$stageFile=Join-Path $stageDirectory 'domain-ca-stage.json'
@{stage='remoting-setup';status='running';updatedAt=[DateTimeOffset]::UtcNow.ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath $stageFile
$job=$null
$credential=$null
try{
Enable-PSRemoting -Force
$credential = [PSCredential]::new('TTQUAL\ttqualification', (ConvertTo-SecureString $DomainPassword -AsPlainText -Force))
$sessionOption=New-PSSessionOption -OpenTimeout 30000 -OperationTimeout 60000
$job=Invoke-Command -ComputerName localhost -Credential $credential -SessionOption $sessionOption -AsJob -ArgumentList $DomainPassword,$HierarchyRole,$stageFile -ScriptBlock {
  param([string]$DomainPassword,[string]$HierarchyRole,[string]$StageFile)
  $ErrorActionPreference = 'Stop'
  function Set-CaStage([string]$Stage){
    @{stage=$Stage;status='running';updatedAt=[DateTimeOffset]::UtcNow.ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath $StageFile
  }
Set-CaStage 'directory-officer'
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
Set-CaStage 'role-install'
$role = Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools
if (-not $role.Success -or $role.RestartNeeded -ne 'No') { throw 'Enterprise CA role install failed or needs another reboot' }
Set-CaStage 'ca-configure'
if($HierarchyRole -eq 'subordinate'){
  New-Item -ItemType Directory -Path 'C:\ttqualification-hierarchy' -ErrorAction Stop | Out-Null
  Install-AdcsCertificationAuthority -CAType EnterpriseSubordinateCA -CACommonName 'TTQualificationRoot' -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -KeyLength 2048 -HashAlgorithmName SHA256 -OutputCertRequestFile 'C:\ttqualification-hierarchy\subordinate.req' -Force | Out-Null
  Write-Output ('CERTOPS_SUBORDINATE_REQUEST='+[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\ttqualification-hierarchy\subordinate.req')))
  Write-Output 'CERTOPS_STAGE=enterprise-subordinate-request-created'
  return
}
Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName 'TTQualificationRoot' -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -KeyLength 2048 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 1 -Force | Out-Null
Set-CaStage 'service-check'
if ((Get-Service CertSvc).Status -ne 'Running') { throw 'Enterprise CA service is not running' }
Write-Output 'CERTOPS_STAGE=enterprise-ca-service-running'

}
# Remoting's OperationTimeout is a transport heartbeat, not an execution limit.
# Bound the complete owned bootstrap job separately; never retry CA creation.
if(-not(Wait-Job -Job $job -Timeout $StageTimeoutSeconds)){throw [TimeoutException]::new('Owned CA bootstrap deadline exceeded')}
Receive-Job -Job $job -ErrorAction Stop
if($job.State -ne 'Completed'){throw 'Owned CA bootstrap did not complete'}
$receipt=Get-Content -LiteralPath $stageFile -Raw|ConvertFrom-Json
$receipt.status='completed';$receipt|ConvertTo-Json|Set-Content -LiteralPath $stageFile
}catch{
$timedOut=$_.Exception -is [TimeoutException]
$stage='remoting-setup'
try{$observed=Get-Content -LiteralPath $stageFile -Raw|ConvertFrom-Json;if($observed.stage -in @('remoting-setup','directory-officer','role-install','ca-configure','service-check')){$stage=$observed.stage}}catch{}
@{stage=$stage;status='failed';timedOut=$timedOut;updatedAt=[DateTimeOffset]::UtcNow.ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath $stageFile
Write-Output ('CERTOPS_CA_FAILED_STAGE='+$stage)
throw 'Owned CA bootstrap failed; inspect the bounded stage receipt'
}finally{
if($job){if($job.State -notin @('Completed','Failed','Stopped')){Stop-Job -Job $job -ErrorAction SilentlyContinue};Remove-Job -Job $job -Force -ErrorAction SilentlyContinue}
$credential=$null;$DomainPassword=$null
}
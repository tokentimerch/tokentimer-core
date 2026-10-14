<#
Bootstrap the isolated lab.certops.test forest and temporary qualification identities on a new
disposable VM. Provisioner-owned Azure resource group/TTL bounds this destructive domain setup;
never run on an existing domain controller.
#>
param([Parameter(Mandatory)][string]$DirectoryRecoveryPassword)
$ErrorActionPreference = 'Stop'
if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) { throw 'Refusing to configure a pre-existing domain' }
$role = Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
if (-not $role.Success) { throw 'AD DS installation failed' }
Import-Module ADDSDeployment
Install-ADDSForest -DomainName 'lab.certops.test' -DomainNetbiosName 'TTQUAL' -InstallDNS -SafeModeAdministratorPassword (ConvertTo-SecureString $DirectoryRecoveryPassword -AsPlainText -Force) -NoRebootOnCompletion -Force
Write-Output 'CERTOPS_STAGE=forest-created-reboot-required'

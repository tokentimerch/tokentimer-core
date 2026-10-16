<#
Join the newly provisioned disposable Windows member to the qualification forest. Uses only its
temporary lab credential and requires a subsequent real reboot/domain verification before installed-
agent tests.
#>
param([Parameter(Mandatory)][string]$DomainPassword)
$ErrorActionPreference = 'Stop'
if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) { throw 'Refusing to rejoin an existing domain member' }
Get-NetAdapter | Where-Object Status -eq 'Up' | Set-DnsClientServerAddress -ServerAddresses '10.64.0.4'
Resolve-DnsName -Name '_ldap._tcp.dc._msdcs.lab.certops.test' -Type SRV -ErrorAction Stop | Out-Null
$role = Install-WindowsFeature Web-Server,Web-Scripting-Tools -IncludeManagementTools
if (-not $role.Success) { throw 'IIS installation failed' }
$credential = [PSCredential]::new('TTQUAL\tt-lab-admin', (ConvertTo-SecureString $DomainPassword -AsPlainText -Force))
Add-Computer -DomainName 'lab.certops.test' -Credential $credential -Force
Write-Output 'CERTOPS_STAGE=member-joined-reboot-required'

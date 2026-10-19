<#
Join the newly provisioned disposable Windows member to the qualification forest. Uses only its
temporary lab credential and requires a subsequent real reboot/domain verification before installed-
agent tests.
#>
param([Parameter(Mandatory)][string]$DomainPassword)
$ErrorActionPreference = 'Stop'
$phase = 'membership'
trap {
  # Run Command output is private. Export only a fixed phase, source line and
  # numeric HRESULT so the provisioner can diagnose a failed join safely.
  Write-Output ('CERTOPS_MEMBER_FAILURE={0}:{1}:{2}' -f $phase,$_.InvocationInfo.ScriptLineNumber,$_.Exception.HResult)
  throw 'Owned domain member setup failed'
}
if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) { throw 'Refusing to rejoin an existing domain member' }
$phase = 'dns-config'
# Azure exposes an additional Up adapter without a DNS-client entry. Select the
# interface owning the member's private IP from main.bicep, not every active link.
$addresses = @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress '10.64.0.5' -ErrorAction Stop)
if ($addresses.Count -ne 1) { throw 'Expected exactly one qualification member IP interface' }
Set-DnsClientServerAddress -InterfaceIndex $addresses[0].InterfaceIndex -ServerAddresses '10.64.0.4'
$phase = 'dns-lookup'
Resolve-DnsName -Name '_ldap._tcp.dc._msdcs.lab.certops.test' -Type SRV -ErrorAction Stop | Out-Null
$phase = 'iis-install'
$role = Install-WindowsFeature Web-Server,Web-Scripting-Tools -IncludeManagementTools
if (-not $role.Success) { throw 'IIS installation failed' }
$phase = 'domain-join'
$credential = [PSCredential]::new('TTQUAL\tt-lab-admin', (ConvertTo-SecureString $DomainPassword -AsPlainText -Force))
Add-Computer -DomainName 'lab.certops.test' -Credential $credential -Force
Write-Output 'CERTOPS_STAGE=member-joined-reboot-required'

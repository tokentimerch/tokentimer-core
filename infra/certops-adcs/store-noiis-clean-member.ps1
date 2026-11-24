# Read-only proof on the newly joined lab member before staging any agent.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$machine = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
if(-not $machine.PartOfDomain -or $machine.Domain -ine 'lab.certops.test' -or -not (Test-ComputerSecureChannel)){
  throw 'Expected the isolated domain-backed member'
}
if($os.ProductType -ne 3 -or [string]$os.BuildNumber -ne '20348' -or
  $machine.SystemType -cnotmatch '^x64-based PC$'){
  throw 'Expected Windows Server 2022 x64 member'
}
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18'){
  throw 'Expected the protected guest command under LocalSystem'
}
$role = Get-WindowsFeature -Name Web-Server -ErrorAction Stop
if($null -eq $role -or $role.Installed){throw 'IIS must be absent on the Store member'}
if($null -ne (Get-CimInstance Win32_Service -Filter "Name='TokenTimerAgent'")){
  throw 'Expected a clean member before any TokenTimerAgent service staging'
}
$null = & certutil.exe -config 'tt-ca.lab.certops.test\TTQualificationRoot' -ping 2>&1
if($LASTEXITCODE){throw 'CA RPC ping failed under the member identity'}
Write-Output 'CERTOPS_STAGE=store-noiis-clean-member-ready'
$proof = [ordered]@{scope='store-noiis-clean-member-readiness';windowsBuild=[string]$os.BuildNumber;architecture='x64';
  localSystem=$true;ownedDomain=$true;iisAbsent=$true;agentServiceAbsent=$true;caRpcPing=$true} | ConvertTo-Json -Compress
Write-Output ('CERTOPS_STORE_NOIIS_RECEIPT=' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($proof)))

Import-Module WebAdministration
$existing = Get-WebBinding -Name "Default Web Site" -Port 11443 -ErrorAction SilentlyContinue
if (-not $existing) {
  New-WebBinding -Name "Default Web Site" -Protocol https -Port 11443 -HostHeader "e2e01.tokentimer-verify.local" -SslFlags 1
}
Get-WebBinding -Name "Default Web Site" | Where-Object { $_.bindingInformation -like "*11443*" } | Select-Object bindingInformation, protocol, sslFlags

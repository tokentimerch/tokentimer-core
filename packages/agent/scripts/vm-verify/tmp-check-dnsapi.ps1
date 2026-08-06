Write-Output "--- state\acme\acme.sh contents ---"
Get-ChildItem -Path "C:\ProgramData\TokenTimerAgent\state\acme\acme.sh" -Recurse -ErrorAction SilentlyContinue | Select-Object FullName
Write-Output "--- tools\acme.sh\dnsapi\dns_certops.sh exists? ---"
Test-Path "C:\ProgramData\TokenTimerAgent\tools\acme.sh\dnsapi\dns_certops.sh"
Write-Output "--- state\acme\acme.sh\dnsapi\dns_certops.sh exists? ---"
Test-Path "C:\ProgramData\TokenTimerAgent\state\acme\acme.sh\dnsapi\dns_certops.sh"

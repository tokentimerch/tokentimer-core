Restart-Service -Name TokenTimerAgent -Force
Start-Sleep -Seconds 3
Get-Service TokenTimerAgent | Select-Object Name, Status

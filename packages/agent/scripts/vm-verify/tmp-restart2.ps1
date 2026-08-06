Restart-Service -Name TokenTimerAgent -Force
Start-Sleep -Seconds 6
Get-Service TokenTimerAgent | Select-Object Name, Status

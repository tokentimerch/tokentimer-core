Get-Content "C:\ProgramData\TokenTimerAgent\state\host.log" -Tail 5
Write-Output "--- current time ---"
Get-Date -Format "u"
Write-Output "--- process check ---"
Get-Process node -ErrorAction SilentlyContinue | Select-Object Id, StartTime

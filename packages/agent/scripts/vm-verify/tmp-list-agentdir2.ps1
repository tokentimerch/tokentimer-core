Get-ChildItem -Path "C:\ProgramData\TokenTimerAgent" -Force | Select-Object Name | Format-Table -AutoSize
Write-Output "---config---"
Get-Content "C:\ProgramData\TokenTimerAgent\config.json" -Raw -ErrorAction SilentlyContinue
Write-Output "---config2---"
Get-Content "C:\ProgramData\TokenTimerAgent\state\config.json" -Raw -ErrorAction SilentlyContinue

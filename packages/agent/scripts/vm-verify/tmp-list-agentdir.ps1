Get-ChildItem -Path "C:\ProgramData\TokenTimerAgent" -Recurse -Depth 3 | Select-Object FullName | Format-Table -AutoSize
Write-Output "---config---"
Get-Content "C:\ProgramData\TokenTimerAgent\config.json" -Raw -ErrorAction SilentlyContinue

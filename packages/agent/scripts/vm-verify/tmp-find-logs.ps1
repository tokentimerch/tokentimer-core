Get-ChildItem "C:\ProgramData\TokenTimerAgent\app\bin" -Filter "*.log" -ErrorAction SilentlyContinue
Get-ChildItem "C:\ProgramData\TokenTimerAgent" -Filter "*.log" -Recurse -ErrorAction SilentlyContinue | Select-Object FullName
Write-Output "--- Application event log (TokenTimerAgent) ---"
Get-EventLog -LogName Application -Source "TokenTimerAgent" -Newest 20 -ErrorAction SilentlyContinue | Select-Object TimeGenerated, EntryType, Message

New-Item -ItemType Directory -Path "C:\ProgramData\TokenTimerAgent\curlhome" -Force | Out-Null
Set-Content -Path "C:\ProgramData\TokenTimerAgent\curlhome\.curlrc" -Value "ssl-no-revoke" -Encoding ascii
[Environment]::SetEnvironmentVariable("HOME", "C:\ProgramData\TokenTimerAgent\curlhome", "Machine")
Write-Output "set HOME machine env var"
Write-Output "--- verify curlrc pickup with HOME set ---"
$env:HOME = "C:\ProgramData\TokenTimerAgent\curlhome"
& "C:\Program Files\Git\bin\bash.exe" -lc "HOME='C:\ProgramData\TokenTimerAgent\curlhome' curl -sS -o /dev/null -w '%{http_code}\n' https://127.0.0.1:14000/dir"

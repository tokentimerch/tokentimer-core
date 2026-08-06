& "C:\Program Files\Git\bin\bash.exe" -lc "grep -n 'ssl-no-revoke\|no-revoke\|schannel' /c/ProgramData/TokenTimerAgent/tools/acme.sh/acme.sh | head -20"
Write-Output "--- retry with --ssl-no-revoke ---"
& "C:\Program Files\Git\bin\bash.exe" -lc "curl --ssl-no-revoke -sS -o /dev/null -w '%{http_code}\n' https://127.0.0.1:14000/dir 2>&1"

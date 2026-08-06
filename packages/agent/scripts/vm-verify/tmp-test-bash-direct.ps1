Write-Output "--- direct bash.exe non-login invocation (mirrors execFile) ---"
& "C:\Program Files\Git\bin\bash.exe" "/c/ProgramData/TokenTimerAgent/tools/acme.sh/acme.sh" --help 2>&1 | Select-Object -First 5
Write-Output "--- node on PATH inside that invocation ---"
& "C:\Program Files\Git\bin\bash.exe" -c "which node; node --version"

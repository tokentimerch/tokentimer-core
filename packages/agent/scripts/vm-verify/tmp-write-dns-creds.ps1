$path = "C:\ProgramData\TokenTimerAgent\state\dns-pebble-challtestsrv-credentials.json"
$json = @{ baseUrl = "http://127.0.0.1:8055"; allowInsecureLocalHttp = $true } | ConvertTo-Json -Compress
[System.IO.File]::WriteAllText($path, $json, (New-Object System.Text.UTF8Encoding($false)))
icacls $path /inheritance:r /grant:r "*S-1-5-18:(F)"
icacls $path

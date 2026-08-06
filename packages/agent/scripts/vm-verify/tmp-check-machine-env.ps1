[Environment]::GetEnvironmentVariable("HOME","Machine")
[Environment]::GetEnvironmentVariable("USERPROFILE","Machine")
Write-Output "---"
[System.Environment]::GetEnvironmentVariables("Machine").Keys -join ","

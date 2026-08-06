$svc = Get-CimInstance Win32_Service -Filter "Name='TokenTimerAgent'"
Write-Output "StartName: $($svc.StartName)"
Write-Output "PathName: $($svc.PathName)"

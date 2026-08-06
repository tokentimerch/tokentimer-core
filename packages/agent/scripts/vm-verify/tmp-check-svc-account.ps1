Get-Service TokenTimerAgent | Select-Object Name, Status
$svc = Get-CimInstance Win32_Service -Filter "Name='TokenTimerAgent'"
$svc | Select-Object Name, StartName, PathName

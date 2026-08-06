Get-ScheduledTask -TaskName "pebble-ca" | Get-ScheduledTaskInfo
(Get-ScheduledTask -TaskName "pebble-ca").Actions
Write-Output "---"
(Get-ScheduledTask -TaskName "pebble-challtestsrv").Actions

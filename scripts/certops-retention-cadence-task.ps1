<#
Exact no-trigger SYSTEM task for the installed default-timer observer.
Public lease publication cannot extend beyond the original immutable sixteen hours.
No agent/service/certificate action is performed by this task adapter.
#>
param([Parameter(Mandatory)][ValidateSet('Start','Observe','WriteLease','Finalize')][string]$Mode,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$Nonce,
 [string]$PublicLeaseBase64)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw 'SYSTEM task ownership required'}
$directory="C:\ttqualification\retention-cadence\$Nonce"
$ConfigPath=Join-Path $directory 'observer-config.json'
$seal=Get-Content -LiteralPath (Join-Path $directory 'configuration-seal.json') -Raw|ConvertFrom-Json
$ConfigSha256=[string]$seal.sha256
if($ConfigSha256 -cnotmatch '^[a-f0-9]{64}$' -or (Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ConfigSha256){throw 'Original protected configuration seal mismatch'}
$c=Get-Content -LiteralPath $ConfigPath -Raw|ConvertFrom-Json
$r=Get-Content -LiteralPath 'C:\ttqualification\runtime.json' -Raw|ConvertFrom-Json
if($r.candidateSha -cne $c.lease.candidateSha -or $r.buildMode -ne 'qualification-only-not-release' -or $c.lease.nonce -cne $Nonce -or $c.lease.taskName -cne "TokenTimer-RetentionCadence-$Nonce"){throw 'Pinned task identity mismatch'}
if($r.source -cne "C:\ttqualification\source\tokentimer-core-$($c.lease.candidateSha)" -or $r.node -cnotmatch '^C:\\ttqualification\\tools\\node-v24\.[0-9]+\.[0-9]+-win-x64\\node.exe$'){throw 'Task runtime outside owned source'}
foreach($ownedPath in @($directory,$ConfigPath,(Join-Path $directory 'configuration-seal.json'))){
 $item=Get-Item -LiteralPath $ownedPath
 if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Task ownership path is reparse'}
 $acl=Get-Acl -LiteralPath $ownedPath
 if(!$acl.AreAccessRulesProtected){throw 'Task ownership ACL is inherited'}
 foreach($rule in $acl.Access){if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'Foreign task control access'}}
}
$node=[string]$r.node;$script=Join-Path $r.source 'scripts\certops-retention-cadence-runtime.js'
if((Get-FileHash -LiteralPath $node -Algorithm SHA256).Hash.ToLowerInvariant() -cne $c.lease.nodeSha256 -or (Get-FileHash -LiteralPath $script -Algorithm SHA256).Hash.ToLowerInvariant() -cne $c.lease.observerSha256){throw 'Task source/runtime hash changed'}
$arguments='"'+$script+'" "'+$ConfigPath+'" '+$ConfigSha256
if($Mode -eq 'Start'){
 if(Get-ScheduledTask -TaskName $c.lease.taskName -ErrorAction SilentlyContinue){throw 'Refuse existing observer task'}
 if(Test-Path -LiteralPath (Join-Path $directory 'observer-started.json')){throw 'Refuse prior observer ownership'}
 $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
 $action=New-ScheduledTaskAction -Execute $node -Argument $arguments -WorkingDirectory $r.source
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 15) -MultipleInstances IgnoreNew
 $null=Register-ScheduledTask -TaskName $c.lease.taskName -Principal $principal -Action $action -Settings $settings
 Start-ScheduledTask -TaskName $c.lease.taskName
 'CERTOPS_RETENTION_CADENCE=task-started';return
}
$task=Get-ScheduledTask -TaskName $c.lease.taskName -ErrorAction Stop
if($task.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or $task.Principal.LogonType -ne 'ServiceAccount' -or $task.Principal.RunLevel -ne 'Highest' -or @($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -cne $node -or $task.Actions[0].Arguments -cne $arguments -or $task.Actions[0].WorkingDirectory -cne $r.source -or @($task.Triggers|Where-Object {$null -ne $_}).Count -ne 0 -or $task.Settings.RestartCount -ne 0 -or [Xml.XmlConvert]::ToTimeSpan($task.Settings.ExecutionTimeLimit).TotalHours -ne 15){throw 'Task XML semantics changed'}
if($Mode -eq 'WriteLease'){
 if(!$PublicLeaseBase64 -or $PublicLeaseBase64.Length -gt 8192){throw 'Bounded public lease required'}
 & $node $script --write-lease $ConfigPath $ConfigSha256 $PublicLeaseBase64
 if($LASTEXITCODE -ne 0){throw 'Original-bound lease publication failed'};return
}
$started=Get-Content -LiteralPath (Join-Path $directory 'observer-started.json') -Raw|ConvertFrom-Json
if($started.configSha256 -cne $ConfigSha256){throw 'Observer source seal mismatch'}
$process=Get-CimInstance Win32_Process -Filter "ProcessId=$($started.processId)"
if($Mode -eq 'Observe'){
 if($task.State -ne 'Running' -or !$process -or $process.ExecutablePath -cne $node -or $process.CreationDate.ToUniversalTime().ToString('o') -cne $started.processCreatedAt -or ($process.CommandLine -cne ('"'+$node+'" '+$arguments) -and $process.CommandLine -cne ($node+' '+$arguments))){throw 'Original observer process absent or changed'}
 $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
 if($owner.ReturnValue -ne 0 -or $owner.Sid -ne 'S-1-5-18'){throw 'Observer process authority changed'}
 & $node $script --observe $ConfigPath $ConfigSha256
 if($LASTEXITCODE -ne 0){throw 'Independent current observer readback failed'}
}else{
 $info=Get-ScheduledTaskInfo -TaskName $c.lease.taskName
 if($task.State -ne 'Ready' -or $info.LastTaskResult -ne 0 -or ($process -and $process.CreationDate.ToUniversalTime().ToString('o') -ceq $started.processCreatedAt)){throw 'Original observer must complete and drain'}
 & $node $script --final-observe $ConfigPath $ConfigSha256
 if($LASTEXITCODE -ne 0){throw 'Independent completed observer readback failed'}
}

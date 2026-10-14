<#
Dedicated task custody adapter. Start is explicit; no logon/reboot trigger or
restart policy can splice distinct resident clocks. Guest readback is supporting
evidence only; the independent controller compares exact VM/nonce/source/task
facts before extending the ordinary four-hour lease. No native certificate action.
#>
param([Parameter(Mandatory)][ValidateSet('Start','Observe','Finalize')][string]$Mode,
 [Parameter(Mandatory)][ValidatePattern('^C:\\ttqualification\\retention24h\\[a-f0-9]{64}\\keeper-config.json$')][string]$ConfigPath,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ConfigSha256)
$ErrorActionPreference='Stop'
$verificationStarted=[DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
if((Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ConfigSha256){throw 'Frozen keeper config mismatch'}
$c=Get-Content -LiteralPath $ConfigPath -Raw|ConvertFrom-Json
$r=Get-Content 'C:\ttqualification\runtime.json' -Raw|ConvertFrom-Json
if($r.candidateSha -cne $c.lease.candidateSha -or $r.buildMode -ne 'qualification-only-not-release'){throw 'Candidate runtime mismatch'}
if($c.lease.taskName -cne "TokenTimer-Retention24h-$($c.lease.nonce)" -or $ConfigPath -cne "C:\ttqualification\retention24h\$($c.lease.nonce)\keeper-config.json"){throw 'Task receipt scope mismatch'}
if($r.source -cne "C:\ttqualification\source\tokentimer-core-$($c.lease.candidateSha)" -or $r.node -cnotmatch '^C:\\ttqualification\\tools\\node-v24\.[0-9]+\.[0-9]+-win-x64\\node.exe$'){throw 'Task command paths outside pinned runtime'}
foreach($ownedPath in @((Split-Path $ConfigPath),$ConfigPath)){
 $acl=Get-Acl -LiteralPath $ownedPath
 if($ownedPath -eq (Split-Path $ConfigPath) -and !$acl.AreAccessRulesProtected){throw 'Keeper ownership directory must have protected ACL'}
 foreach($rule in $acl.Access){if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'Keeper control state ACL permits foreign access'}}
}
$node=[IO.Path]::GetFullPath($r.node);$script=Join-Path $r.source 'scripts\certops-retention24h-runtime.js'
if((Get-FileHash -LiteralPath $node -Algorithm SHA256).Hash.ToLowerInvariant() -cne $c.lease.nodeSha256 -or (Get-FileHash -LiteralPath $script -Algorithm SHA256).Hash.ToLowerInvariant() -cne $c.lease.keeperSha256){throw 'Exact task executable/source mismatch'}
$arguments='"'+$script+'" "'+$ConfigPath+'" '+$ConfigSha256
if($Mode -eq 'Start'){
 if(Get-ScheduledTask -TaskName $c.lease.taskName -ErrorAction SilentlyContinue){throw 'Never adopt existing keeper task'}
 if(Test-Path -LiteralPath (Join-Path (Split-Path $ConfigPath) 'resident-ready.json')){throw 'Never resume a prior resident process'}
 $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
 $action=New-ScheduledTaskAction -Execute $node -Argument $arguments -WorkingDirectory $r.source
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 26) -MultipleInstances IgnoreNew
 $null=Register-ScheduledTask -TaskName $c.lease.taskName -Action $action -Principal $principal -Settings $settings -Description "Owned retention24h $($c.lease.nonce) candidate $($c.lease.candidateSha)"
 Start-ScheduledTask -TaskName $c.lease.taskName
}
$task=Get-ScheduledTask -TaskName $c.lease.taskName -ErrorAction Stop
if($task.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or $task.Principal.LogonType -ne 'ServiceAccount' -or $task.Principal.RunLevel -ne 'Highest' -or @($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -cne $node -or $task.Actions[0].Arguments -cne $arguments -or $task.Actions[0].WorkingDirectory -cne $r.source -or @($task.Triggers|Where-Object {$null -ne $_}).Count -ne 0 -or $task.Settings.RestartCount -ne 0 -or [System.Xml.XmlConvert]::ToTimeSpan($task.Settings.ExecutionTimeLimit).TotalHours -ne 26){throw 'Exact task XML semantics mismatch'}
if($Mode -eq 'Start'){'CERTOPS_RETENTION24H=task-started';return}
$readyPath=Join-Path (Split-Path $ConfigPath) 'resident-ready.json'
if((Get-Item -LiteralPath $readyPath).Length -gt 8192){throw 'Resident readiness receipt exceeds bound'}
$ready=Get-Content -LiteralPath $readyPath -Raw|ConvertFrom-Json
if(($ready.readinessMonotonicElapsedMs -isnot [int] -and $ready.readinessMonotonicElapsedMs -isnot [long]) -or $ready.readinessMonotonicElapsedMs -lt 0 -or $ready.readinessMonotonicElapsedMs -ge 14400000){throw 'Actual readiness monotonic observation absent'}
if($ready.nonce -cne $c.lease.nonce -or $ready.candidateSha -cne $c.lease.candidateSha -or $ready.configSha256 -cne $ConfigSha256 -or $ready.nodeSha256 -cne $c.lease.nodeSha256){throw 'Resident receipt identity mismatch'}
$process=Get-CimInstance Win32_Process -Filter "ProcessId=$($ready.pid)"
$xmlSha=[Security.Cryptography.SHA256]::Create()
try{$xmlHash=([BitConverter]::ToString($xmlSha.ComputeHash([Text.Encoding]::UTF8.GetBytes((Export-ScheduledTask -TaskName $c.lease.taskName))))).Replace('-','').ToLowerInvariant()}finally{$xmlSha.Dispose()}
if($Mode -eq 'Observe'){
 if($task.State -ne 'Running'){throw 'Resident keeper task is not running'}
 if(!$process -or $process.ExecutablePath -cne $node -or ($process.CommandLine -cne ('"'+$node+'" '+$arguments) -and $process.CommandLine -cne ($node+' '+$arguments)) -or $process.CreationDate.ToUniversalTime().ToString('o') -cne $ready.processCreatedAt){throw 'Resident exact process identity mismatch'}
 $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
 if($owner.ReturnValue -ne 0 -or $owner.Sid -ne 'S-1-5-18'){throw 'Resident process is not SYSTEM'}
 $native=& $node $script --observe $ConfigPath $ConfigSha256
 if($LASTEXITCODE -ne 0){throw 'Independent handoff native oracle failed'}
 $observed=$native|ConvertFrom-Json
}else{
 $info=Get-ScheduledTaskInfo -TaskName $c.lease.taskName
 if($task.State -ne 'Ready' -or $info.LastTaskResult -ne 0){throw 'Resident keeper must complete successfully'}
 if($process -and $process.CreationDate.ToUniversalTime().ToString('o') -ceq $ready.processCreatedAt){throw 'Exact resident process remains live'}
 $resultPath=Join-Path (Split-Path $ConfigPath) 'resident-result.json'
 if((Get-Item -LiteralPath $resultPath).Length -gt 16384){throw 'Resident final result exceeds bound'}
 $result=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
 if($result.scope -ne 'resident-timing-only-native-oracles-required' -or $result.collector -ne 'production-default-clock' -or $result.retentionHours -ne 24 -or $result.monotonicElapsedMs -isnot [long] -and $result.monotonicElapsedMs -isnot [int] -or $result.monotonicElapsedMs -lt 86400000 -or $result.monotonicElapsedMs -gt 90000000 -or $result.keptSweepCount -lt 2 -or $result.keptSweepCount -gt 26 -or $result.maximumSweepGapMs -lt 1 -or $result.maximumSweepGapMs -gt 3900000 -or [DateTimeOffset]::Parse($result.preDeadlineObservedAt) -ge [DateTimeOffset]::Parse($c.cleanupDeadline) -or $result.nativeCustodyVerified -ne $true -or $result.trustedTlsVerified -ne $true -or $result.actualProductionLedgerVerified -ne $true -or $result.pid -ne $ready.pid -or $result.processCreatedAt -cne $ready.processCreatedAt -or $result.bootTime -cne $ready.bootTime -or $result.configSha256 -cne $ConfigSha256 -or $result.candidateSha -cne $c.lease.candidateSha -or $result.nonce -cne $c.lease.nonce){throw 'Resident full elapsed result incomplete'}
 $native=& $node $script --final-observe $ConfigPath $ConfigSha256
 if($LASTEXITCODE -ne 0){throw 'Independent final current native oracle failed'}
 $observed=$native|ConvertFrom-Json
}
if($observed.bootTime -cne $ready.bootTime){throw 'Actual VM boot differs from resident process receipt'}
$out=@{}
foreach($name in @('candidateSha','runId','runAttempt','nonce','vmResourceId','vmId','taskName','nodeSha256','keeperSha256')){$out[$name]=$c.lease.$name}
foreach($name in @('nativeCustodyVerified','trustedTlsVerified','soleAgentStoppedAndDrained','productionCutoverVerified','ledgerUnmodified','verifiedCutoverAt','oldNotAfter','cleanupDeadline','bootTime','actualPredecessorCertificateAbsent','actualPredecessorKeyAbsent','replacementCngCustodyVerified','replacementIisSniBindingVerified')){$out[$name]=$observed.$name}
foreach($name in @('taskXmlVerified','vmIdentityVerified','nodeHashVerified','keeperHashVerified','residentProcessVerified')){$out[$name]=$true}
$out.taskXmlSha256=$xmlHash;$out.processId=[int]$ready.pid;$out.processCreatedAt=$ready.processCreatedAt;$out.principalSid='S-1-5-18';$out.taskState=[string]$task.State;$out.configSha256=$ConfigSha256
$out.nativeVerificationStartedAt=$verificationStarted;$out.nativeVerificationFinishedAt=[DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$out.monotonicElapsedMs=if($Mode -eq 'Observe'){[long]$ready.readinessMonotonicElapsedMs}else{[long]$result.monotonicElapsedMs}
if($Mode -eq 'Finalize'){$out.residentResult=$result;$out.currentNativeDeletionVerified=$true}
$out|ConvertTo-Json -Depth 8 -Compress

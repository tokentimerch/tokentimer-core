<#
Separate default-TTL task custody. SYSTEM, original VM/candidate, protected local
config seal and exact task/process are mandatory. Public readback contains no
resume credential or local private config. No certificate/service mutation.
#>
param([Parameter(Mandatory)][ValidateSet('Start','Resident','Observe','WriteLease','Finalize')][string]$Mode,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$Nonce,
 [ValidatePattern('^[A-Za-z0-9+/=]{1,8192}$')][string]$PublicLeaseBase64)
$ErrorActionPreference='Stop'
$started=[DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18' -or (Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Original disposable SYSTEM member required'}
$directory="C:\ttqualification\adcs-ttl24h\$Nonce";$configPath=Join-Path $directory 'runtime-private.json';$sealPath=Join-Path $directory 'configuration-seal.json'
foreach($file in @($directory,$configPath,$sealPath)){
 $item=Get-Item -LiteralPath $file;if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Foreign control-state reparse point preserved'}
 $acl=Get-Acl -LiteralPath $file;if($file -eq $directory -and !$acl.AreAccessRulesProtected){throw 'Private ownership directory ACL must be protected'}
 foreach($rule in $acl.Access){if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'Foreign private-state access refused'}}
}
if((Get-Item -LiteralPath $configPath).Length -gt 16384 -or (Get-Item -LiteralPath $sealPath).Length -gt 4096){throw 'Private control state exceeds bound'}
$seal=Get-Content -LiteralPath $sealPath -Raw|ConvertFrom-Json
if($seal.schemaVersion -ne 1 -or $seal.kind -cne 'certops-native-adcs-ttl24h' -or $seal.nonce -cne $Nonce -or $seal.configSha256 -cnotmatch '^[a-f0-9]{64}$' -or $seal.configFileId -cnotmatch '^[1-9][0-9]{0,19}$'){throw 'Original config seal missing'}
if((Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $seal.configSha256){throw 'Original private config changed'}
$c=Get-Content -LiteralPath $configPath -Raw|ConvertFrom-Json;$r=Get-Content -LiteralPath 'C:\ttqualification\runtime.json' -Raw|ConvertFrom-Json
if($c.kind -cne 'certops-native-adcs-ttl24h' -or $c.lease.nonce -cne $Nonce -or $c.lease.taskName -cne "TokenTimer-AdcsTtl24h-$Nonce" -or $r.candidateSha -cne $c.lease.candidateSha -or $r.buildMode -ne 'qualification-only-not-release'){throw 'Separate original task ownership mismatch'}
if($r.source -cne "C:\ttqualification\source\tokentimer-core-$($c.lease.candidateSha)" -or $r.node -cnotmatch '^C:\\ttqualification\\tools\\node-v24\.[0-9]+\.[0-9]+-win-x64\\node.exe$'){throw 'Pinned original runtime paths required'}
$node=$r.node;$script=Join-Path $r.source 'scripts\certops-adcs-ttl24h-resident.js';$contract=Join-Path $r.source 'scripts\certops-adcs-ttl24h-contract.js';$leasePath=Join-Path $directory 'resident-lease.json'
if((Get-FileHash -LiteralPath $node -Algorithm SHA256).Hash.ToLowerInvariant() -cne $c.lease.nodeSha256 -or (Get-FileHash -LiteralPath $script -Algorithm SHA256).Hash.ToLowerInvariant() -cne $c.lease.keeperSha256){throw 'Exact original Node/resident hashes required'}
$actualFileId=& $node '-e' 'process.stdout.write(require("node:fs").lstatSync(process.argv[1],{bigint:true}).ino.toString())' $configPath
if($LASTEXITCODE -ne 0 -or $actualFileId -cne $seal.configFileId){throw 'Original private config file replaced'}
$env:PATH=$r.path;$env:NODE_ENV='test';$env:NODE_EXTRA_CA_CERTS='C:\ttqualification\api-public.pem';$env:CERTOPS_ADCS_DISPOSABLE_LAB='1';$env:CERTOPS_ADCS_TTL24H='1'
$residentArguments='"'+$script+'" "'+$configPath+'" '+$seal.configSha256+' "'+$leasePath+'"'
if($Mode -eq 'Resident'){
 & $node $script $configPath $seal.configSha256 $leasePath
 if($LASTEXITCODE -ne 0){throw 'Resident failed; preserve private ownership state'}
 exit 0
}
$powershell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$PSCommandPath+'" -Mode Resident -Nonce '+$Nonce
if($Mode -eq 'Start'){
 if(Get-ScheduledTask -TaskName $c.lease.taskName -ErrorAction SilentlyContinue){throw 'Never adopt an existing TTL task'}
 if(Test-Path -LiteralPath (Join-Path $directory 'resident-ready.json')){throw 'Never resume a prior TTL resident'}
 $action=New-ScheduledTaskAction -Execute $powershell -Argument $arguments -WorkingDirectory $r.source
 $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 26) -MultipleInstances IgnoreNew
 $null=Register-ScheduledTask -TaskName $c.lease.taskName -Action $action -Principal $principal -Settings $settings -Description "Owned default AD CS TTL24h $Nonce candidate $($c.lease.candidateSha)"
 Start-ScheduledTask -TaskName $c.lease.taskName
 $wait=[Diagnostics.Stopwatch]::StartNew();while(!(Test-Path -LiteralPath (Join-Path $directory 'resident-ready.json')) -and $wait.Elapsed.TotalSeconds -lt 180){Start-Sleep -Milliseconds 250}
 if(!(Test-Path -LiteralPath (Join-Path $directory 'resident-ready.json'))){throw 'Actual resident readiness missing; preserve task state'}
}
$task=Get-ScheduledTask -TaskName $c.lease.taskName -ErrorAction Stop
if($task.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or $task.Principal.LogonType -ne 'ServiceAccount' -or $task.Principal.RunLevel -ne 'Highest' -or @($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -cne $powershell -or $task.Actions[0].Arguments -cne $arguments -or $task.Actions[0].WorkingDirectory -cne $r.source -or @($task.Triggers|Where-Object {$null -ne $_}).Count -ne 0 -or $task.Settings.RestartCount -ne 0 -or [System.Xml.XmlConvert]::ToTimeSpan($task.Settings.ExecutionTimeLimit).TotalHours -ne 26){throw 'Exact original task XML semantics mismatch'}
$readyPath=Join-Path $directory 'resident-ready.json';if((Get-Item -LiteralPath $readyPath).Length -gt 8192){throw 'Bounded native readiness required'};$ready=Get-Content -LiteralPath $readyPath -Raw|ConvertFrom-Json
if($ready.candidateSha -cne $c.lease.candidateSha -or $ready.nonce -cne $Nonce -or $ready.vmId -cne $c.lease.vmId -or $ready.preparedSha256 -cne $c.preparedSha256 -or $ready.processId -lt 1){throw 'Exact original readiness identity mismatch'}
$process=Get-CimInstance Win32_Process -Filter "ProcessId=$($ready.processId)"
if($Mode -eq 'Finalize'){
 $info=Get-ScheduledTaskInfo -TaskName $c.lease.taskName
 if($task.State -ne 'Ready' -or $info.LastTaskResult -ne 0 -or ($process -and $process.CreationDate.ToUniversalTime().ToString('o') -ceq $ready.processCreatedAt)){throw 'Original resident has not completed and drained'}
}else{
 if($task.State -ne 'Running' -or !$process -or $process.ExecutablePath -cne $node -or ($process.CommandLine -cne ('"'+$node+'" '+$residentArguments) -and $process.CommandLine -cne ($node+' '+$residentArguments)) -or $process.CreationDate.ToUniversalTime().ToString('o') -cne $ready.processCreatedAt){throw 'Exact running resident process required'}
 $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid;if($owner.ReturnValue -ne 0 -or $owner.Sid -ne 'S-1-5-18'){throw 'Original resident must be SYSTEM'}
}
$raw=& $node $script '--observe' $configPath $seal.configSha256;if($LASTEXITCODE -ne 0){throw 'Independent current native observer refused'};$observed=$raw|ConvertFrom-Json
$out=@{};foreach($key in @('candidateSha','runId','runAttempt','nonce','vmResourceId','vmId','taskName','nodeSha256','keeperSha256')){$out[$key]=$c.lease.$key}
foreach($key in @('bootTime','soleAgentStoppedAndDrained','originalCacheAndJournalUnmodified','predecessorNativeCustodyVerified','predecessorTrustedTlsVerified','deferredUnacceptedNativeCustodyVerified')){$out[$key]=$observed.$key}
if($out.bootTime -cne $ready.bootTime){throw 'Resident boot changed'}
$sha=[Security.Cryptography.SHA256]::Create();try{$out.taskXmlSha256=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes((Export-ScheduledTask -TaskName $c.lease.taskName))))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
$out.preparedSha256=$c.preparedSha256;$out.processId=[int]$ready.processId;$out.processCreatedAt=$ready.processCreatedAt;$out.principalSid='S-1-5-18';$out.taskState=[string]$task.State;$out.nativeVerificationStartedAt=$started;$out.nativeVerificationFinishedAt=[DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ');$out.monotonicElapsedMs=[long]$ready.readinessMonotonicElapsedMs
if($Mode -eq 'WriteLease'){
 if(!$PublicLeaseBase64){throw 'Explicit authenticated public lease required'}
 & $node '-e' 'const h=require(process.argv[1]);h.writeLease(process.argv[2],process.argv[3],JSON.parse(Buffer.from(process.argv[4],"base64"))).then(()=>{}).catch(()=>process.exitCode=1)' $script $configPath $seal.configSha256 $PublicLeaseBase64
 if($LASTEXITCODE -ne 0){throw 'Separate authenticated lease write refused'}
}
if($Mode -eq 'Finalize'){$out.residentTiming=Get-Content -LiteralPath (Join-Path $directory 'resident-timing.json') -Raw|ConvertFrom-Json}
$out|ConvertTo-Json -Depth 8 -Compress

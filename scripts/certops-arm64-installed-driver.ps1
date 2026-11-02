<#
Run the actual installed-agent harness as SYSTEM on a disposable hosted ARM64
desktop. Only an exact nonce-owned task may be stopped. An interrupted harness
does not authorize deleting its service, certificates or recovery state; the
ephemeral runner is discarded. No raw settings/state are uploaded.
#>
param([ValidateSet('Run','System')][string]$Mode='Run',[string]$Settings,[string]$SettingsSha256,[string]$Nonce)
$ErrorActionPreference='Stop'
if([Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne [Runtime.InteropServices.Architecture]::Arm64){throw 'Native ARM64 PowerShell required'}
if($Mode -eq 'System'){
 if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw 'Actual SYSTEM identity required'}
 if($Nonce -notmatch '^[a-f0-9]{32}$' -or $SettingsSha256 -notmatch '^[a-f0-9]{64}$'){throw 'Invalid exact task ownership'}
 if((Get-FileHash -LiteralPath $Settings -Algorithm SHA256).Hash.ToLowerInvariant() -ne $SettingsSha256){throw 'Original task environment changed'}
 $v=Get-Content -LiteralPath $Settings -Raw|ConvertFrom-Json
 if($v.nonce -ne $Nonce -or (Split-Path -Leaf (Split-Path -Parent $Settings)) -ne "certops-arm64-agent-task-$Nonce"){throw 'Foreign launch receipt refused'}
 foreach($p in $v.environment.PSObject.Properties){[Environment]::SetEnvironmentVariable($p.Name,[string]$p.Value,'Process')}
 Set-Location -LiteralPath $v.repo
 try{& $v.node 'scripts/certops-arm64-installed-agent.js';$code=$LASTEXITCODE;if($null -eq $code){$code=1}}catch{$code=1}
 [IO.File]::WriteAllText($v.exit,[string]$code)
 exit $code
}
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:CERTOPS_ARM64_AGENT_REQUIRED -ne '1'){throw 'Disposable trusted hosted qualification required'}
$nonce=[Guid]::NewGuid().ToString('N');$root=Join-Path $env:RUNNER_TEMP "certops-arm64-agent-task-$nonce"
if(Test-Path -LiteralPath $root){throw 'Foreign task directory exists'}
New-Item -ItemType Directory -Path $root|Out-Null
$settings=Join-Path $root 'environment.json';$exitFile=Join-Path $root 'exit.txt';$node=(Get-Command node.exe).Source;$pwsh=(Get-Process -Id $PID).Path
$environment=[ordered]@{}
foreach($name in @('NODE_ENV','CERTOPS_ENABLED','CERTOPS_ARM64_AGENT_REQUIRED','CERTOPS_ARM64_AGENT_PWSH','CERTOPS_ARM64_PG_PROOF','GITHUB_ACTIONS','GITHUB_SHA','RUNNER_ENVIRONMENT','RUNNER_TEMP','DB_HOST','DB_PORT','DB_USER','DB_PASSWORD','DB_NAME','PATH')){$environment[$name]=[Environment]::GetEnvironmentVariable($name)}
$environment.GIT_CONFIG_COUNT='1';$environment.GIT_CONFIG_KEY_0='safe.directory';$environment.GIT_CONFIG_VALUE_0=$env:GITHUB_WORKSPACE
@{nonce=$nonce;node=$node;repo=$env:GITHUB_WORKSPACE;exit=$exitFile;environment=$environment}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $settings -Encoding utf8
$digest=(Get-FileHash -LiteralPath $settings -Algorithm SHA256).Hash.ToLowerInvariant();$taskName="CertOpsArm64Agent-$nonce"
if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'Foreign task name exists'}
$arguments="-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Mode System -Settings `"$settings`" -SettingsSha256 $digest -Nonce $nonce"
$action=New-ScheduledTaskAction -Execute $pwsh -Argument $arguments -WorkingDirectory $env:GITHUB_WORKSPACE
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$limits=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 18)
Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $limits|Out-Null
$originalXml=Export-ScheduledTask -TaskName $taskName
function Assert-TaskOwnership{if((Export-ScheduledTask -TaskName $taskName) -cne $originalXml){throw 'Foreign replacement task preserved'}}
try{
 Assert-TaskOwnership;Start-ScheduledTask -TaskName $taskName
 $watch=[Diagnostics.Stopwatch]::StartNew()
 while(!(Test-Path -LiteralPath $exitFile) -and $watch.Elapsed.TotalMinutes -lt 17){Start-Sleep -Milliseconds 500}
 if(!(Test-Path -LiteralPath $exitFile)){throw 'ARM64 installed-agent task timed out; native ownership evidence preserved'}
 Assert-TaskOwnership
 $code=[int](Get-Content -LiteralPath $exitFile -Raw)
 if($code -ne 0){throw 'ARM64 installed-agent harness failed; private state preserved'}
}finally{
 Assert-TaskOwnership
 if((Get-ScheduledTask -TaskName $taskName).State -eq 'Running'){Stop-ScheduledTask -TaskName $taskName}
 $deadline=[Diagnostics.Stopwatch]::StartNew()
 while((Get-ScheduledTask -TaskName $taskName).State -eq 'Running' -and $deadline.Elapsed.TotalSeconds -lt 30){Start-Sleep -Milliseconds 250}
 if((Get-ScheduledTask -TaskName $taskName).State -eq 'Running'){throw 'Owned task did not drain; receipt preserved'}
 Assert-TaskOwnership;Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
 # Task resources are bounded public launch files; retain them privately on
 # failure rather than infer native service/process drainage from task state.
}

<#
Orderly stop/drain of the exact fresh qualification-installed agent. This script
never kills/adopts a PID; it captures native identities before SCM stop, requires
all captured identities absent, and refuses any unexpected surviving descendant.
The stopped installed service stays present for resident-keeper custody checks.
#>
param([Parameter(Mandatory)][ValidatePattern('^C:\\ttqualification\\retention-cadence\\[a-f0-9]{64}\\agent$')][string]$StateDir,
 [Parameter(Mandatory)][string]$RepositoryRoot,[Parameter(Mandatory)][string]$NodeExecutable)
$ErrorActionPreference='Stop'
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18' -or (Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Owned SYSTEM domain service required'}
$r=Get-Content 'C:\ttqualification\runtime.json' -Raw|ConvertFrom-Json
if($RepositoryRoot -cne $r.source -or $NodeExecutable -cne $r.node){throw 'Pinned service runtime mismatch'}
$hostPath=Join-Path $RepositoryRoot 'packages\agent\bin\tokentimer-agent-host-amd64.exe'
$agentPath=Join-Path $RepositoryRoot 'packages\agent\bin\tokentimer-agent.js'
$expected='"'+$hostPath+'" "'+$NodeExecutable+'" "'+$agentPath+'"'
$s=Get-CimInstance Win32_Service -Filter "Name='TokenTimerAgent'"
if(!$s -or $s.PathName -cne $expected -or $s.State -ne 'Running' -or $s.ProcessId -lt 1){throw 'Exact fresh installed running service required'}
$key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services\TokenTimerAgent')
try{
 $configs=@($key.GetValue('Environment')|Where-Object {$_ -like 'TOKENTIMER_AGENT_CONFIG_DIR=*'})
 if($configs.Count -ne 1 -or $configs[0] -cne "TOKENTIMER_AGENT_CONFIG_DIR=$StateDir" -or $null -ne $key.GetValue('FailureActions')){throw 'Foreign config or automatic SCM recovery'}
}finally{$key.Dispose()}
$all=@(Get-CimInstance Win32_Process);$ids=@([int]$s.ProcessId)
for($i=0;$i -lt $ids.Count;$i++){
 foreach($process in $all){if($process.ParentProcessId -eq $ids[$i] -and $process.ProcessId -notin $ids){$ids+=[int]$process.ProcessId;if($ids.Count -gt 64){throw 'Owned native tree exceeds bound'}}}
}
$owned=@($all|Where-Object ProcessId -in $ids)
if($owned.Count -ne $ids.Count){throw 'Native tree changed during capture'}
foreach($process in $owned){$owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid;if($owner.ReturnValue -ne 0 -or $owner.Sid -ne 'S-1-5-18'){throw 'Foreign service descendant principal'}}
Stop-Service TokenTimerAgent -ErrorAction Stop
$deadline=[DateTime]::UtcNow.AddSeconds(30)
do{
 $live=@(Get-CimInstance Win32_Process|Where-Object {foreach($old in $owned){if($_.ProcessId -eq $old.ProcessId -and $_.CreationDate -eq $old.CreationDate -and $_.ExecutablePath -ceq $old.ExecutablePath -and $_.CommandLine -ceq $old.CommandLine){return $true}};return $false})
 if(!$live.Count){break};Start-Sleep -Milliseconds 100
}while([DateTime]::UtcNow -lt $deadline)
if($live.Count){throw 'Exact service tree did not drain; preserve fixture'}
$remaining=@(Get-CimInstance Win32_Process|Where-Object {$_.ParentProcessId -in $ids})
if($remaining.Count){throw 'Unexpected descendant after service stop; preserve fixture'}
$s=Get-CimInstance Win32_Service -Filter "Name='TokenTimerAgent'"
if($s.State -ne 'Stopped' -or $s.ProcessId -ne 0 -or $s.PathName -cne $expected){throw 'Exact installed service did not stop'}
ConvertTo-Json -Compress -InputObject @($owned|ForEach-Object {@{pid=[int]$_.ProcessId;createdAt=$_.CreationDate.ToUniversalTime().ToString('o')}})

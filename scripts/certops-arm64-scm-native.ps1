<#
Native Windows 11 ARM64 SCM adapter. Only an explicitly owned initially absent
TokenTimerAgent service may be created/stopped/deleted. The child is the checked
in mock agent, not the product agent. Retained process creation/command/owner
identities must drain before registry/root cleanup; no PID-only termination.
#>
param(
 [Parameter(Mandatory)][ValidateSet('Run','Cleanup')][string]$Mode,
 [Parameter(Mandatory)][string]$Receipt
)
$ErrorActionPreference='Stop'
function Read-Receipt {
 if((Get-Item -LiteralPath $Receipt).Length-gt 65536){throw 'Bounded ownership receipt required'}
 $script:r=Get-Content -LiteralPath $Receipt -Raw|ConvertFrom-Json
 if($r.schemaVersion-ne 1-or$r.suite-ne'windows-arm64-packaged-scm'-or$r.runId-notmatch'^[a-f0-9-]{36}$'){throw 'Invalid owned SCM receipt'}
 $expected=Join-Path ([IO.Path]::GetTempPath()) ('certops-arm64-scm-'+$r.runId)
 if([IO.Path]::GetFullPath($r.workDir)-ine[IO.Path]::GetFullPath($expected)){throw 'Unexpected owned root'}
 if([IO.Path]::GetFullPath($Receipt)-ine[IO.Path]::GetFullPath((Join-Path $expected 'ownership.json'))){throw 'Unexpected receipt path'}
 foreach($p in @($r.workDir,$Receipt,$r.hostPath,$r.mockPath,$r.nodePath)){
  $item=Get-Item -LiteralPath $p
  if($item.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse ownership path refused'}
 }
 if((Get-Content -LiteralPath (Join-Path $r.workDir '.owner') -Raw)-ne$r.runId){throw 'Owned root marker mismatch'}
 foreach($pair in @(@($r.hostPath,$r.hostSha256),@($r.mockPath,$r.mockSha256),@($r.nodePath,$r.nodeSha256))){if((Get-FileHash -LiteralPath $pair[0] -Algorithm SHA256).Hash.ToLowerInvariant()-ne$pair[1]){throw 'Owned executable/source changed'}}
 if($r.serviceName-ne'TokenTimerAgent'-or$r.initialServiceAbsent-ne$true){throw 'Initial service absence not established'}
 if($r.hostPath-ine(Join-Path $expected 'candidate/package/bin/tokentimer-agent-host-arm64.exe')-or$r.mockPath-ine(Join-Path $expected 'mock-agent.js')){throw 'Unexpected native fixture paths'}
 $expectedBin='"'+$r.hostPath+'" "'+$r.nodePath+'" "'+$r.mockPath+'"'
 if($r.binPath-cne$expectedBin){throw 'Unexpected exact service command'}
 Assert-FileIdentity
}
function Assert-FileIdentity {
 # Actual Node filesystem identities are shared with the creator, rather than
 # approximating inode/volume identity from names or timestamps in PowerShell.
 $validator=Join-Path $PSScriptRoot 'certops-arm64-scm-runtime.js'
 foreach($name in @('certops-arm64-scm-runtime.js','certops-arm64-scm-proof.js','certops-arm64-scm-native.ps1')){
  $rows=@($r.validationSources|Where-Object file -eq ('scripts/'+$name))
  if($rows.Count-ne 1-or(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $name) -Algorithm SHA256).Hash.ToLowerInvariant()-ne$rows[0].sha256){throw 'Original ownership validator source changed'}
 }
 $output=& $r.nodePath -e 'const fs=require("node:fs");require(process.argv[1]).validateReceipt(JSON.parse(fs.readFileSync(process.argv[2],"utf8")),process.argv[2]);console.log("owned-file-identities-verified");' $validator $Receipt
 if($LASTEXITCODE-ne 0-or[string]$output-ne'owned-file-identities-verified'){throw 'Original file identity refused; preserve native fixture'}
}
function Save {
 Assert-FileIdentity
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($r|ConvertTo-Json -Depth 12 -Compress))
 # Retain the original exclusive-created receipt inode. An interrupted write
 # leaves an unreadable receipt and conservatively preserves native resources.
 $stream=[IO.File]::Open($Receipt,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
 try{$stream.Position=0;$stream.Write($bytes,0,$bytes.Length);$stream.SetLength($bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
 Assert-FileIdentity
}
function NowIso { [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }
function Get-ServiceRow { Get-CimInstance Win32_Service -Filter "Name='TokenTimerAgent'" }
function Assert-Service {
 $s=Get-ServiceRow
 if(!$s-or$s.PathName-cne$r.binPath-or$s.StartName-ne'LocalSystem'-or$s.ServiceType-ne'Own Process'-or$s.StartMode-ne'Manual'){throw 'Service ownership/configuration mismatch'}
 $k=Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\TokenTimerAgent'
 try {
  if([string]$k.GetValue('ImagePath')-cne$r.binPath-or[string]$k.GetValueKind('Environment')-ne'MultiString'){throw 'Service registry configuration changed'}
  $envs=@($k.GetValue('Environment',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames))
  if($envs.Count-ne 1-or$envs[0]-cne('TOKENTIMER_AGENT_CONFIG_DIR='+$r.workDir)){throw 'Foreign service environment preserved'}
 } finally {$k.Dispose()}
 return $s
}
function Win-Arg([string]$value) { if($value.Contains('"')-or$value.EndsWith('\')){throw 'Unsafe fixture argument'};if($value-match'[\s]'){return '"'+$value+'"'};return $value }
function Proc-Record($p,$path,$command) {
 if(!$p-or$p.ExecutablePath-ine$path-or$p.CommandLine-cne$command){throw 'Exact process path/command mismatch'}
 $owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid
 if($owner.ReturnValue-ne 0-or$owner.Sid-ne'S-1-5-18'){throw 'Exact LocalSystem process required'}
 return [pscustomobject]@{pid=[int]$p.ProcessId;parent=[int]$p.ParentProcessId;created=$p.CreationDate.ToUniversalTime().ToString('o');path=[string]$p.ExecutablePath;command=[string]$p.CommandLine}
}
function Record-Tree {
 $s=Assert-Service
 if($s.State-ne'Running'-or$s.ProcessId-le 0){throw 'Actual running SCM process required'}
 $all=@(Get-CimInstance Win32_Process)
 $hostRecord=Proc-Record ($all|Where-Object ProcessId -eq $s.ProcessId) $r.hostPath $r.binPath
 $children=@($all|Where-Object ParentProcessId -eq $s.ProcessId)
 if($children.Count-ne 1){throw 'Expected exactly one actual owned mock child'}
 $childCommand=(Win-Arg $r.nodePath)+' '+(Win-Arg $r.mockPath)
 $childRecord=Proc-Record $children[0] $r.nodePath $childCommand
 if(@($all|Where-Object ParentProcessId -eq $childRecord.pid).Count){throw 'Unexpected mock descendants preserved'}
 $r.processes=@($r.processes)+@($hostRecord,$childRecord);Save
 return [pscustomobject]@{hostPid=$hostRecord.pid;hostCreated=$hostRecord.created;childPid=$childRecord.pid;childCreated=$childRecord.created}
}
function Assert-Drained($records,[bool]$RequireAllAbsent=$true) {
 $all=@(Get-CimInstance Win32_Process)
 if($RequireAllAbsent-and@($all|Where-Object {$_.ExecutablePath-ieq$r.hostPath-or($_.ExecutablePath-ieq$r.nodePath-and$_.CommandLine-and$_.CommandLine.Contains($r.mockPath))}).Count){throw 'Owned fixture executable/child still live, even without a captured generation'}
 foreach($record in $records){
  $same=@($all|Where-Object {$_.ProcessId-eq$record.pid-and$_.CreationDate.ToUniversalTime().ToString('o')-eq$record.created})
  if($same.Count){throw 'Captured exact owned process still running'}
  if(@($all|Where-Object ParentProcessId -eq $record.pid).Count){throw 'Unexpected late descendant preserved; never adopt/kill by parent PID'}
 }
}
function Wait-Until([scriptblock]$Check,[int]$Ms=20000) { $timer=[Diagnostics.Stopwatch]::StartNew();while($timer.ElapsedMilliseconds-lt$Ms){if(& $Check){return};Start-Sleep -Milliseconds 150};throw 'Bounded native SCM prerequisite timed out' }
function Wait-Starts([int]$Count) { Wait-Until { $file=Join-Path $r.workDir 'fixture-starts.log';if(!(Test-Path -LiteralPath $file)){return $false};$rows=@((Get-Content -LiteralPath $file -Raw).Trim() -split '\r?\n');if($rows.Count-gt$Count){throw 'Unexpected additional mock startup'};return $rows.Count-eq$Count } }
function Invoke-OwnedSc([string[]]$Arguments) { & sc.exe @Arguments|Out-Null;if($LASTEXITCODE-ne 0){throw 'Owned SCM operation failed'} }
function Stop-Drain {
 $s=Assert-Service
 if($s.State-eq'Running') { $null=Record-Tree;Invoke-OwnedSc @('stop','TokenTimerAgent') }
 elseif($s.State-ne'Stopped'){throw 'Ambiguous service state preserved'}
 Wait-Until { (Assert-Service).State-eq'Stopped' }
 Assert-Drained @($r.processes)
}
Read-Receipt
$os=Get-CimInstance Win32_OperatingSystem
$cpus=@(Get-CimInstance Win32_Processor)
if($os.ProductType-ne 1-or[int]$os.BuildNumber-lt 22000-or[Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture-ne'Arm64'-or$cpus.Count-eq 0-or@($cpus|Where-Object Architecture -ne 12).Count){throw 'Actual native ARM64 Windows 11 desktop required'}
if(-not([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevation required'}
if($Mode-eq'Cleanup'){
 if($r.operationPid){$live=Get-CimInstance Win32_Process -Filter "ProcessId=$($r.operationPid)";if($live-and$live.CreationDate.ToUniversalTime().ToString('o')-eq$r.operationCreated){throw 'Native owner still live; preserve service and root'};if(@(Get-CimInstance Win32_Process|Where-Object ParentProcessId -eq $r.operationPid).Count){throw 'Native owner descendant still live; preserve service and root'}}
 if(Get-ServiceRow){if(!$r.serviceOwned){throw 'Unowned service preserved'};Stop-Drain;Invoke-OwnedSc @('delete','TokenTimerAgent');Wait-Until { $null-eq(Get-ServiceRow) }}
 Assert-Drained @($r.processes)
 if(Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\TokenTimerAgent'){throw 'Service registry remains'}
 $r.cleanupVerified=$true;Save;@{cleanupVerified=$true}|ConvertTo-Json -Compress;exit
}
if(Get-ServiceRow){throw 'Canonical service already exists'}
if(Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\TokenTimerAgent'){throw 'Canonical service registry already exists'}
$self=Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
$r.operationPid=$PID;$r.operationCreated=$self.CreationDate.ToUniversalTime().ToString('o');Save
# Persist intent before SCM creation; a partial create is still exact-path guarded.
$r.serviceOwned=$true;Save
Invoke-OwnedSc @('create','TokenTimerAgent','type=','own','start=','demand','obj=','LocalSystem','binPath=',$r.binPath)
$k=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services\TokenTimerAgent',$true)
if(!$k){throw 'Owned service registry unavailable'}
try {$k.SetValue('Environment',[string[]]@('TOKENTIMER_AGENT_CONFIG_DIR='+$r.workDir),[Microsoft.Win32.RegistryValueKind]::MultiString)} finally {$k.Dispose()}
$null=Assert-Service
Invoke-OwnedSc @('start','TokenTimerAgent');Wait-Until { (Assert-Service).State-eq'Running'-and(Test-Path -LiteralPath (Join-Path $r.workDir 'fixture-starts.log')) }
Wait-Starts 1
$first=Record-Tree
Stop-Drain
Invoke-OwnedSc @('start','TokenTimerAgent');Wait-Until { (Assert-Service).State-eq'Running' };Wait-Starts 2
$second=Record-Tree
Invoke-OwnedSc @('failure','TokenTimerAgent','reset=','60','actions=','restart/1000');Invoke-OwnedSc @('failureflag','TokenTimerAgent','1')
Set-Content -LiteralPath (Join-Path $r.workDir 'fixture-exit-code.txt') -Value '17'
Wait-Until { $s=Assert-Service;$s.State-eq'Running'-and$s.ProcessId-ne$second.hostPid } 30000
Wait-Starts 3;$third=Record-Tree
if((Get-Content -LiteralPath (Join-Path $r.workDir 'host.log') -Raw)-notmatch'stopping service \(exit 17\)'){throw 'Actual child failure17 was not observed by packaged host'}
Assert-Drained @($r.processes|Where-Object {$_.pid-ne$third.hostPid-and$_.pid-ne$third.childPid}) $false
$startsPath=Join-Path $r.workDir 'fixture-starts.log'
$startsBeforeRetirement=Get-Content -LiteralPath $startsPath -Raw
$started=@($startsBeforeRetirement.Trim() -split '\r?\n')
if($started.Count-ne 3-or$started[0]-ne[string]$first.childPid-or$started[1]-ne[string]$second.childPid-or$started[2]-ne[string]$third.childPid){throw 'Actual mock startup receipts differ from the three independently owned children'}
Set-Content -LiteralPath (Join-Path $r.workDir 'fixture-exit-code.txt') -Value '86'
Wait-Until { (Assert-Service).State-eq'Stopped' }
$watch=[Diagnostics.Stopwatch]::StartNew()
while($watch.ElapsedMilliseconds-lt 5000){if((Assert-Service).State-ne'Stopped'){throw 'Retired child caused SCM respawn'};Start-Sleep -Milliseconds 100}
$elapsed=[long]$watch.ElapsedMilliseconds
if((Get-Content -LiteralPath $startsPath -Raw)-cne$startsBeforeRetirement){throw 'Retirement created an unexpected additional mock child'}
if((Get-Content -LiteralPath (Join-Path $r.workDir 'host.log') -Raw)-notmatch'child exited with the retirement code \(86\)'){throw 'Actual retirement86 was not observed by packaged host'}
Assert-Drained @($r.processes)
Invoke-OwnedSc @('delete','TokenTimerAgent');Wait-Until { $null-eq(Get-ServiceRow) }
if(Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\TokenTimerAgent'){throw 'Service registry remains'}
$r.cleanupVerified=$true;$r.result=[pscustomobject]@{productType=[int]$os.ProductType;build=[string]$os.BuildNumber;retirementObservationMs=$elapsed;generations=@($first,$second,$third)};Save
$r.result|ConvertTo-Json -Depth 5 -Compress

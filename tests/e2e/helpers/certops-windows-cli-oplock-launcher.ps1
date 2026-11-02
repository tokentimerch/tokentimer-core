<# External test-only launch gate. The original installer bytes and CLI are
invoked only after the independent holder has registered this exact process.
No source access or installer command happens before that acknowledgement. #>
param([Parameter(Mandatory)][string]$Installer,[Parameter(Mandatory)][string]$ProtocolDirectory,[Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$Token,[Parameter(Mandatory)][int]$OwnerProcessId)
$ErrorActionPreference='Stop'
$owner=Get-CimInstance Win32_Process -Filter "ProcessId=$OwnerProcessId"
$self=Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
if(!$owner -or $self.ParentProcessId -ne $OwnerProcessId){throw 'Installer launch owner mismatch'}
$created=$owner.CreationDate.ToUniversalTime().ToString('o')
$until=[DateTime]::UtcNow.AddSeconds(30)
$signal=Join-Path $ProtocolDirectory 'run-installer'
while(!(Test-Path -LiteralPath $signal)){
 $live=Get-CimInstance Win32_Process -Filter "ProcessId=$OwnerProcessId"
 if(!$live -or $live.CreationDate.ToUniversalTime().ToString('o') -ne $created){throw 'Installer owner exited before launch'}
 if([DateTime]::UtcNow -ge $until){throw 'Installer launch gate expired'}
 Start-Sleep -Milliseconds 20
}
if([IO.File]::ReadAllText($signal) -ne $Token){throw 'Installer launch token mismatch'}
$registered=Get-Content -LiteralPath (Join-Path $ProtocolDirectory 'registered.json') -Raw|ConvertFrom-Json
if($registered.token -ne $Token -or $registered.installerPid -ne $PID){throw 'Installer was not registered by independent holder'}
[string[]]$arguments=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $ProtocolDirectory 'arguments.json')))
& $Installer @arguments
if($LASTEXITCODE){exit $LASTEXITCODE}

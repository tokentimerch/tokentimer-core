# Supporting temporary-file reader/writer only. This never invokes certreq,
# installs an agent, contacts a CA, or edits production journal state.
# The external driver registers this exact process before allowing file access.
param([Parameter(Mandatory)][string]$Root,
      [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$Token,
      [Parameter(Mandatory)][int]$DriverPid,
      [Parameter(Mandatory)][string]$DriverCreated,
      [Parameter(Mandatory)][ValidateRange(0,2)][int]$OutputIndex)
$ErrorActionPreference='Stop'
function Public-Hash([string]$File) {
  $sha=[Security.Cryptography.SHA256]::Create();$stream=[IO.File]::OpenRead($File)
  try{return [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','').ToLowerInvariant()}finally{$stream.Dispose();$sha.Dispose()}
}
$rootPath=[IO.Path]::GetFullPath($Root).TrimEnd('\')
if([IO.Path]::GetFileName($rootPath) -notmatch '^certops-response-barrier-support-[a-f0-9-]{36}$'){throw 'Unowned supporting root'}
if([IO.File]::ReadAllText((Join-Path $rootPath '.owner')) -cne $Token){throw 'Supporting root ownership mismatch'}
$self=Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
if($self.ParentProcessId -ne $DriverPid){throw 'Exact supporting driver must be parent'}
function Assert-Driver {
  $owner=Get-CimInstance Win32_Process -Filter "ProcessId=$DriverPid"
  if(-not $owner -or $owner.CreationDate.ToUniversalTime().ToString('o') -cne $DriverCreated){throw 'Exact driver ownership lost'}
}
function Receipt([string]$Name,$Value) {
  $file=Join-Path $rootPath $Name
  $bytes=[Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Depth 5 -Compress))
  $stream=[IO.File]::Open($file,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
  try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
Assert-Driver
Receipt '.worker-ready.json' @{token=$Token;pid=$PID;parentPid=$DriverPid;created=$self.CreationDate.ToUniversalTime().ToString('o');exe=$self.ExecutablePath;scriptHash=(Public-Hash $PSCommandPath)}
$until=[DateTime]::UtcNow.AddSeconds(30)
$gate=Join-Path $rootPath '.allow-access'
while(-not(Test-Path -LiteralPath $gate)) {
  Assert-Driver
  if(Test-Path -LiteralPath (Join-Path $rootPath '.cancel')){throw 'Controlled support cancelled before access'}
  if([DateTime]::UtcNow -ge $until){throw 'Supporting access was never authorized'}
  Start-Sleep -Milliseconds 10
}
if([IO.File]::ReadAllText($gate) -cne $Token){throw 'Access gate token mismatch'}
Assert-Driver
# Genuine synchronous native open/read. The driver must observe its file oplock
# break, then acknowledge only after every output barrier has been armed.
$bytes=[IO.File]::ReadAllBytes((Join-Path $rootPath 'request.req'))
$sha=[Security.Cryptography.SHA256]::Create()
try{$hash=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
Receipt '.input-read.json' @{token=$Token;sha256=$hash;pid=$PID}
Assert-Driver
$name=@('issued.cer','chain.p7b','submit-response.rsp')[$OutputIndex]
# The output handle must remain blocked until this exact process is terminated.
# No invented CA response bytes or process exit status are used by a product.
[IO.File]::WriteAllBytes((Join-Path $rootPath $name),$bytes)
Receipt '.write-completed.json' @{token=$Token;pid=$PID}
throw 'Controlled writer unexpectedly resumed through an unacknowledged output barrier'

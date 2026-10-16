<#
In-memory domain prepare bootstrap, called by the dedicated provision selector.
The initial four-hour guest receipt is NOT authority to extend Azure TTL; the
independent controller verifies it against Azure/GitHub and seals its artifact.
#>
param([Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$CandidateSha,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$Nonce,
 [Parameter(Mandatory)][ValidatePattern('^[1-9][0-9]{0,19}$')][string]$RunId,
 [Parameter(Mandatory)][ValidatePattern('^[1-9][0-9]{0,19}$')][string]$RunAttempt,
 [Parameter(Mandatory)][string]$CreatedAt)
$ErrorActionPreference='Stop'
$r=Get-Content 'C:\ttqualification\runtime.json' -Raw|ConvertFrom-Json
if($r.candidateSha -cne $CandidateSha -or $r.windowsVersion -ne '2022' -or $env:CERTOPS_ADCS_DISPOSABLE_LAB -ne '1' -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw 'Dedicated actual SYSTEM domain runtime required'}
$m=Invoke-RestMethod -Uri 'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01' -Headers @{Metadata='true'} -TimeoutSec 5
if($m.resourceGroupName -cne "tt-certops-$RunId-$RunAttempt" -or $m.name -cne 'windows-agent' -or $m.vmId -notmatch '^[a-f0-9-]{36}$'){throw 'Actual VM ownership mismatch'}
$created=([DateTimeOffset]::Parse($CreatedAt)).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$leaseInput=@{candidateSha=$CandidateSha;runId=$RunId;runAttempt=$RunAttempt;nonce=$Nonce;vmResourceId="/subscriptions/$($m.subscriptionId)/resourceGroups/$($m.resourceGroupName)/providers/Microsoft.Compute/virtualMachines/windows-agent";vmId=$m.vmId;taskName="TokenTimer-Retention24h-$Nonce";nodeSha256=(Get-FileHash -LiteralPath $r.node -Algorithm SHA256).Hash.ToLowerInvariant();keeperSha256=(Get-FileHash -LiteralPath (Join-Path $r.source 'scripts\certops-retention24h-runtime.js') -Algorithm SHA256).Hash.ToLowerInvariant()}
$initial='C:\ttqualification\retention24h-initial-lease.json'
if(Test-Path -LiteralPath $initial){throw 'Never overwrite immutable original lease'}
$inputBase64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($leaseInput|ConvertTo-Json -Compress)))
Set-Location $r.source
& $r.node -e 'const c=require("./scripts/certops-retention24h-contract"),fs=require("fs");const v=c.createLease(JSON.parse(Buffer.from(process.argv[1],"base64")),process.argv[2]);fs.writeFileSync(process.argv[3],JSON.stringify(v),{flag:"wx"});require("./packages/agent/src/platform").applyRestrictivePermissions(process.argv[3]);' $inputBase64 $created $initial
if($LASTEXITCODE -ne 0){throw 'Immutable initial retention lease failed'}
$env:CERTOPS_ADCS_RETENTION24H='1'
& $r.node tests/e2e/certops-adcs-retention24h-prepare.js $initial
if($LASTEXITCODE -ne 0){throw 'Actual AD CS retention preparation failed; independent teardown required'}
$report="C:\ttqualification\retention24h\$Nonce\prepare-public.json"
if(!(Test-Path -LiteralPath $report)){throw 'Actual bounded prepare receipt absent'}
Copy-Item -LiteralPath $report -Destination 'C:\ttqualification\retention24h-prepare-public.json' -ErrorAction Stop
'CERTOPS_STAGE=retention24h-prepared'

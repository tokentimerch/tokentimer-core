<#
Original SYSTEM preparation for the installed retention timer campaign. Only
the trusted provisioner supplies its in-memory officer credential. The public
initial lease grants four hours; this guest never extends Azure ownership.
The hosted controller must seal and independently re-download the original
receipt before authorizing the separate sixteen-hour observer lease.
#>
param([Parameter(Mandatory)][string]$DomainPassword,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$Nonce,
 [Parameter(Mandatory)][string]$CreatedAt,
 [Parameter(Mandatory)][ValidatePattern('^[1-9][0-9]{0,19}$')][string]$RunId,
 [Parameter(Mandatory)][ValidatePattern('^[1-9][0-9]{0,19}$')][string]$RunAttempt)
$ErrorActionPreference='Stop'
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18' -or (Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Actual disposable SYSTEM forest member required'}
$r=Get-Content -LiteralPath 'C:\ttqualification\runtime.json' -Raw|ConvertFrom-Json
if($r.candidateSha -cnotmatch '^[a-f0-9]{40}$' -or $r.source -cne "C:\ttqualification\source\tokentimer-core-$($r.candidateSha)" -or $r.buildMode -ne 'qualification-only-not-release' -or $r.windowsVersion -ne '2022' -or $r.node -cnotmatch '^C:\\ttqualification\\tools\\node-v24\.[0-9]+\.[0-9]+-win-x64\\node.exe$'){throw 'Exact original Server2022 candidate runtime required'}
$vm=Invoke-RestMethod -Headers @{Metadata='true'} -Uri 'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01' -TimeoutSec 10
if($vm.resourceGroupName -cne "tt-certops-$RunId-$RunAttempt" -or $vm.name -cne 'windows-agent'){throw 'Native VM owner mismatch'}
$observer=Join-Path $r.source 'scripts\certops-retention-cadence-runtime.js'
$owner=@{candidateSha=$r.candidateSha;runId=$RunId;runAttempt=$RunAttempt;nonce=$Nonce;vmResourceId=[string]$vm.resourceId;vmId=[string]$vm.vmId;taskName="TokenTimer-RetentionCadence-$Nonce";nodeSha256=(Get-FileHash -LiteralPath $r.node -Algorithm SHA256).Hash.ToLowerInvariant();observerSha256=(Get-FileHash -LiteralPath $observer -Algorithm SHA256).Hash.ToLowerInvariant()}
$leaseFile="C:\ttqualification\retention-cadence-initial-$Nonce.json"
if(Test-Path -LiteralPath $leaseFile){throw 'Never adopt a prior cadence preparation lease'}
$env:PATH=$r.path
$env:NODE_ENV='test';$env:GITHUB_SHA=$r.candidateSha;$env:GITHUB_ACTIONS='true'
$env:NODE_EXTRA_CA_CERTS='C:\ttqualification\api-public.pem'
[Environment]::SetEnvironmentVariable('NODE_OPTIONS',$null,'Process')
[Environment]::SetEnvironmentVariable('NODE_PATH',$null,'Process')
$env:DB_HOST='10.64.0.6';$env:DB_PORT='5432';$env:DB_USER='tokentimer';$env:DB_PASSWORD='password';$env:DB_NAME='tokentimer'
$env:CERTOPS_ENABLED='true';$env:CERTOPS_CSR_DISPOSABLE_STACK='1';$env:CERTOPS_ADCS_DISPOSABLE_LAB='1'
$env:CERTOPS_ADCS_RETENTION_CADENCE='1';$env:CERTOPS_ADCS_API_URL='https://10.64.0.6'
$env:CERTOPS_SIGNING_ENCRYPTION_KEY='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
$env:CERTOPS_REGISTRATION_ENCRYPTION_KEY='abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'
Set-Location -LiteralPath $r.source
& $r.node '-e' 'const fs=require("node:fs"),h=require("./scripts/certops-retention-cadence-contract"),v=h.createLease(JSON.parse(process.argv[1]),new Date(process.argv[2]).toISOString());fs.writeFileSync(process.argv[3],JSON.stringify(v)+"\n",{flag:"wx"});require("./packages/agent/src/platform").applyRestrictivePermissions(process.argv[3]);' ($owner|ConvertTo-Json -Compress) $CreatedAt $leaseFile
if($LASTEXITCODE -ne 0){throw 'Immutable initial cadence lease refused'}
$env:CERTOPS_ADCS_OFFICER_PASSWORD=$DomainPassword
try {
 & $r.node 'tests/e2e/certops-adcs-retention-cadence-prepare.js' $leaseFile 2>&1|Out-Null
 if($LASTEXITCODE -ne 0){throw 'Actual installed timer preparation failed; independent teardown required'}
 if(!(Test-Path -LiteralPath 'C:\ttqualification\retention-cadence-prepare-public.json')){throw 'Bounded public cadence preparation absent'}
 'CERTOPS_STAGE=retention-cadence-prepared'
} finally {
 $env:CERTOPS_ADCS_OFFICER_PASSWORD=$null
 $DomainPassword=$null
}

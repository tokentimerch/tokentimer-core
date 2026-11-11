<#
Separate SYSTEM guest bootstrap for actual default AD CS TTL preparation.
Called only inside the original trusted disposable-lab provisioning operation
while its one-use officer credential is in memory. No domain secret is saved.
Public preparation output is read later by the independently authenticated
controller; this script cannot extend the original four-hour resource lease.
#>
param([Parameter(Mandatory)][string]$DomainPassword,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$AdcsTtl24hNonce,
 [Parameter(Mandatory)][Alias('CreatedAt')][string]$AdcsTtl24hCreatedAt,
 [Parameter(Mandatory)][Alias('RunId')][ValidatePattern('^[1-9][0-9]{0,19}$')][string]$AdcsTtl24hRunId,
 [Parameter(Mandatory)][Alias('RunAttempt')][ValidatePattern('^[1-9][0-9]{0,19}$')][string]$AdcsTtl24hRunAttempt)
$ErrorActionPreference='Stop'
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18' -or (Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Actual disposable SYSTEM forest member required'}
$r=Get-Content -LiteralPath 'C:\ttqualification\runtime.json' -Raw|ConvertFrom-Json
if($r.candidateSha -cnotmatch '^[a-f0-9]{40}$' -or $r.source -cne "C:\ttqualification\source\tokentimer-core-$($r.candidateSha)" -or $r.buildMode -ne 'qualification-only-not-release' -or $r.windowsVersion -ne '2022' -or $r.node -cnotmatch '^C:\\ttqualification\\tools\\node-v24\.[0-9]+\.[0-9]+-win-x64\\node.exe$'){throw 'Exact original 2022 candidate runtime required'}
$vm=Invoke-RestMethod -Headers @{Metadata='true'} -Uri 'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01' -TimeoutSec 10
$resident=Join-Path $r.source 'scripts\certops-adcs-ttl24h-resident.js';$contract=Join-Path $r.source 'scripts\certops-adcs-ttl24h-contract.js'
$owner=@{candidateSha=$r.candidateSha;runId=$AdcsTtl24hRunId;runAttempt=$AdcsTtl24hRunAttempt;nonce=$AdcsTtl24hNonce;vmResourceId=[string]$vm.resourceId;vmId=[string]$vm.vmId;taskName="TokenTimer-AdcsTtl24h-$AdcsTtl24hNonce";nodeSha256=(Get-FileHash -LiteralPath $r.node -Algorithm SHA256).Hash.ToLowerInvariant();keeperSha256=(Get-FileHash -LiteralPath $resident -Algorithm SHA256).Hash.ToLowerInvariant()}
$leaseFile="C:\ttqualification\adcs-ttl24h-initial-$AdcsTtl24hNonce.json"
if(Test-Path -LiteralPath $leaseFile){throw 'Never adopt a prior TTL prepare lease'}
$env:PATH=$r.path;$env:NODE_ENV='test';$env:GITHUB_SHA=$r.candidateSha;$env:NODE_EXTRA_CA_CERTS='C:\ttqualification\api-public.pem'
$env:DB_HOST='10.64.0.6';$env:DB_PORT='5432';$env:DB_USER='tokentimer';$env:DB_PASSWORD='password';$env:DB_NAME='tokentimer'
$env:CERTOPS_ENABLED='true';$env:CERTOPS_CSR_DISPOSABLE_STACK='1';$env:CERTOPS_ADCS_DISPOSABLE_LAB='1';$env:CERTOPS_ADCS_TTL24H='1';$env:CERTOPS_ADCS_API_URL='https://10.64.0.6'
Set-Location -LiteralPath $r.source
& $r.node '-e' 'const fs=require("node:fs"),h=require(process.argv[1]),v=h.createLease(JSON.parse(process.argv[2]),new Date(process.argv[3]).toISOString());fs.writeFileSync(process.argv[4],JSON.stringify(v)+"\n",{flag:"wx"});require("./packages/agent/src/platform").applyRestrictivePermissions(process.argv[4])' $contract ($owner|ConvertTo-Json -Compress) $AdcsTtl24hCreatedAt $leaseFile
if($LASTEXITCODE -ne 0){throw 'Actual original initial TTL lease refused'}
$env:CERTOPS_ADCS_OFFICER_PASSWORD=$DomainPassword
try{
 # Child output is bounded constant diagnostics; the public closed envelope is
 # independently read from its exact static file, never mixed with log output.
 & $r.node 'tests/e2e/certops-adcs-ttl24h-prepare.js' $leaseFile 2>&1|Out-Null
 if($LASTEXITCODE -ne 0){throw 'Actual default TTL native preparation failed; independent teardown required'}
 'CERTOPS_ADCS_TTL24H=prepared-real-native-fixtures-and-owned-task'
 'CERTOPS_STAGE=adcs-ttl24h-prepared'
}finally{$env:CERTOPS_ADCS_OFFICER_PASSWORD=$null;$DomainPassword=$null}

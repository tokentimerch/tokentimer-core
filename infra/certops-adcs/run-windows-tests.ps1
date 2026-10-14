param([Parameter(Mandatory)][string]$DomainPassword,[ValidateSet('en-US','de-DE','fr-FR')][string]$Language='en-US',[ValidateSet('0','1')][string]$ResponseLossExperiment='0',[ValidateSet('none','keygen_intent','prepared','submitting','installing')][string]$JournalPhaseExperiment='none',[ValidateSet('root','subordinate')][string]$HierarchyRole='root',[string]$RootCertificateBase64)
$ErrorActionPreference = 'Stop'
if ((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test') { throw 'Tests require isolated domain member' }
$runtime=Get-Content 'C:\ttqualification\runtime.json' -Raw | ConvertFrom-Json
$env:PATH=$runtime.path
$env:NODE_ENV='test'
$env:CERTOPS_ENABLED='true'
# Isolated Compose fixture keys must match the API when controller-side services sign jobs.
$env:CERTOPS_SIGNING_ENCRYPTION_KEY='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
$env:CERTOPS_REGISTRATION_ENCRYPTION_KEY='abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'
$env:NODE_EXTRA_CA_CERTS='C:\ttqualification\api-public.pem'
$env:GITHUB_SHA=$runtime.candidateSha
$env:CERTOPS_WINDOWS_VERSION=$runtime.windowsVersion
$env:DB_HOST='10.64.0.6'
$env:DB_PORT='5432'
$env:DB_USER='tokentimer'
$env:DB_PASSWORD='password'
$env:DB_NAME='tokentimer'
$env:CERTOPS_CSR_DISPOSABLE_STACK='1'
$env:CERTOPS_ADCS_DISPOSABLE_LAB='1'
$env:CERTOPS_ADCS_API_URL='https://10.64.0.6'
$env:CERTOPS_ADCS_REPORT='C:\ttqualification\enterprise-adcs-report.json'
$env:CERTOPS_ADCS_OFFICER_PASSWORD=$DomainPassword
$env:CERTOPS_WINDOWS_LANGUAGE=$Language
$env:GITHUB_ACTIONS='true'
$env:CERTOPS_ADCS_RESPONSE_LOSS_EXPERIMENT=$ResponseLossExperiment
if($JournalPhaseExperiment -ne 'none'){$env:CERTOPS_ADCS_JOURNAL_PHASE_EXPERIMENT=$JournalPhaseExperiment}else{$env:CERTOPS_ADCS_JOURNAL_PHASE_EXPERIMENT=$null}
if($JournalPhaseExperiment -ne 'none'){$env:CERTOPS_JOB_LEASE_SECONDS='60';$env:CERTOPS_LEASE_HARD_GRACE_MS='60000'}else{$env:CERTOPS_JOB_LEASE_SECONDS=$null;$env:CERTOPS_LEASE_HARD_GRACE_MS=$null}
$env:CERTOPS_ADCS_HIERARCHY=$HierarchyRole
$env:CERTOPS_ADCS_HIERARCHY_ROOT_CERT=$RootCertificateBase64
Set-Location $runtime.source
try {
  & $runtime.node --test tests/e2e/certops-adcs-real-e2e.test.js
  $testExitCode=$LASTEXITCODE
} finally {
  $env:CERTOPS_ADCS_OFFICER_PASSWORD=$null
}
if ($testExitCode -ne 0) { throw 'Native enterprise AD CS scenarios failed' }
Write-Output 'CERTOPS_STAGE=real-enterprise-adcs-tests-passed'

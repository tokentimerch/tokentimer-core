<#
Guest SYSTEM test entry point called only by provision-lab.ps1 after domain/tool provisioning. Loads
the exact candidate runtime and test-only controller keys, selects the dedicated report, and invokes
the real API-agent/native harness. It clears the officer password after execution.
#>
param([Parameter(Mandatory)][string]$DomainPassword,[ValidateSet('en-US','de-DE','fr-FR')][string]$Language='en-US',[ValidateSet('0','1')][string]$ResponseLossExperiment='0',[ValidateSet('none','keygen_intent','prepared','submitting','installing','accepted-before-bind','bound-before-complete')][string]$JournalPhaseExperiment='none',[ValidateSet('0','1')][string]$PendingElapsedQualification='0',[ValidateSet('0','1')][string]$IssuerReassignment='0',[ValidateSet('root','subordinate')][string]$HierarchyRole='root',[string]$RootCertificateBase64,[ValidateSet('0','1')][string]$Retention24hPrepare='0',[string]$Retention24hNonce,[string]$Retention24hCreatedAt,[string]$Retention24hRunId,[string]$Retention24hRunAttempt)
$ErrorActionPreference = 'Stop'
if($ResponseLossExperiment -ne '0' -or $JournalPhaseExperiment -ne 'none' -or $PendingElapsedQualification -ne '0' -or $IssuerReassignment -ne '0' -or $HierarchyRole -ne 'root' -or $Retention24hPrepare -ne '0'){throw 'Extended campaigns are deferred'}
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
$env:CERTOPS_ADCS_ISSUER_SWITCH=$IssuerReassignment
$env:CERTOPS_ADCS_DESTINATION_CA_CONFIG=if($IssuerReassignment -eq '1'){'tt-ca-switch.lab.certops.test\TTQualificationDestination'}else{$null}
$env:CERTOPS_ADCS_REPORT=if($IssuerReassignment -eq '1'){'C:\ttqualification\native-issuer-reassignment.json'}elseif($PendingElapsedQualification -eq '1'){'C:\ttqualification\pending-elapsed.json'}else{'C:\ttqualification\enterprise-adcs-report.json'}
$env:CERTOPS_ADCS_PENDING_ELAPSED=if($PendingElapsedQualification -eq '1'){'1'}else{$null}
# Every comprehensive base report includes the mandatory native browser cases.
$env:CERTOPS_ADCS_BROWSER=if($IssuerReassignment -eq '1' -or $PendingElapsedQualification -eq '1' -or $Retention24hPrepare -eq '1'){$null}else{'1'}
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

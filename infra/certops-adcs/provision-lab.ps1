<#
Trusted workflow entry point for a disposable enterprise AD CS forest/control plane/member. Uses the
dedicated lab OIDC identity, bounded TTL and owned teardown receipts; explicit selectors separate
full, hierarchy, elapsed and experimental scopes. Raw guest output/credentials are not artifacts.
#>
param([Parameter(Mandatory)][ValidatePattern('^tt-certops-[0-9]+-[0-9]+$')][string]$ResourceGroup,
  [ValidateSet(4,8)][int]$Hours = 4,
  [ValidateSet('2019','2022','2025')][string]$WindowsVersion = '2022',
  [ValidateSet('en-US','de-DE','fr-FR')][string]$Language = 'en-US',
  [ValidateSet('0','1')][string]$ResponseLossExperiment = '0',
  [ValidateSet('0','1')][string]$PendingElapsedQualification = '0',
  [ValidateSet('0','1')][string]$Retention24hPrepare = '0',
  [string]$Retention24hNonce,
  [ValidateSet('none','keygen_intent','prepared','submitting','installing','accepted-before-bind','bound-before-complete')][string]$JournalPhaseExperiment='none',
  [ValidateSet('root','subordinate')][string]$HierarchyRole='root',
  [string]$Location = 'westeurope')
$ErrorActionPreference = 'Stop'
if($HierarchyRole -eq 'subordinate' -and ($ResponseLossExperiment -ne '0' -or $JournalPhaseExperiment -ne 'none')){throw 'Hierarchy and experimental fault profiles cannot be combined'}
if($ResponseLossExperiment -ne '0' -and $JournalPhaseExperiment -ne 'none'){throw 'Only one native fault experiment may own a lab'}
if($PendingElapsedQualification -eq '1' -and ($Hours -ne 4 -or $WindowsVersion -ne '2022' -or $Language -ne 'en-US' -or $HierarchyRole -ne 'root' -or $ResponseLossExperiment -ne '0' -or $JournalPhaseExperiment -ne 'none')){throw 'Elapsed pending qualification requires its isolated four-hour Server2022 en-US profile'}
if($Retention24hPrepare -eq '1' -and ($Hours -ne 4 -or $WindowsVersion -ne '2022' -or $Language -ne 'en-US' -or $HierarchyRole -ne 'root' -or $PendingElapsedQualification -ne '0' -or $ResponseLossExperiment -ne '0' -or $JournalPhaseExperiment -ne 'none' -or $Retention24hNonce -cnotmatch '^[a-f0-9]{64}$' -or $env:GITHUB_RUN_ID -notmatch '^[1-9][0-9]*$' -or $env:GITHUB_RUN_ATTEMPT -notmatch '^[1-9][0-9]*$' -or $ResourceGroup -cne "tt-certops-$env:GITHUB_RUN_ID-$env:GITHUB_RUN_ATTEMPT")){throw 'Retention24h requires explicit isolated four-hour Server2022 en-US preparation'}
$password = 'Tt!' + [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)) + 'a1'
Write-Output "::add-mask::$password"
$createdAt = [DateTimeOffset]::UtcNow
$expiresAt = $createdAt.AddHours($Hours).ToString('o')
$parameterPath = Join-Path $env:RUNNER_TEMP 'certops-adcs-parameters.json'
$candidateSha = $env:GITHUB_SHA
if ($candidateSha -notmatch '^[a-f0-9]{40}$') { throw 'Qualification candidate must be a Git commit SHA' }
$languageAssets=$null
if($Language -ne 'en-US'){
  $languageAssets=$env:CERTOPS_WINDOWS_LANGUAGE_ASSETS | ConvertFrom-Json -AsHashtable
  foreach($version in @('2022',$WindowsVersion)|Select-Object -Unique){
    $asset=$languageAssets["$version/$Language"]
    if(-not $asset -or $asset.sha256 -notmatch '^[a-fA-F0-9]{64}$'){throw 'Configure official language CAB URI and SHA256 for each selected OS before provisioning'}
    $assetUri=[Uri]$asset.uri
    if($assetUri.Scheme -ne 'https' -or $assetUri.Host -notmatch '^[a-z0-9-]+\.blob\.core\.windows\.net$'){throw 'Language fixture must use owned HTTPS Azure Blob'}
    Write-Output "::add-mask::$($asset.uri)"
  }
}
$receipts = [Collections.Generic.List[string]]::new()
$reportStatus = 'failed'
$publicStageData=@{}
function Refresh-LabAuthentication {
  if($env:GITHUB_ACTIONS -eq 'true'){& (Join-Path $PSScriptRoot 'login-oidc.ps1')}
}
function Invoke-Stage([string]$Machine, [string]$Script, [string]$Marker, [string[]]$Parameters = @()) {
  $arguments = @('vm','run-command','invoke','--resource-group',$ResourceGroup,'--name',$Machine,'--command-id','RunPowerShellScript','--scripts',"@$Script",'-o','json')
  if ($Parameters.Count) { $arguments += @('--parameters'); $arguments += $Parameters }
  Refresh-LabAuthentication
  $text = az @arguments
  if ($LASTEXITCODE -ne 0) { throw "Native lab stage failed for $Machine" }
  $response = $text | ConvertFrom-Json
  $message = ($response.value | ForEach-Object message) -join "`n"
  if (-not $message.Contains($Marker)) { throw "Expected stage receipt absent for $Machine" }
  foreach($field in @('CERTOPS_ROOT_CERT','CERTOPS_SUBORDINATE_REQUEST','CERTOPS_SUBORDINATE_CERT')){
    $match=[regex]::Match($message,"(?m)^$field=([A-Za-z0-9+/=]+)\s*$")
    if($match.Success){$publicStageData[$field]=$match.Groups[1].Value}
  }
  # Only allowlisted stage receipts are emitted; raw guest output is excluded.
  Write-Output $Marker
  $receipts.Add($Marker)
}
function Wait-Agent([string]$Machine) {
  Refresh-LabAuthentication
  for ($attempt=0; $attempt -lt 30; $attempt++) {
    $state = az vm get-instance-view -g $ResourceGroup -n $Machine --query "instanceView.vmAgent.statuses[0].code" -o tsv
    if ($LASTEXITCODE -eq 0 -and $state -eq 'ProvisioningState/succeeded') { return }
    Start-Sleep -Seconds 10
  }
  throw "Guest agent did not become ready after reboot: $Machine"
}
function Start-ControlPlane() {
  Refresh-LabAuthentication
  $response = az vm run-command invoke -g $ResourceGroup -n control-plane --command-id RunShellScript --scripts "@$(Join-Path $PSScriptRoot 'control-plane.sh')" --parameters "candidate=$candidateSha" "journal_phase=$JournalPhaseExperiment" -o json | ConvertFrom-Json
  if ($LASTEXITCODE -ne 0) { throw 'Private control plane bootstrap failed' }
  $message = ($response.value | ForEach-Object message) -join "`n"
  if (-not $message.Contains('CERTOPS_STAGE=private-https-control-plane-running')) { throw 'Private HTTPS control plane receipt absent' }
  $match = [regex]::Match($message,'-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----')
  if (-not $match.Success) { throw 'Public API TLS trust bundle absent' }
  [IO.File]::WriteAllText((Join-Path $env:RUNNER_TEMP 'certops-api-public.pem'),$match.Value)
  $receipts.Add('CERTOPS_STAGE=private-https-control-plane-running')
}
try {
  $existing = az group exists --name $ResourceGroup
  if ($LASTEXITCODE -ne 0 -or $existing -ne 'false') { throw 'Qualification resource group must not already exist' }
  $initialTags=@('purpose=certops-adcs-qualification',"expiresAt=$expiresAt","createdAt=$($createdAt.ToString('o'))","candidateSha=$candidateSha")
  if($Retention24hPrepare -eq '1'){
    # Initial ownership permits only exact failed-prepare cleanup. It does not
    # grant the extended lease; that requires independent artifact/task readback.
    $initialTags+=@('retentionPrepareKind=certops-native-retention24h',"retentionPrepareNonce=$Retention24hNonce","retentionPrepareRunId=$env:GITHUB_RUN_ID","retentionPrepareRunAttempt=$env:GITHUB_RUN_ATTEMPT")
  }
  az group create --name $ResourceGroup --location $Location --tags $initialTags -o none
  if ($LASTEXITCODE -ne 0) { throw 'Could not create isolated lab group' }
  @{ expiresAt=@{value=$expiresAt}; candidateSha=@{value=$candidateSha}; windowsVersion=@{value=$WindowsVersion}; hierarchy=@{value=($HierarchyRole -eq 'subordinate')}; adminPassword=@{value=$password} } | ConvertTo-Json -Depth 5 | Set-Content $parameterPath
  az deployment group create -g $ResourceGroup --name qualification --template-file (Join-Path $PSScriptRoot 'main.bicep') --parameters "@$parameterPath" -o none
  if ($LASTEXITCODE -ne 0) { throw 'Private lab deployment failed' }
  if($Language -ne 'en-US'){
    foreach($node in @('domain-ca','windows-agent')){
      $version=if($node -eq 'domain-ca'){'2022'}else{$WindowsVersion}
      $asset=$languageAssets["$version/$Language"]
      Invoke-Stage $node (Join-Path $PSScriptRoot 'language-pack.ps1') 'CERTOPS_STAGE=language-installed-reboot-required' @("Language=$Language","PackageUri=$($asset.uri)","PackageSha256=$($asset.sha256)")
      az vm restart -g $ResourceGroup -n $node -o none
      if($LASTEXITCODE -ne 0){throw 'Language installation reboot failed'}
      Wait-Agent $node
    }
  }
  Invoke-Stage 'domain-ca' (Join-Path $PSScriptRoot 'domain-forest.ps1') 'CERTOPS_STAGE=forest-created-reboot-required' @("DirectoryRecoveryPassword=$password")
  az vm restart -g $ResourceGroup -n domain-ca -o none
  if ($LASTEXITCODE -ne 0) { throw 'Domain controller restart failed' }
  Wait-Agent 'domain-ca'
  if($HierarchyRole -eq 'subordinate'){
    Invoke-Stage 'offline-root' (Join-Path $PSScriptRoot 'hierarchy-root.ps1') 'CERTOPS_STAGE=offline-root-prepared' @('Action=prepare')
    Invoke-Stage 'domain-ca' (Join-Path $PSScriptRoot 'domain-ca.ps1') 'CERTOPS_STAGE=enterprise-subordinate-request-created' @("DomainPassword=$password",'HierarchyRole=subordinate')
    if(-not $publicStageData.CERTOPS_ROOT_CERT -or -not $publicStageData.CERTOPS_SUBORDINATE_REQUEST){throw 'Public hierarchy bootstrap data missing'}
    Invoke-Stage 'offline-root' (Join-Path $PSScriptRoot 'hierarchy-root.ps1') 'CERTOPS_STAGE=subordinate-signed-root-offline' @('Action=sign',"RequestBase64=$($publicStageData.CERTOPS_SUBORDINATE_REQUEST)")
    if(-not $publicStageData.CERTOPS_SUBORDINATE_CERT){throw 'Signed subordinate public certificate missing'}
    Invoke-Stage 'domain-ca' (Join-Path $PSScriptRoot 'hierarchy-subordinate.ps1') 'CERTOPS_STAGE=enterprise-subordinate-service-running' @("DomainPassword=$password","RootCertificateBase64=$($publicStageData.CERTOPS_ROOT_CERT)","SubordinateCertificateBase64=$($publicStageData.CERTOPS_SUBORDINATE_CERT)")
  }else{Invoke-Stage 'domain-ca' (Join-Path $PSScriptRoot 'domain-ca.ps1') 'CERTOPS_STAGE=enterprise-ca-service-running' @("DomainPassword=$password")}
  $safetyCasesBase64=[Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'safety-cases.json')))
  Invoke-Stage 'domain-ca' (Join-Path $PSScriptRoot 'templates.ps1') 'CERTOPS_STAGE=isolated-template-matrix-published' @("DomainPassword=$password","SafetyCasesBase64=$safetyCasesBase64")
  Start-ControlPlane
  if($PendingElapsedQualification -ne '1' -and $Retention24hPrepare -ne '1'){
    Refresh-LabAuthentication
    $browserResponse=az vm run-command invoke -g $ResourceGroup -n control-plane --command-id RunShellScript --scripts "@$(Join-Path $PSScriptRoot 'browser-control-plane.sh')" --parameters "candidate=$candidateSha" -o json | ConvertFrom-Json
    if($LASTEXITCODE -ne 0 -or -not (($browserResponse.value | ForEach-Object message) -join "`n").Contains('CERTOPS_STAGE=private-same-origin-dashboard-ready')){throw 'Private browser dashboard bootstrap failed'}
    $receipts.Add('CERTOPS_STAGE=private-same-origin-dashboard-ready')
  }
  Invoke-Stage 'windows-agent' (Join-Path $PSScriptRoot 'domain-member.ps1') 'CERTOPS_STAGE=member-joined-reboot-required' @("DomainPassword=$password")
  az vm restart -g $ResourceGroup -n windows-agent -o none
  if ($LASTEXITCODE -ne 0) { throw 'Domain member restart failed' }
  Wait-Agent 'windows-agent'
  $verifyParameters=@("HierarchyRole=$HierarchyRole");if($HierarchyRole -eq 'subordinate'){$verifyParameters+="RootCertificateBase64=$($publicStageData.CERTOPS_ROOT_CERT)"}
  Invoke-Stage 'windows-agent' (Join-Path $PSScriptRoot 'domain-verify.ps1') 'CERTOPS_STAGE=domain-member-ca-rpc-verified' $verifyParameters
  foreach($node in @('domain-ca','windows-agent')){Invoke-Stage $node (Join-Path $PSScriptRoot 'language-verify.ps1') 'CERTOPS_STAGE=installed-language-verified' @("Language=$Language")}
  $apiPublic=[Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $env:RUNNER_TEMP 'certops-api-public.pem')))
  Invoke-Stage 'windows-agent' (Join-Path $PSScriptRoot 'windows-tools.ps1') 'CERTOPS_STAGE=isolated-candidate-windows-tools-built' @("CandidateSha=$candidateSha","ApiPublicPemBase64=$apiPublic","WindowsVersion=$WindowsVersion")
  if($PendingElapsedQualification -ne '1' -and $Retention24hPrepare -ne '1'){Invoke-Stage 'windows-agent' (Join-Path $PSScriptRoot 'browser-windows-tools.ps1') 'CERTOPS_STAGE=locked-domain-browser-ready' @("CandidateSha=$candidateSha")}
  if($Retention24hPrepare -eq '1'){
    # Keep the forest credential in this process only. The dedicated producer
    # freezes actual cutover before the external controller may extend TTL.
    Invoke-Stage 'windows-agent' (Join-Path $PSScriptRoot 'run-windows-tests.ps1') 'CERTOPS_STAGE=retention24h-prepared' @("DomainPassword=$password","Retention24hPrepare=1","Retention24hNonce=$Retention24hNonce","Retention24hCreatedAt=$($createdAt.ToString('o'))","Retention24hRunId=$env:GITHUB_RUN_ID","Retention24hRunAttempt=$env:GITHUB_RUN_ATTEMPT")
    $reportStatus='prepared-actual-cutover-awaiting-independent-handoff'
  }else{
  $testParameters=@("DomainPassword=$password","Language=$Language","ResponseLossExperiment=$ResponseLossExperiment","JournalPhaseExperiment=$JournalPhaseExperiment","PendingElapsedQualification=$PendingElapsedQualification","HierarchyRole=$HierarchyRole");if($HierarchyRole -eq 'subordinate'){$testParameters+="RootCertificateBase64=$($publicStageData.CERTOPS_ROOT_CERT)"}
  try { Invoke-Stage 'windows-agent' (Join-Path $PSScriptRoot 'run-windows-tests.ps1') 'CERTOPS_STAGE=real-enterprise-adcs-tests-passed' $testParameters }
  finally {
    $reportErrors=@();$kinds=if($PendingElapsedQualification -eq '1'){@('pending-elapsed')}elseif($HierarchyRole -eq 'subordinate'){@('hierarchy')}else{@('qualification')};if($ResponseLossExperiment -eq '1'){$kinds+='response-loss-experimental'};if($JournalPhaseExperiment -ne 'none'){$kinds+='journal-phase-experimental'}
    foreach($kind in $kinds){try{& (Join-Path $PSScriptRoot 'read-report.ps1') -ResourceGroup $ResourceGroup -ReportKind $kind}catch{$reportErrors+=$kind}}
    if($reportErrors.Count){throw "Guest execution report retrieval failed for: $($reportErrors -join ', ')"}
  }
  $reportStatus = 'provisioned-and-native-scenarios-completed'
  }
} finally {
  New-Item -ItemType Directory -Force 'qualification-results' | Out-Null
  $scenarioReport=if($Retention24hPrepare -eq '1'){'retention24h-prepare-public.json'}elseif($PendingElapsedQualification -eq '1'){'enterprise-adcs-elapsed-pending-real.json'}elseif($HierarchyRole -eq 'subordinate'){'enterprise-adcs-hierarchy-real.json'}else{'enterprise-adcs-real.json'}
  @{ candidateSha=$candidateSha; scope='disposable-enterprise-adcs-infrastructure'; status=$reportStatus; resourceGroup=$ResourceGroup; expiresAt=$expiresAt; scenarioReport=$scenarioReport; hierarchyRole=$HierarchyRole; noncoverage=@('CMC renewal','Additional uncertainty fault variants','Retention and adoption'); stages=@($receipts) } | ConvertTo-Json -Depth 6 | Set-Content 'qualification-results/enterprise-adcs-infrastructure.json'
  Remove-Item -LiteralPath $parameterPath -Force -ErrorAction SilentlyContinue
  $password = $null
}

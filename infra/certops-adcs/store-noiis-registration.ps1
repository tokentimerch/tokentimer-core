param([Parameter(Mandatory)][ValidateSet('register','verify','remove')][string]$Mode)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'store-noiis-prepare-guard.ps1')
$resourceGroup = $env:STORE_GROUP
Assert-CertOpsStorePreparationWorkflow -ResourceGroup $resourceGroup
$guidPattern = '^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
if($env:AZURE_SUBSCRIPTION_ID -cnotmatch $guidPattern -or $env:AZURE_CLIENT_ID -cnotmatch $guidPattern){
  throw 'Scoped lab Azure environment is required'
}
$subscription = az account show --only-show-errors --query id -o tsv
if($LASTEXITCODE -or $subscription -cne $env:AZURE_SUBSCRIPTION_ID){throw 'Selected lab subscription does not match the protected environment'}
$repo = 'tokentimerch/tokentimer-core'

function Read-StoreGroup {
  $raw = az group show --subscription $env:AZURE_SUBSCRIPTION_ID --name $resourceGroup --only-show-errors -o json
  if($LASTEXITCODE){throw 'Store registration group readback failed'}
  return $raw | ConvertFrom-Json -DateKind String
}

if($Mode -eq 'register'){
  if($env:STORE_EXPECTED_SHA -cne $env:GITHUB_SHA -or (git rev-parse HEAD) -cne $env:GITHUB_SHA -or $LASTEXITCODE -or
    $env:STORE_MEDIA_SOURCE -cnotmatch '^[a-f0-9]{40}$' -or $env:STORE_MEDIA_RECEIPT_SHA -cnotmatch '^[a-f0-9]{64}$' -or
    $env:STORE_LOCATION -cnotmatch '^[a-z][a-z0-9]{1,49}$'){
    throw 'Reviewed workflow, media source, custody receipt digest and location required'
  }
  foreach($sha in @($env:GITHUB_SHA,$env:STORE_MEDIA_SOURCE) | Select-Object -Unique){
    $raw = gh api "repos/$repo/commits/$sha" --jq '{sha,verified:.commit.verification.verified}'
    if($LASTEXITCODE){throw 'Could not verify reviewed Store commits'}
    $signature = $raw | ConvertFrom-Json
    if($signature.sha -cne $sha -or $signature.verified -ne $true){throw 'GitHub did not verify the exact reviewed Store commit'}
  }
  & (Join-Path $PSScriptRoot 'assert-lab-capacity.ps1') -Location $env:STORE_LOCATION -VmSize 'Standard_D2s_v5'
  $exists = az group exists --subscription $env:AZURE_SUBSCRIPTION_ID --name $resourceGroup --only-show-errors
  if($LASTEXITCODE -or $exists -cne 'false'){throw 'Store registration must use an unused workflow-owned group name'}
  $created = [DateTimeOffset]::UtcNow
  $registration = [ordered]@{
    schema='certops-adcs-store-registration-v1';resourceGroup=$resourceGroup;
    subscriptionSha256=(Get-CertOpsStoreHash $env:AZURE_SUBSCRIPTION_ID);location=$env:STORE_LOCATION;
    workflowCommit=$env:GITHUB_SHA;runId=$env:GITHUB_RUN_ID;runAttempt=$env:GITHUB_RUN_ATTEMPT;
    mediaSourceCommit=$env:STORE_MEDIA_SOURCE;mediaReceiptSha256=$env:STORE_MEDIA_RECEIPT_SHA;
    registrationNonce=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant();
    createdAt=$created.ToString('o');expiresAt=$created.AddHours(4).ToString('o');
    provisionClientSha256=(Get-CertOpsStoreHash $env:AZURE_CLIENT_ID)
  }
  # A registration is not cleanup-eligible until Azure confirms 201 Created
  # and the run-bound nonce, resources and deployments are read back empty.
  . (Join-Path $PSScriptRoot 'arm-operation.ps1')
  $groupId = "/subscriptions/$env:AZURE_SUBSCRIPTION_ID/resourceGroups/$resourceGroup"
  $uri = [uri]"https://management.azure.com$($groupId)?api-version=2021-04-01"
  $body = @{location=$registration.location;tags=(Get-CertOpsStoreGroupTags -Registration $registration -Pending)} | ConvertTo-Json -Compress
  try {
    $response = Invoke-CertOpsArmRequest -Uri $uri -Method PUT -Body $body -SubscriptionId $env:AZURE_SUBSCRIPTION_ID -RefreshAuthentication {}
  } catch {
    throw 'Empty Store group registration failed or is uncertain; do not retry the same attempt'
  }
  if($response.StatusCode -ne 201){throw 'Store group was not newly created; preserve it for ownership review'}
  Assert-CertOpsStoreRegistrationScope -Registration $registration -Pending
  az tag update --resource-id $groupId --operation Merge --tags purpose=certops-adcs-qualification --only-show-errors -o none
  if($LASTEXITCODE){throw 'Store expiry-tag promotion failed or is uncertain; do not retry the same attempt'}
  Assert-CertOpsStoreGroupIdentity -Registration $registration -Group (Read-StoreGroup)
  Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value ('registration=' + ($registration | ConvertTo-Json -Compress))
  return
}

# Only the successful protected register job supplies this value.
if([string]::IsNullOrEmpty($env:STORE_REGISTRATION) -or $env:STORE_REGISTRATION.Length -gt 4096){
  throw 'Missing owned Store registration from this workflow'
}
$registration = $env:STORE_REGISTRATION | ConvertFrom-Json -AsHashtable -DateKind String
if($registration.schema -cne 'certops-adcs-store-registration-v1' -or $registration.resourceGroup -cne $resourceGroup -or
  $registration.workflowCommit -cne $env:GITHUB_SHA -or $registration.runId -cne $env:GITHUB_RUN_ID -or
  $registration.runAttempt -cne $env:GITHUB_RUN_ATTEMPT -or $registration.registrationNonce -cnotmatch '^[a-f0-9]{64}$' -or
  $registration.subscriptionSha256 -cne (Get-CertOpsStoreHash $env:AZURE_SUBSCRIPTION_ID) -or
  $registration.provisionClientSha256 -cnotmatch '^[a-f0-9]{64}$'){
  throw 'Store registration belongs to another owner or scope'
}
$independent = Get-CertOpsStoreHash $env:AZURE_CLIENT_ID
if($registration.provisionClientSha256 -ceq $independent){throw 'Store cleanup must use the independent Azure identity'}

if($Mode -eq 'remove'){
  if($env:STORE_CLEANUP_ACTIVATION_SHA256 -cnotmatch '^[a-f0-9]{64}$' -or
    $env:STORE_CLEANUP_ACTIVATION_SHA256 -cne $env:STORE_REGISTRATION_SHA256){
    throw 'Exact pre-deployment activation receipt required for immediate cleanup'
  }
  $exists = az group exists --subscription $env:AZURE_SUBSCRIPTION_ID --name $resourceGroup --only-show-errors
  if($LASTEXITCODE){throw 'Could not check owned Store resource-group cleanup'}
  if($exists -ceq 'true'){Assert-CertOpsStoreGroupIdentity -Registration $registration -Group (Read-StoreGroup)}
  elseif($exists -cne 'false'){throw 'Unrecognized Store cleanup existence result'}
  & (Join-Path $PSScriptRoot 'remove-owned-lab.ps1') -ResourceGroup $resourceGroup
  return
}

# Stage 2 is read-only under the native expiry-cleanup identity.
$janitorFile = 'certops-adcs-lab-janitor.yml'
$janitorPath = "repos/$repo/actions/workflows/$janitorFile"
$raw = gh api $janitorPath --jq '{id,state}'
if($LASTEXITCODE -or -not $raw){throw 'Could not read independent AD CS expiry janitor'}
$janitor = $raw | ConvertFrom-Json
if($janitor.state -cne 'active'){throw 'Independent AD CS expiry janitor is not active'}
$manualRunId = $env:STORE_MANUAL_JANITOR_RUN_ID
if($manualRunId){
  if($manualRunId -cnotmatch '^[1-9][0-9]{0,18}$'){throw 'An exact manual expiry janitor run ID is required'}
  $runPath = "repos/$repo/actions/runs/$manualRunId"
  $raw = gh api $runPath --jq '{id,workflow_id,path,event,head_sha,head_branch,head_repo:.head_repository.full_name,status,conclusion,run_attempt}'
  if($LASTEXITCODE -or -not $raw){throw 'Could not read the selected manual expiry janitor run'}
  $run = $raw | ConvertFrom-Json
  if([string]$run.id -cne $manualRunId -or [string]$janitor.id -cnotmatch '^[1-9][0-9]*$' -or $run.workflow_id -ne $janitor.id -or
    $run.path -cne ".github/workflows/$janitorFile" -or $run.head_repo -cne $repo -or
    $run.head_sha -cne $env:GITHUB_SHA -or $run.head_branch -cne 'main' -or $run.event -cne 'workflow_dispatch' -or
    $run.status -cne 'completed' -or $run.conclusion -cne 'success' -or [string]$run.run_attempt -cnotmatch '^[1-9][0-9]*$'){
    throw 'Manual expiry janitor run is not successful on the exact reviewed main commit'
  }
  $raw = gh api "$runPath/attempts/$($run.run_attempt)/jobs" --jq '{total_count,jobs:[.jobs[]|{name,head_sha,status,conclusion,completed_at,steps:[.steps[]|{name,status,conclusion}]}]}'
  if($LASTEXITCODE -or -not $raw){throw 'Could not read the selected manual expiry janitor attempt'}
  $attempt = $raw | ConvertFrom-Json -DateKind String
  $jobs = @($attempt.jobs)
  if($attempt.total_count -ne 1 -or $jobs.Count -ne 1 -or $jobs[0].name -cne 'cleanup' -or
    $jobs[0].head_sha -cne $env:GITHUB_SHA -or $jobs[0].status -cne 'completed' -or $jobs[0].conclusion -cne 'success'){
    throw 'Manual expiry janitor cleanup job did not succeed'
  }
  $job = $jobs[0]
  foreach($stepName in @('Authenticate isolated lab subscription with OIDC','Remove only expired owned qualification groups')){
    $steps = @($job.steps | Where-Object { $_.name -ceq $stepName })
    if($steps.Count -ne 1 -or $steps[0].status -cne 'completed' -or $steps[0].conclusion -cne 'success'){
      throw 'Manual expiry janitor authentication or cleanup step did not succeed'
    }
  }
  $completed = $job.completed_at
} else {
  $raw = gh api "$janitorPath/runs?branch=main&event=schedule&status=success&per_page=1" --jq '.workflow_runs[0] | {id,head_sha,event,status,conclusion,head_branch,updated_at}'
  if($LASTEXITCODE -or -not $raw){throw 'Could not read recent independent expiry janitor evidence'}
  $run = $raw | ConvertFrom-Json -DateKind String
  if([string]$run.id -cnotmatch '^[1-9][0-9]*$' -or $run.head_sha -cnotmatch '^[a-f0-9]{40}$' -or
    $run.event -cne 'schedule' -or $run.status -cne 'completed' -or $run.conclusion -cne 'success' -or $run.head_branch -cne 'main'){
    throw 'Independent expiry janitor lacks recent successful schedule evidence'
  }
  $completed = $run.updated_at
}
$latest = [DateTimeOffset]::MinValue
$now = [DateTimeOffset]::UtcNow
if(-not [DateTimeOffset]::TryParse($completed,[ref]$latest) -or $latest -gt $now -or $latest -lt $now.AddMinutes(-90)){
  throw 'Independent expiry janitor evidence must be successful within the last 90 minutes'
}
Assert-CertOpsStoreGroupIdentity -Registration $registration -Group (Read-StoreGroup)
$registration.observedAt = [DateTimeOffset]::UtcNow.ToString('o')
$registration.cleanupClientSha256 = $independent
$registration.workflowOwnedGroupVerified = $true
$registration.independentExpiryVerified = $true
$registration.janitorRunId = [string]$run.id
$registration.janitorCommit = $run.head_sha
Assert-CertOpsStoreRegistrationTime -Registration $registration -Now ([DateTimeOffset]::UtcNow)
$receipt = $registration | ConvertTo-Json -Compress
$digest = Get-CertOpsStoreHash $receipt
New-Item -ItemType Directory -Force 'qualification-results' | Out-Null
$out = (Resolve-Path 'qualification-results').Path
[IO.File]::WriteAllText((Join-Path $out 'store-noiis-registration.json'),$receipt,[Text.UTF8Encoding]::new($false))
Set-Content -LiteralPath (Join-Path $out 'store-noiis-registration.sha256') -Value $digest
Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value ('receipt=' + $receipt)
Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value ('receipt_sha256=' + $digest)

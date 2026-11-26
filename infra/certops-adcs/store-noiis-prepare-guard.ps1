# The separate cleanup identity verifies the run-owned group and four-hour
# expiry before any VM deployment. ARM group upsert is not a create-only
# claim. The provisioner never creates or retags the already registered group.
function Get-CertOpsStoreHash {
  param([string]$Text)
  return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Text))).ToLowerInvariant()
}

function Assert-CertOpsStorePreparationWorkflow {
  param([string]$ResourceGroup)
  $workflow = 'tokentimerch/tokentimer-core/.github/workflows/certops-adcs-store-noiis-prepare.yml@refs/heads/main'
  if($env:GITHUB_ACTIONS -cne 'true' -or $env:GITHUB_REPOSITORY -cne 'tokentimerch/tokentimer-core' -or
    $env:GITHUB_WORKFLOW_REF -cne $workflow -or $env:GITHUB_REF -cne 'refs/heads/main' -or
    $env:GITHUB_EVENT_NAME -cne 'workflow_dispatch' -or $env:GITHUB_SHA -cnotmatch '^[a-f0-9]{40}$' -or
    $env:GITHUB_RUN_ID -cnotmatch '^[1-9][0-9]*$' -or $env:GITHUB_RUN_ATTEMPT -cnotmatch '^[1-9][0-9]*$' -or
    $ResourceGroup -cne "tt-certops-$env:GITHUB_RUN_ID-$env:GITHUB_RUN_ATTEMPT"){
    throw 'Protected Store preparation workflow and exact run group are required'
  }
}
function Assert-CertOpsStoreRegistrationTime {
  param([System.Collections.IDictionary]$Registration,[DateTimeOffset]$Now)
  $utc = '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|\+00:00)$'
  foreach($name in @('createdAt','expiresAt','observedAt')){
    if($Registration[$name] -isnot [string] -or $Registration[$name] -cnotmatch $utc){throw 'Invalid Store registration time'}
  }
  $created = [DateTimeOffset]::Parse($Registration.createdAt,[Globalization.CultureInfo]::InvariantCulture)
  $expiry = [DateTimeOffset]::Parse($Registration.expiresAt,[Globalization.CultureInfo]::InvariantCulture)
  $observed = [DateTimeOffset]::Parse($Registration.observedAt,[Globalization.CultureInfo]::InvariantCulture)
  if($expiry -ne $created.AddHours(4) -or $observed -lt $created -or $observed -gt $Now -or
    $observed -lt $Now.AddMinutes(-10) -or $expiry -lt $Now.AddMinutes(210)){
    throw 'Store registration must have a fresh independent readback and usable four-hour lease'
  }
}

function Read-CertOpsStoreRegistration {
  param([string]$Path,[string]$ExpectedSha256,[string]$ResourceGroup,[string]$Location,
    [DateTimeOffset]$Now=[DateTimeOffset]::UtcNow)
  Assert-CertOpsStorePreparationWorkflow -ResourceGroup $ResourceGroup
  if([string]::IsNullOrWhiteSpace($Path) -or $ExpectedSha256 -cnotmatch '^[a-f0-9]{64}$'){
    throw 'Independently pinned Store registration receipt required'
  }
  $file = Get-Item -LiteralPath $Path -ErrorAction Stop
  if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -lt 1 -or $file.Length -gt 4096){
    throw 'Expected a bounded regular Store registration receipt'
  }
  $bytes = [IO.File]::ReadAllBytes($file.FullName)
  if($bytes.Length -lt 1 -or $bytes.Length -gt 4096 -or
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant() -cne $ExpectedSha256){
    throw 'Store registration receipt digest mismatch'
  }
  $receipt = [Text.UTF8Encoding]::new($false,$true).GetString($bytes) | ConvertFrom-Json -AsHashtable -DateKind String
  $keys = @('schema','resourceGroup','subscriptionSha256','location','workflowCommit','runId','runAttempt',
    'mediaSourceCommit','mediaReceiptSha256','registrationNonce','createdAt','expiresAt','observedAt',
    'cleanupClientSha256','provisionClientSha256','workflowOwnedGroupVerified','independentExpiryVerified','janitorRunId','janitorCommit')
  if($receipt -isnot [System.Collections.IDictionary] -or (Compare-Object $keys @($receipt.Keys) -CaseSensitive)){
    throw 'Unsupported Store registration receipt schema'
  }
  if($receipt.schema -cne 'certops-adcs-store-registration-v1' -or $receipt.resourceGroup -cne $ResourceGroup -or
    $receipt.subscriptionSha256 -cne (Get-CertOpsStoreHash $env:AZURE_SUBSCRIPTION_ID) -or
    $receipt.location -cne $Location -or $receipt.workflowCommit -cne $env:GITHUB_SHA -or
    $receipt.runId -isnot [string] -or $receipt.runId -cne $env:GITHUB_RUN_ID -or
    $receipt.runAttempt -isnot [string] -or $receipt.runAttempt -cne $env:GITHUB_RUN_ATTEMPT -or
    $receipt.mediaSourceCommit -cnotmatch '^[a-f0-9]{40}$' -or $receipt.mediaReceiptSha256 -cnotmatch '^[a-f0-9]{64}$' -or
    $receipt.registrationNonce -cnotmatch '^[a-f0-9]{64}$' -or
    $receipt.provisionClientSha256 -cne (Get-CertOpsStoreHash $env:AZURE_CLIENT_ID) -or
    $receipt.cleanupClientSha256 -cnotmatch '^[a-f0-9]{64}$' -or $receipt.cleanupClientSha256 -ceq $receipt.provisionClientSha256 -or
    $receipt.workflowOwnedGroupVerified -isnot [bool] -or $receipt.workflowOwnedGroupVerified -ne $true -or $receipt.independentExpiryVerified -isnot [bool] -or
    $receipt.independentExpiryVerified -ne $true -or $receipt.janitorRunId -isnot [string] -or
    $receipt.janitorRunId -cnotmatch '^[1-9][0-9]*$' -or $receipt.janitorCommit -cnotmatch '^[a-f0-9]{40}$'){
    throw 'Store registration is not bound to this exact owned run with independent cleanup'
  }
  Assert-CertOpsStoreRegistrationTime -Registration $receipt -Now $Now
  return $receipt
}

function Get-CertOpsStoreGroupTags {
  param([System.Collections.IDictionary]$Registration,[switch]$Pending)
  return @{
    purpose=$(if($Pending){'certops-adcs-store-registration-pending'}else{'certops-adcs-qualification'});
    candidateSha=$Registration.workflowCommit;createdAt=$Registration.createdAt;expiresAt=$Registration.expiresAt;
    storePrepareRun=$Registration.runId;storePrepareAttempt=$Registration.runAttempt;storePrepareNonce=$Registration.registrationNonce
  }
}

function Assert-CertOpsStoreGroupIdentity {
  param([System.Collections.IDictionary]$Registration,[PSCustomObject]$Group,[switch]$Pending)
  $expectedId = "/subscriptions/$env:AZURE_SUBSCRIPTION_ID/resourceGroups/$($Registration.resourceGroup)"
  if($Group.id -ine $expectedId -or $Group.name -cne $Registration.resourceGroup -or
    $Group.location -cne $Registration.location -or $Group.properties.provisioningState -cne 'Succeeded'){
    throw 'Expected the exact registered Store qualification group'
  }
  $tags = Get-CertOpsStoreGroupTags -Registration $Registration -Pending:$Pending
  foreach($key in $tags.Keys){
    if($Group.tags.$key -cne $tags[$key]){throw 'Store qualification group owner or expiry changed'}
  }
}

function Assert-CertOpsStoreRegistrationScope {
  param([System.Collections.IDictionary]$Registration,[switch]$Pending)
  $subscription = az account show --only-show-errors --query id -o tsv
  if($LASTEXITCODE -or $subscription -cne $env:AZURE_SUBSCRIPTION_ID){throw 'Expected the exact selected Store subscription'}
  $group = az group show --subscription $env:AZURE_SUBSCRIPTION_ID --name $Registration.resourceGroup --only-show-errors -o json
  if($LASTEXITCODE){throw 'Could not read the independently registered Store group'}
  $members = az resource list --subscription $env:AZURE_SUBSCRIPTION_ID --resource-group $Registration.resourceGroup --only-show-errors --query '[].id' -o json
  if($LASTEXITCODE){throw 'Could not verify that the Store group is empty'}
  $deployments = az deployment group list --subscription $env:AZURE_SUBSCRIPTION_ID --resource-group $Registration.resourceGroup --only-show-errors --query '[].id' -o json
  if($LASTEXITCODE){throw 'Could not verify there is no Store group deployment'}
  $memberIds = $members | ConvertFrom-Json -NoEnumerate
  $deploymentIds = $deployments | ConvertFrom-Json -NoEnumerate
  if($memberIds -isnot [array] -or $deploymentIds -isnot [array]){throw 'Azure did not return bounded Store group inventories'}
  Assert-CertOpsStoreGroupIdentity -Registration $Registration -Group ($group | ConvertFrom-Json -DateKind String) -Pending:$Pending
  if($memberIds.Count -or $deploymentIds.Count){throw 'Store qualification group must be empty before the first deployment'}
  if(-not $Pending){Assert-CertOpsStoreRegistrationTime -Registration $Registration -Now ([DateTimeOffset]::UtcNow)}
}

function Read-CertOpsStoreMemberVmId {
  param([System.Collections.IDictionary]$Registration)
  $expectedId = "/subscriptions/$env:AZURE_SUBSCRIPTION_ID/resourceGroups/$($Registration.resourceGroup)/providers/Microsoft.Compute/virtualMachines/windows-agent"
  $raw = az vm show --subscription $env:AZURE_SUBSCRIPTION_ID --resource-group $Registration.resourceGroup --name windows-agent --only-show-errors --query '{id:id,vmId:vmId,provisioningState:provisioningState,tags:tags}' -o json
  if($LASTEXITCODE){throw 'Could not reidentify the prepared Store member'}
  $vm = $raw | ConvertFrom-Json -DateKind String
  if($vm.id -ine $expectedId -or $vm.vmId -notmatch '^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$' -or
    $vm.provisioningState -cne 'Succeeded' -or $vm.tags.purpose -cne 'certops-adcs-qualification' -or
    $vm.tags.candidateSha -cne $Registration.workflowCommit -or $vm.tags.expiresAt -cne $Registration.expiresAt){
    throw 'Prepared Store member ownership or immutable VM ID could not be proven'
  }
  return $vm.vmId.ToLowerInvariant()
}

function Read-CertOpsStoreGuestReceipt {
  param([string]$Encoded)
  if($Encoded -cnotmatch '^[A-Za-z0-9+/=]{20,1024}$'){throw 'Bounded Store member readiness receipt required'}
  $bytes = [Convert]::FromBase64String($Encoded)
  $text = [Text.UTF8Encoding]::new($false,$true).GetString($bytes)
  $proof = $text | ConvertFrom-Json -AsHashtable
  $expected = [ordered]@{scope='store-noiis-clean-member-readiness';windowsBuild='20348';architecture='x64';
    localSystem=$true;ownedDomain=$true;iisAbsent=$true;agentServiceAbsent=$true;caRpcPing=$true}
  if($proof -isnot [System.Collections.IDictionary] -or (Compare-Object @($expected.Keys) @($proof.Keys) -CaseSensitive)){
    throw 'Unrecognized Store member readiness receipt schema'
  }
  foreach($key in $expected.Keys){
    if($null -eq $proof[$key] -or $proof[$key].GetType() -ne $expected[$key].GetType() -or $proof[$key] -cne $expected[$key]){
      throw 'Store member readiness receipt differs from required scope'
    }
  }
  return @{bytes=$bytes;sha256=(Get-CertOpsStoreHash $text)}
}

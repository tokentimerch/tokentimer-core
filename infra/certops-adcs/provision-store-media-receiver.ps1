# This trusted continuation operates only inside the original independently
# registered Store group. Its existing expiry cleanup owns all resources.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'store-noiis-prepare-guard.ps1')

$proof = node (Join-Path $PSScriptRoot 'store-noiis-qualification-inputs.cjs') --receiver
if ($LASTEXITCODE -or -not $proof) { throw 'Verified Store preparation inputs required' }
$binding = $proof | ConvertFrom-Json -AsHashtable -DateKind String
$registration = $binding.registration
$prepared = $binding.prepared
if ($prepared.scope -cne 'store-preparation-inputs-only' -or
    $registration.subscriptionSha256 -cne (Get-CertOpsStoreHash $env:AZURE_SUBSCRIPTION_ID) -or
    $registration.provisionClientSha256 -cne (Get-CertOpsStoreHash $env:AZURE_CLIENT_ID) -or
    $registration.cleanupClientSha256 -ceq $registration.provisionClientSha256) {
  throw 'Expected the original Store provisioning identity and independent cleanup'
}
$expiry = [DateTimeOffset]::Parse($registration.expiresAt,[Globalization.CultureInfo]::InvariantCulture)
$subscription = $env:AZURE_SUBSCRIPTION_ID
$group = $registration.resourceGroup
$groupId = "/subscriptions/$subscription/resourceGroups/$group"
$scope = @('--subscription',$subscription,'--only-show-errors')

function Assert-ActiveLease {
  if ([DateTimeOffset]::UtcNow -ge $expiry) { throw 'The original Store lab lease expired' }
}
function Assert-OriginalTarget {
  Assert-ActiveLease
  $raw = az group show @scope --name $group -o json
  if ($LASTEXITCODE) { throw 'Original registered Store resource group unavailable' }
  Assert-CertOpsStoreGroupIdentity -Registration $registration -Group ($raw | ConvertFrom-Json -DateKind String)
  if ((Read-CertOpsStoreMemberVmId -Registration $registration) -cne $prepared.memberVmId) {
    throw 'Original prepared Store member changed'
  }
}
function Read-MemberIdentity {
  $vm = az vm show @scope --resource-group $group --name windows-agent --query '{vmId:vmId,identity:identity}' -o json
  if ($LASTEXITCODE) { throw 'Could not read the exact Store member identity' }
  $record = $vm | ConvertFrom-Json
  if ($record.vmId -cne $prepared.memberVmId) { throw 'Original prepared Store member changed' }
  if ($null -ne $record.identity -and ($record.identity.type -cne 'SystemAssigned' -or
      $record.identity.principalId -cnotmatch '^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$')) {
    throw 'Store member has an unexpected managed identity'
  }
  return $record.identity
}

Assert-ActiveLease
& (Join-Path $PSScriptRoot 'login-oidc.ps1')
Assert-OriginalTarget
$network = az network vnet show @scope --resource-group $group --name qualification-private --query '{id:id,peerings:virtualNetworkPeerings}' -o json
if ($LASTEXITCODE) { throw 'Could not verify the original isolated network' }
$network = $network | ConvertFrom-Json
if ($network.id -ine "$groupId/providers/Microsoft.Network/virtualNetworks/qualification-private" -or
    $network.peerings -isnot [array] -or $network.peerings.Count -ne 0) {
  throw 'Receiver requires the original unpeered Store network'
}
$originalIdentity = Read-MemberIdentity
$template = Join-Path $PSScriptRoot 'store-private-media-receiver.bicep'
$parameters = @("registrationNonce=$($registration.registrationNonce)","candidateSha=$($registration.workflowCommit)","expiry=$($registration.expiresAt)")
$deployment = az deployment group create @scope --resource-group $group --name store-private-media-receiver --mode Incremental --template-file $template --parameters @parameters --query properties.outputs -o json
if ($LASTEXITCODE -or -not $deployment) { throw 'The owned private receiver deployment failed' }
$outputs = $deployment | ConvertFrom-Json
Assert-OriginalTarget
$hostname = $outputs.blobHostname.value
$match = [regex]::Match($hostname,'^(ttstore[a-z0-9]{13})\.blob\.core\.windows\.net$')
if (-not $match.Success) { throw 'Unexpected owned storage hostname' }
$storageId = "$groupId/providers/Microsoft.Storage/storageAccounts/$($match.Groups[1].Value)"
$endpointId = "$groupId/providers/Microsoft.Network/privateEndpoints/store-media-ingress"
$containerId = "$storageId/blobServices/default/containers/store-media"
if ($outputs.endpointResourceId.value -ine $endpointId -or $outputs.containerResourceId.value -ine $containerId) {
  throw 'The receiver resources do not belong to the original Store group'
}
$storage = az storage account show @scope --ids $storageId --query '{network:publicNetworkAccess,anonymous:allowBlobPublicAccess,sharedKey:allowSharedKeyAccess,tls:minimumTlsVersion}' -o json
if ($LASTEXITCODE) { throw 'Could not verify private receiver storage policy' }
$policy = $storage | ConvertFrom-Json
if ($policy.network -cne 'Disabled' -or $policy.anonymous -isnot [bool] -or $policy.anonymous -ne $false -or
    $policy.sharedKey -isnot [bool] -or $policy.sharedKey -ne $false -or $policy.tls -cne 'TLS1_2') {
  throw 'Receiver did not retain the required private, Entra-only storage policy'
}
$endpointJson = az network private-endpoint show @scope --ids $endpointId -o json
if ($LASTEXITCODE) { throw 'Could not verify the exact receiver private endpoint' }
$endPoint = $endpointJson | ConvertFrom-Json
$connection = @($endPoint.privateLinkServiceConnections)
$interfaces = @($endPoint.networkInterfaces)
if ($endPoint.provisioningState -cne 'Succeeded' -or $connection.Count -ne 1 -or $interfaces.Count -ne 1 -or
    $endPoint.subnet.id -ine "$groupId/providers/Microsoft.Network/virtualNetworks/qualification-private/subnets/qualification" -or
    $connection[0].privateLinkServiceId -ine $storageId -or
    $connection[0].privateLinkServiceConnectionState.status -cne 'Approved' -or
    @($connection[0].groupIds).Count -ne 1 -or $connection[0].groupIds[0] -cne 'blob' -or
    -not $interfaces[0].id.StartsWith("$groupId/providers/Microsoft.Network/networkInterfaces/",[StringComparison]::OrdinalIgnoreCase)) {
  throw 'The endpoint is outside the prepared private Blob network'
}
$addresses = az network nic show @scope --ids $interfaces[0].id --query 'ipConfigurations[].privateIPAddress' -o tsv
if ($LASTEXITCODE -or @($addresses).Count -ne 1 -or $addresses -cnotmatch '^10\.64\.0\.[0-9]{1,3}$') {
  throw 'Could not verify the receiver private endpoint address'
}
$octets = [ipaddress]::Parse($addresses).GetAddressBytes()
if ($octets[3] -le 6 -or $octets[3] -ge 255) { throw 'Private endpoint address overlaps a lab member or reserved range' }
Assert-OriginalTarget
if ($null -eq $originalIdentity) {
  az vm identity assign @scope --resource-group $group --name windows-agent -o none
  if ($LASTEXITCODE) { throw 'Could not enable the owned member system identity' }
}
$identity = Read-MemberIdentity
if ($null -eq $identity -or ($null -ne $originalIdentity -and $identity.principalId -cne $originalIdentity.principalId)) {
  throw 'The exact Store member identity was not retained'
}
Assert-OriginalTarget
$receipt = [ordered]@{
  scope = 'store-private-media-receiver-infrastructure'
  workflowCommit = $env:GITHUB_SHA
  prepareRunId = $registration.runId
  prepareAttempt = $registration.runAttempt
  registrationSha256 = $prepared.registrationDigest
  preparationSha256 = $prepared.preparationDigest
  mediaReceiptSha256 = $registration.mediaReceiptSha256
  resourceGroup = $group
  memberVmId = $prepared.memberVmId
  expiresAt = $registration.expiresAt
  blobHostname = $hostname
  endpointPrivateAddress = $addresses
  memberPrincipalSha256 = Get-CertOpsStoreHash $identity.principalId
  receiverReaderGranted = $false
  mediaTransferred = $false
  qualificationPassed = $false
}
New-Item -ItemType Directory -Force qualification-results | Out-Null
$receipt | ConvertTo-Json -Compress | Set-Content -LiteralPath 'qualification-results/store-private-media-receiver.json'
Write-Output 'Prepared the private Blob receiver and identified its Windows member system identity.'

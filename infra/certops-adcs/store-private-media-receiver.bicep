// Deploy only from the reviewed, independently verified four-hour Store lab
// lifecycle. The caller re-reads the original group and immutable member.
// The existing lab Contributor provisions the receiver without granting access.
targetScope = 'resourceGroup'

@minLength(64)
@maxLength(64)
param registrationNonce string

@minLength(40)
@maxLength(40)
param candidateSha string

param expiry string

var location = resourceGroup().location
var storageName = 'ttstore${uniqueString(resourceGroup().id, registrationNonce)}'
var ownership = {
  purpose: 'certops-adcs-qualification'
  candidateSha: candidateSha
  expiresAt: expiry
}

resource labNetwork 'Microsoft.Network/virtualNetworks@2024-05-01' existing = {
  name: 'qualification-private'
}

resource labSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  parent: labNetwork
  name: 'qualification'
}

resource store 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  tags: ownership
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    allowCrossTenantReplication: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Disabled'
    supportsHttpsTrafficOnly: true
    networkAcls: {
      bypass: 'None'
      defaultAction: 'Deny'
    }
  }
}

resource blobs 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: store
  name: 'default'
}

resource media 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobs
  name: 'store-media'
  properties: { publicAccess: 'None' }
}

resource endpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = {
  name: 'store-media-ingress'
  location: location
  tags: ownership
  properties: {
    subnet: { id: labSubnet.id }
    privateLinkServiceConnections: [
      {
        name: 'blob'
        properties: {
          privateLinkServiceId: store.id
          groupIds: [ 'blob' ]
        }
      }
    ]
  }
}

resource privateDns 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.blob.core.windows.net'
  location: 'global'
  tags: ownership
}

resource dnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: privateDns
  name: 'store-media-lab-only'
  location: 'global'
  tags: ownership
  properties: {
    registrationEnabled: false
    virtualNetwork: { id: labNetwork.id }
  }
}

resource dnsAttachment 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = {
  parent: endpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      { name: 'blob', properties: { privateDnsZoneId: privateDns.id } }
    ]
  }
}

output endpointResourceId string = endpoint.id
output containerResourceId string = media.id
output blobHostname string = '${store.name}.blob.${environment().suffixes.storage}'

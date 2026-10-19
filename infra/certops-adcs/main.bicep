// Disposable AD CS qualification topology owned by one workflow resource group.
// Creates isolated forest/CA/member/control-plane networking and tagged expiry;
// trusted OIDC provisioning, always-run teardown and the independent janitor
// bound lifetime/cost. No permanent Windows runner or existing domain is used.
targetScope = 'resourceGroup'

@description('UTC expiry used by the independent lab janitor.')
param expiresAt string
param candidateSha string
@allowed(['Standard_D2s_v5', 'Standard_D2as_v5'])
param vmSize string = 'Standard_D2s_v5'
param location string = resourceGroup().location
@secure()
param adminPassword string
param adminUsername string = 'ttqualification'
@allowed(['2019', '2022', '2025'])
param windowsVersion string = '2022'
@description('Add an isolated offline-root host only for genuine two-tier qualification.')
param hierarchy bool = false
@description('Optional second enterprise CA for the isolated issuer-switch campaign only.')
param issuerSwitch bool = false
var windowsSkus = { '2019': '2019-datacenter-gensecond', '2022': '2022-datacenter-g2', '2025': '2025-datacenter-g2' }

var ownership = {
  purpose: 'certops-adcs-qualification'
  expiresAt: expiresAt
  candidateSha: candidateSha
}
var nodes = concat([
  { name: 'domain-ca', ip: '10.64.0.4', os: 'Windows' }
  { name: 'windows-agent', ip: '10.64.0.5', os: 'Windows' }
  { name: 'control-plane', ip: '10.64.0.6', os: 'Linux' }
], hierarchy ? [{ name: 'offline-root', ip: '10.64.0.7', os: 'Windows' }] : [], issuerSwitch ? [{ name: 'destination-ca', ip: '10.64.0.8', os: 'Windows' }] : [])

resource network 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: 'qualification-private'
  location: location
  tags: ownership
  properties: {
    addressSpace: { addressPrefixes: ['10.64.0.0/24'] }
    subnets: [{ name: 'qualification', properties: { addressPrefix: '10.64.0.0/24', networkSecurityGroup: { id: nsg.id }, natGateway: { id: nat.id } } }]
  }
}
// Egress-only public address; no VM receives a public IP or public listener.
resource egressIp 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: 'qualification-egress-only'
  location: location
  tags: ownership
  sku: { name: 'Standard' }
  properties: { publicIPAllocationMethod: 'Static' }
}
resource nat 'Microsoft.Network/natGateways@2024-05-01' = {
  name: 'qualification-egress-only'
  location: location
  tags: ownership
  sku: { name: 'Standard' }
  properties: { publicIpAddresses: [{ id: egressIp.id }], idleTimeoutInMinutes: 4 }
}
resource nsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: 'qualification-private'
  location: location
  tags: ownership
  properties: {
    securityRules: [{
      name: 'deny-public-ingress'
      properties: { priority: 100, direction: 'Inbound', access: 'Deny', protocol: '*', sourcePortRange: '*', destinationPortRange: '*', sourceAddressPrefix: 'Internet', destinationAddressPrefix: '*' }
    }]
  }
}
resource interfaces 'Microsoft.Network/networkInterfaces@2024-05-01' = [for node in nodes: {
  name: '${node.name}-nic'
  location: location
  tags: ownership
  properties: {
    ipConfigurations: [{ name: 'private', properties: { privateIPAllocationMethod: 'Static', privateIPAddress: node.ip, subnet: { id: '${network.id}/subnets/qualification' } } }]
  }
}]
resource machines 'Microsoft.Compute/virtualMachines@2024-07-01' = [for (node, index) in nodes: {
  name: node.name
  location: location
  tags: ownership
  properties: {
    hardwareProfile: { vmSize: vmSize }
    networkProfile: { networkInterfaces: [{ id: interfaces[index].id }] }
    storageProfile: {
      imageReference: node.os == 'Windows'
        ? { publisher: 'MicrosoftWindowsServer', offer: 'WindowsServer', sku: index == 1 ? windowsSkus[windowsVersion] : '2022-datacenter-g2', version: 'latest' }
        : { publisher: 'Canonical', offer: '0001-com-ubuntu-server-jammy', sku: '22_04-lts-gen2', version: 'latest' }
      osDisk: { createOption: 'FromImage', managedDisk: { storageAccountType: 'StandardSSD_LRS' }, deleteOption: 'Delete' }
    }
    osProfile: {
      computerName: node.os == 'Windows' ? (index == 0 ? 'tt-ca' : (index == 1 ? 'tt-agent' : (node.name == 'destination-ca' ? 'tt-ca-switch' : 'tt-root'))) : 'tt-control'
      adminUsername: adminUsername
      adminPassword: adminPassword
      windowsConfiguration: node.os == 'Windows' ? { provisionVMAgent: true, enableAutomaticUpdates: true } : null
      linuxConfiguration: node.os == 'Linux' ? { provisionVMAgent: true, disablePasswordAuthentication: false } : null
    }
  }
}]
output nodes array = [for node in nodes: { name: node.name, privateIp: node.ip, os: node.os }]

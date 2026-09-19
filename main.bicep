param location string = resourceGroup().location
param clusterName string = 'aks-ids-cluster'

param acrName string = 'acrids${uniqueString(resourceGroup().id)}'

resource acr 'Microsoft.ContainerRegistry/registries@2023-01-01-preview' = {
  name: acrName
  location: location
  sku: { name: 'Basic' }
  properties: { adminUserEnabled: true }
}

resource aks 'Microsoft.ContainerService/managedClusters@2023-02-01' = {
  name: clusterName
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
  agentPoolProfiles: [
      {
        name: 'agentpool'
        count: 2
        vmSize: 'Standard_D2ads_v7'  // Updated to an allowed v7 SKU
        osType: 'Linux'
        mode: 'System'
      }
    ]
    dnsPrefix: clusterName
  }
}

var acrPullRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
resource aksAcrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, aks.id, acrPullRole)
  scope: acr
  properties: {
    roleDefinitionId: acrPullRole
    principalId: aks.properties.identityProfile.kubeletidentity.objectId
    principalType: 'ServicePrincipal'
  }
}

// Export the ACR Login Server URL to pass to our Docker build script
output acrLoginServer string = acr.properties.loginServer

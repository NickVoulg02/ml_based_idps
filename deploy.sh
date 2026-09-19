#!/bin/bash
set -e 

RESOURCE_GROUP="rg-ids-experiment"
LOCATION="eastus"
CLUSTER_NAME="aks-ids-cluster"

echo "Creating Resource Group..."
az group create --name $RESOURCE_GROUP --location $LOCATION -o none

echo "Deploying Infrastructure via Bicep..."
ACR_SERVER=$(az deployment group create \
  --resource-group $RESOURCE_GROUP \
  --template-file ./main.bicep \
  --query properties.outputs.acrLoginServer.value \
  --output tsv)

echo "Infrastructure provisioned. ACR Server: $ACR_SERVER"

echo "Authenticating Local Tools..."
az aks get-credentials --resource-group $RESOURCE_GROUP --name $CLUSTER_NAME --overwrite-existing
# Strip the '.azurecr.io' suffix to get the raw ACR name for login
az acr login --name ${ACR_SERVER%%.*}

echo "Building and Pushing Docker Images..."
docker build -t $ACR_SERVER/ids-ml-api:v1 ./api
docker push $ACR_SERVER/ids-ml-api:v1

docker build -t $ACR_SERVER/ids-sensor:v1 ./sensor
docker push $ACR_SERVER/ids-sensor:v1

echo "Deploying Kubernetes Manifests..."
# Loop through all yaml files in the k8s folder, replace the placeholder with the real ACR URL, and apply them
for file in ./k8s/*.yaml; do
  sed "s|YOUR-ACR-NAME|$ACR_SERVER|g" $file | kubectl apply -f -
done

echo "Full Environment Deployment Complete!"
kubectl get pods
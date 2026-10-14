<#
Authenticate only the dedicated lab Azure identity using the trusted workflow OIDC token. No
persistent credentials or subscription-wide cleanup is introduced; callers still validate exact
owned resource-group tags/expiry.
#>
$ErrorActionPreference = 'Stop'
foreach ($name in @('AZURE_CLIENT_ID','AZURE_TENANT_ID','AZURE_SUBSCRIPTION_ID')) {
  $value = [Environment]::GetEnvironmentVariable($name)
  if ($value -notmatch '^[0-9a-fA-F-]{36}$') { throw "Missing or invalid $name for isolated lab environment" }
}
if (-not $env:ACTIONS_ID_TOKEN_REQUEST_URL -or -not $env:ACTIONS_ID_TOKEN_REQUEST_TOKEN) { throw 'GitHub OIDC token request unavailable' }
$url = $env:ACTIONS_ID_TOKEN_REQUEST_URL + '&audience=api%3A%2F%2FAzureADTokenExchange'
$oidc = Invoke-RestMethod -Uri $url -Headers @{ Authorization = "Bearer $env:ACTIONS_ID_TOKEN_REQUEST_TOKEN" }
Write-Output "::add-mask::$($oidc.value)"
az login --service-principal --username $env:AZURE_CLIENT_ID --tenant $env:AZURE_TENANT_ID --federated-token $oidc.value --output none
if ($LASTEXITCODE -ne 0) { throw 'Lab OIDC login failed' }
az account set --subscription $env:AZURE_SUBSCRIPTION_ID
if ($LASTEXITCODE -ne 0) { throw 'Could not select isolated lab subscription' }

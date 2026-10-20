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
# The token request is read-only and repeated on every ARM poll; one runner network
# blip must not abort a 90 minute lab or block its own cleanup.
$oidc = $null
for ($attempt = 1; $attempt -le 4 -and -not $oidc; $attempt++) {
  try { $oidc = Invoke-RestMethod -Uri $url -Headers @{ Authorization = "Bearer $env:ACTIONS_ID_TOKEN_REQUEST_TOKEN" } -TimeoutSec 30 }
  catch { if ($attempt -eq 4) { throw 'GitHub OIDC token request failed after retries' }; Start-Sleep -Seconds (5 * $attempt * $attempt) }
}
Write-Output "::add-mask::$($oidc.value)"
az login --service-principal --username $env:AZURE_CLIENT_ID --tenant $env:AZURE_TENANT_ID --federated-token $oidc.value --output none
if ($LASTEXITCODE -ne 0) { throw 'Lab OIDC login failed' }
az account set --subscription $env:AZURE_SUBSCRIPTION_ID
if ($LASTEXITCODE -ne 0) { throw 'Could not select isolated lab subscription' }

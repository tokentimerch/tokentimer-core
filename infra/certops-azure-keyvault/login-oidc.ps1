$ErrorActionPreference = 'Stop'
# WARNING: TEMPORARY PRE-MERGE EXCEPTION. Revert before merging.
# Use the same exact-ref/event policy as provisioning and cleanup.
& node -e "const p = require('./infra/certops-azure-keyvault/policy'); if (process.env.GITHUB_ACTIONS !== 'true' || process.env.GITHUB_REPOSITORY !== p.REPOSITORY || !p.trustedRef(process.env)) process.exit(1)"
if ($LASTEXITCODE -ne 0) { throw 'AZURE_KV_TRUSTED_MAIN_REQUIRED' }
$oidcUrl = [Uri]$env:ACTIONS_ID_TOKEN_REQUEST_URL
if ($oidcUrl.Scheme -ne 'https' -or -not $oidcUrl.Host.EndsWith('.actions.githubusercontent.com')) { throw 'AZURE_KV_OIDC_AUTHORITY_DENIED' }
# Isolate CLI caches from other jobs and from the artifact directory.
$root = & node -e "process.stdout.write(require('./infra/certops-azure-keyvault/lab').privateRoot())"
if ($LASTEXITCODE -ne 0) { throw 'AZURE_KV_PRIVATE_DIRECTORY_REQUIRED' }
$env:AZURE_CONFIG_DIR = Join-Path $root 'azure-cli'
New-Item -ItemType Directory -Force -Path $env:AZURE_CONFIG_DIR | Out-Null
if (-not $IsWindows) { & chmod 700 $env:AZURE_CONFIG_DIR }
Add-Content -LiteralPath $env:GITHUB_ENV -Value "AZURE_CONFIG_DIR=$env:AZURE_CONFIG_DIR"
& (Join-Path $PSScriptRoot '../certops-adcs/login-oidc.ps1')
if ($LASTEXITCODE -ne 0) { throw 'AZURE_KV_OIDC_LOGIN_FAILED' }

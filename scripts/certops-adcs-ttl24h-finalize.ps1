<#
Explicit postday SYSTEM native entry point for the separate TTL purpose. Uses
original local private state and genuine public login; no officer credential is
persisted or requested. Returns only validated bounded native-stage JSON, which
cannot qualify without the independent CA/controller crosscheck.
#>
param([Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$Nonce,
 [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9+/=]{1,32768}$')][string]$PreCaSummaryBase64)
$ErrorActionPreference='Stop'
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18' -or (Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Original disposable SYSTEM member required'}
$r=Get-Content -LiteralPath 'C:\ttqualification\runtime.json' -Raw|ConvertFrom-Json
if($r.candidateSha -cnotmatch '^[a-f0-9]{40}$' -or $r.source -cne "C:\ttqualification\source\tokentimer-core-$($r.candidateSha)" -or $r.buildMode -ne 'qualification-only-not-release' -or $r.node -cnotmatch '^C:\\ttqualification\\tools\\node-v24\.[0-9]+\.[0-9]+-win-x64\\node.exe$'){throw 'Pinned original candidate runtime required'}
$env:PATH=$r.path;$env:NODE_ENV='test';$env:NODE_EXTRA_CA_CERTS='C:\ttqualification\api-public.pem';$env:CERTOPS_ADCS_DISPOSABLE_LAB='1';$env:CERTOPS_ADCS_TTL24H='1';$env:CERTOPS_ENABLED='true'
$env:DB_HOST='10.64.0.6';$env:DB_PORT='5432';$env:DB_USER='tokentimer';$env:DB_PASSWORD='password';$env:DB_NAME='tokentimer'
# Public disposable Compose signing constants match the unchanged API fixture;
# these are test-only controller inputs, never domain or resume credentials.
$env:CERTOPS_SIGNING_ENCRYPTION_KEY='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
$env:CERTOPS_REGISTRATION_ENCRYPTION_KEY='abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'
$env:CERTOPS_ADCS_OFFICER_PASSWORD=$null
Set-Location -LiteralPath $r.source
$script=Join-Path $r.source 'scripts\certops-adcs-ttl24h-finish.js'
# Production maintenance log streams stay private and are not parsed as proof.
& $r.node $script $Nonce $PreCaSummaryBase64 2>&1|Out-Null
if($LASTEXITCODE -ne 0){throw 'Actual postday native TTL check failed; preserve owned recovery state'}
$public=& $r.node $script '--read-stage' $Nonce
if($LASTEXITCODE -ne 0){throw 'Closed public native-stage readback refused'}
if([Text.Encoding]::UTF8.GetByteCount(($public -join [Environment]::NewLine)) -gt 65536){throw 'Bounded public native-stage result required'}
$public

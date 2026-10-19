<#
Install the lockfile-selected Playwright browser only for comprehensive domain
qualification. Runs on the newly owned SYSTEM member after windows-tools.ps1;
does not execute a test, enroll a certificate or modify the Windows trust store.
#>
param([Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$CandidateSha)
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Browser bootstrap requires the owned disposable member'}
$runtime=Get-Content -LiteralPath 'C:\ttqualification\runtime.json' -Raw | ConvertFrom-Json
if($runtime.candidateSha -ne $CandidateSha -or $runtime.buildMode -ne 'qualification-only-not-release'){throw 'Browser candidate runtime mismatch'}
$env:PATH=$runtime.path
Set-Location -LiteralPath $runtime.source
if((Get-Content -LiteralPath 'package.json' -Raw | ConvertFrom-Json).name -ne 'tokentimer-core'){throw 'Unexpected browser candidate source'}
& 'C:\ttqualification\tools\pnpm\pnpm.cmd' install --frozen-lockfile --filter tokentimer-core
if($LASTEXITCODE -ne 0){throw 'Locked browser harness dependencies failed to install'}
$browserCache='C:\ttqualification\browser-cache'
if(Test-Path -LiteralPath $browserCache){throw 'Refusing an existing browser cache'}
$env:PLAYWRIGHT_BROWSERS_PATH=$browserCache
& 'C:\ttqualification\tools\pnpm\pnpm.cmd' exec playwright install chromium
if($LASTEXITCODE -ne 0){throw 'Pinned Chromium download failed'}
$source=Join-Path $runtime.source 'infra\certops-adcs\browser-windows-tools.ps1'
@{candidateSha=$CandidateSha;browserCache=$browserCache;bootstrapSourceSha256=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant();playwrightVersion=(Get-Content -LiteralPath 'package.json' -Raw|ConvertFrom-Json).devDependencies.playwright} | ConvertTo-Json | Set-Content -LiteralPath 'C:\ttqualification\browser-runtime.json'
Write-Output 'CERTOPS_STAGE=locked-domain-browser-ready'

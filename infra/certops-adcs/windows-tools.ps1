<#
Prepare exact candidate source, pinned Node/Go and locally compiled native helpers on the new
disposable Windows member. Writes public runtime digests for later verification; qualification-only
capability selection is never a released build claim.
#>
param([Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$CandidateSha,
  [Parameter(Mandatory)][string]$ApiPublicPemBase64,
  [ValidateSet('2019','2022','2025')][string]$WindowsVersion = '2022')
$ErrorActionPreference = 'Stop'
if ((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test') { throw 'Tool bootstrap requires isolated qualification domain member' }
$root='C:\ttqualification'
if (Test-Path $root) { throw 'Refusing existing qualification workspace' }
New-Item -ItemType Directory -Path "$root\tools" -Force | Out-Null
# Enumerate REST arrays before filtering; Windows PowerShell otherwise pipes the whole array.
$nodeRelease=(Invoke-RestMethod 'https://nodejs.org/dist/index.json') | Where-Object { $_.version -match '^v24\.' -and $_.files -contains 'win-x64-zip' } | Select-Object -First 1
if (-not $nodeRelease) { throw 'Supported Node 24 Windows archive unavailable' }
$nodeName="node-$($nodeRelease.version)-win-x64.zip"
$sums=Invoke-RestMethod "https://nodejs.org/dist/$($nodeRelease.version)/SHASUMS256.txt"
$nodeHash=[regex]::Match($sums,"(?m)^([a-f0-9]{64})\s+$([regex]::Escape($nodeName))\r?$").Groups[1].Value
if (-not $nodeHash) { throw 'Node archive checksum unavailable' }
Invoke-WebRequest "https://nodejs.org/dist/$($nodeRelease.version)/$nodeName" -OutFile "$root\tools\node.zip"
if ((Get-FileHash "$root\tools\node.zip" -Algorithm SHA256).Hash.ToLowerInvariant() -ne $nodeHash) { throw 'Node checksum mismatch' }
Expand-Archive "$root\tools\node.zip" "$root\tools"
$nodeDirectory="$root\tools\node-$($nodeRelease.version)-win-x64"
$goRelease=(Invoke-RestMethod 'https://go.dev/dl/?mode=json') | Where-Object stable | Select-Object -First 1
$goFile=$goRelease.files | Where-Object { $_.os -eq 'windows' -and $_.arch -eq 'amd64' -and $_.kind -eq 'archive' } | Select-Object -First 1
if (-not $goFile) { throw 'Stable Go Windows archive unavailable' }
Invoke-WebRequest "https://go.dev/dl/$($goFile.filename)" -OutFile "$root\tools\go.zip"
if ((Get-FileHash "$root\tools\go.zip" -Algorithm SHA256).Hash.ToLowerInvariant() -ne $goFile.sha256) { throw 'Go checksum mismatch' }
Expand-Archive "$root\tools\go.zip" "$root\tools"
$env:PATH="$nodeDirectory;$root\tools\go\bin;$root\tools\pnpm;$env:PATH"
& "$nodeDirectory\npm.cmd" install --global pnpm@11.13.0 --prefix "$root\tools\pnpm" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Pinned pnpm installation failed' }
Invoke-WebRequest "https://github.com/tokentimerch/tokentimer-core/archive/$CandidateSha.zip" -OutFile "$root\candidate.zip"
Expand-Archive "$root\candidate.zip" "$root\source"
$source="$root\source\tokentimer-core-$CandidateSha"
if (-not (Test-Path "$source\package.json")) { throw 'Candidate archive layout did not match commit' }
Set-Location $source
& "$root\tools\pnpm\pnpm.cmd" install --frozen-lockfile --filter '@tokentimer/api...' --filter '@tokentimer/agent...' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Locked candidate dependencies failed to install' }
& "$nodeDirectory\node.exe" packages/agent/scripts/build-windows-service-host.js | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Native Windows service host build failed' }
foreach ($module in @('adcs-chain','adcs-cmc','verifier')) {
  & "$nodeDirectory\node.exe" "packages/agent/reference/$module/build.cjs" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Native $module helper build failed" }
}
# Compile a distinct qualification build. The checked-in release manifest is
# never edited or promoted by this lab and this package is never published.
$inputPath="$root\qualification-capabilities.json"
$manifest=Get-Content packages/agent/src/capabilities/qualified-capabilities.json -Raw | ConvertFrom-Json
@{qualified=@($manifest.qualified)+@('adcs-enroll-v1')} | ConvertTo-Json | Set-Content $inputPath
& "$nodeDirectory\node.exe" -e "require('./packages/agent/scripts/build-qualified-capabilities').main({inputPath:process.argv[1]})" $inputPath | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Isolated qualification capability compilation failed' }
[IO.File]::WriteAllBytes("$root\api-public.pem",[Convert]::FromBase64String($ApiPublicPemBase64))
& "$nodeDirectory\node.exe" scripts/certops-agent-package.js "$source\packages\agent" "$root\package-candidate" $CandidateSha 'adcs-enroll-v1' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Canonical agent package creation failed' }
$packageReceiptPath="$root\package-candidate\artifact.json"
$packageReceipt=Get-Content $packageReceiptPath -Raw | ConvertFrom-Json
$packageArchive="$root\package-candidate\artifacts\$($packageReceipt.archive)"
if((Get-FileHash $packageArchive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $packageReceipt.sha256){throw 'Candidate package checksum mismatch'}
@{agentPackage=$packageArchive;agentPackageReceipt=$packageReceiptPath;candidateSha=$CandidateSha;source=$source;windowsVersion=$WindowsVersion;node="$nodeDirectory\node.exe";nodeVersion=$nodeRelease.version;nodeArchiveSha256=$nodeHash;goVersion=$goRelease.version;goArchiveSha256=$goFile.sha256;sourceArchiveSha256=(Get-FileHash "$root\candidate.zip" -Algorithm SHA256).Hash;qualifiedModuleSha256=(Get-FileHash packages/agent/src/capabilities/qualified-capabilities.generated.js -Algorithm SHA256).Hash;path=$env:PATH;buildMode='qualification-only-not-release'} | ConvertTo-Json | Set-Content "$root\runtime.json"
Write-Output 'CERTOPS_STAGE=isolated-candidate-windows-tools-built'

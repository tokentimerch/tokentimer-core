<#
Prepare exact candidate source, pinned Node/Go and locally compiled native helpers on the new
disposable Windows member. Writes public runtime digests for later verification; qualification-only
capability selection is never a released build claim.
#>
param([Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$CandidateSha,
  [Parameter(Mandatory)][string]$ApiPublicPemBase64,
  [ValidateSet('2019','2022','2025')][string]$WindowsVersion = '2022')
$ErrorActionPreference = 'Stop'
# Keep transfer progress local to this noninteractive bootstrap.
$script:ProgressPreference = 'SilentlyContinue'
$toolsStage='membership'
try{
if ((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test') { throw 'Tool bootstrap requires isolated qualification domain member' }
$toolsStage='workspace'
$root='C:\ttqualification'
if (Test-Path $root) { throw 'Refusing existing qualification workspace' }
New-Item -ItemType Directory -Path "$root\tools" -Force | Out-Null
# Enumerate REST arrays before filtering; Windows PowerShell otherwise pipes the whole array.
$toolsStage='node-metadata'
$nodeRelease=(Invoke-RestMethod -UseBasicParsing -TimeoutSec 60 'https://nodejs.org/dist/index.json') | Where-Object { $_.version -match '^v24\.' -and $_.files -contains 'win-x64-zip' } | Select-Object -First 1
if (-not $nodeRelease) { throw 'Supported Node 24 Windows archive unavailable' }
$nodeName="node-$($nodeRelease.version)-win-x64.zip"
$toolsStage='node-checksum-metadata'
$sums=Invoke-RestMethod -UseBasicParsing -TimeoutSec 60 "https://nodejs.org/dist/$($nodeRelease.version)/SHASUMS256.txt"
$nodeHash=[regex]::Match($sums,"(?m)^([a-f0-9]{64})\s+$([regex]::Escape($nodeName))\r?$").Groups[1].Value
if (-not $nodeHash) { throw 'Node archive checksum unavailable' }
$toolsStage='node-download'
Invoke-WebRequest -UseBasicParsing -TimeoutSec 300 "https://nodejs.org/dist/$($nodeRelease.version)/$nodeName" -OutFile "$root\tools\node.zip"
$toolsStage='node-verify'
if ((Get-FileHash "$root\tools\node.zip" -Algorithm SHA256).Hash.ToLowerInvariant() -ne $nodeHash) { throw 'Node checksum mismatch' }
$toolsStage='node-extract'
Expand-Archive "$root\tools\node.zip" "$root\tools"
$nodeDirectory="$root\tools\node-$($nodeRelease.version)-win-x64"
$toolsStage='go-metadata'
$goRelease=(Invoke-RestMethod -UseBasicParsing -TimeoutSec 60 'https://go.dev/dl/?mode=json') | Where-Object stable | Select-Object -First 1
$goFile=$goRelease.files | Where-Object { $_.os -eq 'windows' -and $_.arch -eq 'amd64' -and $_.kind -eq 'archive' } | Select-Object -First 1
if (-not $goFile) { throw 'Stable Go Windows archive unavailable' }
$toolsStage='go-download'
Invoke-WebRequest -UseBasicParsing -TimeoutSec 300 "https://go.dev/dl/$($goFile.filename)" -OutFile "$root\tools\go.zip"
$toolsStage='go-verify'
if ((Get-FileHash "$root\tools\go.zip" -Algorithm SHA256).Hash.ToLowerInvariant() -ne $goFile.sha256) { throw 'Go checksum mismatch' }
$toolsStage='go-extract'
Expand-Archive "$root\tools\go.zip" "$root\tools"
$env:PATH="$nodeDirectory;$root\tools\go\bin;$root\tools\pnpm;$env:PATH"
$toolsStage='pnpm-install'
& "$nodeDirectory\npm.cmd" install --global pnpm@11.13.0 --prefix "$root\tools\pnpm" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Pinned pnpm installation failed' }
$toolsStage='source-download'
Invoke-WebRequest -UseBasicParsing -TimeoutSec 300 "https://github.com/tokentimerch/tokentimer-core/archive/$CandidateSha.zip" -OutFile "$root\candidate.zip"
$toolsStage='source-extract'
Expand-Archive "$root\candidate.zip" "$root\source"
$source="$root\source\tokentimer-core-$CandidateSha"
$toolsStage='source-layout'
if (-not (Test-Path "$source\package.json")) { throw 'Candidate archive layout did not match commit' }
Set-Location $source
# The focused native journey starts the production worker entry point, whose
# workspace dependencies are separate from the API and installed agent.
$toolsStage='dependencies'
& "$root\tools\pnpm\pnpm.cmd" install --frozen-lockfile --filter '@tokentimer/api...' --filter '@tokentimer/agent...' --filter '@tokentimer/worker...' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Locked candidate dependencies failed to install' }
$toolsStage='service-host'
& "$nodeDirectory\node.exe" packages/agent/scripts/build-windows-service-host.js | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Native Windows service host build failed' }
foreach ($module in @('adcs-chain','adcs-cmc','verifier')) {
  $toolsStage=@{'adcs-chain'='chain-helper';'adcs-cmc'='cmc-helper';'verifier'='verifier-helper'}[$module]
  & "$nodeDirectory\node.exe" "packages/agent/reference/$module/build.cjs" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Native $module helper build failed" }
}
# Test the actual runtime lookups before enrolling: a successful Go build is
# insufficient when its output name cannot be resolved by the service.
$toolsStage='helper-readiness'
& "$nodeDirectory\node.exe" -e "const i=require('./packages/agent/src/issuers');for(const name of ['resolveAdcsChainHelperPath','resolveAdcsCmcHelperPath']){const r=i[name]();if(r.error||!require('node:fs').statSync(r.path).isFile())throw new Error(name+' did not resolve a built native helper')}"
if ($LASTEXITCODE -ne 0) { throw 'Native AD CS runtime helper readiness failed' }
# Compile a distinct qualification build. The checked-in release manifest is
# never edited or promoted by this lab and this package is never published.
$toolsStage='capability-build'
$inputPath="$root\qualification-capabilities.json"
$manifest=Get-Content packages/agent/src/capabilities/qualified-capabilities.json -Raw | ConvertFrom-Json
@{qualified=@($manifest.qualified)+@('adcs-enroll-v1')} | ConvertTo-Json | Set-Content $inputPath
& "$nodeDirectory\node.exe" -e "require('./packages/agent/scripts/build-qualified-capabilities').main({inputPath:process.argv[1]})" $inputPath | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Isolated qualification capability compilation failed' }
$toolsStage='api-trust'
[IO.File]::WriteAllBytes("$root\api-public.pem",[Convert]::FromBase64String($ApiPublicPemBase64))
$toolsStage='package-build'
& "$nodeDirectory\node.exe" scripts/certops-agent-package.js "$source\packages\agent" "$root\package-candidate" $CandidateSha 'adcs-enroll-v1' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Canonical agent package creation failed' }
$toolsStage='package-verify'
$packageReceiptPath="$root\package-candidate\artifact.json"
$packageReceipt=Get-Content $packageReceiptPath -Raw | ConvertFrom-Json
$packageArchive="$root\package-candidate\artifacts\$($packageReceipt.archive)"
if((Get-FileHash $packageArchive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $packageReceipt.sha256){throw 'Candidate package checksum mismatch'}
$toolsStage='runtime-receipt'
@{agentPackage=$packageArchive;agentPackageReceipt=$packageReceiptPath;candidateSha=$CandidateSha;source=$source;windowsVersion=$WindowsVersion;node="$nodeDirectory\node.exe";nodeVersion=$nodeRelease.version;nodeArchiveSha256=$nodeHash;goVersion=$goRelease.version;goArchiveSha256=$goFile.sha256;sourceArchiveSha256=(Get-FileHash "$root\candidate.zip" -Algorithm SHA256).Hash;qualifiedModuleSha256=(Get-FileHash packages/agent/src/capabilities/qualified-capabilities.generated.js -Algorithm SHA256).Hash;path=$env:PATH;buildMode='qualification-only-not-release'} | ConvertTo-Json | Set-Content "$root\runtime.json"
Write-Output 'CERTOPS_STAGE=isolated-candidate-windows-tools-built'
}catch{
 $errorType=$_.Exception.GetType().Name
 if($errorType -notin @('RuntimeException','WebException','IOException','UnauthorizedAccessException','ArgumentException','InvalidOperationException','MethodInvocationException','FileNotFoundException','HttpResponseException','TaskCanceledException','TimeoutException','ParameterBindingException','ActionPreferenceStopException')){$errorType='Exception'}
 $errorId=([string]$_.FullyQualifiedErrorId -split ',')[0]
 if($errorId -notin @('WebCmdletWebResponseException','WebCmdletIEDomNotSupportedException','NameResolutionFailure','ConnectFailure','RequestCanceled','Timeout','CommandNotFoundException','NamedParameterNotFound','ParameterArgumentValidationError','PathNotFound','InvokeMethodOnNull','InvalidArchiveFile','ExpandArchiveInvalidParameterSet','InvalidArgument')){$errorId='Unclassified'}
 $httpStatus=0
 try{$httpStatus=[int]$_.Exception.Response.StatusCode}catch{}
 if($httpStatus -lt 100 -or $httpStatus -gt 599){$httpStatus=0}
 Write-Output ('CERTOPS_TOOLS_FAILURE='+$toolsStage+':'+$errorType+':'+$errorId+':'+$httpStatus)
 throw 'Windows qualification tools bootstrap failed; inspect bounded step receipt'
}
param(
  [ValidateSet('Up','Test','Status','Stop','Cleanup')][string]$Action = 'Status',
  [ValidatePattern('^tt-wildcard-ux-[a-z0-9-]+$')][string]$Project = 'tt-wildcard-ux-20261009-merge2',
  [ValidateSet('all','functional','observations','setup','prepare-publication','publish','bindings','rejection','authorization','recovery','deployment-recovery','repair','validation','scanner','transfer','transfer-status','status')][string]$Phase = 'all',
  [ValidateRange(1024,65392)][int]$BasePort = 58800,
  [ValidateSet('san','wildcard','ordinary')][string]$CertificateMode = 'san',
  [ValidateSet('vault-kv2','openbao-kv2','azure-key-vault')][string]$MaterialProvider = 'vault-kv2',
  [string]$AzureInputDirectory,
  [string]$SuppliedPackageDirectory,
  [string]$SuppliedArchiveSha256,
  [string]$SuppliedProducerRunId,
  [string]$SuppliedArtifactId,
  [string]$OwnedTeardownReceipt,
  [switch]$BuildImages,
  [switch]$PackageAcceptance,
  [switch]$NativeOpenBao,
  [switch]$OpenBaoPki,
  [string]$ApiImage,
  [string]$WorkerImage,
  [string]$CustomerImage
)
$ErrorActionPreference = 'Stop'
function Write-SetupStatus(
  [ValidateSet('arguments','runtime-options','candidate-images','project-ownership','loopback-ports','package-staging',
    'image-validation','dashboard-build','ca-preparation','ca-services','ca-network','ca-initialization','customers','complete')]
  [string]$Stage,
  [ValidateSet('running','passed','failed','native-exit','command-missing','permission-denied','io-error')]
  [string]$Outcome = 'running'
) {
  if ($Action -ne 'Up' -or !$env:TT_UX_OPENBAO_SETUP_STATUS) { return }
  $script:openBaoSetupStage = $Stage
  [IO.File]::AppendAllText($env:TT_UX_OPENBAO_SETUP_STATUS, "$Stage $Outcome`n")
}
Write-SetupStatus 'arguments'
if (-not $env:TT_UX_CANDIDATE_REPO) { throw 'Scratch runner needs an explicit isolated TT_UX_CANDIDATE_REPO.' }
$repo = (Resolve-Path -LiteralPath $env:TT_UX_CANDIDATE_REPO).Path
$output = Join-Path $repo ".scratch/$Project"
$uxLab = Split-Path -Parent $PSScriptRoot
$compose = Join-Path $uxLab 'compose.yaml'
function Dc {
  $composeFiles = @('-f', $compose)
  if ($MaterialProvider -eq 'azure-key-vault') { $composeFiles += @('-f', (Join-Path $PSScriptRoot 'compose.azure.yaml')) }
  if ($NativeOpenBao) { $composeFiles += @('-f', (Join-Path $PSScriptRoot 'compose.openbao.native.yaml')) }
  if ($OpenBaoPki) { $composeFiles += @('-f', (Join-Path $uxLab 'operator-ca.compose.yaml')) }
  & docker compose -p $Project @composeFiles --profile worker @args
  if ($LASTEXITCODE -ne 0) { throw "Docker Compose failed ($LASTEXITCODE)." }
}
function BuildImage([string]$dockerfile, [string]$tag) {
  # Module downloads can hit transient proxy/network errors; layers are cached, so a retry is cheap.
  for ($attempt = 1; $attempt -le 3; $attempt++) {
    & docker build -f $dockerfile -t $tag --label "io.tokentimer.certops.source-sha=$env:TT_UX_CORE_COMMIT" .
    if ($LASTEXITCODE -eq 0) { return }
    if ($attempt -lt 3) { Start-Sleep -Seconds (15 * $attempt) }
  }
  throw "Image build failed: $tag"
}
Push-Location $repo
$environmentNames = @('TT_WILDCARD_UX_OUTPUT','TT_UX_API_IMAGE','TT_UX_WORKER_IMAGE','TT_UX_CUSTOMER_IMAGE',
  'TT_UX_API_PORT','TT_UX_WEB_PORT','TT_UX_MAIL_PORT','TT_UX_CONTROL_PORT','TT_UX_NGINX_PORT','TT_UX_HAPROXY_PORT',
  'TT_UX_CERTIFICATE_MODE','TT_UX_CORE_COMMIT','TT_UX_PROJECT','TT_UX_PACKAGE_ACCEPTANCE','CERTOPS_DISTRIBUTION_QUALIFICATION',
  'TT_UX_MATERIAL_PROVIDER','TT_UX_KV_IMAGE','TT_UX_KV_BINARY','TT_UX_AZURE_INPUT_DIR','TT_UX_NATIVE_API_PORT','TT_UX_NATIVE_BAO_PORT',
  'TT_UX_OPERATOR_CA','TT_UX_OPERATOR_CA_PRIVATE')
$previousEnvironment = @{}
foreach ($name in $environmentNames) { $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
try {
  Write-SetupStatus 'runtime-options'
  New-Item -ItemType Directory -Force -Path $output | Out-Null
  $env:TT_WILDCARD_UX_OUTPUT = $output
  $optionsFile = Join-Path $output 'runtime-options.json'
  if ($Action -ne 'Up' -and (Test-Path $optionsFile)) {
    $options = Get-Content $optionsFile -Raw | ConvertFrom-Json
    $BasePort = [int]$options.basePort
    $CertificateMode = $options.certificateMode
    $PackageAcceptance = [bool]$options.packageAcceptance
    $NativeOpenBao = [bool]$options.nativeOpenBao
    $OpenBaoPki = [bool]$options.openBaoPki
    if ($options.materialProvider) { $MaterialProvider = $options.materialProvider }
    if ($options.azureInputDirectory) { $AzureInputDirectory = $options.azureInputDirectory }
  }
  $env:TT_UX_API_PORT = "$BasePort"
  $env:TT_UX_WEB_PORT = "$($BasePort + 1)"
  $env:TT_UX_MAIL_PORT = "$($BasePort + 3)"
  $env:TT_UX_CONTROL_PORT = "$($BasePort + 5)"
  $env:TT_UX_NGINX_PORT = "$($BasePort + 43)"
  $env:TT_UX_HAPROXY_PORT = "$($BasePort + 143)"
  if ($NativeOpenBao) {
    if (!$PackageAcceptance -or $CertificateMode -ne 'ordinary' -or $MaterialProvider -ne 'openbao-kv2') {
      throw 'The installed consumer is scoped to ordinary OpenBao package acceptance.'
    }
    if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
        $env:GITHUB_REF -cne 'refs/heads/main' -or $env:GITHUB_EVENT_NAME -cne 'workflow_dispatch' -or
        $env:GITHUB_RUN_ATTEMPT -cne '1' -or $env:CERTOPS_LINUX_SYSTEMD_DISPOSABLE_HOST -cne '1') {
      throw 'The installed consumer requires its owned, trusted hosted Linux runner.'
    }
    $env:TT_UX_NATIVE_API_PORT = "$($BasePort + 6)"
    $env:TT_UX_NATIVE_BAO_PORT = "$($BasePort + 7)"
  }
  $env:TT_UX_CERTIFICATE_MODE = $CertificateMode
  $env:TT_UX_MATERIAL_PROVIDER = $MaterialProvider
  if ($OpenBaoPki -and (!$PackageAcceptance -or $MaterialProvider -ne 'openbao-kv2')) {
    throw 'This runner uses the owned operator CA with OpenBao exact-package acceptance.'
  }
  if ($OpenBaoPki -and $Project -notmatch '^tt-wildcard-ux-qual-[a-z0-9-]+$') {
    throw 'The owned operator CA requires a fresh qualification project.'
  }
  $env:TT_UX_OPERATOR_CA = if ($OpenBaoPki) { 'openbao-pki' } else { 'pebble' }
  $env:TT_UX_OPERATOR_CA_PRIVATE = "$output-operator-ca-private"
  if ($MaterialProvider -eq 'azure-key-vault') {
    if (-not $AzureInputDirectory) { throw 'Azure scratch input directory is required.' }
    $env:TT_UX_AZURE_INPUT_DIR = (Resolve-Path -LiteralPath $AzureInputDirectory).Path
    if (-not (Test-Path -LiteralPath (Join-Path $env:TT_UX_AZURE_INPUT_DIR 'azure-identities.json') -PathType Leaf)) { throw 'Azure identity descriptor is required.' }
    if ($Action -eq 'Up') { throw 'Azure scratch journey is not runnable: renewable scoped identity and package-acceptance wiring remain incomplete.' }
  }
  $env:TT_UX_KV_IMAGE = if($MaterialProvider -eq 'openbao-kv2'){'openbao/openbao:2.4.1'}else{'hashicorp/vault:1.21.0'}
  $env:TT_UX_KV_BINARY = if($MaterialProvider -eq 'openbao-kv2'){'bao'}else{'vault'}
  $env:TT_UX_PACKAGE_ACCEPTANCE = if($PackageAcceptance){'1'}else{'0'}
  if($Action -eq 'Up' -and $PackageAcceptance -and $Project -notmatch '^tt-wildcard-ux-(?:ci|qual)-[a-z0-9-]+$') {
    throw 'Strict package acceptance requires an owned privacy-audit namespace: use tt-wildcard-ux-qual- followed by a unique name.'
  }
  if($PackageAcceptance){
    $env:CERTOPS_DISTRIBUTION_QUALIFICATION='1'
    if($Action -eq 'Test' -and $Phase -ne 'all'){throw 'Package acceptance requires the complete journey'}
  }
  $env:TT_UX_CORE_COMMIT = (& git rev-parse HEAD)
  if ($Action -eq 'Test' -and (!$options -or $options.coreCommit -ne $env:TT_UX_CORE_COMMIT)) { throw "Owned lab candidate differs from current checkout; recreate the lab." }
  $env:TT_UX_PROJECT = $Project
  $imagesFile = Join-Path $output 'runtime-images.json'
  if (Test-Path $imagesFile) {
    $images = Get-Content $imagesFile -Raw | ConvertFrom-Json
    $env:TT_UX_API_IMAGE = $images.api
    $env:TT_UX_WORKER_IMAGE = $images.worker
    $env:TT_UX_CUSTOMER_IMAGE = $images.customers
  }
  if ($ApiImage) { $env:TT_UX_API_IMAGE = $ApiImage }
  if ($WorkerImage) { $env:TT_UX_WORKER_IMAGE = $WorkerImage }
  if ($CustomerImage) { $env:TT_UX_CUSTOMER_IMAGE = $CustomerImage }
  switch ($Action) {
    'Up' {
      Write-SetupStatus 'candidate-images'
      if ($PackageAcceptance) {
        if ($BuildImages -or !$ApiImage -or !$WorkerImage) { throw 'Package acceptance requires explicitly supplied immutable candidate API and worker image IDs; image builds are not accepted here.' }
        & node (Join-Path $PSScriptRoot 'candidate-images.cjs') $env:TT_UX_CORE_COMMIT $ApiImage $WorkerImage | Set-Content -LiteralPath (Join-Path $output 'candidate-image-provenance.json')
        if ($LASTEXITCODE -ne 0) { throw 'Candidate image preflight failed.' }
      }
      Write-SetupStatus 'project-ownership'
      if ($PackageAcceptance) {
        & node (Join-Path $PSScriptRoot 'project-freshness.cjs') $Project
        if ($LASTEXITCODE -ne 0) { throw 'Project inventory is not empty or cannot be verified.' }
      }
      $existing = & docker ps -aq --filter "label=com.docker.compose.project=$Project"
      if ($existing) { throw 'Project already exists. Use Test/Status, or Stop and choose a new Project for a fresh run.' }
      if (Test-Path (Join-Path $output 'journey-state.json')) { throw 'Evidence already exists. Choose a new Project for a fresh run.' }
      Write-SetupStatus 'loopback-ports'
      $ports = @($BasePort,($BasePort+1),($BasePort+3),($BasePort+5),($BasePort+43),($BasePort+143))
      if ($NativeOpenBao) {
        if ($CustomerImage -cnotmatch '^sha256:[a-f0-9]{64}$') { throw 'Supply the immutable customer image ID.' }
        $ports += @(($BasePort + 6), ($BasePort + 7))
      }
      foreach ($port in $ports) {
        $probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $port)
        try { $probe.Start() } catch { throw "Port $port is occupied. Choose a different BasePort." } finally { $probe.Stop() }
      }
      Write-SetupStatus 'package-staging'
      @{basePort=$BasePort;certificateMode=$CertificateMode;materialProvider=$MaterialProvider;coreCommit=$env:TT_UX_CORE_COMMIT;packageAcceptance=[bool]$PackageAcceptance;nativeOpenBao=[bool]$NativeOpenBao;openBaoPki=[bool]$OpenBaoPki;azureInputDirectory=$AzureInputDirectory} | ConvertTo-Json | Set-Content $optionsFile
      if($PackageAcceptance){
        if ($MaterialProvider -in @('azure-key-vault','openbao-kv2')) {
          $stageResult = & node (Join-Path $PSScriptRoot 'stage-supplied-package.cjs') $SuppliedPackageDirectory $SuppliedArchiveSha256 $env:TT_UX_CORE_COMMIT (Join-Path $output 'agent-package') $SuppliedProducerRunId $SuppliedArtifactId
          if($LASTEXITCODE -ne 0){throw 'Supplied package staging failed'}
          $stagedInput = $stageResult | ConvertFrom-Json
          $runtimeOptions = Get-Content -LiteralPath $optionsFile -Raw | ConvertFrom-Json -AsHashtable
          $runtimeOptions.packageArtifact = $stagedInput.packageArtifact
          $runtimeOptions | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $optionsFile
        } else {
          $providerCapability = & node (Join-Path $PSScriptRoot 'azure-ux-adapter.cjs') --capability $MaterialProvider
          if ($LASTEXITCODE -ne 0) { throw 'Invalid lab provider capability' }
          & node scripts/certops-agent-package.js (Join-Path $repo 'packages/agent') (Join-Path $output 'agent-package') $env:TT_UX_CORE_COMMIT "$providerCapability,certificate-publication-v1,deploy-from-store-v1"
          if($LASTEXITCODE -ne 0){throw 'Canonical package creation failed'}
        }
      }
      Write-SetupStatus 'image-validation'
      if ($BuildImages) {
        # Separate lab tags; never replace existing release/candidate image tags.
        $env:TT_UX_API_IMAGE = "$Project-api"
        $env:TT_UX_WORKER_IMAGE = "$Project-worker"
        $env:TT_UX_CUSTOMER_IMAGE = "$Project-customers"
        BuildImage 'deploy/compose/Dockerfile.api' $env:TT_UX_API_IMAGE
        BuildImage 'deploy/compose/Dockerfile.worker' $env:TT_UX_WORKER_IMAGE
        BuildImage 'tests/wildcard-vault/Dockerfile.fixture' $env:TT_UX_CUSTOMER_IMAGE
      }
      foreach ($image in @($(if($env:TT_UX_API_IMAGE){$env:TT_UX_API_IMAGE}else{'tt-wildcard-core-api:20261008'}),$(if($env:TT_UX_WORKER_IMAGE){$env:TT_UX_WORKER_IMAGE}else{'localhost:58600/core-worker:20261008'}),$(if($env:TT_UX_CUSTOMER_IMAGE){$env:TT_UX_CUSTOMER_IMAGE}else{'tt-wildcard-vault-fixture:20261008'}))) {
        & docker image inspect $image --format '{{.Id}}' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Missing dependency image $image. Run Up -BuildImages." }
        $imageSha = & docker image inspect $image --format '{{index .Config.Labels "io.tokentimer.certops.source-sha"}}'
        if ($LASTEXITCODE -ne 0 -or $imageSha.Trim() -ne $env:TT_UX_CORE_COMMIT) {
          throw 'Dependency image does not match this candidate. Run Up -BuildImages with a new project.'
        }
      }
      @{api=$env:TT_UX_API_IMAGE;worker=$env:TT_UX_WORKER_IMAGE;customers=$env:TT_UX_CUSTOMER_IMAGE} | ConvertTo-Json | Set-Content $imagesFile
      Write-SetupStatus 'dashboard-build'
      & pnpm --filter '@tokentimer/dashboard' build *> (Join-Path $output 'dashboard-build.log')
      if ($LASTEXITCODE -ne 0) { throw "Dashboard build failed. See $output/dashboard-build.log" }
      if ($OpenBaoPki) {
        $caSetup = Join-Path $uxLab 'operator-ca-setup.cjs'
        $caOutput = Join-Path $output 'operator-ca'
        Write-SetupStatus 'ca-preparation'
        if ($NativeOpenBao -and $IsLinux) {
          $nodeExecutable = (Get-Command node -CommandType Application).Source
          & sudo --non-interactive -- $nodeExecutable $caSetup create-owned $env:TT_UX_OPERATOR_CA_PRIVATE $caOutput
        } else {
          & node $caSetup create $env:TT_UX_OPERATOR_CA_PRIVATE $caOutput
        }
        if ($LASTEXITCODE -ne 0) { throw 'Owned operator CA preparation failed.' }
        Write-SetupStatus 'ca-services'
        Dc up -d --build operator-ca operator-dns
        Write-SetupStatus 'ca-network'
        $privateNetwork = & docker network inspect "$($Project)_operator-ca" --format '{{.Internal}} {{index .Labels "com.docker.compose.project"}}'
        if ($LASTEXITCODE -ne 0 -or $privateNetwork -cne "true $Project") { throw 'Owned operator CA network is not internal.' }
        Write-SetupStatus 'ca-initialization'
        Dc run --rm --no-deps operator-ca-init
      }
      Write-SetupStatus 'customers'
      Dc up -d
      if (!$OpenBaoPki) {
        Dc cp 'pebble:/test/certs/pebble.minica.pem' (Join-Path $output 'pebble-ca.pem')
      }
      Write-SetupStatus 'complete' 'passed'
      Write-Host "Lab started: dashboard http://127.0.0.1:$($BasePort+1), inbox http://127.0.0.1:$($BasePort+3). Run Test to execute the API journey."
    }
    'Test' {
      if ($PackageAcceptance -and $MaterialProvider -in @('azure-key-vault','openbao-kv2')) {
        $stagedInput = Get-Content -LiteralPath (Join-Path $output 'agent-package/harness-input.json') -Raw | ConvertFrom-Json
        if (!$options.packageArtifact -or ($options.packageArtifact | ConvertTo-Json -Depth 4 -Compress) -cne ($stagedInput.packageArtifact | ConvertTo-Json -Depth 4 -Compress)) {
          throw 'Staged package identity differs from the owned lab input.'
        }
      }
      if ($NativeOpenBao -and $OpenBaoPki) {
        & node (Join-Path $PSScriptRoot 'openbao-operator-strict-journey.cjs') 2>&1 | Tee-Object -FilePath (Join-Path $output "journey-$Phase.log")
      } elseif ($NativeOpenBao) {
        & node (Join-Path $PSScriptRoot 'native-openbao-journey.cjs') 2>&1 | Tee-Object -FilePath (Join-Path $output "journey-$Phase.log")
      } else {
        & node (Join-Path $uxLab 'journey.cjs') $Phase 2>&1 | Tee-Object -FilePath (Join-Path $output "journey-$Phase.log")
      }
      $result = $LASTEXITCODE
      if ($result -ne 0) { throw "Journey failed; evidence retained in $output. The lab remains running." }
      if($PackageAcceptance -and $Phase -eq 'all' -and !($NativeOpenBao -and $OpenBaoPki)){
        $proof=(Get-Content (Join-Path $output 'qualification.json') -Raw | ConvertFrom-Json).packageAcceptance
        $receipt=Get-Content (Join-Path $output 'agent-package/artifact.json') -Raw | ConvertFrom-Json
        if($proof.packageSha256 -ne $receipt.sha256 -or $proof.candidateSha -ne $env:TT_UX_CORE_COMMIT){throw 'Acceptance used a different package or candidate'}
      }
    }
    'Status' { Dc ps; if(Test-Path (Join-Path $output 'report.json')){Get-Content (Join-Path $output 'report.json')} }
    'Stop' {
      Dc down
      if ($OpenBaoPki) {
        & node (Join-Path $uxLab 'operator-ca-setup.cjs') dispose $env:TT_UX_OPERATOR_CA_PRIVATE (Join-Path $output 'operator-ca')
        if ($LASTEXITCODE -ne 0) { throw 'Owned operator CA credential cleanup failed.' }
      }
      Write-Host 'Named UX lab stopped; volumes and evidence retained. Use a NEW project for replay (Vault is volatile).'
    }
    'Cleanup' {

      if (-not $OwnedTeardownReceipt) { throw 'Owned teardown receipt is required.' }
      $owned = Get-Content -LiteralPath $OwnedTeardownReceipt -Raw | ConvertFrom-Json
      if ($owned.project -cne $Project) { throw 'Owned teardown receipt project mismatch.' }
      if ($NativeOpenBao -and $OpenBaoPki) {
        & node (Join-Path $PSScriptRoot 'openbao-operator-evidence.cjs') $OwnedTeardownReceipt
      } elseif ($NativeOpenBao) {
        & node (Join-Path $PSScriptRoot 'native-openbao-support.cjs') $OwnedTeardownReceipt
      } else {
        & node (Join-Path $PSScriptRoot 'owned-teardown-run.cjs') --execute $OwnedTeardownReceipt
      }
      if ($LASTEXITCODE -ne 0) { throw 'Owned teardown refused or incomplete.' }
      if ($OpenBaoPki -and !$NativeOpenBao) {
        & node (Join-Path $uxLab 'operator-ca-setup.cjs') dispose $env:TT_UX_OPERATOR_CA_PRIVATE (Join-Path $output 'operator-ca')
        if ($LASTEXITCODE -ne 0) { throw 'Owned operator CA credential cleanup failed.' }
      }
    }
  }
} catch {
  if ($Action -eq 'Up' -and $env:TT_UX_OPENBAO_SETUP_STATUS -and $script:openBaoSetupStage) {
    $failure = switch ($_.Exception.GetType().Name) {
      'NativeCommandExitException' { 'native-exit' }
      'CommandNotFoundException' { 'command-missing' }
      'UnauthorizedAccessException' { 'permission-denied' }
      'IOException' { 'io-error' }
      default { 'failed' }
    }
    Write-SetupStatus $script:openBaoSetupStage $failure
  }
  throw
} finally {
  foreach ($name in $environmentNames) { [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process') }
  Pop-Location
}

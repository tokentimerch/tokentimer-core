param(
  [ValidateSet('Up','Test','Status','Stop')][string]$Action = 'Status',
  [ValidatePattern('^tt-wildcard-ux-[a-z0-9-]+$')][string]$Project = 'tt-wildcard-ux-20261009-merge2',
  [ValidateSet('all','setup','prepare-publication','publish','bindings','rejection','authorization','recovery','deployment-recovery','repair','validation','scanner','transfer','transfer-status','status')][string]$Phase = 'all',
  [ValidateRange(1024,65392)][int]$BasePort = 58800,
  [ValidateSet('san','wildcard','ordinary')][string]$CertificateMode = 'san',
  [switch]$BuildImages,
  [switch]$PackageAcceptance
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
$output = Join-Path $repo ".scratch/$Project"
$compose = Join-Path $PSScriptRoot 'compose.yaml'
function Dc {
  & docker compose -p $Project -f $compose --profile worker @args
  if ($LASTEXITCODE -ne 0) { throw "Docker Compose failed ($LASTEXITCODE)." }
}
function BuildImage([string]$dockerfile, [string]$tag) {
  & docker build -f $dockerfile -t $tag --label "io.tokentimer.certops.source-sha=$env:TT_UX_CORE_COMMIT" .
  if ($LASTEXITCODE -ne 0) { throw "Image build failed: $tag" }
}
Push-Location $repo
$environmentNames = @('TT_WILDCARD_UX_OUTPUT','TT_UX_API_IMAGE','TT_UX_WORKER_IMAGE','TT_UX_CUSTOMER_IMAGE',
  'TT_UX_API_PORT','TT_UX_WEB_PORT','TT_UX_MAIL_PORT','TT_UX_CONTROL_PORT','TT_UX_NGINX_PORT','TT_UX_HAPROXY_PORT',
  'TT_UX_CERTIFICATE_MODE','TT_UX_CORE_COMMIT','TT_UX_PROJECT','TT_UX_PACKAGE_ACCEPTANCE','CERTOPS_DISTRIBUTION_QUALIFICATION')
$previousEnvironment = @{}
foreach ($name in $environmentNames) { $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
try {
  New-Item -ItemType Directory -Force -Path $output | Out-Null
  $env:TT_WILDCARD_UX_OUTPUT = $output
  $optionsFile = Join-Path $output 'runtime-options.json'
  if ($Action -ne 'Up' -and (Test-Path $optionsFile)) {
    $options = Get-Content $optionsFile -Raw | ConvertFrom-Json
    $BasePort = [int]$options.basePort
    $CertificateMode = $options.certificateMode
    $PackageAcceptance = [bool]$options.packageAcceptance
  }
  $env:TT_UX_API_PORT = "$BasePort"
  $env:TT_UX_WEB_PORT = "$($BasePort + 1)"
  $env:TT_UX_MAIL_PORT = "$($BasePort + 3)"
  $env:TT_UX_CONTROL_PORT = "$($BasePort + 5)"
  $env:TT_UX_NGINX_PORT = "$($BasePort + 43)"
  $env:TT_UX_HAPROXY_PORT = "$($BasePort + 143)"
  $env:TT_UX_CERTIFICATE_MODE = $CertificateMode
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
  switch ($Action) {
    'Up' {
      $existing = & docker ps -aq --filter "label=com.docker.compose.project=$Project"
      if ($existing) { throw 'Project already exists. Use Test/Status, or Stop and choose a new Project for a fresh run.' }
      if (Test-Path (Join-Path $output 'journey-state.json')) { throw 'Evidence already exists. Choose a new Project for a fresh run.' }
      foreach ($port in @($BasePort,($BasePort+1),($BasePort+3),($BasePort+5),($BasePort+43),($BasePort+143))) {
        $probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $port)
        try { $probe.Start() } catch { throw "Port $port is occupied. Choose a different BasePort." } finally { $probe.Stop() }
      }
      @{basePort=$BasePort;certificateMode=$CertificateMode;coreCommit=$env:TT_UX_CORE_COMMIT;packageAcceptance=[bool]$PackageAcceptance} | ConvertTo-Json | Set-Content $optionsFile
      if($PackageAcceptance){
        & node scripts/certops-agent-package.js (Join-Path $repo 'packages/agent') (Join-Path $output 'agent-package') $env:TT_UX_CORE_COMMIT 'material-store-vault-kv2-v1,certificate-publication-v1,deploy-from-store-v1'
        if($LASTEXITCODE -ne 0){throw 'Canonical package creation failed'}
      }
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
      & pnpm --filter '@tokentimer/dashboard' build *> (Join-Path $output 'dashboard-build.log')
      if ($LASTEXITCODE -ne 0) { throw "Dashboard build failed. See $output/dashboard-build.log" }
      Dc up -d
      # Public Pebble transport CA only. Customer processes read this mount.
      Dc cp 'pebble:/test/certs/pebble.minica.pem' (Join-Path $output 'pebble-ca.pem')
      Write-Host "Lab started: dashboard http://127.0.0.1:$($BasePort+1), inbox http://127.0.0.1:$($BasePort+3). Run Test to execute the API journey."
    }
    'Test' {
      & node (Join-Path $PSScriptRoot 'journey.cjs') $Phase 2>&1 | Tee-Object -FilePath (Join-Path $output "journey-$Phase.log")
      $result = $LASTEXITCODE
      if ($result -ne 0) { throw "Journey failed; evidence retained in $output. The lab remains running." }
      if($PackageAcceptance -and $Phase -eq 'all'){
        $proof=(Get-Content (Join-Path $output 'qualification.json') -Raw | ConvertFrom-Json).packageAcceptance
        $receipt=Get-Content (Join-Path $output 'agent-package/artifact.json') -Raw | ConvertFrom-Json
        if($proof.packageSha256 -ne $receipt.sha256 -or $proof.candidateSha -ne $env:TT_UX_CORE_COMMIT){throw 'Acceptance used a different package or candidate'}
      }
    }
    'Status' { Dc ps; if(Test-Path (Join-Path $output 'report.json')){Get-Content (Join-Path $output 'report.json')} }
    'Stop' { Dc down; Write-Host 'Named UX lab stopped; volumes and evidence retained. Use a NEW project for replay (Vault is volatile).' }
  }
} finally {
  foreach ($name in $environmentNames) { [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process') }
  Pop-Location
}

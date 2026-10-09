param(
  [ValidateSet('Up','Test','Status','Stop')][string]$Action = 'Status',
  [ValidatePattern('^tt-wildcard-ux-[a-z0-9-]+$')][string]$Project = 'tt-wildcard-ux-20261009-merge2',
  [ValidateSet('all','setup','publish','bindings','rejection','authorization','recovery','repair','status')][string]$Phase = 'all',
  [switch]$BuildImages
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
  & docker build -f $dockerfile -t $tag .
  if ($LASTEXITCODE -ne 0) { throw "Image build failed: $tag" }
}
Push-Location $repo
$previousOutput = $env:TT_WILDCARD_UX_OUTPUT
$previousApiImage = $env:TT_UX_API_IMAGE
$previousWorkerImage = $env:TT_UX_WORKER_IMAGE
$previousCustomerImage = $env:TT_UX_CUSTOMER_IMAGE
try {
  New-Item -ItemType Directory -Force -Path $output | Out-Null
  $env:TT_WILDCARD_UX_OUTPUT = $output
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
      foreach ($port in @(58800,58801,58803,58805,58843,58943)) {
        if (Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue) { throw "Port $port is occupied. Stop only the previous named UX lab first." }
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
      }
      @{api=$env:TT_UX_API_IMAGE;worker=$env:TT_UX_WORKER_IMAGE;customers=$env:TT_UX_CUSTOMER_IMAGE} | ConvertTo-Json | Set-Content $imagesFile
      & pnpm --filter '@tokentimer/dashboard' build *> (Join-Path $output 'dashboard-build.log')
      if ($LASTEXITCODE -ne 0) { throw "Dashboard build failed. See $output/dashboard-build.log" }
      Dc up -d
      # Public Pebble transport CA only. Customer processes read this mount.
      $caDirectory = Join-Path $repo '.scratch/wildcard-ux'
      New-Item -ItemType Directory -Force -Path $caDirectory | Out-Null
      Dc cp 'pebble:/test/certs/pebble.minica.pem' (Join-Path $caDirectory 'pebble-ca.pem')
      Write-Host 'Lab started. Run Test to execute the API journey.'
    }
    'Test' {
      & node (Join-Path $PSScriptRoot 'journey.cjs') $Phase 2>&1 | Tee-Object -FilePath (Join-Path $output "journey-$Phase.log")
      $result = $LASTEXITCODE
      if ($result -ne 0) { throw "Journey failed; evidence retained in $output. The lab remains running." }
    }
    'Status' { Dc ps; if(Test-Path (Join-Path $output 'report.json')){Get-Content (Join-Path $output 'report.json')} }
    'Stop' { Dc down; Write-Host 'Named UX lab stopped; volumes and evidence retained. Use a NEW project for replay (Vault is volatile).' }
  }
} finally {
  $env:TT_WILDCARD_UX_OUTPUT = $previousOutput
  $env:TT_UX_API_IMAGE = $previousApiImage
  $env:TT_UX_WORKER_IMAGE = $previousWorkerImage
  $env:TT_UX_CUSTOMER_IMAGE = $previousCustomerImage
  Pop-Location
}

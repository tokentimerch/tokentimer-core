[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Initialize','Extract','Inventory','SignInventory','Seal')][string]$Operation,
    [Parameter(Mandatory)][string]$Stage
)

$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'windows-signing-pilot-stage.ps1') -RunnerTemp $env:RUNNER_TEMP -VerifyStage $Stage

$archiveName = "tokentimer-agent-$($env:PILOT_VERSION)-windows-amd64.tgz"
$stem = [IO.Path]::GetFileNameWithoutExtension($archiveName)
$incoming = Join-Path $Stage 'unsigned'
$unsigned = Join-Path $incoming $archiveName
$files = Join-Path $Stage 'files'
$archive = Join-Path $Stage $archiveName
$checksum = "$archive.sha256"
$sbom = Join-Path $Stage "$stem.cdx.json"
$inventory = Join-Path $Stage "$stem.inventory.json"
$signature = "$inventory.p7"
$nativeReceipt = Join-Path $incoming 'native-provenance.json'
$nodeInput = Join-Path $Stage 'node.zip'
$syft = Join-Path $Stage 'syft/syft.exe'
$schemaValidator = Join-Path $Stage 'cyclonedx.exe'
$age = Join-Path $Stage 'age/age/age.exe'
$pinnedSyft = 'ea9deaf53c9ddb3bdaa23b76c70ad5182b45e98dd2ea1ffc599776ca15819e20'
$pinnedValidator = '9b360974c41a5d612eb026fb5e3bb1fa28e08865f7a4f915665b8bc94bd3bc31'
$pinnedAge = '2821a4ed191da07372acd302e5f6feae7a7985e285e1417765ebe74025af45f0'

function Get-Sha([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Receive-PinnedFile([string]$Url, [string]$Destination, [string]$Digest) {
    if ($Digest -cnotmatch '^[a-f0-9]{64}$' -or (Test-Path -LiteralPath $Destination)) {
        throw 'Invalid download digest or occupied destination'
    }
    Invoke-WebRequest -Uri $Url -OutFile $Destination -MaximumRedirection 4 -TimeoutSec 120
    if ((Get-Sha $Destination) -cne $Digest) { throw 'Pinned pilot download digest mismatch' }
}

function Invoke-PilotPython([string]$Script, [string[]]$Arguments) {
    & python -B (Join-Path $PSScriptRoot $Script) @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Pilot helper failed: $Script" }
}

function Read-SmallJson([string]$Path) {
    $file = Get-Item -LiteralPath $Path -Force
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $file.Length -lt 2 -or $file.Length -gt 64KB) {
        throw 'Invalid pilot producer metadata'
    }
    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

if ($env:PILOT_SOURCE -cnotmatch '^[a-f0-9]{40}$' -or $env:GITHUB_SHA -cnotmatch '^[a-f0-9]{40}$' -or
    $env:GITHUB_RUN_ID -cnotmatch '^[0-9]+$' -or $env:GITHUB_RUN_ATTEMPT -cnotmatch '^[0-9]+$' -or
    $env:PILOT_VERSION -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or
    $env:PILOT_UNSIGNED_SHA256 -cnotmatch '^[a-f0-9]{64}$' -or $env:PILOT_UNSIGNED_ARTIFACT -cnotmatch '^[0-9]+$') {
    throw 'Invalid exact-run producer context'
}

$archiveArgs = @(
    '--archive', $unsigned, '--archive-sha256', $env:PILOT_UNSIGNED_SHA256,
    '--node-zip', $nodeInput, '--stage', $files
)
$archiveScript = 'windows-signing-pilot-archive.py'
$targetsModule = Join-Path $PSScriptRoot 'windows-signing-targets.cjs'
function Test-PilotBinding([string]$Digest) {
    Invoke-PilotPython 'windows-release-artifact-binding.py' @(
        '--archive', $archive, '--archive-sha256', $Digest, '--sbom', $sbom, '--inventory', $inventory,
        '--version', $env:PILOT_VERSION, '--architecture', 'amd64', '--source-commit', $env:PILOT_SOURCE
    )
}

function Get-CertificateSha([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate) {
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Certificate.RawData)).ToLowerInvariant()
}

function Get-TimestampedSigner([string]$Path) {
    $result = Get-AuthenticodeSignature -LiteralPath $Path
    if ($result.Status -ne 'Valid' -or !$result.SignerCertificate -or !$result.TimeStamperCertificate) {
        throw 'Expected a valid and timestamped Authenticode signature'
    }
    $result.SignerCertificate
}

switch ($Operation) {
    'Initialize' {
        if ($env:PILOT_ENDPOINT -cnotmatch '^https://[a-z][a-z0-9-]*\.codesigning\.azure\.net$' -or
            $env:PILOT_ACCOUNT -cnotmatch '^[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]$' -or
            $env:PILOT_PROFILE -cnotmatch '^[A-Za-z][A-Za-z0-9-]{3,98}[A-Za-z0-9]$' -or
            $env:PILOT_PROFILE_EKU -cnotmatch '^1\.3\.6\.1\.4\.1\.311\.97\.(?:[0-9]+\.){2,}[0-9]+$' -or
            $env:PILOT_PROFILE_EKU -cmatch '^1\.3\.6\.1\.4\.1\.311\.97\.1\.(?:0|3\.1|4\.1)(?:\.|$)' -or
            $env:PILOT_ISSUER_SHA256 -cnotmatch '^[a-f0-9]{64}$' -or
            $env:PILOT_LAB_RECIPIENT -cnotmatch '^age1[023456789acdefghjklmnpqrstuvwxyz]{58}$') {
            throw 'Independently verified publisher pins and one protected lab recipient are required'
        }
        Receive-PinnedFile "https://nodejs.org/dist/v$($env:PILOT_NODE_VERSION)/node-v$($env:PILOT_NODE_VERSION)-win-x64.zip" $nodeInput $env:PILOT_NODE_ZIP_HASH
        Receive-PinnedFile 'https://github.com/anchore/syft/releases/download/v1.56.0/syft_1.56.0_windows_amd64.zip' `
            (Join-Path $Stage 'syft.zip') 'c4cd2846dc0128e29a947bc6f56e1e5ef01707275b0e58590fbe48105198661d'
        Receive-PinnedFile 'https://github.com/CycloneDX/cyclonedx-cli/releases/download/v0.33.1/cyclonedx-win-x64.exe' $schemaValidator $pinnedValidator
        Receive-PinnedFile 'https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-windows-amd64.zip' `
            (Join-Path $Stage 'age.zip') 'f48d8f8f9ebe903ab5027ed067652f2cc1db94bc206976430133b905dcd8e8c7'
        Expand-Archive -LiteralPath (Join-Path $Stage 'syft.zip') -DestinationPath (Join-Path $Stage 'syft')
        Expand-Archive -LiteralPath (Join-Path $Stage 'age.zip') -DestinationPath (Join-Path $Stage 'age')
        if ((Get-Sha $syft) -cne $pinnedSyft -or (Get-Sha $age) -cne $pinnedAge) {
            throw 'Pinned pilot executable digest mismatch'
        }
        $probe = Join-Path $Stage 'recipient-check.txt'
        [IO.File]::WriteAllText($probe, 'Windows signing pilot recipient check')
        & $age --encrypt --recipient $env:PILOT_LAB_RECIPIENT --output "$probe.age" $probe
        if ($LASTEXITCODE -ne 0) { throw 'Invalid protected lab recipient key' }
    }
    'Extract' {
        $producer = Read-SmallJson (Join-Path $incoming 'producer.json')
        $native = Read-SmallJson $nativeReceipt
        if ($producer.sourceCommit -cne $env:PILOT_SOURCE -or $producer.workflowCommit -cne $env:GITHUB_SHA -or
            $producer.runId -cne $env:GITHUB_RUN_ID -or $producer.runAttempt -cne $env:GITHUB_RUN_ATTEMPT -or
            $producer.archive -cne $archiveName -or $producer.sha256 -cne $env:PILOT_UNSIGNED_SHA256 -or
            $native.status -cne 'passed' -or $native.archive -cne $archiveName -or
            $native.archiveSha256 -cne $env:PILOT_UNSIGNED_SHA256 -or $native.sourceSha -cne $env:PILOT_SOURCE -or
            $native.goVersion -cne "go$($env:PILOT_GO_VERSION)" -or $native.goToolchain -cne 'local' -or
            $native.builtAtRun -cne $env:GITHUB_RUN_ID -or @($native.binaries).Count -ne 9) {
            throw 'Unsigned candidate provenance does not match this exact run and reviewed source'
        }
        Invoke-PilotPython $archiveScript (@('extract') + $archiveArgs)
        $binaryPaths = & node -e 'console.log(JSON.stringify(require(process.argv[1]).OWNED.filter(x => x.endsWith(".exe")).map(x => "package/" + x)));' $targetsModule
        if ($LASTEXITCODE -ne 0) { throw 'Could not derive trusted helper inventory' }
        $approvedPaths = @(($binaryPaths | ConvertFrom-Json)) + @('package/runtime/amd64/node.exe')
        foreach ($validCandidate in $approvedPaths) {
            $receiptsForPath = @($native.binaries | Where-Object path -CEQ $validCandidate)
            if ($receiptsForPath.Count -ne 1 -or $receiptsForPath[0].sha256 -cnotmatch '^[a-f0-9]{64}$' -or
                (Get-Sha (Join-Path $files $validCandidate)) -cne $receiptsForPath[0].sha256) {
                throw 'Staged binary differs from the verified producer receipt'
            }
        }
    }
    'Inventory' {
        $targets = Join-Path $Stage 'signing-targets.json'
        $allowed = & node -e 'console.log(JSON.stringify(require(process.argv[1]).OWNED))' $targetsModule
        if ($LASTEXITCODE -ne 0) { throw 'Could not derive approved first-party signing targets' }
        [IO.File]::WriteAllText($targets, $allowed)
        Invoke-PilotPython $archiveScript (@('repack') + $archiveArgs + @('--signing-targets', $targets, '--output', $archive))
        $digest = Get-Sha $archive
        "$digest  $archiveName" | Set-Content -LiteralPath $checksum -Encoding ascii
        $env:PILOT_PWSH = Join-Path $PSHOME 'pwsh.exe'
        Invoke-PilotPython 'agent-sbom-generate.py' @(
            '--archive', $archive, '--archive-sha256', $digest, '--node-zip', $nodeInput,
            '--architecture', 'amd64', '--syft', $syft, '--syft-sha256', $pinnedSyft,
            '--validator', $schemaValidator, '--validator-sha256', $pinnedValidator, '--out', $sbom,
            '--windows-stage', $Stage
        )
        Push-Location (Join-Path $PSScriptRoot 'agent-release-inventory')
        try {
            & go run . --archive $archive --sbom $sbom --version $env:PILOT_VERSION --architecture amd64 `
                --source-commit $env:PILOT_SOURCE --out $inventory
            if ($LASTEXITCODE -ne 0) { throw 'Could not generate immutable pilot inventory' }
        } finally {
            Pop-Location
        }
        $bound = Test-PilotBinding $digest
        if ($bound -cnotmatch '^[a-f0-9]{64}$' -or $bound -cne (Get-Sha $inventory)) {
            throw 'Independent pilot archive and inventory digest binding did not agree'
        }
        "sha256=$bound" >> $env:GITHUB_OUTPUT
    }
    'SignInventory' {
        $expected = $env:PILOT_INVENTORY_SHA256
        if ($Stage -cne $env:PILOT_STAGE -or $expected -cnotmatch '^[a-f0-9]{64}$' -or
            (Test-PilotBinding (Get-Sha $archive)) -cne $expected -or (Test-Path -LiteralPath $signature)) {
            throw 'The exact validated inventory is required before CMS signing'
        }

        $packageRoot = Join-Path $files 'package'
        $targetList = @((Read-SmallJson (Join-Path $Stage 'signing-targets.json')))
        $publisherPins = @(foreach ($target in $targetList) {
            Get-CertificateSha (Get-TimestampedSigner (Join-Path $packageRoot $target))
        })
        if ($publisherPins.Count -ne 11 -or @($publisherPins | Select-Object -Unique).Count -ne 1) {
            throw 'The eleven Authenticode signatures must share one publisher leaf before CMS signing'
        }

        $sdkZip = Join-Path $Stage 'dotnet-sdk-10.0.404-win-x64.zip'
        Invoke-WebRequest -Uri 'https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.404/dotnet-sdk-10.0.404-win-x64.zip' -OutFile $sdkZip -MaximumRedirection 2 -TimeoutSec 180
        $sdkHash = (Get-FileHash -LiteralPath $sdkZip -Algorithm SHA512).Hash.ToLowerInvariant()
        if ($sdkHash -cne '330ddd2665b43cd2e428216a0d8ea1ac7bb19b5434fdc530e62010dc3b52823a620bf95489d628e1ed6f5122401793ee4887cca4a019122361a1231497f632ee') {
            throw 'The exact Microsoft .NET SDK archive is required'
        }
        $sdk = Join-Path $Stage 'cms-dotnet'
        [IO.Compression.ZipFile]::ExtractToDirectory($sdkZip, $sdk)
        $dotnet = Join-Path $sdk 'dotnet.exe'
        $source = Join-Path $PSScriptRoot 'windows-inventory-cms-signer'
        $project = Join-Path $Stage 'cms-signer-source'
        $build = Join-Path $Stage 'cms-signer-build'
        [IO.Directory]::CreateDirectory($project) | Out-Null
        foreach ($filename in @('InventoryCmsSigner.csproj','InventoryCmsProducer.cs','NuGet.Config','Program.cs','packages.lock.json')) {
            Copy-Item -LiteralPath (Join-Path $source $filename) -Destination $project
        }
        $env:DOTNET_CLI_HOME = Join-Path $Stage 'cms-dotnet-home'
        $env:NUGET_PACKAGES = Join-Path $Stage 'cms-nuget-packages'
        $env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
        $env:DOTNET_GENERATE_ASPNET_CERTIFICATE = 'false'
        Push-Location -LiteralPath $project
        try {
            if ((& $dotnet --version) -cne '10.0.404' -or $LASTEXITCODE -ne 0) {
                throw 'Wrong pinned .NET SDK version'
            }
            & $dotnet restore ./InventoryCmsSigner.csproj --configfile ./NuGet.Config --locked-mode
            if ($LASTEXITCODE -ne 0) { throw 'Could not restore the locked CMS signer dependencies' }
            & $dotnet build ./InventoryCmsSigner.csproj --no-restore -c Release --output $build
            if ($LASTEXITCODE -ne 0) { throw 'Could not compile the reviewed CMS signer' }
        } finally {
            Pop-Location
        }

        & $dotnet (Join-Path $build 'InventoryCmsSigner.dll') $publisherPins[0]
        if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $signature -PathType Leaf)) {
            throw 'The Artifact Signing SDK did not produce the exact inventory CMS'
        }
    }
    'Seal' {
        if ((Get-Sha $age) -cne $pinnedAge -or $env:PILOT_INVENTORY_SHA256 -cnotmatch '^[a-f0-9]{64}$') {
            throw 'Pilot encryption tool or exact inventory digest unavailable'
        }
        Import-Module (Join-Path $PSScriptRoot 'windows-inventory-cms.psm1')
        $proof = Confirm-WindowsInventoryCms -InventoryPath $inventory -SignaturePath $signature `
            -ExpectedInventorySha256 $env:PILOT_INVENTORY_SHA256 -PublisherProfileEku $env:PILOT_PROFILE_EKU `
            -PublisherIssuerSha256 $env:PILOT_ISSUER_SHA256
        $digest = Get-Sha $archive
        $bound = Test-PilotBinding $digest
        if ($bound -cne $proof.InventorySha256 -or (Get-Content -LiteralPath $checksum -Raw).Trim() -cne "$digest  $archiveName") {
            throw 'Pilot media changed after inventory signing'
        }

        # The launcher must embed this exact tuple before it is built and signed
        # in a follow-up step. Keep the actual leaf pins inside the sealed transfer.
        $cms = [Security.Cryptography.Pkcs.SignedCms]::new()
        $cms.Decode([IO.File]::ReadAllBytes($signature))
        $publisher = $cms.SignerInfos[0].Certificate
        $publisherSha = Get-CertificateSha $publisher
        if ($publisher.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) {
            throw 'The CMS signing leaf cannot be used for the forthcoming native window'
        }
        $packageRoot = Join-Path $files 'package'
        $targetList = Read-SmallJson (Join-Path $Stage 'signing-targets.json')
        if (@($targetList).Count -ne 11) { throw 'Expected the exact eleven first-party targets' }
        $leaves = [ordered]@{}
        foreach ($target in $targetList) {
            $leaf = Get-TimestampedSigner (Join-Path $packageRoot $target)
            $leafSha = Get-CertificateSha $leaf
            if ($leafSha -cne $publisherSha) { throw 'The publisher leaf rotated within the package pilot' }
            $leaves[$target] = $leafSha
        }
        $runtime = Join-Path $packageRoot 'runtime/amd64/node.exe'
        if ((Get-Sha $runtime) -cne $env:PILOT_NODE_EXE_HASH) { throw 'Signed workflow changed the upstream runtime' }
        $runtimePublisher = Get-TimestampedSigner $runtime
        $launcherPolicy = Join-Path $Stage 'launcher-policy.json'
        [ordered]@{
            publisherLeafSha256 = $publisherSha
            upstreamRuntimePublisherLeafSha256 = Get-CertificateSha $runtimePublisher
            installerSha256 = Get-Sha (Join-Path $packageRoot 'scripts/install-agent.ps1')
            sourceCommit = $env:PILOT_SOURCE
            version = $env:PILOT_VERSION
            architecture = 'amd64'
            publisherNotAfterUtc = $publisher.NotAfter.ToUniversalTime().ToString('o')
            firstPartyLeaves = $leaves
        } | ConvertTo-Json -Depth 3 -Compress | Set-Content -LiteralPath $launcherPolicy -Encoding utf8NoBOM

        $plaintext = Join-Path $Stage 'windows-amd64-pilot.zip'
        Compress-Archive -LiteralPath @($archive, $checksum, $sbom, $inventory, $signature, $nativeReceipt, $launcherPolicy) -DestinationPath $plaintext
        $sealed = Join-Path $Stage 'sealed'
        New-Item -ItemType Directory -Path $sealed | Out-Null
        $ciphertext = Join-Path $sealed 'windows-amd64-pilot.zip.age'
        & $age --encrypt --recipient $env:PILOT_LAB_RECIPIENT --output $ciphertext $plaintext
        if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $ciphertext -PathType Leaf)) {
            throw 'Pilot transfer encryption did not produce a ciphertext file'
        }
        Remove-Item -LiteralPath $plaintext
        [ordered]@{
            sourceCommit = $env:PILOT_SOURCE
            workflowCommit = $env:GITHUB_SHA
            runId = $env:GITHUB_RUN_ID
            runAttempt = $env:GITHUB_RUN_ATTEMPT
            unsignedArtifactId = $env:PILOT_UNSIGNED_ARTIFACT
            unsignedArchiveSha256 = $env:PILOT_UNSIGNED_SHA256
            archive = $archiveName
            archiveSha256 = $digest
            checksumSha256 = Get-Sha $checksum
            sbomSha256 = Get-Sha $sbom
            inventorySha256 = $proof.InventorySha256
            cmsSha256 = Get-Sha $signature
            launcherPolicySha256 = Get-Sha $launcherPolicy
            encryptedHandoffSha256 = Get-Sha $ciphertext
            verifiedTimestampUtc = $proof.Timestamp
            architecture = 'amd64'
            disposition = 'lab-only'
            launcherRequiredBeforeInstallation = $true
        } | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $sealed 'receipt.json') -Encoding utf8NoBOM
    }
}

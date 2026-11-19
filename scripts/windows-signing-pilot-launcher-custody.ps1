[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('PrepareBuild','RecordBuild','PrepareSign','Bind','Seal')][string]$Operation,
    [Parameter(Mandatory)][string]$Stage
)

$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'windows-signing-pilot-stage.ps1') -RunnerTemp $env:RUNNER_TEMP -VerifyStage $Stage

$hashPattern = '^[a-f0-9]{64}$'
$positiveNumber = '^[1-9][0-9]{0,18}$'
$launcherName = 'tokentimer-agent-launcher.exe'
$policyPath = Join-Path $Stage 'launcher-policy.json'
$launcher = Join-Path $Stage "unsigned/$launcherName"
$unsignedCopy = Join-Path $Stage 'unsigned-launcher.original'
$age = Join-Path $Stage 'age/age/age.exe'
$ageSha = '2821a4ed191da07372acd302e5f6feae7a7985e285e1417765ebe74025af45f0'
if ($env:GITHUB_SHA -cnotmatch '^[a-f0-9]{40}$' -or $env:GITHUB_RUN_ID -cnotmatch $positiveNumber -or
    $env:GITHUB_RUN_ATTEMPT -cnotmatch $positiveNumber -or $env:PACKAGE_WORKFLOW_SHA -cnotmatch '^[a-f0-9]{40}$' -or
    $env:PACKAGE_RUN_ID -cnotmatch $positiveNumber -or $env:PACKAGE_RUN_ATTEMPT -cnotmatch $positiveNumber -or
    $env:PACKAGE_ARTIFACT_ID -cnotmatch $positiveNumber -or $env:LAUNCHER_POLICY_SHA256 -cnotmatch $hashPattern) {
    throw 'Invalid exact launcher run, package receipt or policy context'
}

function Get-Sha([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Read-JsonReceipt([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -lt 2 -or $item.Length -gt 16KB) {
        throw 'Expected a bounded regular custody receipt'
    }
    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable
}

function Read-LauncherPolicy([string]$Inspect = '') {
    $argsForPolicy = @{
        ValidatePolicy = $true
        PolicyPath = $policyPath
        ExpectedPolicySha256 = $env:LAUNCHER_POLICY_SHA256
    }
    if ($Inspect) { $argsForPolicy.InspectLauncherPath = $Inspect }
    & (Join-Path $PSScriptRoot 'windows-signing-pilot-launcher.ps1') @argsForPolicy
}

function Save-LauncherPolicy {
    $encoded = $env:LAUNCHER_POLICY_BASE64
    if ($encoded.Length -lt 4 -or $encoded.Length -gt 24KB -or $encoded -cnotmatch '^[A-Za-z0-9+/]+={0,2}$') {
        throw 'Expected the exact base64 package launcher policy'
    }
    $bytes = [Convert]::FromBase64String($encoded)
    if ([Convert]::ToBase64String($bytes) -cne $encoded) { throw 'Noncanonical launcher policy encoding' }
    [IO.File]::WriteAllBytes($policyPath, $bytes)
    $null = Read-LauncherPolicy
}

function Assert-ProducerReceipt {
    $files = @(Get-ChildItem -LiteralPath (Split-Path -Parent $launcher) -Force)
    if ($files.Count -ne 2 -or (Compare-Object @($launcherName,'unsigned-launcher-receipt.json') @($files.Name) -CaseSensitive)) {
        throw 'Expected only the exact same-run launcher and its producer receipt'
    }
    $receipt = Read-JsonReceipt (Join-Path (Split-Path -Parent $launcher) 'unsigned-launcher-receipt.json')
    if ($env:LAUNCHER_UNSIGNED_ARTIFACT -cnotmatch $positiveNumber -or $env:LAUNCHER_UNSIGNED_SHA256 -cnotmatch $hashPattern -or
        $receipt.unsignedLauncherSha256 -cne $env:LAUNCHER_UNSIGNED_SHA256 -or $receipt.unsignedLauncher -cne $launcherName -or
        $receipt.sourceCommit -cne $env:PILOT_SOURCE -or $receipt.version -cne '0.20.0' -or $receipt.architecture -cne 'amd64' -or
        $receipt.policySha256 -cne $env:LAUNCHER_POLICY_SHA256 -or $receipt.workflowCommit -cne $env:GITHUB_SHA -or
        $receipt.runId -cne $env:GITHUB_RUN_ID -or $receipt.runAttempt -cne $env:GITHUB_RUN_ATTEMPT -or
        $receipt.packageWorkflowCommit -cne $env:PACKAGE_WORKFLOW_SHA -or $receipt.packageRunId -cne $env:PACKAGE_RUN_ID -or
        $receipt.packageRunAttempt -cne $env:PACKAGE_RUN_ATTEMPT -or $receipt.packageArtifactId -cne $env:PACKAGE_ARTIFACT_ID) {
        throw 'Launcher producer receipt does not match this exact run, source and verified package'
    }
}

function Assert-ImagePreserved {
    if ((Get-Sha $unsignedCopy) -cne $env:LAUNCHER_UNSIGNED_SHA256) {
        throw 'The independently bound unsigned launcher copy changed'
    }
    $original = [IO.File]::ReadAllBytes($unsignedCopy)
    $signed = [IO.File]::ReadAllBytes($launcher)
    $optionalHeader = [BitConverter]::ToInt32($original, 0x3c) + 24
    $certDirectory = $optionalHeader + 144
    if ($certDirectory + 8 -gt $original.Length -or $signed.Length -le $original.Length -or
        [BitConverter]::ToUInt16($original, $optionalHeader) -ne 0x20b -or
        [BitConverter]::ToUInt64($original, $certDirectory) -ne 0) {
        throw 'Unexpected Authenticode signature directory'
    }
    $certOffset = [int64][BitConverter]::ToUInt32($signed, $certDirectory)
    $certLength = [int64][BitConverter]::ToUInt32($signed, $certDirectory + 4)
    if ($certOffset -lt $original.Length -or $certOffset -gt $original.Length + 7 -or
        $certOffset % 8 -ne 0 -or $certLength -lt 8 -or $certOffset + $certLength -ne $signed.Length) {
        throw 'A single Authenticode certificate table must follow the original image'
    }
    for ($i = $original.Length; $i -lt $certOffset; $i++) {
        if ($signed[$i] -ne 0) { throw 'Unexpected image data in Authenticode alignment' }
    }
    $projected = [byte[]]::new($original.Length)
    [Array]::Copy($signed, $projected, $projected.Length)
    $checksum = $optionalHeader + 64
    [Array]::Copy($original, $checksum, $projected, $checksum, 4)
    [Array]::Copy($original, $certDirectory, $projected, $certDirectory, 8)
    $digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($projected)).ToLowerInvariant()
    if ($digest -cne $env:LAUNCHER_UNSIGNED_SHA256) { throw 'Signing changed the original launcher image' }
}

switch ($Operation) {
    'PrepareBuild' {
        Save-LauncherPolicy
        $packageDir = Join-Path $Stage 'package'
        $files = @(Get-ChildItem -LiteralPath $packageDir -Force)
        if ($files.Count -ne 2 -or (Compare-Object @('receipt.json','windows-amd64-pilot.zip.age') @($files.Name) -CaseSensitive)) {
            throw 'Package custody artifact has unexpected files'
        }
        $receipt = Read-JsonReceipt (Join-Path $packageDir 'receipt.json')
        if ($receipt.workflowCommit -cne $env:PACKAGE_WORKFLOW_SHA -or $receipt.runId -cne $env:PACKAGE_RUN_ID -or
            $receipt.runAttempt -cne $env:PACKAGE_RUN_ATTEMPT -or $receipt.sourceCommit -cne $env:PILOT_SOURCE -or
            $receipt.architecture -cne 'amd64' -or $receipt.archive -cne 'tokentimer-agent-0.20.0-windows-amd64.tgz' -or
            $receipt.disposition -cne 'lab-only' -or $receipt.launcherRequiredBeforeInstallation -ne $true -or
            $receipt.launcherPolicySha256 -cne $env:LAUNCHER_POLICY_SHA256 -or $receipt.encryptedHandoffSha256 -cnotmatch $hashPattern -or
            (Get-Sha (Join-Path $packageDir 'windows-amd64-pilot.zip.age')) -cne $receipt.encryptedHandoffSha256) {
            throw 'The exact protected package run did not issue this policy and ciphertext'
        }
    }
    'RecordBuild' {
        $exe = Join-Path $Stage $launcherName
        $receiptPath = Join-Path $Stage 'unsigned-launcher-receipt.json'
        $receipt = Read-JsonReceipt $receiptPath
        if ($receipt.policySha256 -cne $env:LAUNCHER_POLICY_SHA256 -or $receipt.unsignedLauncher -cne $launcherName -or
            $receipt.sourceCommit -cne $env:PILOT_SOURCE -or $receipt.architecture -cne 'amd64' -or
            $receipt.unsignedLauncherSha256 -cne (Get-Sha $exe) -or
            (Get-AuthenticodeSignature -LiteralPath $exe).Status -ne 'NotSigned') {
            throw 'Launcher build receipt does not match the exact unsigned PE'
        }
        $receipt.workflowCommit = $env:GITHUB_SHA
        $receipt.runId = $env:GITHUB_RUN_ID
        $receipt.runAttempt = $env:GITHUB_RUN_ATTEMPT
        $receipt.packageWorkflowCommit = $env:PACKAGE_WORKFLOW_SHA
        $receipt.packageRunId = $env:PACKAGE_RUN_ID
        $receipt.packageRunAttempt = $env:PACKAGE_RUN_ATTEMPT
        $receipt.packageArtifactId = $env:PACKAGE_ARTIFACT_ID
        $receipt | ConvertTo-Json -Compress | Set-Content -LiteralPath $receiptPath -Encoding utf8NoBOM
        "sha256=$($receipt.unsignedLauncherSha256)" >> $env:GITHUB_OUTPUT
    }
    'PrepareSign' {
        if ($env:PILOT_ENDPOINT -cnotmatch '^https://[a-z][a-z0-9-]*\.codesigning\.azure\.net$' -or
            $env:PILOT_ACCOUNT -cnotmatch '^[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]$' -or
            $env:PILOT_PROFILE -cnotmatch '^[A-Za-z][A-Za-z0-9-]{3,98}[A-Za-z0-9]$' -or
            $env:PILOT_PROFILE_EKU -cnotmatch '^1\.3\.6\.1\.4\.1\.311\.97\.(?:[0-9]+\.){2,}[0-9]+$' -or
            $env:PILOT_PROFILE_EKU -cmatch '^1\.3\.6\.1\.4\.1\.311\.97\.1\.(?:0|3\.1|4\.1)(?:\.|$)' -or
            $env:PILOT_ISSUER_SHA256 -cnotmatch $hashPattern -or
            $env:PILOT_LAB_RECIPIENT -cnotmatch '^age1[023456789acdefghjklmnpqrstuvwxyz]{58}$') {
            throw 'Expected independently verified signer pins and a protected age recipient'
        }
        Save-LauncherPolicy
        $zip = Join-Path $Stage 'age.zip'
        Invoke-WebRequest -Uri 'https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-windows-amd64.zip' -OutFile $zip -MaximumRedirection 2 -TimeoutSec 120
        if ((Get-Sha $zip) -cne 'f48d8f8f9ebe903ab5027ed067652f2cc1db94bc206976430133b905dcd8e8c7') {
            throw 'Wrong pinned age archive'
        }
        [IO.Compression.ZipFile]::ExtractToDirectory($zip, (Join-Path $Stage 'age'))
        if ((Get-Sha $age) -cne $ageSha) { throw 'Wrong pinned age executable' }
        $probe = Join-Path $Stage 'recipient-check.txt'
        [IO.File]::WriteAllText($probe, 'Windows launcher pilot recipient check')
        & $age --encrypt --recipient $env:PILOT_LAB_RECIPIENT --output "$probe.age" $probe
        if ($LASTEXITCODE -ne 0) { throw 'Invalid protected age recipient' }
    }
    'Bind' {
        Assert-ProducerReceipt
        $null = Read-LauncherPolicy $launcher
        if ((Get-Sha $launcher) -cne $env:LAUNCHER_UNSIGNED_SHA256 -or
            (Get-AuthenticodeSignature -LiteralPath $launcher).Status -ne 'NotSigned') {
            throw 'Sign only the exact unsigned amd64 launcher produced by this run'
        }
        [IO.File]::Copy($launcher, $unsignedCopy)
        "path=$launcher" >> $env:GITHUB_OUTPUT
    }
    'Seal' {
        Assert-ProducerReceipt
        $policy = Read-LauncherPolicy $launcher
        $signature = Get-AuthenticodeSignature -LiteralPath $launcher
        if ($signature.Status -ne 'Valid' -or !$signature.SignerCertificate -or !$signature.TimeStamperCertificate) {
            throw 'Expected a valid timestamped launcher signature'
        }
        Assert-ImagePreserved
        $leaf = $signature.SignerCertificate
        $leafSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($leaf.RawData)).ToLowerInvariant()
        $usages = @($leaf.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } |
            ForEach-Object { $_.EnhancedKeyUsages } | ForEach-Object { $_.Value })
        if ($leafSha -cne $policy.publisherLeafSha256 -or
            $leaf.NotAfter.ToUniversalTime().ToString('o') -cne $policy.publisherNotAfterUtc -or
            $leaf.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or
            $leaf.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow -or
            $usages -cnotcontains '1.3.6.1.5.5.7.3.3' -or $usages -cnotcontains $env:PILOT_PROFILE_EKU) {
            throw 'Launcher leaf changed or differs from the exact live package CMS signer'
        }
        $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
        try {
            $chain.ChainPolicy.RevocationMode = 'Offline'
            $chain.ChainPolicy.RevocationFlag = 'ExcludeRoot'
            if (!$chain.Build($leaf) -or $chain.ChainElements.Count -lt 2 -or
                [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($chain.ChainElements[1].Certificate.RawData)).ToLowerInvariant() -cne $env:PILOT_ISSUER_SHA256) {
                throw 'Launcher publisher chain or exact immediate issuer is unverified'
            }
        } finally {
            $chain.Dispose()
        }
        $signedSha = Get-Sha $launcher
        if ($signedSha -ceq $env:LAUNCHER_UNSIGNED_SHA256 -or (Get-Sha $age) -cne $ageSha) {
            throw 'Launcher signing did not change the artifact or age pin differs'
        }
        $custody = [ordered]@{
            sourceCommit = $env:PILOT_SOURCE
            workflowCommit = $env:GITHUB_SHA
            runId = $env:GITHUB_RUN_ID
            runAttempt = $env:GITHUB_RUN_ATTEMPT
            packageWorkflowCommit = $env:PACKAGE_WORKFLOW_SHA
            packageRunId = $env:PACKAGE_RUN_ID
            packageRunAttempt = $env:PACKAGE_RUN_ATTEMPT
            packageArtifactId = $env:PACKAGE_ARTIFACT_ID
            launcherPolicySha256 = $env:LAUNCHER_POLICY_SHA256
            unsignedLauncherArtifactId = $env:LAUNCHER_UNSIGNED_ARTIFACT
            unsignedLauncherSha256 = $env:LAUNCHER_UNSIGNED_SHA256
            signedLauncherSha256 = $signedSha
            launcher = $launcherName
            architecture = 'amd64'
            disposition = 'lab-only'
        }
        $privateReceipt = Join-Path $Stage 'launcher-receipt.json'
        $custody | ConvertTo-Json -Compress | Set-Content -LiteralPath $privateReceipt -Encoding utf8NoBOM
        $zip = Join-Path $Stage 'windows-amd64-launcher.zip'
        Compress-Archive -LiteralPath @($launcher,$privateReceipt) -DestinationPath $zip
        $sealed = Join-Path $Stage 'sealed'
        [IO.Directory]::CreateDirectory($sealed) | Out-Null
        $ciphertext = Join-Path $sealed 'windows-amd64-launcher.zip.age'
        & $age --encrypt --recipient $env:PILOT_LAB_RECIPIENT --output $ciphertext $zip
        if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $ciphertext -PathType Leaf)) {
            throw 'Could not seal the signed launcher to the lab recipient'
        }
        Remove-Item -LiteralPath $zip
        $custody.encryptedHandoffSha256 = Get-Sha $ciphertext
        $custody | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $sealed 'receipt.json') -Encoding utf8NoBOM
    }
}

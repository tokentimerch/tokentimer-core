$ErrorActionPreference = 'Stop'

# Test target binding and traversal of the signature verifier with local fixtures.
$tempDirectory = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$root = Join-Path $tempDirectory "agent-signing-test-$([guid]::NewGuid())"
$issuerBytes = [byte[]](1, 2, 3)
$issuerPin = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($issuerBytes)).ToLowerInvariant()
$profile = '1.3.6.1.4.1.311.97.990309390.766961637.194916062.941502583'
$checked = [System.Collections.Generic.List[string]]::new()

function Get-AuthenticodeSignature {
    [CmdletBinding()]
    param([string]$LiteralPath)
    $checked.Add($LiteralPath)
    $extension = [pscustomobject]@{
        Oid = @{ Value = '2.5.29.37' }
        EnhancedKeyUsages = @(@{ Value = '1.3.6.1.5.5.7.3.3' }, @{ Value = $profile })
    }
    return [pscustomobject]@{
        Status = 'Valid'
        SignerCertificate = @{ Extensions = @($extension) }
        TimeStamperCertificate = $true
    }
}

function New-Object {
    param([string]$TypeName)
    if ($TypeName -ne 'Security.Cryptography.X509Certificates.X509Chain') { throw 'Unexpected fixture type' }
    $chain = [pscustomobject]@{
        ChainPolicy = @{ RevocationMode = $null; RevocationFlag = $null; VerificationFlags = $null }
        ChainElements = @(@{}, @{ Certificate = @{ RawData = $issuerBytes } })
    }
    $chain | Add-Member -MemberType ScriptMethod -Name Build -Value { return $true }
    $chain | Add-Member -MemberType ScriptMethod -Name Dispose -Value {}
    return $chain
}

function Invoke-TestVerifier([string[]]$Paths) {
    $env:TT_SIGNING_FILES = $Paths -join "`n"
    $checked.Clear()
    & (Join-Path $PSScriptRoot 'verify-windows-signing.ps1')
}

function Assert-StageRejected([string[]]$Paths) {
    try { Invoke-TestVerifier $Paths }
    catch {
        if ($checked.Count -eq 0 -and $_.Exception.Message -match 'Unexpected signing target count|Signing targets differ|Unsupported Windows native executable|Unexpected or missing executable signing target') { return }
        throw
    }
    throw 'Invalid stage reached verification'
}

try {
    foreach ($arch in 'amd64', 'arm64') {
        $stage = Join-Path $root $arch
        $relative = @('scripts/install-agent.ps1', 'src/acme/windows-command.ps1', 'src/windows-material/connector.ps1')
        foreach ($helperArch in 'amd64', 'arm64') {
            foreach ($family in 'tokentimer-adcs-chain', 'tokentimer-adcs-cmc', 'tokentimer-agent-host', 'tokentimer-observed-revocation-windows') {
                $relative += "bin/$family-$helperArch.exe"
            }
        }
        $runtime = Join-Path $stage "runtime/$arch/node.exe"
        $paths = @($relative | ForEach-Object { Join-Path $stage $_ })
        foreach ($file in ($paths + $runtime)) {
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($file)) | Out-Null
            [IO.File]::WriteAllText($file, 'test fixture')
        }
        $env:TT_SIGNING_PACKAGE_ROOT = $stage
        $env:TT_SIGNING_ARCHITECTURE = $arch
        $env:TT_SIGNING_NODE_EXPECTED = $env:TT_SIGNING_NODE_SHA256 = (Get-FileHash -LiteralPath $runtime).Hash.ToLowerInvariant()
        $env:TT_SIGNING_PROFILE_EKU = $profile
        $env:TT_SIGNING_ISSUER_SHA256 = $issuerPin
        Invoke-TestVerifier $paths
        if ($checked.Count -ne 11 -or ($checked -join "`n") -cne ($paths -join "`n")) { throw 'Wrong files reached the signature verifier' }
        Assert-StageRejected ($paths[0..9] + $paths[0])
        Assert-StageRejected ($paths[0..9] + $runtime)
        Remove-Item -LiteralPath $paths[-1]
        Assert-StageRejected $paths
        Write-Output "Verified traversal of 11 first-party targets for $arch and rejected duplicate, substituted and missing targets"
    }
} finally {
    if (Test-Path -LiteralPath $root) {
        $resolved = (Resolve-Path -LiteralPath $root).Path
        if ([IO.Path]::GetDirectoryName($resolved) -cne [IO.Path]::TrimEndingDirectorySeparator($tempDirectory)) { throw 'Unsafe fixture cleanup path' }
        [IO.Directory]::Delete($resolved, $true)
    }
}

#Requires -Version 7.4

# Standalone verification for the signed-inventory preflight.
# Archive and SBOM binding and executable Authenticode checks are separate.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security.Cryptography.Pkcs

$sha256Oid = '2.16.840.1.101.3.4.2.1'
$codeSigningOid = '1.3.6.1.5.5.7.3.3'
$timestampingOid = '1.3.6.1.5.5.7.3.8'
$publicTrustOid = '1.3.6.1.4.1.311.97.1.0'

function Read-InventoryVerificationFile([string]$Path, [long]$Limit) {
    $filePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $stream = [IO.File]::OpenRead($filePath)
    try {
        if ($stream.Length -lt 1 -or $stream.Length -gt $Limit) {
            throw 'Inventory verification input has an invalid size'
        }
        $bytes = [byte[]]::new([int]$stream.Length)
        $stream.ReadExactly($bytes, 0, $bytes.Length)
        return ,$bytes
    } finally {
        $stream.Dispose()
    }
}

function Read-WindowsInventoryCms(
    [byte[]]$Inventory,
    [byte[]]$Signature,
    [string]$ExpectedInventorySha256
) {
    $inventorySha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Inventory)).ToLowerInvariant()
    if ($inventorySha256 -cne $ExpectedInventorySha256) {
        throw 'Inventory differs from the independently expected SHA-256'
    }
    $signatureMemory = [ReadOnlyMemory[byte]]::new($Signature)
    $reader = [System.Formats.Asn1.AsnReader]::new($signatureMemory, [System.Formats.Asn1.AsnEncodingRules]::BER)
    $null = $reader.ReadEncodedValue()
    if ($reader.HasData) { throw 'Unexpected bytes after the inventory CMS' }

    $cms = [Security.Cryptography.Pkcs.SignedCms]::new()
    $cms.Decode($Signature)
    if ($cms.Detached -or $cms.ContentInfo.ContentType.Value -cne '1.2.840.113549.1.7.1' -or $cms.SignerInfos.Count -ne 1) {
        throw 'Expected an embedded data CMS with exactly one publisher'
    }
    if (![Linq.Enumerable]::SequenceEqual[byte]($cms.ContentInfo.Content, $Inventory)) {
        throw 'Inventory CMS does not contain the exact inventory bytes'
    }
    $signer = $cms.SignerInfos[0]
    if (!$signer.Certificate -or $signer.DigestAlgorithm.Value -cne $sha256Oid) {
        throw 'Inventory publisher certificate or SHA-256 signature is missing'
    }
    $cms.CheckSignature($true)

    $timestampOids = @('1.3.6.1.4.1.311.3.3.1', '1.2.840.113549.1.9.16.2.14')
    $attributes = @($signer.UnsignedAttributes | Where-Object { $_.Oid.Value -cin $timestampOids })
    if ($attributes.Count -ne 1 -or $attributes[0].Values.Count -ne 1 -or $signer.CounterSignerInfos.Count -ne 0) {
        throw 'Expected exactly one RFC 3161 timestamp'
    }
    $tokenBytes = $attributes[0].Values[0].RawData
    $token = $null
    $consumed = 0
    $timestampSigner = $null
    if (![Security.Cryptography.Pkcs.Rfc3161TimestampToken]::TryDecode(
            [ReadOnlyMemory[byte]]::new($tokenBytes), [ref]$token, [ref]$consumed) -or
        $consumed -ne $tokenBytes.Length -or $token.TokenInfo.HashAlgorithmId.Value -cne $sha256Oid -or
        !$token.VerifySignatureForSignerInfo($signer, [ref]$timestampSigner, $null)) {
        throw 'RFC 3161 timestamp does not verify against the inventory publisher signature'
    }
    if ($token.TokenInfo.Timestamp -gt [DateTimeOffset]::UtcNow) {
        throw 'Inventory signature timestamp is in the future'
    }

    return [pscustomobject]@{
        InventorySha256 = $inventorySha256
        Publisher = $signer.Certificate
        PublisherCertificates = $cms.Certificates
        Timestamp = $token.TokenInfo.Timestamp
        TimestampSigner = $timestampSigner
        TimestampCertificates = $token.AsSignedCms().Certificates
    }
}

function Assert-InventoryCertificateChain(
    [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
    [Security.Cryptography.X509Certificates.X509Certificate2Collection]$IntermediateCertificates,
    [DateTimeOffset]$Timestamp,
    [string]$RequiredUsage,
    [string]$IssuerSha256
) {
    if (!('WindowsInventoryCertificateChain' -as [type])) {
        Add-Type -Path (Join-Path $PSScriptRoot 'windows-inventory-cms-trust.cs')
    }
    $issuer = [WindowsInventoryCertificateChain]::Verify(
        $Certificate, $IntermediateCertificates, $Timestamp.UtcDateTime, $RequiredUsage, [bool]$IssuerSha256)
    if ($IssuerSha256) {
        $issuerHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($issuer)).ToLowerInvariant()
        if ($issuerHash -cne $IssuerSha256) { throw 'Inventory publisher issuer differs from the independent pin' }
    }
}

function Confirm-WindowsInventoryCms {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$InventoryPath,
        [Parameter(Mandatory)][string]$SignaturePath,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$', Options = 'None')][string]$ExpectedInventorySha256,
        [Parameter(Mandatory)][string]$PublisherProfileEku,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$', Options = 'None')][string]$PublisherIssuerSha256
    )

    if (!$IsWindows) { throw 'Windows certificate stores are required for inventory verification' }
    if ($PublisherProfileEku -cnotmatch '^1\.3\.6\.1\.4\.1\.311\.97\.(?:[0-9]+\.){2,}[0-9]+$' -or
        $PublisherProfileEku -cmatch '^1\.3\.6\.1\.4\.1\.311\.97\.1\.(?:0|3\.1|4\.1)(?:\.|$)') {
        throw 'An independently configured Public Trust profile EKU is required'
    }

    # The existing archive-binding verifier permits a 16 MiB inventory.
    $inventory = Read-InventoryVerificationFile $InventoryPath 16MB
    $signature = Read-InventoryVerificationFile $SignaturePath 17MB
    $proof = Read-WindowsInventoryCms $inventory $signature $ExpectedInventorySha256
    $usages = @($proof.Publisher.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } |
        ForEach-Object { $_.EnhancedKeyUsages } | ForEach-Object { $_.Value })
    if ($usages -cnotcontains $codeSigningOid -or $usages -cnotcontains $publicTrustOid -or
        $usages -cnotcontains $PublisherProfileEku) {
        throw 'Inventory signer does not match the independent Public Trust publisher profile'
    }

    Assert-InventoryCertificateChain $proof.TimestampSigner $proof.TimestampCertificates $proof.Timestamp $timestampingOid
    Assert-InventoryCertificateChain $proof.Publisher $proof.PublisherCertificates $proof.Timestamp $codeSigningOid $PublisherIssuerSha256
    return [pscustomobject]@{
        InventorySha256 = $proof.InventorySha256
        ProfileEku = $PublisherProfileEku
        Timestamp = $proof.Timestamp.UtcDateTime.ToString('o')
    }
}

Export-ModuleMember -Function Confirm-WindowsInventoryCms

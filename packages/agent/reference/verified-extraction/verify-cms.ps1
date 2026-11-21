# Embedded into the authenticated launcher; never executed from the package.
$ErrorActionPreference = 'Stop'
try {
    $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
    if ($request.pin -notmatch '^[0-9a-f]{64}$') { throw 'Invalid publisher pin' }
    Add-Type -AssemblyName System.Security
    $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
    $cms.Decode([Convert]::FromBase64String($request.cms))
    if ($cms.Detached -or $cms.SignerInfos.Count -ne 1) { throw 'Exactly one encapsulated signer is required' }
    $signer = $cms.SignerInfos[0]
    if ($signer.DigestAlgorithm.Value -cne '2.16.840.1.101.3.4.2.1' -or -not $signer.Certificate) { throw 'Unsupported digest or missing signer certificate' }
    $cms.CheckSignature($true)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $pin = ([BitConverter]::ToString($sha.ComputeHash($signer.Certificate.RawData))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
    if ($pin -cne $request.pin) { throw 'Untrusted publisher' }
    $hasCodeSigning = $false
    foreach ($extension in $signer.Certificate.Extensions) {
        if ($extension.Oid.Value -eq '2.5.29.37') {
            foreach ($usage in $extension.EnhancedKeyUsages) {
                if ($usage.Value -eq '1.3.6.1.5.5.7.3.3') { $hasCodeSigning = $true }
            }
        }
    }
    if (-not $hasCodeSigning) { throw 'Code signing EKU missing' }
    $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
    try {
        $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::Offline
        $chain.ChainPolicy.RevocationFlag = [Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
        $chain.ChainPolicy.VerificationFlags = [Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::Zero
        $chain.ChainPolicy.ApplicationPolicy.Add((New-Object Security.Cryptography.Oid('1.3.6.1.5.5.7.3.3'))) | Out-Null
        foreach ($cert in $cms.Certificates) { $chain.ChainPolicy.ExtraStore.Add($cert) | Out-Null }
        if (-not $chain.Build($signer.Certificate)) { throw 'Publisher chain or cached revocation status is not valid' }
    }
    finally { $chain.Dispose() }
    [Console]::Out.Write([Convert]::ToBase64String($cms.ContentInfo.Content))
}
catch {
    [Console]::Error.WriteLine('Signed manifest verification failed.')
    exit 1
}

# Experimental only: called after native timestamp verification, never by launcher.
$ErrorActionPreference = 'Stop'
try {
    $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
    if ($request.publisherIssuer -cnotmatch '^[a-f0-9]{64}$' -or $request.timestampIssuer -cnotmatch '^[a-f0-9]{64}$' -or
        $request.profile -notmatch '^1\.3\.6\.1\.4\.1\.311\.97\.(?:[0-9]+\.){2,}[0-9]+$' -or
        $request.profile -match '^1\.3\.6\.1\.4\.1\.311\.97\.1\.(?:0|3\.1|4\.1)(?:\.|$)') { throw 'Bad independent trust policy' }
    Add-Type -AssemblyName System.Security
    $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
    $cms.Decode([Convert]::FromBase64String($request.cms))
    if ($cms.Detached -or $cms.SignerInfos.Count -ne 1 -or $cms.ContentInfo.ContentType.Value -cne '1.2.840.113549.1.7.1') { throw 'Bad CMS' }
    $cms.CheckSignature($true)
    $signer = $cms.SignerInfos[0]
    if (-not $signer.Certificate -or $signer.DigestAlgorithm.Value -cne '2.16.840.1.101.3.4.2.1') { throw 'Bad publisher signature' }
    $tokens = @($signer.UnsignedAttributes | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.3.3.1' } | ForEach-Object { $_.Values })
    if ($tokens.Count -ne 1) { throw 'Exactly one RFC3161 timestamp required' }
    $timestampCMS = New-Object System.Security.Cryptography.Pkcs.SignedCms
    $timestampCMS.Decode($tokens[0].RawData)
    $stamp = [DateTime]::Parse($request.timestamp, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    if ($stamp -gt [DateTime]::UtcNow.AddMinutes(5)) { throw 'Timestamp is in the future' }
    $tsa = New-Object Security.Cryptography.X509Certificates.X509Certificate2(,[Convert]::FromBase64String($request.timestampCertificate))
    $tsaEKU = @($tsa.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
    if ($tsaEKU.Count -ne 1 -or -not $tsaEKU[0].Critical -or $tsaEKU[0].EnhancedKeyUsages.Count -ne 1 -or $tsaEKU[0].EnhancedKeyUsages[0].Value -cne '1.3.6.1.5.5.7.3.8') { throw 'Invalid TSA EKU' }
    $publisherEKU = @($signer.Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
    if ($publisherEKU.Count -ne 1 -or @($publisherEKU[0].EnhancedKeyUsages.Value) -cnotcontains '1.3.6.1.5.5.7.3.3' -or @($publisherEKU[0].EnhancedKeyUsages.Value) -cnotcontains $request.profile) { throw 'Invalid publisher EKU' }
    function Assert-Chain($certificate, $additional, [string]$usage, [string]$pin) {
        $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
        try {
            $chain.ChainPolicy.RevocationMode = 'Offline'
            $chain.ChainPolicy.RevocationFlag = 'ExcludeRoot'
            $chain.ChainPolicy.VerificationFlags = 'NoFlag'
            $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::Zero
            $chain.ChainPolicy.VerificationTime = $stamp.ToLocalTime()
            $chain.ChainPolicy.ApplicationPolicy.Add((New-Object Security.Cryptography.Oid($usage))) | Out-Null
            foreach ($extra in $additional) { $chain.ChainPolicy.ExtraStore.Add($extra) | Out-Null }
            if (-not $chain.Build($certificate)) { throw 'Untrusted chain or unavailable cached revocation' }
            $sha = [Security.Cryptography.SHA256]::Create()
            try {
                $found = $false
                for ($i=1; $i -lt $chain.ChainElements.Count; $i++) {
                    $digest = ([BitConverter]::ToString($sha.ComputeHash($chain.ChainElements[$i].Certificate.RawData))).Replace('-','').ToLowerInvariant()
                    if ($digest -ceq $pin) { $found = $true }
                }
                if (-not $found) { throw 'Issuer pin mismatch' }
            } finally { $sha.Dispose() }
        } finally { $chain.Dispose() }
    }
    Assert-Chain $tsa $timestampCMS.Certificates '1.3.6.1.5.5.7.3.8' $request.timestampIssuer
    Assert-Chain $signer.Certificate $cms.Certificates '1.3.6.1.5.5.7.3.3' $request.publisherIssuer
    [Console]::Out.Write([Convert]::ToBase64String($cms.ContentInfo.Content))
} catch {
    [Console]::Error.WriteLine('Experimental Azure CMS verification failed.')
    exit 1
}

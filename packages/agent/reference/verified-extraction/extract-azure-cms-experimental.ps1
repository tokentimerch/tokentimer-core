# Experimental only. This extracts cryptographic input; it does not establish trust.
$ErrorActionPreference = 'Stop'
try {
    $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
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
    $publisherCertificates = @($cms.Certificates | ForEach-Object { [Convert]::ToBase64String($_.RawData) })
    $timestampCertificates = @($timestampCMS.Certificates | ForEach-Object { [Convert]::ToBase64String($_.RawData) })
    $output = @{ token=[Convert]::ToBase64String($tokens[0].RawData); signature=[Convert]::ToBase64String($signer.GetSignature());
        publisher=[Convert]::ToBase64String($signer.Certificate.RawData); content=[Convert]::ToBase64String($cms.ContentInfo.Content);
        publisherCertificates=$publisherCertificates; timestampCertificates=$timestampCertificates } | ConvertTo-Json -Compress -Depth 4
    [Console]::Out.Write($output)
} catch {
    [Console]::Error.WriteLine('Experimental CMS extraction failed.')
    exit 1
}

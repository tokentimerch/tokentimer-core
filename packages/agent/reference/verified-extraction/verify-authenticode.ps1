# Embedded launcher code; never loaded from the downloaded package.
$ErrorActionPreference = 'Stop'
try {
    $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
    if (-not $request.files -or $request.files.Count -eq 0) { throw 'No signed files supplied' }
    foreach ($file in $request.files) {
        if ($file.pin -notmatch '^[0-9a-f]{64}$') { throw 'Invalid signer pin' }
        $signature = Get-AuthenticodeSignature -LiteralPath $file.path -ErrorAction Stop
        if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or -not $signature.TimeStamperCertificate) { throw 'Missing/invalid signature or timestamp' }
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $pin = ([BitConverter]::ToString($sha.ComputeHash($signature.SignerCertificate.RawData))).Replace('-','').ToLowerInvariant() }
        finally { $sha.Dispose() }
        if ($pin -cne $file.pin) { throw 'Unexpected publisher' }
    }
    [Console]::Out.Write('OK')
}
catch {
    [Console]::Error.WriteLine('Authenticode publisher/timestamp verification failed.')
    exit 1
}

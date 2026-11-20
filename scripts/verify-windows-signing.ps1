# CI preflight only: this does not qualify an archive or authorize publication.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-signing-chain-cache.ps1')
$profile = $env:TT_SIGNING_PROFILE_EKU
$issuerPin = $env:TT_SIGNING_ISSUER_SHA256
if ($profile -notmatch '^1\.3\.6\.1\.4\.1\.311\.97\.(?:[0-9]+\.){2,}[0-9]+$' -or
    $profile -match '^1\.3\.6\.1\.4\.1\.311\.97\.1\.(?:0|3\.1|4\.1)(?:\.|$)' -or $issuerPin -cnotmatch '^[a-f0-9]{64}$') {
    throw 'Independently configured publisher profile and issuer pin are required'
}
$paths = @($env:TT_SIGNING_FILES -split "`n" | ForEach-Object { $_.TrimEnd("`r") } | Where-Object { $_ })
if ($env:TT_SIGNING_ARCHITECTURE -cnotin @('amd64', 'arm64') -or $env:TT_SIGNING_NODE_EXPECTED -cnotmatch '^[a-f0-9]{64}$' -or
    $env:TT_SIGNING_NODE_SHA256 -cne $env:TT_SIGNING_NODE_EXPECTED) { throw 'Upstream runtime pin unavailable' }
$selector = Join-Path $PSScriptRoot 'windows-signing-targets.cjs'
$expected = @(node -e 'for (const file of require(process.argv[1]).collect(process.argv[2], process.argv[3])) console.log(file);' $selector $env:TT_SIGNING_PACKAGE_ROOT $env:TT_SIGNING_ARCHITECTURE)
if ($LASTEXITCODE -ne 0 -or $expected.Count -eq 0 -or $paths.Count -ne $expected.Count) { throw 'Unexpected signing target count' }
for ($i = 0; $i -lt $paths.Count; $i++) {
    if ($paths[$i] -cne $expected[$i]) { throw 'Signing targets differ from the verified package stage' }
}
$runtime = Join-Path $env:TT_SIGNING_PACKAGE_ROOT "runtime/$($env:TT_SIGNING_ARCHITECTURE)/node.exe"
if ((Get-FileHash -LiteralPath $runtime -Algorithm SHA256).Hash.ToLowerInvariant() -cne $env:TT_SIGNING_NODE_EXPECTED) { throw 'Third-party runtime changed during signing' }
foreach ($file in $paths) {
    $signature = Get-AuthenticodeSignature -LiteralPath $file -ErrorAction Stop
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or -not $signature.TimeStamperCertificate) {
        throw 'Signed file or timestamp is not trusted'
    }
    $usages = @($signature.SignerCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | ForEach-Object { $_.EnhancedKeyUsages } | ForEach-Object { $_.Value })
    if ($usages -cnotcontains '1.3.6.1.5.5.7.3.3' -or $usages -cnotcontains $profile) { throw 'Wrong publisher profile' }
    $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
    try {
        Assert-WindowsSigningChain -Chain $chain -Certificate $signature.SignerCertificate
        $matched = $false
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            for ($i = 1; $i -lt $chain.ChainElements.Count; $i++) {
                $hash = ([BitConverter]::ToString($sha.ComputeHash($chain.ChainElements[$i].Certificate.RawData))).Replace('-', '').ToLowerInvariant()
                if ($hash -ceq $issuerPin) { $matched = $true }
            }
        } finally { $sha.Dispose() }
        if (-not $matched) { throw 'Publisher issuer does not match the independent pin' }
    } finally { $chain.Dispose() }
}

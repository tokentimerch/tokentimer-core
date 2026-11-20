function Assert-WindowsSigningChain {
    param(
        [Security.Cryptography.X509Certificates.X509Chain]$Chain,
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $Chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::Offline
    $Chain.ChainPolicy.RevocationFlag = [Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
    $Chain.ChainPolicy.VerificationFlags = [Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
    if ($Chain.Build($Certificate)) { return }

    $cacheMissFlags = [Security.Cryptography.X509Certificates.X509ChainStatusFlags]'OfflineRevocation,RevocationStatusUnknown,PartialChain'
    $statuses = @($Chain.ChainStatus | ForEach-Object Status)
    if (!$statuses.Count -or @($statuses | Where-Object { [int]$_ -band (-bnot [int]$cacheMissFlags) }).Count) {
        throw "Publisher chain rejected ($($statuses -join ', '))"
    }
    # Populate the Windows cache through a fully validated online chain, then
    # require offline verification of the same certificate.
    $Chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::Online
    $Chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(25)
    if (-not $Chain.Build($Certificate)) {
        throw "Publisher chain could not refresh its cache ($($Chain.ChainStatus.Status -join ', '))"
    }
    $Chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::Offline
    if (-not $Chain.Build($Certificate)) {
        throw "Publisher cached chain still failed ($($Chain.ChainStatus.Status -join ', '))"
    }
}

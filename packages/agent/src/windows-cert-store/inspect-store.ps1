param(
  [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{40}$')][string]$Thumbprint,
  [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_-]{1,128}$')][string]$Container
)
$ErrorActionPreference = 'Stop'
$certPath = 'Cert:\LocalMachine\My\' + $Thumbprint
if (-not (Test-Path -LiteralPath $certPath -ErrorAction Stop)) {
  @{ present = $false } | ConvertTo-Json -Compress
  exit 0
}
$cert = Get-Item -LiteralPath $certPath -ErrorAction Stop
$key = $null
$public = $null
try {
  $sha = [Security.Cryptography.SHA256]::Create()
  try { $fingerprint = ([BitConverter]::ToString($sha.ComputeHash($cert.RawData))).Replace('-', '').ToLowerInvariant() }
  finally { $sha.Dispose() }
  if ($cert.HasPrivateKey) {
    if ($cert.PublicKey.Oid.Value -eq '1.2.840.113549.1.1.1') {
      $key = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    } elseif ($cert.PublicKey.Oid.Value -eq '1.2.840.10045.2.1') {
      $key = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
    }
  }
  $cng = if ($key -and $key.Key -is [Security.Cryptography.CngKey]) { $key.Key } else { $null }
  $possession = $false
  if ($cng) {
    $challenge = New-Object byte[] 32
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($challenge) } finally { $random.Dispose() }
    if ($cert.PublicKey.Oid.Value -eq '1.2.840.113549.1.1.1') {
      $public = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
      $signature = $key.SignData($challenge, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
      $possession = $public.VerifyData($challenge, $signature, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    } elseif ($cert.PublicKey.Oid.Value -eq '1.2.840.10045.2.1') {
      $public = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($cert)
      $signature = $key.SignData($challenge, [Security.Cryptography.HashAlgorithmName]::SHA256)
      $possession = $public.VerifyData($challenge, $signature, [Security.Cryptography.HashAlgorithmName]::SHA256)
    }
  }
  @{
    present = $true
    fingerprintSha256 = $fingerprint
    thumbprint = $cert.Thumbprint
    hasPrivateKey = [bool]$cert.HasPrivateKey
    machineKey = [bool]($cng -and $cng.IsMachineKey)
    nonExportable = [bool]($cng -and [int]$cng.ExportPolicy -eq 0)
    containerMatches = [bool]($cng -and $cng.KeyName -ceq $Container)
    keyPossessionVerified = [bool]$possession
    notBefore = $cert.NotBefore.ToUniversalTime().ToString('o')
    notAfter = $cert.NotAfter.ToUniversalTime().ToString('o')
    serialNumber = $cert.SerialNumber
  } | ConvertTo-Json -Compress
} finally {
  if ($public) { $public.Dispose() }
  if ($key) { $key.Dispose() }
  if ($cert) { $cert.Dispose() }
}

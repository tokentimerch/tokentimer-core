param(
  [Parameter(Mandatory)][string]$CertificateBase64,
  [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_-]{1,128}$')][string]$Container
)
$ErrorActionPreference = 'Stop'
$leaf = $null
$store = $null
$private = $null
$public = $null
try {
  $leaf = [Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($CertificateBase64))
  $oid = $leaf.PublicKey.Oid.Value
  if ($oid -notin @('1.2.840.113549.1.1.1', '1.2.840.10045.2.1')) { throw 'Unsupported key algorithm' }
  $keyValue = [Convert]::ToBase64String($leaf.PublicKey.EncodedKeyValue.RawData)
  $parameters = [Convert]::ToBase64String($leaf.PublicKey.EncodedParameters.RawData)
  $store = [Security.Cryptography.X509Certificates.X509Store]::new('REQUEST', [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
  $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
  $matches = @($store.Certificates | Where-Object {
    $_.PublicKey.Oid.Value -ceq $oid -and
    [Convert]::ToBase64String($_.PublicKey.EncodedKeyValue.RawData) -ceq $keyValue -and
    [Convert]::ToBase64String($_.PublicKey.EncodedParameters.RawData) -ceq $parameters
  })
  if ($matches.Count -ne 1) {
    @{ matchingRequests = $matches.Count; verified = $false } | ConvertTo-Json -Compress
    exit 0
  }
  $pending = $matches[0]
  if ($pending.HasPrivateKey) {
    if ($oid -ceq '1.2.840.113549.1.1.1') {
      $private = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($pending)
      $public = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($leaf)
    } else {
      $private = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($pending)
      $public = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($leaf)
    }
  }
  $cng = if ($private -and $private.Key -is [Security.Cryptography.CngKey]) { $private.Key } else { $null }
  $protected = [bool]($cng -and $cng.IsMachineKey -and [int]$cng.ExportPolicy -eq 0 -and
    $cng.KeyName -ceq $Container -and $cng.Provider.Provider -ceq 'Microsoft Software Key Storage Provider')
  $possession = $false
  if ($protected -and $public) {
    $challenge = New-Object byte[] 32
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($challenge) } finally { $random.Dispose() }
    if ($oid -ceq '1.2.840.113549.1.1.1') {
      $signature = $private.SignData($challenge, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
      $possession = $public.VerifyData($challenge, $signature, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    } else {
      $signature = $private.SignData($challenge, [Security.Cryptography.HashAlgorithmName]::SHA256)
      $possession = $public.VerifyData($challenge, $signature, [Security.Cryptography.HashAlgorithmName]::SHA256)
    }
  }
  @{ matchingRequests = 1; verified = [bool]($protected -and $possession) } | ConvertTo-Json -Compress
} finally {
  if ($public) { $public.Dispose() }
  if ($private) { $private.Dispose() }
  if ($store) { $store.Close(); $store.Dispose() }
  if ($leaf) { $leaf.Dispose() }
}

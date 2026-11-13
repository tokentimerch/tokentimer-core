param([Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$Fingerprint)
$ErrorActionPreference = 'Stop'
$sha = [Security.Cryptography.SHA256]::Create()
try {
  $found = @()
  foreach ($cert in (Get-ChildItem -LiteralPath 'Cert:\LocalMachine\My' -ErrorAction Stop)) {
    $value = ([BitConverter]::ToString($sha.ComputeHash($cert.RawData))).Replace('-', '').ToLowerInvariant()
    if ($value -ceq $Fingerprint) {
      $found += @{ fingerprintSha256 = $value; thumbprintSha1 = $cert.Thumbprint; serialNumber = $cert.SerialNumber;
        notAfter = $cert.NotAfter.ToUniversalTime().ToString('o'); hasPrivateKey = [bool]$cert.HasPrivateKey }
    }
  }
  if ($found.Count -ne 1) { throw 'Expected one exact predecessor certificate in the machine store' }
  $found[0] | ConvertTo-Json -Compress
} finally { $sha.Dispose() }

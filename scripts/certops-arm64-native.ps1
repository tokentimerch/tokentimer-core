# Native ARM64 test support only. No CA private key is exported or written.
# Sign uses .NET's verified PKCS#10 loader on the production certreq CSR. Other
# commands only observe exact receipt-owned identities; Node owns orchestration.
[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('Probe','Sign','Key','Trust','RemoveRoot','RemoveLeaf','RemoveKey')][string]$Mode,
      [Parameter(Mandatory)][string]$InputPath)
$ErrorActionPreference = 'Stop'
$inputData = Get-Content -LiteralPath $InputPath -Raw | ConvertFrom-Json
if ([Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne [System.Runtime.InteropServices.Architecture]::Arm64) { throw 'Native ARM64 PowerShell is mandatory' }
$provider = [Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
$machine = [Security.Cryptography.CngKeyOpenOptions]::MachineKey
function Open-OwnedKey($record) {
  if ($record.containerName -notmatch '^tokentimer-enr-[a-f0-9-]{36}$') { throw 'Invalid receipt key identity' }
  $key = [Security.Cryptography.CngKey]::Open($record.containerName, $provider, $machine)
  $expectedPolicy = if ($null -ne $record.exportPolicy) { [int]$record.exportPolicy } else { 0 }
  if (-not $key.IsMachineKey -or $key.Provider.Provider -ne $provider.Provider -or [int]$key.ExportPolicy -ne $expectedPolicy -or
      ($record.uniqueName -and $key.UniqueName -cne $record.uniqueName)) { $key.Dispose(); throw 'Owned key identity mismatch' }
  return $key
}
function Open-OwnedCertificate($record, $store) {
  if ($record.thumbprint -notmatch '^[A-F0-9]{40}$' -or -not $record.der) { throw 'Public certificate receipt incomplete' }
  $certificate = Get-Item -LiteralPath "Cert:\LocalMachine\$store\$($record.thumbprint)"
  if ([Convert]::ToBase64String($certificate.RawData) -cne $record.der) { $certificate.Dispose(); throw 'Public certificate identity mismatch' }
  return $certificate
}
switch ($Mode) {
  'Probe' {
    $os = Get-CimInstance Win32_OperatingSystem
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $administrator = [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $owner = [Diagnostics.Process]::GetProcessById([int]$inputData.ownerPid)
    try { @{ productType = [int]$os.ProductType; build = [string]$os.BuildNumber; cpuArchitectures = @((Get-CimInstance Win32_Processor) | ForEach-Object { [int]$_.Architecture }); powershellArchitecture = 'arm64'; administrator = $administrator; ownerStartTicks = $owner.StartTime.ToUniversalTime().Ticks.ToString() } | ConvertTo-Json -Compress } finally { $owner.Dispose() }
  }
  'Sign' {
    $rsa = [Security.Cryptography.RSACng]::new(2048); $root = $null
    try {
      if ($rsa -isnot [Security.Cryptography.RSACng] -or -not $rsa.Key.IsEphemeral) { throw 'Signing CA must use an unpersisted ephemeral CNG key' }
      $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new("CN=CertOps ARM64 $($inputData.runId)", $rsa, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
      $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true,$false,0,$true))
      $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new([Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign,$true))
      $root = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddDays(2))
      $leaves = @()
      foreach ($item in $inputData.cases) {
        # UnsafeLoadCertificateExtensions copies the owned test CSR's extensions;
        # SkipSignatureValidation is never enabled. A corrupt signature must fail.
        $csr = [IO.File]::ReadAllText($item.csrPath)
        $loaded = [Security.Cryptography.X509Certificates.CertificateRequest]::LoadSigningRequestPem($csr,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.X509Certificates.CertificateRequestLoadOptions]::UnsafeLoadCertificateExtensions,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $corrupt = [Convert]::FromBase64String(($csr -replace '-----[^-]+-----','' -replace '\s',''))
        $corrupt[$corrupt.Length - 1] = $corrupt[$corrupt.Length - 1] -bxor 1
        $rejected = $false
        try { [void][Security.Cryptography.X509Certificates.CertificateRequest]::LoadSigningRequest($corrupt,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.X509Certificates.CertificateRequestLoadOptions]::UnsafeLoadCertificateExtensions,[Security.Cryptography.RSASignaturePadding]::Pkcs1) } catch {
          $exception = $_.Exception
          for ($depth = 0; $depth -lt 8 -and $exception -isnot [Security.Cryptography.CryptographicException] -and $null -ne $exception.InnerException; $depth++) { $exception = $exception.InnerException }
          if ($exception -isnot [Security.Cryptography.CryptographicException]) { throw }
          $rejected = $true
        }
        if (-not $rejected) { throw 'Corrupt CSR signature was accepted' }
        $san = @($loaded.CertificateExtensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' })
        $usage = @($loaded.CertificateExtensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' })
        if ($san.Count -ne 1 -or $usage.Count -ne 1) { throw 'CSR SAN/key usage extensions missing' }
        $typedUsage = [Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new($usage[0],$usage[0].Critical)
        if (($typedUsage.KeyUsages -band [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature) -eq 0) { throw 'CSR digital-signature key usage missing' }
        $serial = [Security.Cryptography.RandomNumberGenerator]::GetBytes(16); $serial[0] = $serial[0] -band 0x7f
        $leaf = $loaded.Create($root,[DateTimeOffset]::UtcNow.AddMinutes(-2),[DateTimeOffset]::UtcNow.AddDays(1),$serial)
        try { $leaves += @{ profile=$item.profile; pem=$leaf.ExportCertificatePem(); der=[Convert]::ToBase64String($leaf.RawData); thumbprint=$leaf.Thumbprint; csrSignatureVerified=$true; keyUsageVerified=$true } } finally { $leaf.Dispose() }
      }
      @{ rootPem=$root.ExportCertificatePem(); rootDer=[Convert]::ToBase64String($root.RawData); rootThumbprint=$root.Thumbprint; rootEphemeralVerified=$true; cases=$leaves } | ConvertTo-Json -Depth 5 -Compress
    } finally { if ($root) { $root.Dispose() }; $rsa.Dispose() }
  }
  'Key' {
    $key = Open-OwnedKey $inputData
    try { @{ uniqueName=$key.UniqueName; keyName=$key.KeyName; provider=$key.Provider.Provider; machineKey=$key.IsMachineKey; exportPolicy=[int]$key.ExportPolicy } | ConvertTo-Json -Compress } finally { $key.Dispose() }
  }
  'Trust' {
    if ($inputData.thumbprint -notmatch '^[A-F0-9]{40}$') { throw 'Root receipt missing' }
    $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($inputData.der))
    $store = [Security.Cryptography.X509Certificates.X509Store]::new('Root','LocalMachine')
    try {
      if ($cert.Thumbprint -cne $inputData.thumbprint -or $cert.HasPrivateKey) { throw 'Public-only root identity mismatch' }
      $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
      if (@($store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,$cert.Thumbprint,$false)).Count -ne 0) { throw 'Root already exists; refusing adoption' }
      $store.Add($cert)
      $observed = Open-OwnedCertificate $inputData 'Root'; $observed.Dispose(); 'trusted'
    } finally { $store.Close(); $cert.Dispose() }
  }
  'RemoveRoot' {
    $target = "Cert:\LocalMachine\Root\$($inputData.thumbprint)"
    if (Test-Path -LiteralPath $target) { $cert = Open-OwnedCertificate $inputData 'Root'; try { if ($cert.HasPrivateKey) { throw 'Root unexpectedly has a private key' }; Remove-Item -LiteralPath $target } finally { $cert.Dispose() } }
    if (Test-Path -LiteralPath $target) { throw 'Owned root remains' }; 'absent'
  }
  'RemoveLeaf' {
    $target = "Cert:\LocalMachine\My\$($inputData.thumbprint)"
    if (Test-Path -LiteralPath $target) {
      $cert = Open-OwnedCertificate $inputData 'My'; $private = $null
      try {
        $private = if ($inputData.profile -eq 'rsa-2048') { [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert) } else { [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert) }
        if (-not $private -or $private.Key.KeyName -cne $inputData.containerName -or $private.Key.UniqueName -cne $inputData.uniqueName -or -not $private.Key.IsMachineKey -or $private.Key.Provider.Provider -ne $provider.Provider -or [int]$private.Key.ExportPolicy -ne 0) { throw 'Certificate private-key association mismatch' }
        Remove-Item -LiteralPath $target
      } finally { if ($private) { $private.Dispose() }; $cert.Dispose() }
    }
    if (Test-Path -LiteralPath $target) { throw 'Owned leaf remains' }; 'absent'
  }
  'RemoveKey' {
    if (-not $inputData.uniqueName) { throw 'Unobserved key cannot be adopted during cleanup' }
    if ([Security.Cryptography.CngKey]::Exists($inputData.containerName,$provider,$machine)) {
      $key = Open-OwnedKey $inputData
      try { $key.Delete() } finally { $key.Dispose() }
    }
    if ([Security.Cryptography.CngKey]::Exists($inputData.containerName,$provider,$machine)) { throw 'Owned key remains' }; 'absent'
  }
}

# Disposable hosted-Windows feasibility smoke for native standalone CA/certreq/CNG.
# certops-standalone-adcs-smoke.yml invokes this with elevation on a fresh owned runner.
# It refuses existing CA state, cleans up its role/key/certificate and reports its limited
# scope; standalone success cannot qualify enterprise domain templates or agent orchestration.
param([string]$ReportDirectory = 'qualification-results/adcs')
$ErrorActionPreference = 'Stop'
# Deliberately limited to a disposable GitHub-hosted machine; never an existing CA.
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Requires disposable GitHub-hosted Windows runner' }
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevation required' }
if ((Get-WindowsFeature ADCS-Cert-Authority).Installed -or (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration')) { throw 'Existing CA detected; refusing changes' }
New-Item -ItemType Directory -Force $ReportDirectory | Out-Null
$hostOs = Get-CimInstance Win32_OperatingSystem
$report = [ordered]@{ scope='standalone-native-certreq-cng-smoke'; candidateSha=$env:GITHUB_SHA; sourceSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash; experimental=$true; qualified=$false; host=@{measurement='native';version=$hostOs.Version;build=$hostOs.BuildNumber}; image=$env:ImageVersion; identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name; caType='StandaloneRootCA'; noncoverage=@('TokenTimer orchestration','Enterprise templates','Domain enrollment','Renewal','Denial and timeout'); status='failed'; scenarios=@(); cleanup='pending'; cleanupErrors=@() }
$caOwned = $false
$roleOwned = $false
$webRoleOwned = $false
$siteOwned = $false
$siteName = 'CertOps-Standalone-' + [Guid]::NewGuid().ToString('N')
$thumbprint = $null
$caName = 'CertOps-Smoke-' + [Guid]::NewGuid().ToString('N').Substring(0,12)
$keyName = 'CertOps-Smoke-Key-' + [Guid]::NewGuid().ToString('N')
function Native([string]$Executable, [string[]]$Arguments) {
  $output = & $Executable @Arguments 2>&1
  if ($LASTEXITCODE -ne 0) { throw "$Executable failed ($LASTEXITCODE): $output" }
  return $output
}
try {
  $webWasInstalled = (Get-WindowsFeature Web-Server).Installed
  $webRoleOwned = -not $webWasInstalled
  $web = Install-WindowsFeature Web-Server -IncludeManagementTools
  if (-not $web.Success -or $web.RestartNeeded -ne 'No') { throw 'Hosted IIS installation requires reboot or failed; standalone qualification unsupported' }
  $installed = Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools
  $roleOwned = $true
  if (-not $installed.Success -or $installed.RestartNeeded -ne 'No') { throw 'Hosted AD CS installation requires reboot or failed; qualification unsupported on this image' }
  $caOwned = $true
  Install-AdcsCertificationAuthority -CAType StandaloneRootCA -CACommonName $caName -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -KeyLength 2048 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 1 -Force | Out-Null
  $config = "$env:COMPUTERNAME\$caName"
  $inf = Join-Path $ReportDirectory 'request.inf'
  @'
[Version]
Signature="$Windows NT$"
[NewRequest]
Subject="CN=certops-smoke.invalid"
KeyLength=2048
KeyAlgorithm=RSA
ProviderName="Microsoft Software Key Storage Provider"
MachineKeySet=TRUE
Exportable=FALSE
RequestType=PKCS10
KeyUsage=0xa0
'@ | Set-Content -LiteralPath $inf -Encoding ascii
  Add-Content -LiteralPath $inf -Value "KeyContainer=$keyName" -Encoding ascii
  @'
[Extensions]
2.5.29.17="{text}"
_continue_="dns=certops-smoke.invalid"
2.5.29.37="{text}1.3.6.1.5.5.7.3.1"
'@ | Add-Content -LiteralPath $inf -Encoding ascii
  $csr = Join-Path $ReportDirectory 'request.pem'
  $cer = Join-Path $ReportDirectory 'issued.cer'
  Native certreq @('-new','-q',$inf,$csr) | Out-Null
  $request = New-Object -ComObject CertificateAuthority.Request
  $disposition = $request.Submit(0x100, (Get-Content -LiteralPath $csr -Raw), '', $config)
  $requestId = $request.GetRequestId()
  if ($requestId -le 0 -or $disposition -ne 5) { throw "Expected standalone pending request; disposition=$disposition request=$requestId" }
  $report.scenarios += 'pending-request-observed'
  Native certutil @('-config',$config,'-resubmit',"$requestId") | Out-Null
  Native certreq @('-retrieve','-q','-config',$config,"$requestId",$cer) | Out-Null
  $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($cer)
  $thumbprint = $certificate.Thumbprint
  Native certreq @('-accept','-machine',$cer) | Out-Null
  $stored = Get-Item "Cert:\LocalMachine\My\$thumbprint"
  if (-not $stored.HasPrivateKey) { throw 'Accepted certificate lacks private key' }
  $key = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($stored)
  try {
    if ($key -isnot [Security.Cryptography.RSACng]) { throw 'Expected CNG private key' }
    if ($key.Key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None) { throw 'Expected nonexportable CNG private key' }
  } finally { if ($key) { $key.Dispose() } }
  $report.scenarios += 'issued-retrieved-accepted-nonexportable-cng'
  Import-Module WebAdministration
  if (Test-Path "IIS:\Sites\$siteName") { throw 'Unexpected owned site-name collision' }
  $webRoot = [IO.Path]::GetFullPath((Join-Path $ReportDirectory 'site'))
  $reportRoot = [IO.Path]::GetFullPath($ReportDirectory)
  if (-not $webRoot.StartsWith($reportRoot + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Site fixture path must remain inside report directory' }
  New-Item -ItemType Directory -Path $webRoot -Force | Out-Null
  'standalone qualification' | Set-Content -LiteralPath (Join-Path $webRoot 'index.html')
  $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
  $listener.Start()
  $port = $listener.LocalEndpoint.Port
  $listener.Stop()
  $siteOwned = $true
  New-Website -Name $siteName -PhysicalPath $webRoot -IPAddress '127.0.0.1' -Port $port -HostHeader 'certops-smoke.invalid' -Ssl | Out-Null
  Set-WebBinding -Name $siteName -Protocol https -BindingInformation "127.0.0.1:${port}:certops-smoke.invalid" -PropertyName sslFlags -Value 1
  $binding = Get-WebBinding -Name $siteName -Protocol https
  $binding.AddSslCertificate($thumbprint,'My')
  $tcp = [Net.Sockets.TcpClient]::new()
  $tcp.ReceiveTimeout = 10000
  $tcp.SendTimeout = 10000
  $ssl = $null
  try {
    $tcp.Connect('127.0.0.1',$port)
    $ssl = [Net.Security.SslStream]::new($tcp.GetStream(),$false)
    $ssl.ReadTimeout = 10000
    $ssl.WriteTimeout = 10000
    $ssl.AuthenticateAsClient('certops-smoke.invalid')
    $peer = [Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
    try { if ($peer.Thumbprint -ne $thumbprint) { throw 'Independent IIS TLS leaf differs from accepted certificate' } }
    finally { $peer.Dispose() }
  } finally { if ($ssl) { $ssl.Dispose() }; $tcp.Dispose() }
  $report.scenarios += 'standalone-issued-iis-sni-trusted-tls'
  $report.status = 'passed'
} finally {
  $cleanupActions = @(
    {
      if ($siteOwned -and (Test-Path "IIS:\Sites\$siteName")) {
        try {
          Get-WebBinding -Name $siteName -Protocol https | ForEach-Object {
            try { $_.RemoveSslCertificate() } catch { $report.cleanupErrors += 'Owned IIS TLS binding removal failed' }
          }
        } catch { $report.cleanupErrors += 'Owned IIS binding enumeration failed' }
        # Attempt site removal even when HTTP.sys binding cleanup failed.
        Remove-Website -Name $siteName
        if (Test-Path "IIS:\Sites\$siteName") { throw 'Owned IIS site remains after cleanup' }
      }
    },
    { if ($thumbprint -and (Test-Path "Cert:\LocalMachine\My\$thumbprint")) { Remove-Item -LiteralPath "Cert:\LocalMachine\My\$thumbprint" -DeleteKey } },
    {
    if ([Security.Cryptography.CngKey]::Exists($keyName, [Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider, [Security.Cryptography.CngKeyOpenOptions]::MachineKey)) {
      $ownedKey = [Security.Cryptography.CngKey]::Open($keyName, [Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider, [Security.Cryptography.CngKeyOpenOptions]::MachineKey)
      try { $ownedKey.Delete() } finally { $ownedKey.Dispose() }
    }
    if ([Security.Cryptography.CngKey]::Exists($keyName, [Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider, [Security.Cryptography.CngKeyOpenOptions]::MachineKey)) { throw 'Owned leaf CNG key remains after cleanup' }
    },
    { if ($caOwned) { Uninstall-AdcsCertificationAuthority -Force | Out-Null } },
    {
      foreach ($store in @('Root','My','CA')) {
        try {
          Get-ChildItem "Cert:\LocalMachine\$store" | Where-Object Subject -eq "CN=$caName" | ForEach-Object {
            try { $_ | Remove-Item -DeleteKey } catch { $report.cleanupErrors += "Owned CA certificate removal failed in $store" }
          }
          if (Get-ChildItem "Cert:\LocalMachine\$store" | Where-Object Subject -eq "CN=$caName") { throw 'Owned CA certificate remains after cleanup' }
        } catch { $report.cleanupErrors += "Owned CA store cleanup failed in $store" }
      }
    },
    { if ($roleOwned) { $removed = Uninstall-WindowsFeature ADCS-Cert-Authority; if (-not $removed.Success) { throw 'AD CS role removal failed' } } },
    { if ($webRoleOwned) { $removed = Uninstall-WindowsFeature Web-Server; if (-not $removed.Success) { throw 'Owned IIS role removal failed' } } }
  )
  foreach ($cleanupAction in $cleanupActions) {
    try { & $cleanupAction } catch { $report.cleanupErrors += $_.Exception.Message }
  }
  if ($report.cleanupErrors.Count) { $report.cleanup='failed'; $report.status='failed' } else { $report.cleanup='completed' }
  $report | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $ReportDirectory 'report.json')
  if ($report.cleanupErrors.Count) { throw "Owned resource cleanup failed: $($report.cleanupErrors -join '; ')" }
}

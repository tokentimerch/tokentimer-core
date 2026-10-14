<#
Configure the genuine enterprise subordinate CA using the isolated standalone root-signed public
certificate. Used only by the hierarchy workflow; all CA keys/requests remain in the disposable lab
and public chain facts are verified independently.
#>
param([Parameter(Mandatory)][string]$RootCertificateBase64,[Parameter(Mandatory)][string]$SubordinateCertificateBase64,[Parameter(Mandatory)][string]$DomainPassword)
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Expected isolated qualification directory'}
$credential=[PSCredential]::new('TTQUAL\ttqualification',(ConvertTo-SecureString $DomainPassword -AsPlainText -Force))
Invoke-Command -ComputerName localhost -Credential $credential -ArgumentList $RootCertificateBase64,$SubordinateCertificateBase64 -ScriptBlock {
  param($RootCertificateBase64,$SubordinateCertificateBase64)
  $ErrorActionPreference='Stop'
  $directory='C:\ttqualification-hierarchy'
  if(-not(Test-Path (Join-Path $directory 'subordinate.req'))){throw 'Owned subordinate CSR missing'}
  foreach($item in @(@{name='root';encoded=$RootCertificateBase64},@{name='subordinate';encoded=$SubordinateCertificateBase64})){
    $bytes=[Convert]::FromBase64String($item.encoded)
    if($bytes.Length -gt 65536){throw 'Public CA certificate exceeded bound'}
    [IO.File]::WriteAllBytes((Join-Path $directory ($item.name+'.cer')),$bytes)
  }
  $root=[Security.Cryptography.X509Certificates.X509Certificate2]::new((Join-Path $directory 'root.cer'))
  $sub=[Security.Cryptography.X509Certificates.X509Certificate2]::new((Join-Path $directory 'subordinate.cer'))
  try{if($root.Subject -ne 'CN=TTQualificationOfflineRoot' -or $sub.Subject -ne 'CN=TTQualificationRoot' -or $sub.Issuer -ne $root.Subject){throw 'Unexpected hierarchy certificate identity'}}finally{$root.Dispose();$sub.Dispose()}
  Import-Certificate -FilePath (Join-Path $directory 'root.cer') -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
  certutil.exe -dspublish -f (Join-Path $directory 'root.cer') RootCA | Out-Null
  if($LASTEXITCODE){throw 'Directory root publication failed'}
  certutil.exe -installcert (Join-Path $directory 'subordinate.cer') | Out-Null
  if($LASTEXITCODE){throw 'Actual subordinate CA acceptance failed'}
  Start-Service CertSvc
  certutil.exe -crl | Out-Null
  if($LASTEXITCODE -or (Get-Service CertSvc).Status -ne 'Running'){throw 'Subordinate CRL publication or service startup failed'}
  Write-Output 'CERTOPS_STAGE=enterprise-subordinate-service-running'
}

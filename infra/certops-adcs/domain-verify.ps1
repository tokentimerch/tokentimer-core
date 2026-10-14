<#
Native domain/CA connectivity preflight on the disposable member after reboot. Verifies actual
forest membership, RPC and expected authority state; successful infrastructure setup does not itself
qualify certificate E2E scenarios.
#>
param([ValidateSet('root','subordinate')][string]$HierarchyRole='root',[string]$RootCertificateBase64)
$ErrorActionPreference = 'Stop'
$machine = Get-CimInstance Win32_ComputerSystem
if ($machine.Domain -ne 'lab.certops.test' -or -not $machine.PartOfDomain) { throw 'Member did not join expected isolated domain' }
if (-not (Test-ComputerSecureChannel)) { throw 'Domain machine trust failed' }
$config = 'tt-ca.lab.certops.test\TTQualificationRoot'
$null = & certutil.exe -config $config -ping 2>&1
if ($LASTEXITCODE -ne 0) { throw 'Domain-backed AD CS RPC ping failed' }
$publicCa=Join-Path $env:TEMP 'TTQualificationRoot.cer'
& certutil.exe -f -config $config -ca.cert $publicCa | Out-Null
if($LASTEXITCODE -ne 0){throw 'Qualification CA public certificate export failed'}
$certificate=[Security.Cryptography.X509Certificates.X509Certificate2]::new($publicCa)
if($certificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) -ne 'TTQualificationRoot'){throw 'Unexpected qualification root certificate subject'}
if($HierarchyRole -eq 'subordinate'){
  if($certificate.Issuer -ne 'CN=TTQualificationOfflineRoot'){throw 'Expected actual subordinate issuer'}
  $rootFile=Join-Path $env:TEMP 'TTQualificationOfflineRoot.cer'
  [IO.File]::WriteAllBytes($rootFile,[Convert]::FromBase64String($RootCertificateBase64))
  $root=[Security.Cryptography.X509Certificates.X509Certificate2]::new($rootFile)
  try{if($root.Subject -ne 'CN=TTQualificationOfflineRoot' -or $root.Issuer -ne $root.Subject){throw 'Unexpected hierarchy root'}}finally{$root.Dispose()}
  certutil.exe -addstore Root $rootFile | Out-Null
  if($LASTEXITCODE){throw 'Owned offline root trust failed'}
  Remove-Item -LiteralPath $rootFile -Force
  certutil.exe -addstore CA $publicCa | Out-Null
  Enable-PSRemoting -Force
  Set-Item WSMan:\localhost\Client\TrustedHosts -Value '10.64.0.7' -Force
}else{& certutil.exe -addstore Root $publicCa | Out-Null}
if($LASTEXITCODE -ne 0){throw 'Could not trust owned qualification root certificate'}
Remove-Item -LiteralPath $publicCa -Force
Write-Output 'CERTOPS_STAGE=domain-member-ca-rpc-verified'

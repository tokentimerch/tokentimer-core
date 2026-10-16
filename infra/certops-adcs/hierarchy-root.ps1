<#
Create the isolated standalone root for the optional real hierarchy workflow. Exports only its
public certificate/CRL and leaves signing service offline; parent-owned resource group destruction
removes private root material.
#>
param([ValidateSet('prepare','sign')][string]$Action='prepare',[string]$RequestBase64)
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).PartOfDomain -or $env:COMPUTERNAME -ne 'tt-root'){throw 'Requires isolated standalone qualification root host'}
$directory='C:\ttqualification-hierarchy'
if($Action -eq 'prepare'){
  if(Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'){throw 'Refusing existing CA'}
  New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
  Enable-PSRemoting -Force
  New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force | Out-Null
  $feature=Install-WindowsFeature ADCS-Cert-Authority,Web-Server,Web-Scripting-Tools -IncludeManagementTools
  if(-not $feature.Success -or $feature.RestartNeeded -ne 'No'){throw 'Offline-root roles require unsupported reboot'}
  Install-AdcsCertificationAuthority -CAType StandaloneRootCA -CACommonName 'TTQualificationOfflineRoot' -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -KeyLength 4096 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 1 -Force | Out-Null
  # HTTP remains available while the root signing service is stopped. Public
  # CA/CRL files only; the root private key never leaves its native store.
  certutil.exe -setreg CA\CRLPublicationURLs "1:$directory\%3%8%9.crl\n2:http://10.64.0.7/pki/%3%8%9.crl" | Out-Null
  if($LASTEXITCODE){throw 'Root CDP configuration failed'}
  certutil.exe -setreg CA\CACertPublicationURLs "1:$directory\%1_%3%4.crt\n2:http://10.64.0.7/pki/%1_%3%4.crt" | Out-Null
  if($LASTEXITCODE){throw 'Root AIA configuration failed'}
  certutil.exe -setreg CA\ValidityPeriod Days | Out-Null
  if($LASTEXITCODE){throw 'Root validity configuration failed'}
  certutil.exe -setreg CA\ValidityPeriodUnits 90 | Out-Null
  if($LASTEXITCODE){throw 'Root validity length configuration failed'}
  Restart-Service CertSvc
  certutil.exe -crl | Out-Null
  if($LASTEXITCODE){throw 'Root CRL publication failed'}
  certutil.exe -ca.cert (Join-Path $directory 'root.cer') | Out-Null
  if($LASTEXITCODE){throw 'Root public certificate export failed'}
  Copy-Item -LiteralPath (Join-Path $directory 'root.cer') -Destination (Join-Path $directory "$($env:COMPUTERNAME)_TTQualificationOfflineRoot.crt")
  Import-Module WebAdministration
  New-WebVirtualDirectory -Site 'Default Web Site' -Name pki -PhysicalPath $directory | Out-Null
  foreach($mime in @(@{extension='.crl';type='application/pkix-crl'},@{extension='.crt';type='application/x-x509-ca-cert'},@{extension='.cer';type='application/pkix-cert'})){
    if(-not(Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/staticContent/mimeMap' -Name '.'|Where-Object fileExtension -eq $mime.extension)){
      Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/staticContent' -Name '.' -Value @{fileExtension=$mime.extension;mimeType=$mime.type}
    }
  }
  $public=Get-ChildItem $directory -File | Where-Object Extension -in '.cer','.crt','.crl'
  if(-not @($public|Where-Object Extension -eq '.crl').Count){throw 'Root published CRL missing'}
  Write-Output ('CERTOPS_ROOT_CERT='+[Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $directory 'root.cer'))))
  Write-Output 'CERTOPS_STAGE=offline-root-prepared'
}else{
  if(-not(Test-Path (Join-Path $directory 'root.cer')) -or (Get-Service CertSvc).Status -ne 'Running'){throw 'Owned root preparation missing'}
  $bytes=[Convert]::FromBase64String($RequestBase64)
  if($bytes.Length -gt 65536 -or $bytes.Length -lt 100){throw 'Invalid subordinate request size'}
  $request=Join-Path $directory 'subordinate.req'
  [IO.File]::WriteAllBytes($request,$bytes)
  # The submitted request must be a CA request for the exact owned subordinate.
  $dump=certutil.exe -dump $request
  if($LASTEXITCODE -or -not(($dump -join "`n") -match 'TTQualificationRoot')){throw 'Unexpected subordinate CSR subject'}
  $out=certreq.exe -submit -config 'tt-root\TTQualificationOfflineRoot' $request (Join-Path $directory 'subordinate.cer')
  if($LASTEXITCODE -notin 0,3){throw 'Owned subordinate submission failed'}
  $view=certutil.exe -view -restrict 'CommonName=TTQualificationRoot' -out 'RequestID' csv
  if($LASTEXITCODE){throw 'Owned subordinate CA request lookup failed'}
  $ids=@($view|ForEach-Object{if($_ -match '^"?([0-9]+)"?\s*$'){[uint32]$matches[1]}})
  if($ids.Count -ne 1){throw 'Expected exactly one owned subordinate request'}
  certutil.exe -resubmit $ids[0] | Out-Null
  if($LASTEXITCODE){throw 'Owned subordinate approval failed'}
  certreq.exe -retrieve -config 'tt-root\TTQualificationOfflineRoot' $ids[0] (Join-Path $directory 'subordinate.cer') | Out-Null
  if($LASTEXITCODE){throw 'Owned subordinate retrieval failed'}
  $leaf=[Security.Cryptography.X509Certificates.X509Certificate2]::new((Join-Path $directory 'subordinate.cer'))
  try{if($leaf.Subject -ne 'CN=TTQualificationRoot' -or $leaf.Issuer -ne 'CN=TTQualificationOfflineRoot'){throw 'Retrieved certificate is not owned subordinate'}}finally{$leaf.Dispose()}
  Write-Output ('CERTOPS_SUBORDINATE_CERT='+[Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $directory 'subordinate.cer'))))
  Stop-Service CertSvc
  Set-Service CertSvc -StartupType Disabled
  if((Get-Service CertSvc).Status -ne 'Stopped'){throw 'Offline root signing service remains online'}
  Write-Output 'CERTOPS_STAGE=subordinate-signed-root-offline'
}

<#
Proves the owned historical-leaf revoke and base-CRL provider refresh as
definitions only. Native lab execution is still pending. Called exclusively
by the pinned, contained OCSP remote dispatcher on the existing disposable
issuing CA. A revoked historical leaf is never unrevoked: active resources
are removed and the lab is destroyed.
#>
function Get-OwnedOcspHistoricalRequest($Owner,[long]$RequestId,[byte[]]$ExpectedDer,[int]$Disposition) {
 if($RequestId -lt 1 -or $RequestId -gt 4294967295 -or $Disposition -notin @(20,21)) {
  throw 'Exact original native issued request required'
 }
 $pin=Open-OwnedOcspCaRegistry $Owner $false
 $pin.Dispose()
 $expectedDigest=Get-OcspPublicDigest $ExpectedDer
 $certificate=[Security.Cryptography.X509Certificates.X509Certificate2]::new($ExpectedDer)
 try {
  $commonName=$certificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)
  if($commonName -cne ('certops-adcs-'+$Owner.ownership.runId+'-rsa2048.example.test') -or
     $certificate.SerialNumber -cnotmatch '^[A-F0-9]{2,40}$') {
   throw 'Exact historical/current owned leaf subject and serial required'
  }
  $serial=$certificate.SerialNumber
 } finally { $certificate.Dispose() }
 $view=$null;$rows=$null;$columns=$null
 try {
  $view=New-Object -ComObject 'CertificateAuthority.View'
  [void]$view.OpenConnection('tt-ca.lab.certops.test\TTQualificationRoot')
  $indices=@()
  foreach($aliases in @(@('RequestID'),@('CommonName'),@('RequesterName'),@('Request.Disposition','Disposition'),@('RawCertificate'))) {
   $resolved=@()
   foreach($alias in $aliases) { try { $resolved+=,$view.GetColumnIndex($false,$alias) } catch {} }
   $unique=@($resolved|Select-Object -Unique)
   if($unique.Count -ne 1) { throw 'Unambiguous native CA column required' }
   $indices+=,$unique[0]
  }
  $view.SetResultColumnCount(5)
  foreach($index in $indices) { $view.SetResultColumn($index) }
  $view.SetRestriction($indices[0],1,0,[uint32]$RequestId)
  $rows=$view.OpenView()
  if($rows.Next() -eq -1) { throw 'Owned original request absent' }
  $columns=$rows.EnumCertViewColumn();$values=@();$index=0
  while($columns.Next() -ne -1) {
   $values+=,$columns.GetValue($(if($index -eq 4){1}else{0}));$index++
  }
  if($values.Count -ne 5 -or [long]$values[0] -ne $RequestId -or
     [string]$values[1] -cne $commonName -or [string]$values[2] -ine 'TTQUAL\tt-agent$' -or
     [int]$values[3] -ne $Disposition -or
     (Get-OcspPublicDigest ([Convert]::FromBase64String([string]$values[4]))) -cne $expectedDigest -or
     $rows.Next() -ne -1) { throw 'Historical/native request ownership changed' }
  return @{requestId=$RequestId;disposition=$Disposition;certificateSha256=$expectedDigest;serial=$serial}
 } finally {
  foreach($resource in @($columns,$rows,$view)) {
   if($null -ne $resource -and [Runtime.InteropServices.Marshal]::IsComObject($resource)) {
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($resource)
   }
  }
 }
}

function Assert-OwnedOcspOriginalService($Owner) {
 $accepted=Read-OwnedOcspPhase $Owner 'signer-accepted' @('certificateSha256','fingerprint','serviceIdentity','appliedDacl')
 $current=Get-OwnedOcspServiceIdentity
 foreach($key in @('name','account','sid','path','processId','processCreatedAt','executablePath','processSid')) {
  if($current[$key] -cne $accepted.phase.facts.serviceIdentity.$key) {
   throw 'Original responder process changed during historical revocation'
  }
 }
}

function Invoke-OwnedOcspHistoricalRevocation(
 $Owner,[long]$HistoricalRequestId,[byte[]]$HistoricalDer,
 [long]$CurrentRequestId,[byte[]]$CurrentDer,
 [byte[]]$CaDer,[byte[]]$SignerDer,[byte[]]$OriginalCrl
) {
 Assert-OwnedOcspOriginalService $Owner
 $restored=Read-OwnedOcspPhase $Owner 'publication-restored' @('originalPublicationRestored')
 if($restored.phase.facts.originalPublicationRestored -isnot [bool] -or !$restored.phase.facts.originalPublicationRestored -or
    $HistoricalRequestId -eq $CurrentRequestId -or (Get-OcspPublicDigest $HistoricalDer) -ceq (Get-OcspPublicDigest $CurrentDer)) {
  throw 'Distinct historical unserved leaf after original-publication replacement required'
 }
 [void](Get-OwnedOcspConfigurationObservation $Owner.ownership.baseline.signingTemplateName $CaDer $SignerDer $OriginalCrl)
 $historical=Get-OwnedOcspHistoricalRequest $Owner $HistoricalRequestId $HistoricalDer 20
 $current=Get-OwnedOcspHistoricalRequest $Owner $CurrentRequestId $CurrentDer 20
 $facts=@{historicalRequestId=$HistoricalRequestId;currentRequestId=$CurrentRequestId;
  historicalSha256=$historical.certificateSha256;currentSha256=$current.certificateSha256;
  originalCrlSha256=(Get-OcspPublicDigest $OriginalCrl);serial=$historical.serial}
 [void](Write-OwnedOcspPhase $Owner 'historical-revoke-intent' $facts)
 # Original serial comes from the exact native DER whose CA database row was
 # independently bound above. No caller-provided arbitrary serial is accepted.
 [void](Invoke-OcspContainedCommand 'certutil.exe' @('-config','tt-ca.lab.certops.test\TTQualificationRoot','-revoke',$historical.serial,'1') $Owner.directory 120)
 [void](Get-OwnedOcspHistoricalRequest $Owner $HistoricalRequestId $HistoricalDer 21)
 [void](Get-OwnedOcspHistoricalRequest $Owner $CurrentRequestId $CurrentDer 20)
 [void](Invoke-OcspContainedCommand 'certutil.exe' @('-config','tt-ca.lab.certops.test\TTQualificationRoot','-CRL') $Owner.directory 120)
 $directory=Join-Path $env:SystemRoot 'System32\CertSrv\CertEnroll'
 [void][TTQualificationOcspReceipt]::DirectoryIdentity($directory)
 $crl=[TTQualificationOcspReceipt]::ReadPublic((Join-Path $directory 'TTQualificationRoot.crl'))
 $digest=Get-OcspPublicDigest $crl
 if($digest -ceq $facts.originalCrlSha256) { throw 'Native CA did not publish a fresh CRL' }
 Assert-OwnedOcspOriginalService $Owner
 [void](Write-OwnedOcspPhase $Owner 'historical-revoked' @{
  historicalRequestId=$HistoricalRequestId;currentRequestId=$CurrentRequestId;
  historicalSha256=$historical.certificateSha256;currentSha256=$current.certificateSha256;
  originalCrlSha256=$facts.originalCrlSha256;revokedCrlSha256=$digest;nativeDisposition=21
 })
 return @{crlDerBase64=[Convert]::ToBase64String($crl);historicalRequestId=$HistoricalRequestId;currentRequestId=$CurrentRequestId;nativeDisposition=21}
}

function Get-OwnedOcspProviderFingerprint($Properties) {
 if($Properties -isnot [Array] -or $Properties.Rank -ne 2 -or $Properties.GetLength(1) -ne 2 -or
    $Properties.GetLength(0) -lt 1 -or $Properties.GetLength(0) -gt 32 -or
    $Properties.GetLowerBound(0) -ne 0 -or $Properties.GetLowerBound(1) -ne 0) {
  throw 'Bounded native provider matrix required'
 }
 $seen=@{};$rows=@();$total=0
 for($index=0;$index -lt $Properties.GetLength(0);$index++) {
  $name=$Properties[$index,0];$value=$Properties[$index,1]
  if($name -isnot [string] -or $name -cnotmatch '^[A-Za-z][A-Za-z0-9]{0,127}$' -or $seen.ContainsKey($name)) {
   throw 'Unique native provider property required'
  }
  $seen[$name]=$true
  if($value -is [byte[]]) {
   if($value.Length -gt 65536) { throw 'Native provider value exceeds bound' }
   $kind='bytes';$encoded=[Convert]::ToBase64String($value)
  } elseif($value -is [Array] -and $value.Rank -eq 1) {
   if($value.Length -gt 32 -or @($value|Where-Object {$_ -isnot [string] -or $_.Length -gt 2048}).Count) {
    throw 'Bounded native MULTI_SZ provider property required'
   }
   $kind=$value.GetType().FullName;$encoded=ConvertTo-Json -InputObject @($value) -Compress
  } elseif($value -is [string]) {
   if($value.Length -gt 8192) { throw 'Native provider string exceeds bound' }
   $kind='string';$encoded=$value
  } elseif($value -is [int] -or $value -is [uint32] -or $value -is [long] -or $value -is [uint64] -or $value -is [bool]) {
   $kind=$value.GetType().FullName;$encoded=$value.ToString([Globalization.CultureInfo]::InvariantCulture)
  } elseif($null -eq $value) { $kind='empty';$encoded='' }
  else { throw 'Unrecognized native provider variant cannot be overwritten' }
  $total+=$encoded.Length
  if($total -gt 131072) { throw 'Native provider snapshot exceeds bound' }
  $rows+=,[ordered]@{name=$name;kind=$kind;value=$encoded}
 }
 $canonical=@($rows|Sort-Object { $_.name })|ConvertTo-Json -Depth 4 -Compress
 $hash=[Security.Cryptography.SHA256]::Create()
 try { return [BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical))).Replace('-','').ToLowerInvariant() }
 finally { $hash.Dispose() }
}

function Set-OwnedOcspRevokedProvider($Owner,[byte[]]$CaDer,[byte[]]$SignerDer,[byte[]]$OriginalCrl,[byte[]]$RevokedCrl) {
 Assert-OwnedOcspOriginalService $Owner
 $published=Read-OwnedOcspPhase $Owner 'historical-revoked' @('historicalRequestId','currentRequestId','historicalSha256','currentSha256','originalCrlSha256','revokedCrlSha256','nativeDisposition')
 if($published.phase.facts.originalCrlSha256 -cne (Get-OcspPublicDigest $OriginalCrl) -or
    $published.phase.facts.revokedCrlSha256 -cne (Get-OcspPublicDigest $RevokedCrl) -or
    [int]$published.phase.facts.nativeDisposition -ne 21) {
  throw 'Independently verified actual native CRL transition required'
 }
 $identifier=$Owner.ownership.baseline.signingTemplateName
 [void](Get-OwnedOcspConfigurationObservation $identifier $CaDer $SignerDer $OriginalCrl)
 $admin=$null;$collection=$null;$entry=$null
 try {
  $admin=New-Object -ComObject 'CertAdm.OCSPAdmin'
  [void]$admin.GetConfiguration('tt-ca.lab.certops.test',$false)
  $collection=$admin.OCSPCAConfigurationCollection
  if($collection.Count -ne 1) { throw 'Sole original owned responder configuration required' }
  $entry=$collection.ItemByName($identifier)
  if($entry.Identifier -cne $identifier -or (Get-OcspPublicDigest ([byte[]]$entry.CACertificate)) -cne (Get-OcspPublicDigest $CaDer) -or
     (Get-OcspPublicDigest ([byte[]]$entry.SigningCertificate)) -cne (Get-OcspPublicDigest $SignerDer) -or
     [int]$entry.SigningFlags -ne 0x69 -or $entry.HashAlgorithm -cne 'SHA256' -or
     ([string]$entry.ProviderCLSID).ToLowerInvariant() -cne '{4956d17f-88fd-4198-b287-1e6e65883b19}' -or [int]$entry.ErrorCode -ne 0) {
   throw 'Native responder identity changed before provider refresh'
  }
  $before=$entry.ProviderProperties;$originalFingerprint=Get-OwnedOcspProviderFingerprint $before
  $after=$before.Clone();$matches=0
  for($index=0;$index -lt $after.GetLength(0);$index++) {
   if($after[$index,0] -ceq 'BaseCrl') {
    if((Get-OcspPublicDigest ([byte[]]$after[$index,1])) -cne (Get-OcspPublicDigest $OriginalCrl)) { throw 'Original native base CRL changed' }
    $after[$index,1]=[byte[]]$RevokedCrl;$matches++
   }
  }
  if($matches -ne 1) { throw 'Exactly one native base CRL must be replaced' }
  $appliedFingerprint=Get-OwnedOcspProviderFingerprint $after
  [void](Write-OwnedOcspPhase $Owner 'revocation-refresh-intent' @{originalProviderSha256=$originalFingerprint;appliedProviderSha256=$appliedFingerprint;revokedCrlSha256=$published.phase.facts.revokedCrlSha256})
  if((Get-OwnedOcspProviderFingerprint $entry.ProviderProperties) -cne $originalFingerprint) { throw 'Provider changed immediately before refresh' }
  # Preserve every other native VARIANT, including its original type/value.
  # No URL fallback, cache policy or unrelated responder property is edited.
  $entry.ProviderProperties=$after
  [void]$admin.SetConfiguration('tt-ca.lab.certops.test',$false)
 } finally {
  foreach($resource in @($entry,$collection,$admin)) {
   if($null -ne $resource -and [Runtime.InteropServices.Marshal]::IsComObject($resource)) {
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($resource)
   }
  }
 }
 Assert-OwnedOcspOriginalService $Owner
 $observation=Get-OwnedOcspConfigurationObservation $identifier $CaDer $SignerDer $RevokedCrl
 $admin=$null;$collection=$null;$entry=$null
 try {
  $admin=New-Object -ComObject 'CertAdm.OCSPAdmin';[void]$admin.GetConfiguration('tt-ca.lab.certops.test',$false)
  $collection=$admin.OCSPCAConfigurationCollection
  if($collection.Count -ne 1) { throw 'Provider refresh readback is ambiguous' }
  $entry=$collection.ItemByName($identifier)
  if((Get-OwnedOcspProviderFingerprint $entry.ProviderProperties) -cne $appliedFingerprint) { throw 'Exact native provider refresh readback failed' }
 } finally {
  foreach($resource in @($entry,$collection,$admin)) {
   if($null -ne $resource -and [Runtime.InteropServices.Marshal]::IsComObject($resource)) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($resource) }
  }
 }
 [void](Write-OwnedOcspPhase $Owner 'revocation-refreshed' @{originalProviderSha256=$originalFingerprint;appliedProviderSha256=$appliedFingerprint;revokedCrlSha256=$published.phase.facts.revokedCrlSha256})
 return $observation
}

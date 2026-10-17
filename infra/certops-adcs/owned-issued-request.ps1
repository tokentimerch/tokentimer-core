<#
Read-only exact issued-leaf fingerprint/request association for a qualification CN. Native CA rows
independently bind observed IIS TLS DER to a genuine request; no issuance or database state is
invented.
#>
param(
  [Parameter(Mandatory)][ValidatePattern('^certops-adcs-[a-f0-9]+-(?:[a-z0-9]+|issuer-switch)\.example\.test$')][string]$CommonName,
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$FingerprintSha256,
  [ValidateSet('tt-ca.lab.certops.test\TTQualificationRoot','tt-ca-switch.lab.certops.test\TTQualificationDestination')][string]$CaConfig='tt-ca.lab.certops.test\TTQualificationRoot'
)
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Issued request observation requires the isolated qualification forest'}
if(-not $env:CERTOPS_ADCS_OFFICER_PASSWORD){throw 'Isolated officer credential absent'}
$credential=[PSCredential]::new('TTQUAL\tt-lab-admin',(ConvertTo-SecureString $env:CERTOPS_ADCS_OFFICER_PASSWORD -AsPlainText -Force))
Invoke-Command -ComputerName ($CaConfig.Split('\')[0]) -Credential $credential -ArgumentList $CommonName,$FingerprintSha256,$CaConfig -ScriptBlock {
  param([string]$CommonName,[string]$FingerprintSha256,[string]$CaConfig)
  $ErrorActionPreference='Stop'
  $view=New-Object -ComObject CertificateAuthority.View
  $hash=[Security.Cryptography.SHA256]::Create()
  try {
    $null=$view.OpenConnection($CaConfig)
    $names=@('RequestID','CommonName','RequesterName','Disposition','RawCertificate')
    $view.SetResultColumnCount($names.Count)
    foreach($name in $names){$view.SetResultColumn($view.GetColumnIndex($false,$name))}
    $view.SetRestriction($view.GetColumnIndex($false,'CommonName'),1,0,$CommonName)
    $rows=$view.OpenView();$count=0;$matched=@()
    while($rows.Next() -ne -1){
      $columns=$rows.EnumCertViewColumn();$values=@()
      # CV_OUT_BASE64 (1) returns only the public DER certificate for the
      # binary column; scalar columns retain their native value types.
      while($columns.Next() -ne -1){$values+=,$columns.GetValue($(if($values.Count -eq 4){1}else{0}))}
      if($values.Count -ne 5 -or $values[1] -ne $CommonName -or $values[2] -ine 'TTQUAL\tt-agent$'){throw 'Foreign or malformed native issued request observation'}
      $count++;if($count -gt 64){throw 'Owned request observation exceeded its bounded fixture scope'}
      if([int]$values[3] -ne 20 -or -not $values[4]){continue}
      $raw=[Convert]::FromBase64String([string]$values[4])
      $fingerprint=([BitConverter]::ToString($hash.ComputeHash($raw))).Replace('-','').ToLowerInvariant()
      if($fingerprint -ne $FingerprintSha256){continue}
      $certificate=[Security.Cryptography.X509Certificates.X509Certificate2]::new($raw)
      try {$matched+=@{requestId=[long]$values[0];disposition=[int]$values[3];fingerprintSha256=$fingerprint;serialNumber=$certificate.SerialNumber}}
      finally {$certificate.Dispose()}
    }
    if($matched.Count -ne 1 -or $matched[0].requestId -lt 1){throw 'Expected exactly one owned issued CA request with the independently observed leaf fingerprint'}
    $matched[0].subjectRequestCount=$count
    $matched[0]|ConvertTo-Json -Compress
  } finally {if($hash){$hash.Dispose()};if($view){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)}}
}

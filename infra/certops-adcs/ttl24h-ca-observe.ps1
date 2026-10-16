<# Read-only CA observation for the separate default24h fixture. Azure invokes
this on the independently identified original CA VM as SYSTEM. No officer
credential, issuance, approval, CRL publication or private-key export occurs. #>
param([Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{10}$')][string]$RunId,
 [Parameter(Mandatory)][ValidateRange(1,4294967295)][long]$InstalledRequestId,
 [Parameter(Mandatory)][ValidateRange(1,4294967295)][long]$DeferredRequestId,
 [ValidateRange(0,4294967295)][long]$FreshRequestId=0,
 [ValidatePattern('^$|^[a-f0-9]{64}$')][string]$FreshFingerprintSha256='')
$ErrorActionPreference='Stop'
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18' -or (Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test' -or $env:COMPUTERNAME -ine 'tt-ca'){throw 'Original isolated SYSTEM CA required'}
# Azure VM Running does not imply the CA service has finished booting. This
# bounded read-only wait neither starts a service nor changes CA configuration.
$readyClock=[Diagnostics.Stopwatch]::StartNew()
while((Get-Service CertSvc -ErrorAction Stop).Status -ne 'Running'){
 if($readyClock.ElapsedMilliseconds -ge 120000){throw 'Original CA service did not become ready within its read-only deadline'}
 Start-Sleep -Milliseconds 500
}
$readyClock.Stop()
$expectedIds=@($InstalledRequestId,$DeferredRequestId);if($FreshRequestId){$expectedIds+=,$FreshRequestId};if(@($expectedIds|Select-Object -Unique).Count -ne $expectedIds.Count){throw 'Distinct owned request identities required'}
$freshMatches=0
$view=New-Object -ComObject CertificateAuthority.View
try{
 $null=$view.OpenConnection('tt-ca.lab.certops.test\TTQualificationRoot')
 $names=@('RequestID','CommonName','RequesterName','Disposition','RawCertificate');$view.SetResultColumnCount($names.Count);foreach($name in $names){if($name -eq 'Disposition'){$indices=@();foreach($alias in @('Request.Disposition','Disposition')){try{$indices+=,$view.GetColumnIndex($false,$alias)}catch{}};$unique=@($indices|Select-Object -Unique);if($unique.Count -ne 1){throw 'Native disposition column unavailable or ambiguous'};$view.SetResultColumn($unique[0])}else{$view.SetResultColumn($view.GetColumnIndex($false,$name))}}
 $rows=$view.OpenView();$count=0;$requesterCount=0;$owned=@()
 while($rows.Next() -ne -1){if(++$count -gt 2048){throw 'CA observation exceeds isolated bound'};$columns=$rows.EnumCertViewColumn();$values=@();while($columns.Next() -ne -1){$values+=,$columns.GetValue($(if($values.Count -eq 4){1}else{0}))};if($values.Count -ne 5){throw 'Malformed CA observation'}
  if([string]$values[2] -ieq 'TTQUAL\tt-agent$'){$requesterCount++;if([string]$values[1] -cne "certops-adcs-$RunId-ttlvalidation.example.test"){throw 'Unexpected member request subject'}}
  $matchesFresh=$false
  if($FreshFingerprintSha256 -and [int]$values[3] -eq 20 -and $values[4]){
   $candidate=[Convert]::FromBase64String([string]$values[4]);if($candidate.Length -lt 100 -or $candidate.Length -gt 65536){throw 'Invalid public certificate bound'}
   $sha=[Security.Cryptography.SHA256]::Create();try{$candidateSha=([BitConverter]::ToString($sha.ComputeHash($candidate))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
   if($candidateSha -ceq $FreshFingerprintSha256){
    if([long]$values[0] -lt 1 -or [long]$values[0] -gt 4294967295){throw 'Native request identity outside bound'}
    if([long]$values[0] -in @($InstalledRequestId,$DeferredRequestId) -or ($FreshRequestId -and [long]$values[0] -ne $FreshRequestId)){throw 'Fresh leaf request lineage mismatch'}
    $freshMatches++;$matchesFresh=$true
    if(-not $FreshRequestId){$expectedIds+=,[long]$values[0]}
   }
  }
  if([long]$values[0] -in $expectedIds -or $matchesFresh){
   if([string]$values[2] -ine 'TTQUAL\tt-agent$' -or [string]$values[1] -cne "certops-adcs-$RunId-ttlvalidation.example.test" -or [int]$values[3] -ne 20){throw 'Foreign or non-issued original request'}
   $der=[Convert]::FromBase64String([string]$values[4]);if($der.Length -lt 100 -or $der.Length -gt 65536){throw 'Invalid public certificate bound'}
   $owned+=@{requestId=[string]$values[0];disposition=20;certificateB64=[Convert]::ToBase64String($der)}
  }
 }
 if($FreshFingerprintSha256 -and $freshMatches -ne 1){throw 'Exactly one independently matched fresh leaf required'}
 if($owned.Count -ne $expectedIds.Count -or $requesterCount -ne $expectedIds.Count){throw 'Exact original two-request CA lineage required'}
 $config=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\TTQualificationRoot';$thumb=@($config.CACertHash);if($thumb.Count -ne 1 -or $thumb[0] -notmatch '^[a-fA-F0-9]{40}$'){throw 'Exact original CA certificate required'}
 $ca=Get-Item -LiteralPath "Cert:\LocalMachine\My\$($thumb[0])"
 try{$crls=@(Get-Item -LiteralPath "$env:SystemRoot\System32\CertSrv\CertEnroll\TTQualificationRoot.crl" -ErrorAction Stop);if($crls.Count -ne 1 -or $crls[0].PSIsContainer -or ($crls[0].Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Single regular original root CRL required'};$crl=[IO.File]::ReadAllBytes($crls[0].FullName);if($crl.Length -lt 100 -or $crl.Length -gt 65536){throw 'CRL public bound exceeded'}
  @{scope='read-only-original-domain-ca-default-ttl24h';observedAt=[DateTime]::UtcNow.ToString('o');nativeTotalRequestCount=$count;nativeRequesterCount=$requesterCount;requests=$owned;caCertificateB64=[Convert]::ToBase64String($ca.RawData);crlB64=[Convert]::ToBase64String($crl)}|ConvertTo-Json -Depth 5 -Compress
 }finally{$ca.Dispose()}
}finally{if($view){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)}}

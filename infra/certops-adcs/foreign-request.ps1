<#
Create and clean an actual foreign-requester certificate in the disposable forest for native
retrieval-boundary tests. A run-token receipt and native row identity fence cleanup; revocation uses
the exact returned certificate serial, never a fabricated RequestID.
#>
param([Parameter(Mandatory)][ValidateSet('create','revoke')][string]$Action,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{10}$')][string]$RunId,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9-]{36}$')][string]$OwnershipToken,
 [ValidateRange(0,4294967295)][long]$RequestId=0)
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test' -or -not $env:CERTOPS_ADCS_OFFICER_PASSWORD){throw 'Foreign requester fixture requires the isolated forest'}
$credential=[PSCredential]::new('TTQUAL\tt-lab-admin',(ConvertTo-SecureString $env:CERTOPS_ADCS_OFFICER_PASSWORD -AsPlainText -Force))
Invoke-Command -ComputerName 'tt-ca.lab.certops.test' -Credential $credential -ArgumentList $Action,$RunId,$RequestId,$OwnershipToken -ScriptBlock {
 param($Action,$RunId,$RequestId,$OwnershipToken)
 $ErrorActionPreference='Stop'
 if($env:COMPUTERNAME -ine 'tt-ca' -or [Security.Principal.WindowsIdentity]::GetCurrent().Name -ine 'TTQUAL\tt-lab-admin'){throw 'Foreign fixture identity mismatch'}
 $commonName="certops-adcs-$RunId-foreign.example.test"
 $receipt=Join-Path $env:TEMP "tokentimer-foreign-$RunId.ownership.json"
 function Read-OwnedRequest {
  param([bool]$AllowMissing=$false)
  $view=New-Object -ComObject CertificateAuthority.View
  try {
   $null=$view.OpenConnection('tt-ca.lab.certops.test\TTQualificationRoot')
   $names=@('RequestID','CommonName','RequesterName','Disposition','RawCertificate');$view.SetResultColumnCount($names.Count)
   foreach($name in $names){$view.SetResultColumn($view.GetColumnIndex($false,$name))}
   $view.SetRestriction($view.GetColumnIndex($false,'CommonName'),1,0,$commonName)
   $rows=$view.OpenView();if($rows.Next() -eq -1){if($AllowMissing){return $null};throw 'Actual foreign requester row absent'}
   $columns=$rows.EnumCertViewColumn();$values=@();while($columns.Next() -ne -1){$values+=,$columns.GetValue($(if($values.Count -eq 4){1}else{0}))}
   if($values.Count -ne 5 -or $values[1] -ne $commonName -or $values[2] -ine 'TTQUAL\tt-lab-admin' -or $rows.Next() -ne -1){throw 'Foreign request ownership is ambiguous'}
   return @{requestId=[long]$values[0];commonName=$commonName;requester=[string]$values[2];disposition=[int]$values[3];certificateB64=[string]$values[4]}
  }finally{if($view){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)}}
 }
 $directory=Join-Path $env:TEMP "tokentimer-foreign-$RunId";$keyName="tokentimer-qualification-foreign-$RunId"
 function Clear-OwnedArtifacts {
  if([Security.Cryptography.CngKey]::Exists($keyName,[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)){$owned=[Security.Cryptography.CngKey]::Open($keyName,[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey);try{$owned.Delete()}finally{$owned.Dispose()}}
  if(Test-Path -LiteralPath $directory){$item=Get-Item -LiteralPath $directory;if(-not $item.PSIsContainer -or $item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Foreign fixture cleanup refuses reparse point'};Remove-Item -LiteralPath $directory -Recurse -Force}
 }
 if($Action -eq 'revoke'){
  if(-not (Test-Path -LiteralPath $receipt)){if($RequestId -ne 0){throw 'Foreign request ownership receipt missing'};@{absent=$true}|ConvertTo-Json -Compress;return}
  $receiptItem=Get-Item -LiteralPath $receipt;if($receiptItem.PSIsContainer -or $receiptItem.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Unsafe foreign receipt'}
  $proof=Get-Content -LiteralPath $receipt -Raw|ConvertFrom-Json;if($proof.commonName -ne $commonName -or $proof.requester -ine 'TTQUAL\tt-lab-admin' -or $proof.ownershipToken -ne $OwnershipToken){throw 'Foreign receipt ownership mismatch'}
  Clear-OwnedArtifacts
  $row=Read-OwnedRequest -AllowMissing ($RequestId -eq 0);if(-not $row){Remove-Item -LiteralPath $receipt;@{absent=$true}|ConvertTo-Json -Compress;return};if(($RequestId -ne 0 -and $row.requestId -ne $RequestId) -or $row.disposition -notin @(20,21)){throw 'Refusing foreign or non-issued request revocation'};$RequestId=$row.requestId;if($row.disposition -eq 21){Remove-Item -LiteralPath $receipt;@{requestId=$RequestId;revoked=$true}|ConvertTo-Json -Compress;return}
  $certificate=[Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($row.certificateB64))
  try{$serial=$certificate.SerialNumber}finally{$certificate.Dispose()}
  if($serial -notmatch '^[a-fA-F0-9]{2,128}$'){throw 'Owned foreign request lacks its actual certificate serial'}
  & certutil.exe -config 'tt-ca.lab.certops.test\TTQualificationRoot' -revoke $serial 0 | Out-Null;if($LASTEXITCODE -ne 0){throw 'Owned foreign request revocation failed'}
  $row=Read-OwnedRequest;if($row.disposition -ne 21){throw 'Owned foreign request not revoked'}
  Remove-Item -LiteralPath $receipt
  @{requestId=$RequestId;revoked=$true}|ConvertTo-Json -Compress;return
 }
 if(Test-Path -LiteralPath $directory){throw 'Refusing preexisting foreign fixture directory'}
 if([Security.Cryptography.CngKey]::Exists($keyName,[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,[Security.Cryptography.CngKeyOpenOptions]::MachineKey)){throw 'Refusing preexisting foreign fixture key'}
 if(Read-OwnedRequest -AllowMissing $true){throw 'Refusing existing foreign CA subject'}
 $stream=[IO.File]::Open($receipt,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$bytes=[Text.Encoding]::UTF8.GetBytes((@{commonName=$commonName;requester='TTQUAL\tt-lab-admin';ownershipToken=$OwnershipToken}|ConvertTo-Json -Compress));$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
 $null=New-Item -ItemType Directory -Path $directory
 $key=$null;$rsa=$null
 try{
  $parameters=[Security.Cryptography.CngKeyCreationParameters]::new();$parameters.Provider=[Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider;$parameters.KeyCreationOptions=[Security.Cryptography.CngKeyCreationOptions]::MachineKey;$parameters.ExportPolicy=[Security.Cryptography.CngExportPolicies]::None
  $parameters.Parameters.Add([Security.Cryptography.CngProperty]::new('Length',[BitConverter]::GetBytes([int]2048),[Security.Cryptography.CngPropertyOptions]::None))
  $key=[Security.Cryptography.CngKey]::Create([Security.Cryptography.CngAlgorithm]::Rsa,$keyName,$parameters);$rsa=[Security.Cryptography.RSACng]::new($key)
  $request=[Security.Cryptography.X509Certificates.CertificateRequest]::new("CN=$commonName",$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
  $san=[Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new();$san.AddDnsName($commonName);$request.CertificateExtensions.Add($san.Build())
  $csr=Join-Path $directory 'public.csr';[IO.File]::WriteAllBytes($csr,$request.CreateSigningRequest())
  & certreq.exe -submit -q -config 'tt-ca.lab.certops.test\TTQualificationRoot' -attrib 'CertificateTemplate:TTQualificationRSAShort' $csr (Join-Path $directory 'public.cer') | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Actual officer requester submission failed'}
  $row=Read-OwnedRequest;if($row.disposition -ne 20){throw 'Actual officer request was not issued'}
  $row|ConvertTo-Json -Compress
 }finally{
  if($rsa){$rsa.Dispose()};if($key){$key.Dispose()}
  Clear-OwnedArtifacts
 }
}

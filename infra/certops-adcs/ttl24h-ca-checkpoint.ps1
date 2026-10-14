<#
Draft TTL-only read-only CA high-water/count oracle, including a genuinely empty
requester baseline before its first enrollment. Zero is never issuance proof.
Retains exact isolated requester/subject and bounded structured native CA checks.
#>
param([Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{10}$')][string]$RunId)
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test' -or -not $env:CERTOPS_ADCS_OFFICER_PASSWORD){throw 'Native CA checkpoint requires isolated forest credentials'}
$credential=[PSCredential]::new('TTQUAL\tt-lab-admin',(ConvertTo-SecureString $env:CERTOPS_ADCS_OFFICER_PASSWORD -AsPlainText -Force))
Invoke-Command -ComputerName 'tt-ca.lab.certops.test' -Credential $credential -ArgumentList $RunId -ScriptBlock {
 param([string]$RunId)
 $ErrorActionPreference='Stop';$view=New-Object -ComObject CertificateAuthority.View
 try{
  $null=$view.OpenConnection('tt-ca.lab.certops.test\TTQualificationRoot');$names=@('RequestID','CommonName','RequesterName');$view.SetResultColumnCount($names.Count);foreach($name in $names){$view.SetResultColumn($view.GetColumnIndex($false,$name))}
  $rows=$view.OpenView();$maximum=0L;$count=0;$requesterCount=0
  while($rows.Next() -ne -1){if(++$count -gt 2048){throw 'Actual CA checkpoint exceeds isolated qualification bound'};$columns=$rows.EnumCertViewColumn();$values=@();while($columns.Next() -ne -1){$values+=,$columns.GetValue(0)};if($values.Count -ne 3){throw 'Malformed native CA row'};if($values[2] -ieq 'TTQUAL\tt-agent$'){$requesterCount++;if([string]$values[1] -notmatch "^certops-adcs-$RunId-[a-z0-9]+\.example\.test$"){throw 'Foreign agent request encountered in isolated checkpoint'}};if([long]$values[0] -lt 1 -or [long]$values[0] -gt 4294967295){throw 'Actual CA RequestId out of supported range'};$maximum=[Math]::Max($maximum,[long]$values[0])}
  @{highestRequestId=$maximum;nativeRequesterCount=$requesterCount;nativeTotalRequestCount=$count;requester='TTQUAL\tt-agent$';observedOnly=$true}|ConvertTo-Json -Compress
 }finally{if($view){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)}}
}

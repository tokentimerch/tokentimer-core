<#
Read-only native CA high-water/count oracle for the current qualification run. Called before and
after actual submissions to detect resubmission; does not alter CA rows or synthesize request IDs.
#>
param([Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{10}$')][string]$RunId)
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test' -or -not $env:CERTOPS_ADCS_OFFICER_PASSWORD){throw 'Native CA checkpoint requires isolated forest credentials'}
$credential=[PSCredential]::new('TTQUAL\tt-lab-admin',(ConvertTo-SecureString $env:CERTOPS_ADCS_OFFICER_PASSWORD -AsPlainText -Force))
Invoke-Command -ComputerName 'tt-ca.lab.certops.test' -Credential $credential -ArgumentList $RunId -ScriptBlock {
 param([string]$RunId)
 $ErrorActionPreference='Stop';$view=New-Object -ComObject CertificateAuthority.View
 $previousUiCulture=$null;$previousThreadLanguage=0;$threadLanguageChanged=$false
 try{
  try {$null=$view.OpenConnection('tt-ca.lab.certops.test\TTQualificationRoot')}
  catch {
   $originalFailure=$_;$exception=$_.Exception;$fileNotFound=$false
   for($i=0;$i -lt 8 -and $null -ne $exception;$i++){
    if([BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$exception.HResult),0) -eq [uint32]2147942402){$fileNotFound=$true;break}
    $exception=$exception.InnerException
   }
   if(-not $fileNotFound){throw}
   try {
    if(-not ('TTQualificationThreadLanguage' -as [type])){Add-Type -TypeDefinition 'using System.Runtime.InteropServices; public static class TTQualificationThreadLanguage { [DllImport("kernel32.dll")] public static extern ushort GetThreadUILanguage(); [DllImport("kernel32.dll")] public static extern ushort SetThreadUILanguage(ushort language); }'}
    $previousUiCulture=[Threading.Thread]::CurrentThread.CurrentUICulture
    $previousThreadLanguage=[TTQualificationThreadLanguage]::GetThreadUILanguage()
    if([TTQualificationThreadLanguage]::SetThreadUILanguage(1033) -eq 0){throw 'Thread language fallback unavailable'}
    $threadLanguageChanged=$true
    [Threading.Thread]::CurrentThread.CurrentUICulture=[Globalization.CultureInfo]::GetCultureInfo('en-US')
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view);$view=$null
    $view=New-Object -ComObject CertificateAuthority.View
    $null=$view.OpenConnection('tt-ca.lab.certops.test\TTQualificationRoot')
   } catch {throw $originalFailure}
  }
  $names=@('RequestID','CommonName','RequesterName');$view.SetResultColumnCount($names.Count);foreach($name in $names){$view.SetResultColumn($view.GetColumnIndex($false,$name))}
  $rows=$view.OpenView();$maximum=0L;$count=0;$requesterCount=0
  while($rows.Next() -ne -1){if(++$count -gt 2048){throw 'Actual CA checkpoint exceeds isolated qualification bound'};$columns=$rows.EnumCertViewColumn();$values=@();while($columns.Next() -ne -1){$values+=,$columns.GetValue(0)};if($values.Count -ne 3){throw 'Malformed native CA row'};if($values[2] -ieq 'TTQUAL\tt-agent$'){$requesterCount++;if([string]$values[1] -notmatch "^certops-adcs-$RunId-[a-z0-9]+\.example\.test$"){throw 'Foreign agent request encountered in isolated checkpoint'}};if([long]$values[0] -lt 1 -or [long]$values[0] -gt 4294967295){throw 'Actual CA RequestId out of supported range'};$maximum=[Math]::Max($maximum,[long]$values[0])}
  if($requesterCount -eq 0){throw 'Expected actual agent CA requests absent'};@{highestRequestId=$maximum;nativeRequesterCount=$requesterCount;nativeTotalRequestCount=$count;requester='TTQUAL\tt-agent$';observedOnly=$true}|ConvertTo-Json -Compress
 }finally{
  try {if($view){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)}}
  finally {if($null -ne $previousUiCulture){[Threading.Thread]::CurrentThread.CurrentUICulture=$previousUiCulture};if($threadLanguageChanged){[void][TTQualificationThreadLanguage]::SetThreadUILanguage($previousThreadLanguage)}}
 }
}

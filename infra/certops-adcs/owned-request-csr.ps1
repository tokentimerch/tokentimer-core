<#
Read-only ownership oracle for a previously submitted qualification CSR.
Reads actual CA RequestID, requester, template, disposition and public RawRequest.
It never submits, approves, revokes, changes a CA row or exports a private key.
#>
param(
  [Parameter(Mandatory)][ValidatePattern('^certops-adcs-[a-f0-9]{10}-[a-z0-9]+\.example\.test$')][string]$CommonName,
  [Parameter(Mandatory)][ValidateRange(1,4294967295)][long]$RequestId
)
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test' -or -not $env:CERTOPS_ADCS_OFFICER_PASSWORD){throw 'Read-only CSR observation requires isolated forest credentials'}
$credential=[PSCredential]::new('TTQUAL\tt-lab-admin',(ConvertTo-SecureString $env:CERTOPS_ADCS_OFFICER_PASSWORD -AsPlainText -Force))
Invoke-Command -ComputerName 'tt-ca.lab.certops.test' -Credential $credential -ArgumentList $CommonName,$RequestId -ScriptBlock {
  param([string]$CommonName,[long]$RequestId)
  $ErrorActionPreference='Stop'
  $view=New-Object -ComObject CertificateAuthority.View
  $previousUiCulture=$null;$previousThreadLanguage=0;$threadLanguageChanged=$false
  try {
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
        $previousUiCulture=[Threading.Thread]::CurrentThread.CurrentUICulture;$previousThreadLanguage=[TTQualificationThreadLanguage]::GetThreadUILanguage()
        if([TTQualificationThreadLanguage]::SetThreadUILanguage(1033) -eq 0){throw 'Thread language fallback unavailable'}
        $threadLanguageChanged=$true;[Threading.Thread]::CurrentThread.CurrentUICulture=[Globalization.CultureInfo]::GetCultureInfo('en-US')
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view);$view=$null;$view=New-Object -ComObject CertificateAuthority.View
        $null=$view.OpenConnection('tt-ca.lab.certops.test\TTQualificationRoot')
      } catch {throw $originalFailure}
    }
    $names=@('RequestID','CommonName','RequesterName','Disposition','RawRequest','CertificateTemplate')
    $view.SetResultColumnCount($names.Count)
    foreach($name in $names){$view.SetResultColumn($view.GetColumnIndex($false,$name))}
    $view.SetRestriction($view.GetColumnIndex($false,'RequestID'),1,0,[int]$RequestId)
    $rows=$view.OpenView()
    if($rows.Next() -eq -1){throw 'Exact owned CA request absent'}
    $columns=$rows.EnumCertViewColumn();$values=@()
    while($columns.Next() -ne -1){$values+=,$columns.GetValue($(if($values.Count -eq 4){1}else{0}))}
    if($values.Count -ne 6 -or [long]$values[0] -ne $RequestId -or $values[1] -cne $CommonName -or $values[2] -ine 'TTQUAL\tt-agent$' -or $rows.Next() -ne -1){throw 'Foreign or ambiguous CA request ownership'}
    $csr=[Convert]::FromBase64String([string]$values[4])
    if($csr.Length -lt 100 -or $csr.Length -gt 65536 -or [string]$values[5] -notmatch '^\d+(\.\d+)+$'){throw 'Invalid owned public CSR or template identity'}
    @{requestId=[long]$values[0];commonName=[string]$values[1];requester=[string]$values[2];disposition=[int]$values[3];csrDerB64=[Convert]::ToBase64String($csr);templateOid=[string]$values[5]}|ConvertTo-Json -Compress
  } finally {
    try {if($view){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)}}
    finally {if($null -ne $previousUiCulture){[Threading.Thread]::CurrentThread.CurrentUICulture=$previousUiCulture};if($threadLanguageChanged){[void][TTQualificationThreadLanguage]::SetThreadUILanguage($previousThreadLanguage)}}
  }
}

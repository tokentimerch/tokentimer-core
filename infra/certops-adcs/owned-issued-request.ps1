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
try { Invoke-Command -ComputerName ($CaConfig.Split('\')[0]) -Credential $credential -ArgumentList $CommonName,$FingerprintSha256,$CaConfig -ScriptBlock {
  param([string]$CommonName,[string]$FingerprintSha256,[string]$CaConfig)
  $ErrorActionPreference='Stop'
  $view=New-Object -ComObject CertificateAuthority.View
  $hash=[Security.Cryptography.SHA256]::Create()
  $stage='connection'
  $previousUiCulture=$null;$previousThreadLanguage=0;$threadLanguageChanged=$false
  try {
    try { $null=$view.OpenConnection($CaConfig) }
    catch {
      $originalConnectionFailure=$_
      # Server 2022 CertView can fail to load its localized management
      # resources even while the localized CA issues successfully. Retry only
      # that native file-not-found result with this thread's UI set to en-US;
      # the CA, agent, certificate checks and database oracle stay unchanged.
      $connectionException=$_.Exception;$fileNotFound=$false
      for($i=0;$i -lt 8 -and $null -ne $connectionException;$i++){
        if($connectionException -is [Runtime.InteropServices.COMException] -and [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$connectionException.HResult),0) -eq [uint32]2147942402){$fileNotFound=$true;break}
        $connectionException=$connectionException.InnerException
      }
      if(-not $fileNotFound){throw}
      try {
        if(-not ('TTQualificationThreadLanguage' -as [type])){
          Add-Type -TypeDefinition 'using System.Runtime.InteropServices; public static class TTQualificationThreadLanguage { [DllImport("kernel32.dll")] public static extern ushort GetThreadUILanguage(); [DllImport("kernel32.dll")] public static extern ushort SetThreadUILanguage(ushort language); }'
        }
        $previousUiCulture=[Threading.Thread]::CurrentThread.CurrentUICulture
        $previousThreadLanguage=[TTQualificationThreadLanguage]::GetThreadUILanguage()
        if([TTQualificationThreadLanguage]::SetThreadUILanguage(1033) -eq 0){throw 'Thread language fallback unavailable'}
        $threadLanguageChanged=$true
        [Threading.Thread]::CurrentThread.CurrentUICulture=[Globalization.CultureInfo]::GetCultureInfo('en-US')
        try {[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)}catch{}
        $view=New-Object -ComObject CertificateAuthority.View
        $null=$view.OpenConnection($CaConfig)
      } catch {
        if($null -ne $previousUiCulture){[Threading.Thread]::CurrentThread.CurrentUICulture=$previousUiCulture}
        if($threadLanguageChanged){[void][TTQualificationThreadLanguage]::SetThreadUILanguage($previousThreadLanguage)}
        $previousUiCulture=$null;$previousThreadLanguage=0;$threadLanguageChanged=$false
        throw $originalConnectionFailure
      }
    }
    $stage='columns'
    $names=@('RequestID','CommonName','RequesterName','Disposition','RawCertificate')
    $view.SetResultColumnCount($names.Count)
    foreach($name in $names){$view.SetResultColumn($view.GetColumnIndex($false,$name))}
    $stage='restriction'
    $view.SetRestriction($view.GetColumnIndex($false,'CommonName'),1,0,$CommonName)
    $stage='enumeration'
    $rows=$view.OpenView();$count=0;$matched=@()
    while($rows.Next() -ne -1){
      $stage='enumeration'
      $columns=$rows.EnumCertViewColumn();$values=@()
      # CV_OUT_BASE64 (1) returns only the public DER certificate for the
      # binary column; scalar columns retain their native value types.
      while($columns.Next() -ne -1){$values+=,$columns.GetValue($(if($values.Count -eq 4){1}else{0}))}
      $stage='row-validation'
      if($values.Count -ne 5 -or $values[1] -ne $CommonName -or $values[2] -ine 'TTQUAL\tt-agent$'){throw 'Foreign or malformed native issued request observation'}
      $count++;if($count -gt 64){throw 'Owned request observation exceeded its bounded fixture scope'}
      if([int]$values[3] -ne 20 -or -not $values[4]){continue}
      $stage='certificate-decode'
      $raw=[Convert]::FromBase64String([string]$values[4])
      $fingerprint=([BitConverter]::ToString($hash.ComputeHash($raw))).Replace('-','').ToLowerInvariant()
      if($fingerprint -ne $FingerprintSha256){continue}
      $certificate=[Security.Cryptography.X509Certificates.X509Certificate2]::new($raw)
      try {$matched+=@{requestId=[long]$values[0];disposition=[int]$values[3];fingerprintSha256=$fingerprint;serialNumber=$certificate.SerialNumber}}
      finally {$certificate.Dispose()}
    }
    $stage='match'
    if($matched.Count -ne 1 -or $matched[0].requestId -lt 1){throw 'Expected exactly one owned issued CA request with the independently observed leaf fingerprint'}
    $matched[0].subjectRequestCount=$count
    $matched[0]|ConvertTo-Json -Compress
  } catch {
    Write-Output "CERTOPS_ISSUED_FAILURE=$stage"
    # HRESULTs identify the Windows failure without exposing localized messages,
    # command arguments or CA credentials. Traverse only a bounded exception chain.
    $exception=$_.Exception
    for($i=0;$i -lt 8 -and $null -ne $exception;$i++){
      $code=[BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$exception.HResult),0).ToString('X8')
      Write-Output "CERTOPS_ISSUED_HRESULT=0x$code"
      $exception=$exception.InnerException
    }
    if($stage -eq 'connection'){
      # Read-only distinction between an unexpected CA identity and a local
      # CertView failure. Never substitute this probe for the required oracle.
      $parts=$CaConfig.Split('\'); $probe=$null
      try {
        $active=(Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' -Name Active).Active
        $expectedHost=$parts[0].Split('.')[0]
        if($parts.Count -ne 2 -or $env:COMPUTERNAME -ine $expectedHost -or $active -ine $parts[1]){
          Write-Output 'CERTOPS_ISSUED_CA_DIAG=identity-mismatch'
        } else {
          Write-Output 'CERTOPS_ISSUED_CA_DIAG=identity-match'
          $probe=New-Object -ComObject CertificateAuthority.View
          try {$null=$probe.OpenConnection("$expectedHost\$active");Write-Output 'CERTOPS_ISSUED_CA_DIAG=local-open-success'}
          catch {
            Write-Output 'CERTOPS_ISSUED_CA_DIAG=local-open-failure'
            # Diagnostic only: test whether the view client is affected by its
            # thread UI language. Restore both settings and never replace the
            # original failed connection or the independent request oracle.
            $englishProbe=$null;$oldCulture=[Threading.Thread]::CurrentThread.CurrentUICulture;$oldLanguage=0
            try {
              if(-not ('TTQualificationThreadLanguage' -as [type])){
                Add-Type -TypeDefinition 'using System.Runtime.InteropServices; public static class TTQualificationThreadLanguage { [DllImport("kernel32.dll")] public static extern ushort GetThreadUILanguage(); [DllImport("kernel32.dll")] public static extern ushort SetThreadUILanguage(ushort language); }'
              }
              $oldLanguage=[TTQualificationThreadLanguage]::GetThreadUILanguage()
              if([TTQualificationThreadLanguage]::SetThreadUILanguage(1033) -eq 0){throw 'Thread language diagnostic unavailable'}
              [Threading.Thread]::CurrentThread.CurrentUICulture=[Globalization.CultureInfo]::GetCultureInfo('en-US')
              $englishProbe=New-Object -ComObject CertificateAuthority.View
              try {$null=$englishProbe.OpenConnection($CaConfig);Write-Output 'CERTOPS_ISSUED_CA_DIAG=english-open-success'}
              catch {Write-Output 'CERTOPS_ISSUED_CA_DIAG=english-open-failure'}
            } catch {Write-Output 'CERTOPS_ISSUED_CA_DIAG=english-probe-unavailable'}
            finally {
              if($englishProbe){try {[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($englishProbe)}catch{}}
              [Threading.Thread]::CurrentThread.CurrentUICulture=$oldCulture
              if($oldLanguage -ne 0){[void][TTQualificationThreadLanguage]::SetThreadUILanguage($oldLanguage)}
            }
          }
        }
      } catch {Write-Output 'CERTOPS_ISSUED_CA_DIAG=identity-unavailable'}
      finally {if($probe){try {[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($probe)}catch{}}}
    }
    throw
  }
  finally {
    try {if($hash){$hash.Dispose()};if($view){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)}}
    finally {
      if($null -ne $previousUiCulture){[Threading.Thread]::CurrentThread.CurrentUICulture=$previousUiCulture}
      if($threadLanguageChanged){[void][TTQualificationThreadLanguage]::SetThreadUILanguage($previousThreadLanguage)}
    }
  }
} } catch { Write-Output 'CERTOPS_ISSUED_FAILURE=remoting'; throw }

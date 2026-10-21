<#
Read the exact owned CA row public certificate for independent signature/SPKI/template assertions.
Only disposable qualification identities are accepted; no CA ACL changes or private-key exports
occur. With -ListIssued the agent's issued rows for that one identity are returned instead, for
callers that must bind a CA row to a journaled CSR public key because a directly issued CMC
response carries no RequestId.
#>
param([Parameter(Mandatory)][ValidatePattern('^certops-adcs-[a-f0-9]+-[a-z0-9]+\.example\.test$')][string]$CommonName,
  [ValidateRange(1,4294967295)][long]$RequestId,[switch]$ListIssued)
$ErrorActionPreference='Stop'
if(-not $ListIssued -and -not $RequestId){throw 'RequestId is required unless -ListIssued is used'}
if($ListIssued -and $RequestId){throw 'RequestId and -ListIssued are mutually exclusive'}
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test' -or -not $env:CERTOPS_ADCS_OFFICER_PASSWORD){throw 'Certificate observation requires isolated forest credentials'}
$credential=[PSCredential]::new('TTQUAL\tt-lab-admin',(ConvertTo-SecureString $env:CERTOPS_ADCS_OFFICER_PASSWORD -AsPlainText -Force))
Invoke-Command -ComputerName 'tt-ca.lab.certops.test' -Credential $credential -ArgumentList $CommonName,$RequestId,([bool]$ListIssued) -ScriptBlock {
  param([string]$CommonName,[long]$RequestId,[bool]$ListIssued)
  $ErrorActionPreference='Stop'
  $view=New-Object -ComObject CertificateAuthority.View
  try {
    $null=$view.OpenConnection('tt-ca.lab.certops.test\TTQualificationRoot')
    $names=@('RequestID','CommonName','RequesterName','Disposition','RawCertificate')
    $view.SetResultColumnCount($names.Count)
    foreach($name in $names){$view.SetResultColumn($view.GetColumnIndex($false,$name))}
    if($ListIssued){
      $view.SetRestriction($view.GetColumnIndex($false,'CommonName'),1,0,$CommonName)
      $view.SetRestriction($view.GetColumnIndex($false,'Disposition'),1,0,[int]20)
    } else {
      $view.SetRestriction($view.GetColumnIndex($false,'RequestID'),1,0,[int]$RequestId)
    }
    $rows=$view.OpenView()
    $read={
      $columns=$rows.EnumCertViewColumn();$values=@()
      while($columns.Next() -ne -1){$values+=,$columns.GetValue($(if($values.Count -eq 4){1}else{0}))}
      ,$values
    }
    if($ListIssued){
      $found=@()
      while($rows.Next() -ne -1){
        $values=& $read
        if($values.Count -ne 5 -or $values[1] -ne $CommonName -or $values[2] -ine 'TTQUAL\tt-agent$' -or [int]$values[3] -ne 20){continue}
        $raw=[Convert]::FromBase64String([string]$values[4]);if($raw.Length -lt 100 -or $raw.Length -gt 65536){throw 'Invalid public CA certificate size'}
        $found+=@{requestId=[long]$values[0];certificateB64=[Convert]::ToBase64String($raw)}
        if($found.Count -gt 64){throw 'Unexpectedly many issued rows for one disposable identity'}
      }
      @{rows=$found}|ConvertTo-Json -Compress -Depth 4
    } else {
      if($rows.Next() -eq -1){throw 'Owned issued request absent'}
      $values=& $read
      if($values.Count -ne 5 -or [long]$values[0] -ne $RequestId -or $values[1] -ne $CommonName -or $values[2] -ine 'TTQUAL\tt-agent$' -or [int]$values[3] -ne 20){throw 'Foreign or non-issued CA certificate row'}
      if($rows.Next() -ne -1){throw 'Ambiguous native issued request'}
      $raw=[Convert]::FromBase64String([string]$values[4]);if($raw.Length -lt 100 -or $raw.Length -gt 65536){throw 'Invalid public CA certificate size'}
      @{requestId=$RequestId;disposition=20;certificateB64=[Convert]::ToBase64String($raw)}|ConvertTo-Json -Compress
    }
  } finally {if($view){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)}}
}

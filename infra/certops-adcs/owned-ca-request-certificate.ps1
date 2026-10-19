<#
Read the exact owned CA row public certificate for independent signature/SPKI/template assertions.
Only disposable qualification identities are accepted; no CA ACL changes or private-key exports
occur.
#>
param([Parameter(Mandatory)][ValidatePattern('^certops-adcs-[a-f0-9]+-[a-z0-9]+\.example\.test$')][string]$CommonName,
  [Parameter(Mandatory)][ValidateRange(1,4294967295)][long]$RequestId)
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test' -or -not $env:CERTOPS_ADCS_OFFICER_PASSWORD){throw 'Certificate observation requires isolated forest credentials'}
$credential=[PSCredential]::new('TTQUAL\tt-lab-admin',(ConvertTo-SecureString $env:CERTOPS_ADCS_OFFICER_PASSWORD -AsPlainText -Force))
Invoke-Command -ComputerName 'tt-ca.lab.certops.test' -Credential $credential -ArgumentList $CommonName,$RequestId -ScriptBlock {
  param([string]$CommonName,[long]$RequestId)
  $ErrorActionPreference='Stop'
  $view=New-Object -ComObject CertificateAuthority.View
  try {
    $null=$view.OpenConnection('tt-ca.lab.certops.test\TTQualificationRoot')
    $names=@('RequestID','CommonName','RequesterName','Disposition','RawCertificate')
    $view.SetResultColumnCount($names.Count)
    foreach($name in $names){$view.SetResultColumn($view.GetColumnIndex($false,$name))}
    $view.SetRestriction($view.GetColumnIndex($false,'RequestID'),1,0,[uint32]$RequestId)
    $rows=$view.OpenView();if($rows.Next() -eq -1){throw 'Owned issued request absent'}
    $columns=$rows.EnumCertViewColumn();$values=@()
    while($columns.Next() -ne -1){$values+=,$columns.GetValue($(if($values.Count -eq 4){1}else{0}))}
    if($values.Count -ne 5 -or [long]$values[0] -ne $RequestId -or $values[1] -ne $CommonName -or $values[2] -ine 'TTQUAL\tt-agent$' -or [int]$values[3] -ne 20){throw 'Foreign or non-issued CA certificate row'}
    if($rows.Next() -ne -1){throw 'Ambiguous native issued request'}
    $raw=[Convert]::FromBase64String([string]$values[4]);if($raw.Length -lt 100 -or $raw.Length -gt 65536){throw 'Invalid public CA certificate size'}
    @{requestId=$RequestId;disposition=20;certificateB64=[Convert]::ToBase64String($raw)}|ConvertTo-Json -Compress
  } finally {if($view){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)}}
}

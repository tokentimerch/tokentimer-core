<#
Read-only independent CA request/disposition/count oracle for an exact qualification CN and request
ID. Used by native pending/recovery cases; preserves original CA permissions and emits only bounded
public observations.
#>
param([Parameter(Mandatory)][ValidatePattern('^certops-adcs-[a-f0-9]+-(?:[a-z0-9]+|issuer-switch)\.example\.test$')][string]$CommonName,
  [ValidateRange(0,4294967295)][long]$RequestId=0,
  [switch]$Discover)
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Observation requires isolated qualification forest'}
if(-not $env:CERTOPS_ADCS_OFFICER_PASSWORD){throw 'Isolated officer credential absent'}
if(-not $Discover -and $RequestId -lt 1){throw 'An exact request identifier is required'}
$credential=[PSCredential]::new('TTQUAL\tt-lab-admin',(ConvertTo-SecureString $env:CERTOPS_ADCS_OFFICER_PASSWORD -AsPlainText -Force))
Invoke-Command -ComputerName 'tt-ca.lab.certops.test' -Credential $credential -ArgumentList $CommonName,$RequestId,[bool]$Discover -ScriptBlock {
  param([string]$CommonName,[long]$RequestId,[bool]$Discover)
  $ErrorActionPreference='Stop'
  $view=New-Object -ComObject CertificateAuthority.View
  try {
    $null=$view.OpenConnection('tt-ca.lab.certops.test\TTQualificationRoot')
    $names=@('RequestID','CommonName','RequesterName','Disposition')
    $view.SetResultColumnCount($names.Count)
    foreach($name in $names){
      if($name -eq 'Disposition'){
        # MS-CSRA names Request.Disposition; ICertView exposes nonlocalized
        # schema names. Accept only these exact equivalent native aliases.
        $indices=@()
        foreach($alias in @('Request.Disposition','Disposition')){try{$indices+=,$view.GetColumnIndex($false,$alias)}catch{}}
        $unique=@($indices | Select-Object -Unique)
        if($unique.Count -ne 1){throw 'Native disposition column unavailable or ambiguous'}
        $view.SetResultColumn($unique[0])
      }else{$view.SetResultColumn($view.GetColumnIndex($false,$name))}
    }
    $view.SetRestriction($view.GetColumnIndex($false,'CommonName'),1,0,$CommonName)
    $rows=$view.OpenView();$count=0;$matched=0;$disposition=$null
    while($rows.Next() -ne -1){
      $columns=$rows.EnumCertViewColumn();$values=@()
      while($columns.Next() -ne -1){$values+=,$columns.GetValue(0)}
      if($values.Count -ne 4 -or $values[1] -ne $CommonName -or $values[2] -ine 'TTQUAL\tt-agent$'){throw 'Foreign or malformed native CA observation'}
      $count++
      if($Discover -or [long]$values[0] -eq $RequestId){$matched++;$disposition=[int]$values[3];if($Discover){$RequestId=[long]$values[0]}}
    }
    if($Discover -and $count -eq 0){@{subjectRequestCount=0;requestId=$null;disposition=$null}|ConvertTo-Json -Compress;return}
    if($matched -ne 1){throw 'Expected exactly one owned CA RequestId'}
    @{subjectRequestCount=$count;requestId=$RequestId;disposition=$disposition}|ConvertTo-Json -Compress
  } finally { if($view){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)} }
}

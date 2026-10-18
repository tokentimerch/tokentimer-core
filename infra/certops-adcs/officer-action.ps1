<#
Disposable lab CA officer action for an exact owned request/CN/requester. Approve/deny/revoke use
actual native CA state; revocation resolves the real serial number. Called by AD CS E2E helpers with
the temporary lab officer credential.
#>
param([Parameter(Mandatory)][ValidateRange(1,4294967295)][long]$RequestId,
  [Parameter(Mandatory)][ValidateSet('approve','deny','revoke')][string]$Action,
  [Parameter(Mandatory)][ValidatePattern('^certops-adcs-[a-f0-9]+-[a-z0-9]+\.example\.test$')][string]$CommonName)
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Officer action requires isolated qualification forest'}
if(-not $env:CERTOPS_ADCS_OFFICER_PASSWORD){throw 'Isolated officer credential absent'}
$credential=[PSCredential]::new('TTQUAL\tt-lab-admin',(ConvertTo-SecureString $env:CERTOPS_ADCS_OFFICER_PASSWORD -AsPlainText -Force))
Invoke-Command -ComputerName 'tt-ca.lab.certops.test' -Credential $credential -ArgumentList $RequestId,$Action,$CommonName -ScriptBlock {
  param([long]$RequestId,[string]$Action,[string]$CommonName)
  $ErrorActionPreference='Stop'
  $view=New-Object -ComObject CertificateAuthority.View
  $null=$view.OpenConnection('tt-ca.lab.certops.test\TTQualificationRoot')
  $columnCount=if($Action -eq 'revoke'){3}else{2}
  $view.SetResultColumnCount($columnCount)
  $view.SetResultColumn($view.GetColumnIndex($false,'CommonName'))
  $view.SetResultColumn($view.GetColumnIndex($false,'RequesterName'))
  if($Action -eq 'revoke'){$view.SetResultColumn($view.GetColumnIndex($false,'SerialNumber'))}
  $view.SetRestriction($view.GetColumnIndex($false,'RequestID'),1,0,[uint32]$RequestId)
  $rows=$view.OpenView()
  if($rows.Next() -eq -1){throw 'Owned pending CA request not found'}
  $columns=$rows.EnumCertViewColumn()
  $found=@()
  while($columns.Next() -ne -1){$found+=,$columns.GetValue(0)}
  if($found.Count -ne $columnCount -or $found[0] -ne $CommonName -or $found[1] -ine 'TTQUAL\tt-agent$'){throw 'Refusing action on foreign request identity'}
  if($rows.Next() -ne -1){throw 'Ambiguous request identity'}
  if($Action -eq 'approve'){& certutil.exe -config 'tt-ca.lab.certops.test\TTQualificationRoot' -resubmit "$RequestId" | Out-Null}
  elseif($Action -eq 'deny'){& certutil.exe -config 'tt-ca.lab.certops.test\TTQualificationRoot' -deny "$RequestId" | Out-Null}
  else{
    $serial=([string]$found[2]).Replace(' ','')
    if($serial -notmatch '^[a-fA-F0-9]{2,128}$'){throw 'Owned issued request lacks a native certificate serial'}
    & certutil.exe -config 'tt-ca.lab.certops.test\TTQualificationRoot' -revoke $serial 1 | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Native owned certificate revocation failed'}
    & certutil.exe -config 'tt-ca.lab.certops.test\TTQualificationRoot' -CRL | Out-Null
  }
  if($LASTEXITCODE -ne 0){throw 'Native officer decision failed'}
  Write-Output "CERTOPS_OFFICER=$Action"
}

<#
Owned CA-manager template-mismatch fixture. Changes only a verified pending qualification request,
using actual CA issuance for the native validator oracle; the E2E parent owns late-issued
certificate cleanup.
#>
param([Parameter(Mandatory)][ValidatePattern('^certops-adcs-[a-f0-9]+-[a-z0-9]+\.example\.test$')][string]$CommonName,
  [Parameter(Mandatory)][ValidateRange(1,4294967295)][long]$RequestId,
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{10}$')][string]$RunId,
  [Parameter(Mandatory)][ValidatePattern('^\d+(\.\d+)+$')][string]$FrozenTemplateOid)
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test' -or -not $env:CERTOPS_ADCS_OFFICER_PASSWORD){throw 'Template fault requires isolated forest credentials'}
$credential=[PSCredential]::new('TTQUAL\tt-lab-admin',(ConvertTo-SecureString $env:CERTOPS_ADCS_OFFICER_PASSWORD -AsPlainText -Force))
Invoke-Command -ComputerName 'tt-ca.lab.certops.test' -Credential $credential -ArgumentList $CommonName,$RequestId,$RunId,$FrozenTemplateOid -ScriptBlock {
  param([string]$CommonName,[long]$RequestId,[string]$RunId,[string]$FrozenTemplateOid)
  $ErrorActionPreference='Stop'
  if($env:COMPUTERNAME -ine 'TT-CA' -or (Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Refusing foreign CA host'}
  $view=New-Object -ComObject CertificateAuthority.View
  $extension=$null;$oid=$null;$template=$null;$ownedDerFile=$false
  $derFile="C:\ttqualification\template-mismatch-$RunId-$RequestId.der"
  try {
    $null=$view.OpenConnection('tt-ca.lab.certops.test\TTQualificationRoot')
    $names=@('CommonName','RequesterName','Disposition');$view.SetResultColumnCount(3)
    foreach($name in $names){$view.SetResultColumn($view.GetColumnIndex($false,$name))}
    $view.SetRestriction($view.GetColumnIndex($false,'RequestID'),1,0,[uint32]$RequestId)
    $rows=$view.OpenView();if($rows.Next() -eq -1){throw 'Owned pending request absent'}
    $columns=$rows.EnumCertViewColumn();$values=@();while($columns.Next() -ne -1){$values+=,$columns.GetValue(0)}
    if($values.Count -ne 3 -or $values[0] -ne $CommonName -or $values[1] -ine 'TTQUAL\tt-agent$' -or [int]$values[2] -ne 9 -or $rows.Next() -ne -1){throw 'Refusing mutation of a foreign or non-pending request'}
    $configuration=([ADSI]'LDAP://RootDSE').configurationNamingContext
    $template=[ADSI]("LDAP://CN=TTQualificationRSA,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configuration")
    $wrongOid=[string]$template.Get('msPKI-Cert-Template-OID')
    if($wrongOid -notmatch '^\d+(\.\d+)+$' -or $wrongOid -eq $FrozenTemplateOid){throw 'Distinct owned safe template OID unavailable'}
    if(Test-Path -LiteralPath $derFile){throw 'Refusing existing template fault file'}
    $oid=New-Object -ComObject X509Enrollment.CObjectId;$oid.InitializeFromValue($wrongOid)
    $extension=New-Object -ComObject X509Enrollment.CX509ExtensionTemplate;$extension.InitializeEncode($oid,0,0)
    [IO.File]::WriteAllBytes($derFile,[Convert]::FromBase64String($extension.RawData(1)));$ownedDerFile=$true
    & certutil.exe -config 'tt-ca.lab.certops.test\TTQualificationRoot' -setattributes "$RequestId" 'CertificateTemplate:TTQualificationRSA' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Native owned template attribute fault failed'}
    & certutil.exe -config 'tt-ca.lab.certops.test\TTQualificationRoot' -setextension "$RequestId" '1.3.6.1.4.1.311.21.7' 0 "@$derFile" | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Native owned template extension fault failed'}
    @{requestId=$RequestId;frozenTemplateOid=$FrozenTemplateOid;issuedTemplateOid=$wrongOid;template='TTQualificationRSA';nativeAdminMutation=true}|ConvertTo-Json -Compress
  } finally {
    if($ownedDerFile -and (Test-Path -LiteralPath $derFile)){Remove-Item -LiteralPath $derFile}
    if($template){$template.Dispose()}
    foreach($object in @($extension,$oid,$view)){if($object){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($object)}}
  }
}

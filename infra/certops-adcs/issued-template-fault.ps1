<#
Owned CA-manager template-identity fault. For one verified pending qualification request the CA
issues a real signed leaf whose Certificate Template Information OID differs from the OID the agent
froze. The CA refuses certutil -setextension on that extension and rejects a resubmit whose stored
extensions disagree with the template, so the stored extension rows of this one request are deleted
and the template OID is changed only for the duration of the CA's own resubmit (approval), then
restored. The E2E parent owns late-issued certificate cleanup.
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
  $config='tt-ca.lab.certops.test\TTQualificationRoot'
  $view=New-Object -ComObject CertificateAuthority.View
  $template=$null;$csr=$null;$changed=$false;$originalOid=$null;$issuedOid=$null
  $sanFile="C:\ttqualification\template-san-$RunId-$RequestId.der";$ownedSanFile=$false
  try {
    $null=$view.OpenConnection($config)
    $names=@('CommonName','RequesterName','Disposition','RawRequest');$view.SetResultColumnCount($names.Count)
    foreach($name in $names){$view.SetResultColumn($view.GetColumnIndex($false,$name))}
    $view.SetRestriction($view.GetColumnIndex($false,'RequestID'),1,0,[int]$RequestId)
    $rows=$view.OpenView();if($rows.Next() -eq -1){throw 'Owned pending request absent'}
    $columns=$rows.EnumCertViewColumn();$values=@();while($columns.Next() -ne -1){$values+=,$columns.GetValue($(if($values.Count -eq 3){1}else{0}))}
    if($values.Count -ne 4 -or $values[0] -ne $CommonName -or $values[1] -ine 'TTQUAL\tt-agent$' -or [int]$values[2] -ne 9 -or $rows.Next() -ne -1){throw 'Refusing mutation of a foreign or non-pending request'}
    $configuration=([ADSI]'LDAP://RootDSE').configurationNamingContext
    $container=[ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configuration"
    $searcher=New-Object DirectoryServices.DirectorySearcher($container,'(objectClass=pKICertificateTemplate)',@('cn','msPKI-Cert-Template-OID'))
    $all=@($searcher.FindAll()|ForEach-Object{[pscustomobject]@{Name=[string]$_.Properties['cn'][0];Oid=[string]$_.Properties['msPKI-Cert-Template-OID'][0]}})
    $owned=@($all|Where-Object{$_.Oid -eq $FrozenTemplateOid})
    if($owned.Count -ne 1 -or $owned[0].Name -notlike 'TTQualification*'){throw 'Frozen template is not exactly one owned qualification template'}
    $originalOid=$owned[0].Oid
    $parts=$originalOid.Split('.');$parts[-1]=[string]([uint64]$parts[-1]+1);$issuedOid=$parts -join '.'
    if($all|Where-Object{$_.Oid -eq $issuedOid}){throw 'Distinct template identity unavailable'}
    $template=[ADSI]"LDAP://CN=$($owned[0].Name),CN=Certificate Templates,CN=Public Key Services,CN=Services,$configuration"
    # A resubmit regenerates template-derived extensions but not the SAN once the stored rows are gone,
    # so the SAN is carried over from the request's own CSR.
    $csr=New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10;$csr.InitializeDecode([string]$values[3],1)
    $san=$null;foreach($extension in $csr.X509Extensions){if($extension.ObjectId.Value -eq '2.5.29.17'){$san=$extension.RawData(1)}}
    if(-not $san){throw 'Owned request carries no SAN'}
    if(Test-Path -LiteralPath $sanFile){throw 'Refusing existing template fault file'}
    [IO.File]::WriteAllBytes($sanFile,[Convert]::FromBase64String($san));$ownedSanFile=$true
    try {
      # Extension rows of this one request only; the CA regenerates the rest from the template.
      & certutil.exe -config $config -deleterow "$RequestId" Ext | Out-Null
      if($LASTEXITCODE -ne 0){throw 'Native owned request extension reset failed'}
      & certutil.exe -config $config -setextension "$RequestId" '2.5.29.17' 0 "@$sanFile" | Out-Null
      if($LASTEXITCODE -ne 0){throw 'Native owned request SAN restore failed'}
      $template.Put('msPKI-Cert-Template-OID',$issuedOid);$template.SetInfo();$changed=$true
      & certutil.exe -config $config -resubmit "$RequestId" | Out-Null
      if($LASTEXITCODE -ne 0){throw 'Native owned template identity approval failed'}
    } finally {
      if($changed){
        $template.Put('msPKI-Cert-Template-OID',$originalOid);$template.SetInfo()
        $template.RefreshCache(@('msPKI-Cert-Template-OID'))
        if([string]$template.Get('msPKI-Cert-Template-OID') -ne $originalOid){throw 'Template identity restore failed'}
      }
    }
    @{requestId=$RequestId;frozenTemplateOid=$FrozenTemplateOid;issuedTemplateOid=$issuedOid;template=$owned[0].Name;nativeAdminMutation=$true}|ConvertTo-Json -Compress
  } finally {
    if($ownedSanFile -and (Test-Path -LiteralPath $sanFile)){Remove-Item -LiteralPath $sanFile}
    if($template){$template.Dispose()}
    foreach($object in @($csr,$view)){if($object){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($object)}}
  }
}

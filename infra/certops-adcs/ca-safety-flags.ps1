<#
Receipt-backed unsafe CA flag mutations in the disposable forest. Snapshot and restore exact native
policy values; independently observed CA counts prove refused enrollment did not submit. The caller
owns the isolated lab and cleanup.
#>
param(
  [Parameter(Mandatory)][ValidateSet('apply','restore','request-count')][string]$Action,
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{10}$')][string]$RunId,
  [ValidateSet('san-attribute-enabled','encrypted-requests-disabled','both-ca-flags-unsafe')][string]$CaseId,
  [ValidatePattern('^certops-adcs-[a-f0-9]+-[a-z0-9]+\.example\.test$')][string]$CommonName
)
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test' -or -not $env:CERTOPS_ADCS_OFFICER_PASSWORD){throw 'Safety faults require isolated forest credentials'}
$credential=[PSCredential]::new('TTQUAL\tt-lab-admin',(ConvertTo-SecureString $env:CERTOPS_ADCS_OFFICER_PASSWORD -AsPlainText -Force))
$definition=if($Action -eq 'apply'){@((Get-Content (Join-Path $PSScriptRoot 'safety-cases.json') -Raw | ConvertFrom-Json).caFlagCases | Where-Object id -eq $CaseId)}else{@()}
if($Action -eq 'apply' -and $definition.Count -ne 1){throw 'Unknown native CA fault case'}
if($Action -eq 'request-count' -and -not $CommonName){throw 'Owned request common name required'}
Invoke-Command -ComputerName 'tt-ca.lab.certops.test' -Credential $credential -ArgumentList $Action,$RunId,$CaseId,$CommonName,$definition -ScriptBlock {
  param($Action,$RunId,$CaseId,$CommonName,$Definition)
  $ErrorActionPreference='Stop'
  if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test' -or $env:COMPUTERNAME -ine 'TT-CA'){throw 'Refusing foreign CA host'}
  $configuration='HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
  if((Get-ItemProperty -LiteralPath $configuration -Name Active).Active -ne 'TTQualificationRoot'){throw 'Refusing foreign CA configuration'}
  if($Action -eq 'request-count'){
    $view=New-Object -ComObject CertificateAuthority.View
    $null=$view.OpenConnection('tt-ca.lab.certops.test\TTQualificationRoot')
    $column=$view.GetColumnIndex($false,'CommonName');$view.SetResultColumnCount(1);$view.SetResultColumn($column)
    $view.SetRestriction($column,1,0,$CommonName)
    $rows=$view.OpenView();$count=0
    while($rows.Next() -ne -1){$columns=$rows.EnumCertViewColumn();if($columns.Next() -eq -1 -or [string]$columns.GetValue(0) -ne $CommonName){throw 'Foreign request row'};$count++}
    Write-Output $count
    return
  }
  $ca="$configuration\TTQualificationRoot"
  $policy="$ca\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy"
  $snapshot="C:\ttqualification\ca-safety-$RunId.json"
  if($Action -eq 'apply'){
    if(Test-Path -LiteralPath $snapshot){throw 'Refusing to replace native CA safety snapshot'}
    $before=@{runId=$RunId;ca='TTQualificationRoot';editFlags=[uint32](Get-ItemProperty -LiteralPath $policy -Name EditFlags).EditFlags;interfaceFlags=[uint32](Get-ItemProperty -LiteralPath $ca -Name InterfaceFlags).InterfaceFlags}
    if(($before.editFlags -band 0x40000) -ne 0 -or ($before.interfaceFlags -band 0x200) -eq 0){throw 'CA must begin hardened before owned safety mutation'}
    $before | ConvertTo-Json | Set-Content -LiteralPath $snapshot
    Set-ItemProperty -LiteralPath $policy -Name EditFlags -Type DWord -Value ([uint32]($before.editFlags -bor [uint32]$Definition[0].editFlagsSet))
    Set-ItemProperty -LiteralPath $ca -Name InterfaceFlags -Type DWord -Value ([uint32]($before.interfaceFlags -band (-bnot [uint32]$Definition[0].interfaceFlagsClear)))
    Restart-Service CertSvc
    $after=@{editFlags=[uint32](Get-ItemProperty -LiteralPath $policy -Name EditFlags).EditFlags;interfaceFlags=[uint32](Get-ItemProperty -LiteralPath $ca -Name InterfaceFlags).InterfaceFlags}
    if(($after.editFlags -band 0x40000) -ne [uint32]$Definition[0].editFlagsSet -or (($after.interfaceFlags -band 0x200) -eq 0) -ne ([uint32]$Definition[0].interfaceFlagsClear -eq 0x200)){throw 'Actual native CA fault flags were not observed'}
    $after | ConvertTo-Json -Compress
  }else{
    if(-not(Test-Path -LiteralPath $snapshot)){throw 'Native CA safety snapshot absent'}
    $before=Get-Content -LiteralPath $snapshot -Raw | ConvertFrom-Json
    if($before.runId -ne $RunId -or $before.ca -ne 'TTQualificationRoot'){throw 'Refusing foreign CA safety snapshot'}
    Set-ItemProperty -LiteralPath $policy -Name EditFlags -Type DWord -Value ([uint32]$before.editFlags)
    Set-ItemProperty -LiteralPath $ca -Name InterfaceFlags -Type DWord -Value ([uint32]$before.interfaceFlags)
    Restart-Service CertSvc
    if([uint32](Get-ItemProperty -LiteralPath $policy -Name EditFlags).EditFlags -ne [uint32]$before.editFlags -or [uint32](Get-ItemProperty -LiteralPath $ca -Name InterfaceFlags).InterfaceFlags -ne [uint32]$before.interfaceFlags){throw 'Native CA flags restoration was not observed'}
    Remove-Item -LiteralPath $snapshot
    Write-Output 'CERTOPS_CA_SAFETY=restored-original-flags'
  }
}

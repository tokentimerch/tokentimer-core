<#
Native same-key or new-key CA renewal on the disposable qualification forest. Called with the
temporary officer identity to exercise actual pin continuity/rotation; the entire lab is
subsequently destroyed, never a persistent enterprise CA.
#>
param([ValidateSet('new-key','reuse-key')][string]$Mode='new-key')
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test' -or -not $env:CERTOPS_ADCS_OFFICER_PASSWORD){throw 'CA key rotation requires isolated qualification forest officer'}
$credential=[PSCredential]::new('TTQUAL\tt-lab-admin',(ConvertTo-SecureString $env:CERTOPS_ADCS_OFFICER_PASSWORD -AsPlainText -Force))
Invoke-Command -ComputerName 'tt-ca.lab.certops.test' -Credential $credential -ArgumentList $Mode -ScriptBlock {
  param([string]$Mode)
  $ErrorActionPreference='Stop'
  $config='HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
  if((Get-ItemProperty -LiteralPath $config -Name Active).Active -ne 'TTQualificationRoot'){throw 'Refusing another CA configuration'}
  $before=@((Get-ItemProperty -LiteralPath "$config\TTQualificationRoot" -Name CACertHash).CACertHash)
  if($Mode -eq 'reuse-key'){& certutil.exe -f -renewCert ReuseKeys | Out-Null}
  else{& certutil.exe -f -renewCert | Out-Null}
  if($LASTEXITCODE -ne 0){throw 'Native isolated CA key renewal failed'}
  Restart-Service CertSvc
  & certutil.exe -CRL | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Native renewed CA CRL publication failed'}
  $after=@((Get-ItemProperty -LiteralPath "$config\TTQualificationRoot" -Name CACertHash).CACertHash)
  if($after.Count -le $before.Count -or $after[-1] -eq $before[-1]){throw 'No new native CA certificate recorded'}
  if($Mode -eq 'reuse-key'){Write-Output 'CERTOPS_CA_RENEWAL=reused-key-certificate-recorded'}
  else{Write-Output 'CERTOPS_CA_REKEY=new-certificate-recorded'}
}

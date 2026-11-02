<#
Native same-key or new-key CA renewal on the disposable qualification forest. Called with the
temporary officer identity to exercise actual pin continuity/rotation; the entire lab is
subsequently destroyed, never a persistent enterprise CA.
#>
param([ValidateSet('new-key','reuse-key')][string]$Mode='new-key')
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test' -or -not $env:CERTOPS_ADCS_OFFICER_PASSWORD){throw 'CA key rotation requires isolated qualification forest officer'}
$credential=[PSCredential]::new('TTQUAL\tt-lab-admin',(ConvertTo-SecureString $env:CERTOPS_ADCS_OFFICER_PASSWORD -AsPlainText -Force))
$renewal=Invoke-Command -ComputerName 'tt-ca.lab.certops.test' -Credential $credential -ArgumentList $Mode -ScriptBlock {
  param([string]$Mode)
  $ErrorActionPreference='Stop'
  $config='HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
  if((Get-ItemProperty -LiteralPath $config -Name Active).Active -ne 'TTQualificationRoot'){throw 'Refusing another CA configuration'}
  $before=@((Get-ItemProperty -LiteralPath "$config\TTQualificationRoot" -Name CACertHash).CACertHash)
  if($Mode -eq 'reuse-key'){& certutil.exe -f -renewCert ReuseKeys | Out-Null}
  else{& certutil.exe -f -renewCert | Out-Null}
  if($LASTEXITCODE -ne 0){throw 'Native isolated CA key renewal failed'}
  Restart-Service CertSvc
  # Restart-Service returns before the CA RPC endpoint is up (0x800706BA on the first call).
  $published=$false
  for($attempt=0;$attempt -lt 20 -and -not $published;$attempt++){
    & certutil.exe -CRL | Out-Null
    if($LASTEXITCODE -eq 0){$published=$true}else{Start-Sleep -Seconds 3}
  }
  if(-not $published){throw 'Native renewed CA CRL publication failed'}
  $after=@((Get-ItemProperty -LiteralPath "$config\TTQualificationRoot" -Name CACertHash).CACertHash)
  if($after.Count -le $before.Count -or $after[-1] -eq $before[-1]){throw 'No new native CA certificate recorded'}
  $renewed=@(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -ieq [string]$after[-1] })[0]
  if(-not $renewed){$renewed=@(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq $_.Issuer -and $_.Subject -like 'CN=TTQualificationRoot,*' } | Sort-Object NotBefore)[-1]}
  if(-not $renewed){throw 'Renewed native CA certificate is not readable'}
  [pscustomobject]@{marker=$(if($Mode -eq 'reuse-key'){'CERTOPS_CA_RENEWAL=reused-key-certificate-recorded'}else{'CERTOPS_CA_REKEY=new-certificate-recorded'});certificate=[Convert]::ToBase64String($renewed.RawData)}
}
# Enterprise root trust normally reaches domain members only on the next Group Policy /
# autoenrollment pulse (up to minutes later). Native validation of a leaf issued by the
# renewed CA would otherwise race that propagation and fail with an untrusted root. Install the
# public renewed root deterministically, exactly as domain-verify.ps1 does for the first root.
$store=[Security.Cryptography.X509Certificates.X509Store]::new('Root','LocalMachine')
try {
  $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
  $store.Add([Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String([string]$renewal.certificate)))
} finally { $store.Close() }
Write-Output ([string]$renewal.marker)

<#
Install explicitly supplied native Windows language assets on the disposable CA/member. Validates
version-specific asset inputs and leaves reboot/installed-language verification to the provisioner;
no mock locale labels qualify a language slot.
#>
param([ValidateSet('en-US','de-DE','fr-FR')][string]$Language='en-US',
  [string]$PackageUri='', [string]$PackageSha256='')
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Domain -notin @('WORKGROUP','lab.certops.test')){throw 'Language qualification refuses existing enterprise domains'}
if($Language -ne 'en-US'){
  if($PackageSha256 -notmatch '^[a-fA-F0-9]{64}$'){throw 'Matching Windows Server language CAB SHA256 required'}
  $uri=[Uri]$PackageUri
  if($uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Host -notmatch '^[a-z0-9-]+\.blob\.core\.windows\.net$'){throw 'Use an owned HTTPS Azure Blob containing the licensed official Windows Server language CAB'}
  $directory=Join-Path $env:TEMP ('certops-language-'+[Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $directory | Out-Null
  try{
    $cab=Join-Path $directory 'language.cab'
    Invoke-WebRequest -Uri $uri -OutFile $cab
    if((Get-FileHash -LiteralPath $cab -Algorithm SHA256).Hash -ine $PackageSha256){throw 'Language CAB digest mismatch'}
    $installed=Add-WindowsPackage -Online -PackagePath $cab -NoRestart
    if(-not $installed){throw 'Language package installation returned no result'}
  } finally {
    $cleanupPath=[IO.Path]::GetFullPath($directory)
    $cleanupRoot=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\'
    if(-not $cleanupPath.StartsWith($cleanupRoot,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $cleanupPath -Leaf) -notmatch '^certops-language-[a-f0-9]{32}$'){throw 'Refusing language fixture cleanup outside owned temporary directory'}
    Remove-Item -LiteralPath $cleanupPath -Recurse -Force
  }
}
# Run Command uses LocalSystem, the same identity as the agent service.
Set-WinUILanguageOverride -Language $Language
Set-WinSystemLocale -SystemLocale $Language
Set-Culture -CultureInfo $Language
if(Get-Command Copy-UserInternationalSettingsToSystem -ErrorAction SilentlyContinue){
  Copy-UserInternationalSettingsToSystem -WelcomeScreen $true -NewUser $true
}
if($Language -ne 'en-US' -and -not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\MUI\UILanguages\$Language")){throw 'Actual Windows display language resources not installed'}
Write-Output 'CERTOPS_STAGE=language-installed-reboot-required'

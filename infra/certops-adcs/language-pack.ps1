<#
Install explicitly supplied native Windows language assets on the disposable CA/member. Validates
version-specific asset inputs and leaves reboot/installed-language verification to the provisioner;
no mock locale labels qualify a language slot.
#>
param([ValidateSet('en-US','de-DE','fr-FR')][string]$Language='en-US',
  [string]$PackageUri='', [string]$PackageSha256='')
$ErrorActionPreference='Stop'
$phase='membership'
trap {
  # A URL may contain a private SAS. Never export exception text, arguments or
  # the unfiltered PowerShell error identifier: it can contain that same URL.
  $class=$_.Exception.GetType().Name
  if($class -notin @('RuntimeException','WebException','InvalidOperationException','ArgumentException','COMException','IOException','UnauthorizedAccessException','ParameterBindingException','ActionPreferenceStopException','PSInvalidOperationException')){$class='Exception'}
  $code=([string]$_.FullyQualifiedErrorId).Split(',')[0]
  if($code -notin @('WebCmdletWebResponseException','WebCmdletIEDomNotSupportedException','DISMAPI_Error__Failed_To_Add_Package','DISMAPI_Error__Not_Applicable','NamedParameterNotFound','CommandNotFoundException','ParameterArgumentValidationError','PathNotFound','InvokeMethodOnNull','AddWindowsPackageError')){$code='Unclassified'}
  Write-Output ('CERTOPS_LANGUAGE_FAILURE={0}:{1}:{2}:{3}:{4}' -f $phase,$_.InvocationInfo.ScriptLineNumber,$_.Exception.HResult,$class,$code)
  throw 'Native language provisioning failed; inspect bounded language failure marker'
}
if((Get-CimInstance Win32_ComputerSystem).Domain -notin @('WORKGROUP','lab.certops.test')){throw 'Language qualification refuses existing enterprise domains'}
if($Language -ne 'en-US'){
  $phase='asset-input'
  if($PackageSha256 -notmatch '^[a-fA-F0-9]{64}$'){throw 'Matching Windows Server language CAB SHA256 required'}
  $uri=[Uri]$PackageUri
  if($uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Host -notmatch '^[a-z0-9-]+\.blob\.core\.windows\.net$'){throw 'Use an owned HTTPS Azure Blob containing the licensed official Windows Server language CAB'}
  $directory=Join-Path $env:TEMP ('certops-language-'+[Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $directory | Out-Null
  try{
    $cab=Join-Path $directory 'language.cab'
    $phase='download'
    Invoke-WebRequest -Uri $uri -OutFile $cab
    $phase='digest'
    if((Get-FileHash -LiteralPath $cab -Algorithm SHA256).Hash -ine $PackageSha256){throw 'Language CAB digest mismatch'}
    $phase='package-install'
    $installed=Add-WindowsPackage -Online -PackagePath $cab -NoRestart
    if(-not $installed){throw 'Language package installation returned no result'}
  } finally {
    $operationPhase=$phase
    $phase='temporary-cleanup'
    $cleanupPath=[IO.Path]::GetFullPath($directory)
    $cleanupRoot=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\'
    if(-not $cleanupPath.StartsWith($cleanupRoot,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $cleanupPath -Leaf) -notmatch '^certops-language-[a-f0-9]{32}$'){throw 'Refusing language fixture cleanup outside owned temporary directory'}
    Remove-Item -LiteralPath $cleanupPath -Recurse -Force
    $phase=$operationPhase
  }
}
# Run Command uses LocalSystem, the same identity as the agent service.
$phase='ui-language'
Set-WinUILanguageOverride -Language $Language
$phase='system-locale'
Set-WinSystemLocale -SystemLocale $Language
$phase='culture'
Set-Culture -CultureInfo $Language
$phase='system-settings-copy'
if(Get-Command Copy-UserInternationalSettingsToSystem -ErrorAction SilentlyContinue){
  Copy-UserInternationalSettingsToSystem -WelcomeScreen $true -NewUser $true
}
$phase='resource-verification'
if($Language -ne 'en-US' -and -not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\MUI\UILanguages\$Language")){throw 'Actual Windows display language resources not installed'}
Write-Output 'CERTOPS_STAGE=language-installed-reboot-required'

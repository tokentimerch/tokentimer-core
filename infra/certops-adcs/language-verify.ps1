<#
Read actual installed Windows UI culture/build on the disposable CA/member after language setup.
Called by provision-lab.ps1 before tests; fails when native language differs from the selected
qualification environment.
#>
param([ValidateSet('en-US','de-DE','fr-FR')][string]$Language='en-US')
$ErrorActionPreference='Stop'
$phase='membership'
$uiLcid=0
$systemLcid=0
trap {
  # Fixed phases and numeric LCIDs diagnose a real mismatch without exposing
  # arbitrary guest output, account details or supplied download credentials.
  Write-Output ('CERTOPS_LANGUAGE_VERIFY_FAILURE={0}:{1}:{2}:{3}:{4}' -f $phase,$_.InvocationInfo.ScriptLineNumber,$_.Exception.HResult,$uiLcid,$systemLcid)
  throw 'Native language verification failed; inspect bounded language failure marker'
}
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Language verification requires owned domain'}
$phase='ui-language'
$ui=Get-UICulture
$uiLcid=[int]$ui.LCID
if($ui.Name -ne $Language){throw 'Native LocalSystem UI language differs from requested qualification language'}
$phase='system-locale'
$system=Get-WinSystemLocale
$systemLcid=[int]$system.LCID
if($system.Name -ne $Language){throw 'System locale differs from requested qualification language'}
$phase='resource-verification'
if(-not(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\MUI\UILanguages\$Language")){throw 'Language resource package absent'}
Write-Output 'CERTOPS_STAGE=installed-language-verified'

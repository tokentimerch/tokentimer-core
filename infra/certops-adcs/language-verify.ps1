<#
Read actual installed Windows UI culture/build on the disposable CA/member after language setup.
Called by provision-lab.ps1 before tests; fails when native language differs from the selected
qualification environment.
#>
param([ValidateSet('en-US','de-DE','fr-FR')][string]$Language='en-US')
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Language verification requires owned domain'}
if((Get-UICulture).Name -ne $Language){throw 'Native LocalSystem UI language differs from requested qualification language'}
if((Get-WinSystemLocale).Name -ne $Language){throw 'System locale differs from requested qualification language'}
if(-not(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\MUI\UILanguages\$Language")){throw 'Language resource package absent'}
Write-Output 'CERTOPS_STAGE=installed-language-verified'

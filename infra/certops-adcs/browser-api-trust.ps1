<#
Temporarily trust only the exact owned control-plane public certificate for
Chromium under SYSTEM's CurrentUser Root store. A receipt records whether this
helper added it; removal checks exact DER and never removes pre-existing trust.
#>
param([Parameter(Mandatory)][ValidateSet('Add','Remove')][string]$Mode,[Parameter(Mandatory)][string]$Receipt)
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).Domain -ne 'lab.certops.test'){throw 'Trust fixture requires owned domain member'}
$resolvedReceipt=[IO.Path]::GetFullPath($Receipt)
$temporary=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$ownedDirectory=Split-Path -Parent $resolvedReceipt
if((Split-Path -Parent $ownedDirectory).TrimEnd('\') -ine $temporary.TrimEnd('\') -or (Split-Path -Leaf $ownedDirectory) -notmatch '^certops-domain-adcs-[A-Za-z0-9_-]+$' -or [IO.Path]::GetFileName($resolvedReceipt) -ne 'browser-api-trust.json'){throw 'Unexpected owned trust receipt path'}
$pem='C:\ttqualification\api-public.pem'
$public=[Security.Cryptography.X509Certificates.X509Certificate2]::new($pem)
try {
  if($public.Subject -ne 'CN=tt-control.lab.certops.test' -or $public.HasPrivateKey -or $public.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow){throw 'Unexpected public API trust certificate'}
  $thumb=$public.Thumbprint
  $encoded=[Convert]::ToBase64String($public.RawData)
  $store=[Security.Cryptography.X509Certificates.X509Store]::new('Root','CurrentUser')
  $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
  try {
    $existing=@($store.Certificates|Where-Object Thumbprint -eq $thumb)
    if($Mode -eq 'Add') {
      if(Test-Path -LiteralPath $resolvedReceipt){throw 'Owned trust receipt already exists'}
      if($existing.Count -gt 1){throw 'Ambiguous existing public trust certificate'}
      if($existing.Count -eq 1 -and [Convert]::ToBase64String($existing[0].RawData) -ne $encoded){throw 'Existing trust certificate mismatch'}
      # Publish ownership before mutation, so a later failure remains recoverable.
      @{thumbprint=$thumb;publicDer=$encoded;added=($existing.Count -eq 0)} | ConvertTo-Json | Set-Content -LiteralPath $resolvedReceipt
      if($existing.Count -eq 0){$store.Add($public)}
      if(@($store.Certificates|Where-Object Thumbprint -eq $thumb).Count -ne 1){throw 'Public browser trust was not installed'}
    } else {
      $owned=Get-Content -LiteralPath $resolvedReceipt -Raw | ConvertFrom-Json
      if($owned.thumbprint -ne $thumb -or $owned.publicDer -ne $encoded -or $owned.added -isnot [bool]){throw 'Owned trust receipt mismatch'}
      if($owned.added) {
        if($existing.Count -gt 1){throw 'Ambiguous owned trust cleanup'}
        foreach($entry in $existing){if([Convert]::ToBase64String($entry.RawData) -ne $encoded){throw 'Owned trust DER changed'};$store.Remove($entry)}
        if(@($store.Certificates|Where-Object Thumbprint -eq $thumb).Count -ne 0){throw 'Owned public trust remains'}
      }
      Remove-Item -LiteralPath $resolvedReceipt -Force
    }
  } finally {$store.Close()}
} finally {$public.Dispose()}
Write-Output 'Owned browser API trust operation completed'

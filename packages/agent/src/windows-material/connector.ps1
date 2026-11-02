param([Parameter(Mandatory=$true)][string]$InputFile)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# This is an installed, fixed connector. The input contains data only; no
# commands, script fragments, paths to executables or application pool actions.
try {
  $inputData = Get-Content -LiteralPath $InputFile -Raw | ConvertFrom-Json
  if ($inputData.operation -notin @('preflight','import','commit','verify')) { throw 'operation' }
  $b = $inputData.binding
  Add-Type -Path (Join-Path $env:windir 'System32\inetsrv\Microsoft.Web.Administration.dll')
  $manager = New-Object Microsoft.Web.Administration.ServerManager
  try {
    $sites = @($manager.Sites | Where-Object { $_.Name -ceq $b.site -or [string]$_.Id -ceq $b.site })
    if ($sites.Count -ne 1) { throw 'site' }
    $hostname = if ($b.sniHost) { [string]$b.sniHost } else { '' }
    $selector = '{0}:{1}:{2}' -f $b.address,$b.port,$hostname
    $selected = @($sites[0].Bindings | Where-Object { $_.Protocol -eq 'https' -and $_.BindingInformation -ieq $selector })
    if ($selected.Count -ne 1) { throw 'binding' }
    $selected = $selected[0]
    $sni = ([int]$selected.SslFlags -band 1) -eq 1
    # Centralized Certificate Store changes the custody/activation model.
    if ($sni -ne [bool]$b.sniHost -or ([int]$selected.SslFlags -band 2) -ne 0) { throw 'flags' }
    # Reject a shared http.sys selector owned by another site/address, so an
    # exact-site authorization cannot mutate that site's certificate too.
    foreach ($site in $manager.Sites) {
      foreach ($other in $site.Bindings) {
        if ($other.Protocol -ne 'https') { continue }
        if ($site.Id -eq $sites[0].Id -and $other.BindingInformation -ieq $selector) { continue }
        if ($sni) {
          $otherHost = $other.Host
          if ($other.EndPoint.Port -eq $b.port -and $otherHost -ieq $hostname -and ([int]$other.SslFlags -band 1) -eq 1) { throw 'shared selector' }
        } elseif ($other.EndPoint.Port -eq $b.port -and $other.EndPoint.Address.ToString() -eq $selected.EndPoint.Address.ToString() -and ([int]$other.SslFlags -band 1) -eq 0) { throw 'shared selector' }
      }
    }
    if ($inputData.operation -eq 'preflight') { '{"ok":true}'; exit 0 }
    Add-Type -Path (Join-Path $PSScriptRoot 'MaterialImport.cs')
    if ($inputData.operation -eq 'import') {
      $bytes = [Convert]::FromBase64String($inputData.pfx)
      try { [TokenTimer.MaterialImport]::Install($bytes,[string]$inputData.password,[string]$b.store,[string]$inputData.thumbprint,[string[]]$inputData.serviceAccountSids) }
      finally { [Array]::Clear($bytes,0,$bytes.Length) }
    }
    [TokenTimer.MaterialImport]::Verify([string]$b.store,[string]$inputData.thumbprint,[string]$inputData.fingerprint,[string[]]$inputData.serviceAccountSids)
    if ($inputData.operation -eq 'commit') {
      $hash = New-Object byte[] 20
      for ($i=0;$i -lt 20;$i++) { $hash[$i]=[Convert]::ToByte($inputData.thumbprint.Substring($i*2,2),16) }
      $selected.CertificateHash = $hash
      $selected.CertificateStoreName = [string]$b.store
      $manager.CommitChanges()
    } elseif ($inputData.operation -eq 'verify') {
      $current = ($selected.CertificateHash | ForEach-Object { $_.ToString('X2') }) -join ''
      if ($current -cne $inputData.thumbprint -or $selected.CertificateStoreName -ine $b.store) { throw 'identity' }
    }
    '{"ok":true}'
  } finally { $manager.Dispose() }
} catch {
  # Exception messages may include paths or provider diagnostics. Never emit.
  $stage = 'input'
  if ('TokenTimer.MaterialImport' -as [type]) { $stage = [TokenTimer.MaterialImport]::FailureStage }
  $allowed = @('input','store-open','existing-key','pfx-import','key-association','key-custody','key-acl','store-add','verify-cert','verify-key','verify-acl','verify-signature','acl-presence','acl-protection','acl-shape','acl-principal','acl-membership')
  if ($stage -notin $allowed -and $stage -cnotmatch '^acl-access-mask-[0-9A-F]{8}$') { $stage = 'input' }
  $code = $_.Exception.GetBaseException().HResult.ToString('X8')
  [Console]::Error.WriteLine(('material_windows_connector_failed:{0}:{1}' -f $stage,$code))
  exit 1
}

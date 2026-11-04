# Supporting stream/privacy regression: the actual script runs against a
# deliberately failing local COM stand-in. No domain, CA or certificate is used.
$ErrorActionPreference = 'Stop'
$source = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\infra\certops-adcs\owned-issued-request.ps1')).Path
$root = Join-Path ([IO.Path]::GetTempPath()) ('certops-issued-diagnostic-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$wrapper = Join-Path $root 'wrapper.ps1'
try {
  $text = @'
param([string]$Source)
$ErrorActionPreference='Stop'
$env:CERTOPS_ADCS_OFFICER_PASSWORD='synthetic-test-only'
function Get-CimInstance { param([string]$ClassName) @{Domain='lab.certops.test'} }
function New-Object {
  param([string]$ComObject)
  if($ComObject -ne 'CertificateAuthority.View'){throw 'Unexpected fixture COM request'}
  $value=[pscustomobject]@{}
  $value | Add-Member -MemberType ScriptMethod -Name OpenConnection -Value { param($value) throw [Runtime.InteropServices.COMException]::new('private-diagnostic-sentinel',-2147024891) }
  return $value
}
function Invoke-Command {
  param([string]$ComputerName,[PSCredential]$Credential,[object[]]$ArgumentList,[scriptblock]$ScriptBlock)
  & $ScriptBlock @ArgumentList
}
try { & $Source -CommonName 'certops-adcs-0123456789-rsa2048.example.test' -FingerprintSha256 ('a' * 64); exit 2 }
catch { exit 7 }
'@
  [IO.File]::WriteAllText($wrapper,$text,[Text.UTF8Encoding]::new($false))
  $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $output = @(& $powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $wrapper -Source $source 2>&1 | ForEach-Object { [string]$_ })
  if ($LASTEXITCODE -ne 7) { throw 'Expected the owned diagnostic fixture to fail' }
  if ('CERTOPS_ISSUED_FAILURE=connection' -notin $output -or 'CERTOPS_ISSUED_FAILURE=remoting' -notin $output) { throw 'Fixed diagnostic stages were not preserved' }
  if ('CERTOPS_ISSUED_HRESULT=0x80070005' -notin $output) { throw 'Native HRESULT was not preserved' }
  if (($output -join "`n") -match 'private-diagnostic-sentinel|synthetic-test-only') { throw 'Private fixture text escaped the diagnostic boundary' }
  'CA observation diagnostic stream and privacy control passed'
} finally {
  $resolved = [IO.Path]::GetFullPath($root)
  if ([IO.Path]::GetDirectoryName($resolved).TrimEnd('\') -ne [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') -or [IO.Path]::GetFileName($resolved) -notmatch '^certops-issued-diagnostic-[a-f0-9]{32}$') { throw 'Refuse cleanup outside the owned diagnostic root' }
  if (Test-Path -LiteralPath $wrapper) { Remove-Item -LiteralPath $wrapper -Force }
  Remove-Item -LiteralPath $resolved -Force
}
$global:LASTEXITCODE = 0

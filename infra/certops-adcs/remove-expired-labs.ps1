<#
Independent janitor for expired, explicitly tagged qualification resource groups. Inspects
ownership/expiry before deleting only matching lab groups; protects against interrupted workflow
teardown and does not enumerate arbitrary resources for deletion.
#>
param([switch]$WhatIf)
$ErrorActionPreference = 'Stop'
$groups = az group list --query "[?tags.purpose=='certops-adcs-qualification'].{name:name,expiresAt:tags.expiresAt,purpose:tags.purpose}" -o json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Could not enumerate owned qualification groups' }
$failures = [Collections.Generic.List[string]]::new()
foreach ($group in $groups) {
  if ($group.name -notmatch '^tt-certops-[0-9]+-[0-9]+$' -or $group.purpose -ne 'certops-adcs-qualification') { continue }
  $expiry = [DateTimeOffset]::MinValue
  if (-not [DateTimeOffset]::TryParse($group.expiresAt, [ref]$expiry)) { $failures.Add("Owned lab $($group.name) has invalid expiry"); continue }
  if ($expiry -gt [DateTimeOffset]::UtcNow) { continue }
  if ($WhatIf) { Write-Output "Would delete expired owned lab $($group.name)"; continue }
  az group delete --name $group.name --yes --no-wait
  if ($LASTEXITCODE -ne 0) { $failures.Add("Could not delete expired owned lab $($group.name)"); continue }
  Write-Output "Requested deletion of expired owned lab $($group.name)"
}
if ($failures.Count) { throw ($failures -join '; ') }

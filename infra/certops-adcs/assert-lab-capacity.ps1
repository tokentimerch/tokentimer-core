<#
Read-only capacity preflight for the three-machine disposable AD CS lab. Run after
OIDC login and before creating a resource group, so subscription restrictions and
quota failures do not start a paid or partially provisioned lab.
#>
param(
  [Parameter(Mandatory)][ValidatePattern('^[a-z][a-z0-9]{1,49}$')][string]$Location,
  [Parameter(Mandatory)][ValidateSet('Standard_D2s_v5','Standard_D2as_v5')][string]$VmSize
)
$ErrorActionPreference = 'Stop'
$raw = az vm list-skus --location $Location --resource-type virtualMachines --size $VmSize --all -o json
if ($LASTEXITCODE -ne 0) { throw 'Could not inspect subscription VM availability; no lab was created' }
$selectedSkus = @(($raw | ConvertFrom-Json) | Where-Object { $_.name -eq $VmSize })
if ($selectedSkus.Count -ne 1) { throw "VM size $VmSize is unavailable in $Location; choose an approved region and size" }
$sku = $selectedSkus[0]
$blocked = @($sku.restrictions | Where-Object {
  $_.type -eq 'Location' -and (
    (-not $_.restrictionInfo.locations -and -not $_.values) -or
    $Location -in $_.restrictionInfo.locations -or $Location -in $_.values
  )
})
if ($blocked.Count) { throw "Subscription does not allow $VmSize in $Location; choose an approved region and size or request Azure access" }
if (-not $sku.family) { throw 'VM family evidence missing; no lab was created' }
$raw = az vm list-usage --location $Location -o json
if ($LASTEXITCODE -ne 0) { throw 'Could not inspect subscription vCPU quota; no lab was created' }
$usage = $raw | ConvertFrom-Json
foreach ($quota in @('cores', $sku.family)) {
  $rows = @($usage | Where-Object { $_.name.value -eq $quota })
  if ($rows.Count -ne 1 -or $null -eq $rows[0].limit -or $null -eq $rows[0].currentValue -or
      ([long]$rows[0].limit - [long]$rows[0].currentValue) -lt 6) {
    throw "At least six free vCPUs are required for $quota in $Location; no lab was created"
  }
}
Write-Output "AD CS lab capacity preflight passed for $VmSize in $Location"

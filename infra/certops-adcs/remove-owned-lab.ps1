<#
Always-run teardown for the exact current workflow-owned disposable lab group. Requires its
canonical name and ownership tags before deletion and writes bounded cleanup evidence; never deletes
a foreign or unverified resource group.
#>
param([Parameter(Mandatory)][ValidatePattern('^tt-certops-[0-9]+-[0-9]+$')][string]$ResourceGroup)
$ErrorActionPreference = 'Stop'
$report = @{resourceGroup=$ResourceGroup;candidateSha=$env:GITHUB_SHA;cleanup='failed';completedAt=$null}
New-Item -ItemType Directory -Force 'qualification-results' | Out-Null
try {
  if($env:GITHUB_ACTIONS -eq 'true'){& (Join-Path $PSScriptRoot 'login-oidc.ps1')}
  $exists = az group exists --name $ResourceGroup
  if ($LASTEXITCODE -ne 0) { throw 'Could not inspect owned group for teardown' }
  if ($exists -eq 'true') {
    $purpose = az group show --name $ResourceGroup --query tags.purpose -o tsv
    if ($LASTEXITCODE -ne 0 -or $purpose -ne 'certops-adcs-qualification') { throw 'Refusing teardown of unowned resource group' }
    az group delete --name $ResourceGroup --yes --no-wait
    if ($LASTEXITCODE -ne 0) { throw 'Owned lab teardown request failed' }
    $deadline = [DateTimeOffset]::UtcNow.AddMinutes(15)
    do {
      $exists = az group exists --name $ResourceGroup
      if ($LASTEXITCODE -ne 0) { throw 'Could not verify resource-group deletion' }
      if ($exists -eq 'false') { break }
      Start-Sleep -Seconds 15
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    if ($exists -ne 'false') { throw 'Owned lab deletion remains incomplete; independent TTL cleanup is required' }
  }
  $report.cleanup='completed'
  $report.completedAt=[DateTimeOffset]::UtcNow.ToString('o')
} finally { $report | ConvertTo-Json | Set-Content 'qualification-results/enterprise-adcs-cleanup.json' }

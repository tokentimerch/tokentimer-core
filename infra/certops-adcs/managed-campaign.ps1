# The action Run Command API has a 90-minute ceiling. The serial comprehensive
# campaign uses a managed command with an explicit guest deadline instead.
# Provisioning success is never execution evidence: poll the instance view and
# require both Succeeded and exitCode=0 before exposing the existing stage marker.
function Invoke-CertOpsManagedCampaign {
  param([string]$SubscriptionId,[string]$ResourceGroup,[string]$Location,
    [string]$Script,[string[]]$Parameters,[scriptblock]$RefreshAuthentication={})
  if($ResourceGroup -notmatch '^tt-certops-[0-9]+-[0-9]+$'){throw 'Invalid owned campaign resource group'}
  $uri="https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Compute/virtualMachines/windows-agent/runCommands/comprehensive?api-version=2024-07-01"
  $items=@(foreach($parameter in $Parameters){
    $split=$parameter.IndexOf('=')
    if($split -lt 1 -or $parameter.Substring(0,$split) -notmatch '^[A-Za-z][A-Za-z0-9_]*$'){throw 'Invalid managed guest parameter'}
    @{name=$parameter.Substring(0,$split);value=$parameter.Substring($split+1)}
  })
  $body=@{location=$Location;properties=@{source=@{script=$Script};protectedParameters=$items;asyncExecution=$true;timeoutInSeconds=11400}}|ConvertTo-Json -Depth 12 -Compress
  # Submit exactly once; auth/poll errors never replay the campaign.
  $null=Invoke-CertOpsArmOperation -Uri $uri -Method PUT -Body $body -SubscriptionId $SubscriptionId -RefreshAuthentication $RefreshAuthentication -TimeoutSeconds 300
  $deadline=[Diagnostics.Stopwatch]::StartNew()
  while($deadline.Elapsed.TotalSeconds -lt 11700){
    Start-Sleep -Seconds 10
    $response=Invoke-CertOpsArmRequest -Uri ($uri+'&$expand=instanceView') -Method GET -Body '' -SubscriptionId $SubscriptionId -RefreshAuthentication $RefreshAuthentication
    if($response.StatusCode -ne 200){throw 'Managed campaign status unavailable'}
    $result=ConvertFrom-CertOpsArmJson $response.Content
    if($result.properties.provisioningState -in 'Failed','Canceled','Cancelled'){throw 'Managed campaign provisioning failed'}
    $view=$result.properties.instanceView
    if(-not $view -or $view.executionState -in 'Pending','Running','Unknown'){continue}
    if($view.executionState -ne 'Succeeded' -or $null -eq $view.exitCode -or $view.exitCode -ne 0){throw 'Managed campaign execution failed; private output withheld'}
    return [pscustomobject]@{value=@([pscustomobject]@{message=[string]$view.output})}
  }
  throw 'Managed campaign deadline exceeded; action was not resubmitted'
}

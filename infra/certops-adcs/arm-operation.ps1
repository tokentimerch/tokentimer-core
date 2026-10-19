<#
Submit ARM operations once, then poll with a fresh short-lived authentication
context per request. Never replay a guest action after a polling/auth failure.
Responses stay in the caller; scripts, parameters and access tokens are not logs.
#>
function Assert-CertOpsArmUri {
  param([Parameter(Mandatory)][uri]$Uri,[Parameter(Mandatory)][string]$SubscriptionId)
  if($Uri.Scheme -ne 'https' -or $Uri.Host -ne 'management.azure.com' -or $Uri.Port -ne 443 -or $Uri.UserInfo -or $Uri.AbsoluteUri.Length -gt 16384 -or -not $Uri.AbsolutePath.StartsWith("/subscriptions/$SubscriptionId/",[StringComparison]::OrdinalIgnoreCase)){
    throw 'Refusing ARM endpoint outside the isolated subscription'
  }
}
function Invoke-CertOpsArmRequest {
  param([uri]$Uri,[string]$Method,[string]$Body,[string]$SubscriptionId,[scriptblock]$RefreshAuthentication)
  Assert-CertOpsArmUri $Uri $SubscriptionId
  & $RefreshAuthentication | ForEach-Object { Write-Host $_ }
  $token=az account get-access-token --subscription $SubscriptionId --resource https://management.azure.com/ --query accessToken --output tsv --only-show-errors
  if($LASTEXITCODE -ne 0 -or -not $token){throw 'Could not obtain fresh lab ARM access token'}
  try {
    $request=@{Uri=$Uri;Method=$Method;Headers=@{Authorization="Bearer $token"};TimeoutSec=60;MaximumRedirection=0;ErrorAction='Stop';UseBasicParsing=$true}
    if($Body){$request.Body=$Body;$request.ContentType='application/json'}
    try { Invoke-WebRequest @request } catch {
      $httpStatus=if($_.Exception.Response){[int]$_.Exception.Response.StatusCode}else{0}
      if($httpStatus -ge 100 -and $httpStatus -le 599){Write-Host ("CERTOPS_ARM_HTTP_FAILURE={0}:{1}" -f $Method,$httpStatus)}
      throw 'Lab ARM request failed; private response withheld'
    }
  } finally { $token=$null }
}
function ConvertFrom-CertOpsArmJson([string]$Content) {
  if(-not $Content){return $null}
  try { return ($Content|ConvertFrom-Json -ErrorAction Stop) }
  catch { throw 'Invalid ARM response; private content withheld' }
}
function Invoke-CertOpsArmOperation {
  param(
    [Parameter(Mandatory)][uri]$Uri,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$SubscriptionId,
    [ValidateSet('POST','PUT')][string]$Method='POST',[string]$Body,
    [scriptblock]$RefreshAuthentication={},
    [ValidateRange(60,7200)][int]$TimeoutSeconds=3600,
    [ValidateRange(1,30)][int]$PollSeconds=10
  )
  $started=[DateTimeOffset]::UtcNow
  $deadline=$started.AddSeconds($TimeoutSeconds)
  $lastProgress=0
  $response=Invoke-CertOpsArmRequest $Uri $Method $Body $SubscriptionId $RefreshAuthentication
  if($response.StatusCode -notin 200,201,202,204){throw 'Unexpected lab ARM submission status'}
  if($response.StatusCode -in 200,204){
    if(-not $response.Content){return $null}
    return (ConvertFrom-CertOpsArmJson $response.Content)
  }
  $location=[string](@($response.Headers['Location'])[0])
  $poll=[string](@($response.Headers['Azure-AsyncOperation'])[0])
  if(-not $poll){$poll=$location}
  if(-not $poll){throw 'ARM asynchronous operation has no polling receipt'}
  Assert-CertOpsArmUri ([uri]$poll) $SubscriptionId
  if($location){Assert-CertOpsArmUri ([uri]$location) $SubscriptionId}
  while([DateTimeOffset]::UtcNow -lt $deadline){
    $delay=$PollSeconds
    $retry=0
    if([int]::TryParse([string](@($response.Headers['Retry-After'])[0]),[ref]$retry) -and $retry -gt 0){$delay=[Math]::Min(30,$retry)}
    Start-Sleep -Seconds $delay
    # A new CLI/token exchange is used on every GET. A long-running CLI poller
    # would retain the original five-minute GitHub federation assertion.
    $response=Invoke-CertOpsArmRequest ([uri]$poll) 'GET' '' $SubscriptionId $RefreshAuthentication
    if($response.StatusCode -notin 200,202,204){throw 'Unexpected lab ARM polling status'}
    $result=ConvertFrom-CertOpsArmJson $response.Content
    $elapsed=[int]([DateTimeOffset]::UtcNow-$started).TotalSeconds
    if($elapsed-$lastProgress -ge 60){Write-Host ('CERTOPS_ARM_PENDING_SECONDS='+$elapsed);$lastProgress=$elapsed}
    $status=if($result){[string]$result.status}else{''}
    if($status -in 'Failed','Canceled','Cancelled'){throw 'Lab ARM operation failed; private response withheld'}
    if($status -in 'InProgress','Running','Accepted','Creating','Updating' -or $response.StatusCode -eq 202){continue}
    if($status -and $status -ne 'Succeeded'){throw 'Unknown lab ARM operation state'}
    if($status -eq 'Succeeded' -and $location -and $poll -ne $location){$poll=$location;continue}
    return $result
  }
  throw 'Lab ARM operation timed out; action was not resubmitted'
}
function Invoke-CertOpsVmRunCommand {
  param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][ValidatePattern('^tt-certops-[0-9]+-[0-9]+$')][string]$ResourceGroup,
    [Parameter(Mandatory)][ValidateSet('domain-ca','windows-agent','control-plane','offline-root','destination-ca')][string]$Machine,
    [Parameter(Mandatory)][string]$Script,[string[]]$Parameters=@(),
    [scriptblock]$RefreshAuthentication={},[int]$TimeoutSeconds=3600,[int]$PollSeconds=10
  )
  $commandId=if($Machine -eq 'control-plane'){'RunShellScript'}else{'RunPowerShellScript'}
  $items=@(foreach($parameter in $Parameters){
    $split=$parameter.IndexOf('=')
    if($split -lt 1 -or $parameter.Substring(0,$split) -notmatch '^[A-Za-z][A-Za-z0-9_]*$'){throw 'Invalid named guest parameter'}
    @{name=$parameter.Substring(0,$split);value=$parameter.Substring($split+1)}
  })
  $body=@{commandId=$commandId;script=@($Script);parameters=$items}|ConvertTo-Json -Depth 12 -Compress
  $uri="https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Compute/virtualMachines/$Machine/runCommand?api-version=2024-07-01"
  $result=Invoke-CertOpsArmOperation -Uri $uri -SubscriptionId $SubscriptionId -Body $body -RefreshAuthentication $RefreshAuthentication -TimeoutSeconds $TimeoutSeconds -PollSeconds $PollSeconds
  if(-not $result -or -not $result.PSObject.Properties['value']){throw 'Guest operation completed without a result receipt'}
  return $result
}
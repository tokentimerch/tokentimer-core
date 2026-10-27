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
  $token=$null
  try {
    $request=@{Uri=$Uri;Method=$Method;Headers=@{};TimeoutSec=60;MaximumRedirection=0;ErrorAction='Stop';UseBasicParsing=$true}
    if($Body){$request.Body=$Body;$request.ContentType='application/json'}
    # Read-only polls are idempotent: a transient network timeout or 5xx/429 must not
    # abandon a guest action that is still running. Submissions (POST/PUT) are never replayed.
    $maxAttempts=if($Method -eq 'GET'){8}else{1}
    for($attempt=1;$attempt -le $maxAttempts;$attempt++){
      # A network retry can outlive the token acquired for the first attempt.
      # Refresh at every read boundary, including a rejected authentication.
      & $RefreshAuthentication | ForEach-Object { Write-Host $_ }
      $token=az account get-access-token --subscription $SubscriptionId --resource https://management.azure.com/ --query accessToken --output tsv --only-show-errors
      if($LASTEXITCODE -ne 0 -or -not $token){throw 'Could not obtain fresh lab ARM access token'}
      $request.Headers.Authorization="Bearer $token"
      try { return (Invoke-WebRequest @request) } catch {
        $httpStatus=if($_.Exception.Response){[int]$_.Exception.Response.StatusCode}else{0}
        $transient=($httpStatus -eq 0 -or $httpStatus -eq 401 -or $httpStatus -eq 408 -or $httpStatus -eq 429 -or $httpStatus -ge 500)
        if($attempt -lt $maxAttempts -and $transient){
          Write-Host ("CERTOPS_ARM_POLL_RETRY={0}:{1}" -f $attempt,$httpStatus)
          Start-Sleep -Seconds ([Math]::Min(30,5*$attempt))
          continue
        }
        if($httpStatus -ge 100 -and $httpStatus -le 599){Write-Host ("CERTOPS_ARM_HTTP_FAILURE={0}:{1}" -f $Method,$httpStatus)}
        $requestFailure=[InvalidOperationException]::new('Lab ARM request failed; private response withheld')
        $requestFailure.Data['CertOpsArmHttpStatus']=$httpStatus
        throw $requestFailure
      }
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
function ConvertTo-CertOpsWindowsGuestScript {
  param([Parameter(Mandatory)][string]$Script,[object[]]$Parameters)
  # Action Run Command expands named Windows arguments through a command line.
  # Keep their exact values in the script body instead of escaping shell syntax.
  if($Parameters.Count -gt 128){throw 'Guest parameter envelope exceeds bounds'}
  $names=@{}
  foreach($parameter in $Parameters){
    if($parameter.name -isnot [string] -or $parameter.name.Length -gt 128 -or $parameter.name -notmatch '^[A-Za-z][A-Za-z0-9_]*$' -or $parameter.value -isnot [string] -or $names.ContainsKey($parameter.name)){throw 'Invalid Windows guest parameter envelope'}
    $names[$parameter.name]=$true
  }
  $utf8=[Text.UTF8Encoding]::new($false,$true)
  # ConvertFrom-Json can coerce date-shaped strings on PowerShell 7. Keep each
  # value opaque until strict UTF-8 decoding immediately before parameter binding.
  try {$encodedParameters=@(foreach($parameter in $Parameters){@{name=$parameter.name;valueBase64=[Convert]::ToBase64String($utf8.GetBytes($parameter.value))}})}
  catch {throw 'Invalid Windows guest parameter encoding; private content withheld'}
  $parameterJson=@{parameters=@($Parameters)}|ConvertTo-Json -Depth 5 -Compress
  if($utf8.GetByteCount($parameterJson) -gt 262144 -or $utf8.GetByteCount($Script) -gt 1048576){throw 'Guest parameter envelope exceeds bounds'}
  $json=@{schemaVersion=1;script=$Script;parameters=$encodedParameters}|ConvertTo-Json -Depth 5 -Compress
  $bytes=$utf8.GetBytes($json)
  if($bytes.Length -gt 2097152){throw 'Guest parameter envelope exceeds bounds'}
  $encoded=[Convert]::ToBase64String($bytes)
  $sha=[Security.Cryptography.SHA256]::Create()
  try {$digest=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
  $wrapper=@'
$certopsGuestEnvelope='__CERTOPS_ENVELOPE__'
$certopsGuestDigest='__CERTOPS_DIGEST__'
$certopsGuestArguments=@{}
try {
  if($certopsGuestEnvelope.Length -gt 2796204){throw 'Envelope bounds'}
  $certopsGuestBytes=[Convert]::FromBase64String($certopsGuestEnvelope)
  if($certopsGuestBytes.Length -gt 2097152){throw 'Envelope bounds'}
  $certopsGuestSha=[Security.Cryptography.SHA256]::Create()
  try {$certopsGuestActual=[BitConverter]::ToString($certopsGuestSha.ComputeHash($certopsGuestBytes)).Replace('-','').ToLowerInvariant()}finally{$certopsGuestSha.Dispose()}
  if($certopsGuestActual -cne $certopsGuestDigest){throw 'Envelope digest'}
  $certopsGuestPayload=[Text.UTF8Encoding]::new($false,$true).GetString($certopsGuestBytes)|ConvertFrom-Json -ErrorAction Stop
  if($certopsGuestPayload -isnot [pscustomobject] -or $certopsGuestPayload.schemaVersion -ne 1 -or $certopsGuestPayload.script -isnot [string] -or [Text.Encoding]::UTF8.GetByteCount($certopsGuestPayload.script) -gt 1048576 -or $certopsGuestPayload.parameters -isnot [array] -or $certopsGuestPayload.parameters.Count -gt 128){throw 'Envelope schema'}
  $certopsGuestDecodedParameters=@()
  foreach($certopsGuestParameter in $certopsGuestPayload.parameters){
    if($certopsGuestParameter.name -isnot [string] -or $certopsGuestParameter.name.Length -gt 128 -or $certopsGuestParameter.name -notmatch '^[A-Za-z][A-Za-z0-9_]*$' -or $certopsGuestParameter.valueBase64 -isnot [string] -or $certopsGuestParameter.valueBase64.Length -gt 349528 -or $certopsGuestArguments.ContainsKey($certopsGuestParameter.name)){throw 'Envelope parameter'}
    $certopsGuestValueBytes=[Convert]::FromBase64String($certopsGuestParameter.valueBase64)
    if($certopsGuestValueBytes.Length -gt 262144 -or [Convert]::ToBase64String($certopsGuestValueBytes) -cne $certopsGuestParameter.valueBase64){throw 'Envelope parameter encoding'}
    $certopsGuestValue=[Text.UTF8Encoding]::new($false,$true).GetString($certopsGuestValueBytes)
    $certopsGuestArguments[$certopsGuestParameter.name]=$certopsGuestValue
    $certopsGuestDecodedParameters+=@{name=$certopsGuestParameter.name;value=$certopsGuestValue}
  }
  $certopsGuestParameterJson=@{parameters=$certopsGuestDecodedParameters}|ConvertTo-Json -Depth 5 -Compress
  if([Text.Encoding]::UTF8.GetByteCount($certopsGuestParameterJson) -gt 262144){throw 'Envelope bounds'}
} catch {throw 'Invalid encoded guest parameters; private content withheld'}
$certopsGuestDirectory=Join-Path ([IO.Path]::GetTempPath()) ('tt-certops-guest-'+[guid]::NewGuid().ToString('N'))
$certopsGuestScript=Join-Path $certopsGuestDirectory 'original.ps1'
$certopsGuestCreated=$false
try {
  try {
    if(Test-Path -LiteralPath $certopsGuestDirectory){throw 'Guest directory collision'}
    $null=[IO.Directory]::CreateDirectory($certopsGuestDirectory)
    $certopsGuestCreated=$true
    if(([IO.File]::GetAttributes($certopsGuestDirectory) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Guest directory changed'}
    if([Environment]::OSVersion.Platform -eq 'Win32NT'){
      $certopsGuestOwner=[Security.Principal.WindowsIdentity]::GetCurrent().User
      $certopsGuestAcl=[Security.AccessControl.DirectorySecurity]::new()
      $certopsGuestAcl.SetAccessRuleProtection($true,$false)
      $certopsGuestAcl.SetOwner($certopsGuestOwner)
      foreach($certopsGuestSid in @($certopsGuestOwner.Value,'S-1-5-18','S-1-5-32-544')|Select-Object -Unique){
        $certopsGuestRule=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($certopsGuestSid),'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $null=$certopsGuestAcl.AddAccessRule($certopsGuestRule)
      }
      Set-Acl -LiteralPath $certopsGuestDirectory -AclObject $certopsGuestAcl -ErrorAction Stop
    }else{
      & chmod 700 -- $certopsGuestDirectory
      if($LASTEXITCODE -ne 0){throw 'Guest directory permissions'}
    }
    # A real UTF-8 BOM file preserves Windows PowerShell source decoding and
    # $PSCommandPath self-reentry, including new child-process switches.
    [IO.File]::WriteAllText($certopsGuestScript,$certopsGuestPayload.script,[Text.UTF8Encoding]::new($true))
  }catch{throw 'Could not prepare private guest script; private content withheld'}
  $global:LASTEXITCODE=0
  & $certopsGuestScript @certopsGuestArguments
  $certopsGuestSucceeded=$?
  $certopsGuestExitCode=$LASTEXITCODE
}finally{
  if($certopsGuestCreated){
    try {
      if(([IO.File]::GetAttributes($certopsGuestDirectory) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Guest directory changed'}
      [IO.File]::Delete($certopsGuestScript)
      [IO.Directory]::Delete($certopsGuestDirectory,$false)
    }catch{throw 'Private guest script cleanup failed; private content withheld'}
  }
}
# Propagate an explicit failed script exit, without using a stale native exit
# code after a script that succeeded or returned normally.
if(-not $certopsGuestSucceeded -and $certopsGuestExitCode -ne 0){exit $certopsGuestExitCode}
'@
  return $wrapper.Replace('__CERTOPS_ENVELOPE__',$encoded).Replace('__CERTOPS_DIGEST__',$digest)
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
  if($commandId -eq 'RunPowerShellScript' -and $items.Count){
    $Script=ConvertTo-CertOpsWindowsGuestScript -Script $Script -Parameters $items
    $items=@()
  }
  $body=@{commandId=$commandId;script=@($Script);parameters=$items}|ConvertTo-Json -Depth 12 -Compress
  $uri="https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Compute/virtualMachines/$Machine/runCommand?api-version=2024-07-01"
  $result=Invoke-CertOpsArmOperation -Uri $uri -SubscriptionId $SubscriptionId -Body $body -RefreshAuthentication $RefreshAuthentication -TimeoutSeconds $TimeoutSeconds -PollSeconds $PollSeconds
  if(-not $result -or -not $result.PSObject.Properties['value']){throw 'Guest operation completed without a result receipt'}
  return $result
}

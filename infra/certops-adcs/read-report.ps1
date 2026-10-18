<#
Retrieve only the selected sanitized guest JSON report through bounded checksum-verified chunks.
Called by the provisioner after native execution; it neither exports private state nor treats
absent/incomplete reports as a passing qualification.
#>
param([Parameter(Mandatory)][ValidatePattern('^tt-certops-[0-9]+-[0-9]+$')][string]$ResourceGroup,[ValidateSet('package-acceptance','uncertain-abandon','browser-enrollment','issuer-switch','qualification','hierarchy','response-loss-experimental','journal-phase-experimental','pending-elapsed')][string]$ReportKind='qualification')
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'arm-operation.ps1')
if($env:GITHUB_ACTIONS -eq 'true'){& (Join-Path $PSScriptRoot 'login-oidc.ps1')}
$bytes=[Collections.Generic.List[byte]]::new()
$length=$null
$expectedHash=$null
$offset=0
$guestFile=if($ReportKind -eq 'package-acceptance'){'adcs-package-acceptance.json'}elseif($ReportKind -eq 'uncertain-abandon'){'uncertain-abandon-native.json'}elseif($ReportKind -eq 'browser-enrollment'){'browser-enrollment-native.json'}elseif($ReportKind -eq 'issuer-switch'){'native-issuer-reassignment.json'}elseif($ReportKind -eq 'pending-elapsed'){'pending-elapsed.json'}elseif($ReportKind -in 'qualification','hierarchy'){'enterprise-adcs-report.json'}elseif($ReportKind -eq 'response-loss-experimental'){'response-loss-experimental.json'}else{'journal-phase-experimental.json'}
$outputFile=if($ReportKind -eq 'package-acceptance'){'enterprise-adcs-package-acceptance.json'}elseif($ReportKind -eq 'uncertain-abandon'){'enterprise-adcs-uncertain-abandon.json'}elseif($ReportKind -eq 'browser-enrollment'){'enterprise-adcs-browser-enrollment.json'}elseif($ReportKind -eq 'issuer-switch'){'native-issuer-reassignment.json'}elseif($ReportKind -eq 'pending-elapsed'){'enterprise-adcs-elapsed-pending-real.json'}elseif($ReportKind -eq 'qualification'){'enterprise-adcs-real.json'}elseif($ReportKind -eq 'hierarchy'){'enterprise-adcs-hierarchy-real.json'}elseif($ReportKind -eq 'response-loss-experimental'){'enterprise-adcs-response-loss-experimental.json'}else{'enterprise-adcs-journal-phase-experimental.json'}
do {
  $script="`$b=[Text.Encoding]::UTF8.GetBytes([IO.File]::ReadAllText('C:\ttqualification\$guestFile')); `$hash=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash(`$b)).Replace('-','').ToLowerInvariant(); Write-Output ('CERTOPS_REPORT_SHA256='+`$hash); Write-Output ('CERTOPS_REPORT_LENGTH='+`$b.Length); if (`$b.Length -gt $offset) { Write-Output ('CERTOPS_REPORT_CHUNK='+[Convert]::ToBase64String(`$b,$offset,[Math]::Min(2048,`$b.Length-$offset))) }"
  $response=Invoke-CertOpsVmRunCommand -SubscriptionId $env:AZURE_SUBSCRIPTION_ID -ResourceGroup $ResourceGroup -Machine windows-agent -Script $script -RefreshAuthentication {if($env:GITHUB_ACTIONS -eq 'true'){& (Join-Path $PSScriptRoot 'login-oidc.ps1')}}
  if($LASTEXITCODE -ne 0){throw 'Could not retrieve sanitized guest execution evidence'}
  $message=($response.value|ForEach-Object message)-join "`n"
  $match=[regex]::Match($message,'CERTOPS_REPORT_LENGTH=([0-9]+)')
  if(-not $match.Success){throw 'Guest report length receipt absent'}
  $current=[int]$match.Groups[1].Value
  if($current -lt 1 -or $current -gt 1048576){throw 'Guest report exceeds bounded evidence size'}
  if($null -eq $length){$length=$current}elseif($length -ne $current){throw 'Guest report changed during retrieval'}
  $hashMatch=[regex]::Match($message,'CERTOPS_REPORT_SHA256=([a-f0-9]{64})')
  if(-not $hashMatch.Success){throw 'Guest report hash receipt absent'}
  $hash=$hashMatch.Groups[1].Value
  if($null -eq $expectedHash){$expectedHash=$hash}elseif($expectedHash -ne $hash){throw 'Guest report bytes changed during retrieval'}
  $chunk=[regex]::Match($message,'CERTOPS_REPORT_CHUNK=([A-Za-z0-9+/=]+)')
  if(-not $chunk.Success){throw 'Guest report chunk receipt absent'}
  $part=[Convert]::FromBase64String($chunk.Groups[1].Value)
  if($part.Length -ne [Math]::Min(2048,$length-$offset)){throw 'Guest report chunk length mismatch'}
  $bytes.AddRange($part)
  $offset += $part.Length
}while($offset -lt $length)
$report=[Text.Encoding]::UTF8.GetString($bytes.ToArray())
if([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes.ToArray())).Replace('-','').ToLowerInvariant() -ne $expectedHash){throw 'Reconstructed guest evidence checksum mismatch'}
$null=$report|ConvertFrom-Json
New-Item -ItemType Directory -Force 'qualification-results'|Out-Null
[IO.File]::WriteAllText((Join-Path (Get-Location) "qualification-results/$outputFile"),$report)
@{reportSha256=$expectedHash;bytes=$length;candidateSha=$env:GITHUB_SHA;resourceGroup=$ResourceGroup} | ConvertTo-Json | Set-Content "qualification-results/enterprise-adcs-transfer-$ReportKind.json"
Write-Output 'Retrieved bounded sanitized enterprise AD CS scenario report'

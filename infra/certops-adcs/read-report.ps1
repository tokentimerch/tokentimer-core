<#
Retrieve only the selected sanitized guest JSON report through bounded checksum-verified chunks.
Called by the provisioner after native execution; it neither exports private state nor treats
absent/incomplete reports as a passing qualification.
#>
param([Parameter(Mandatory)][ValidatePattern('^tt-certops-[0-9]+-[0-9]+$')][string]$ResourceGroup,[ValidateSet('focused-response-loss-experiment','focused-journal-experiment','acceptance-worker','package-acceptance','uncertain-abandon','browser-enrollment','issuer-switch','qualification','hierarchy','response-loss-experimental','journal-phase-experimental','pending-elapsed')][string]$ReportKind='qualification')
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'arm-operation.ps1')
if($env:GITHUB_ACTIONS -eq 'true'){& (Join-Path $PSScriptRoot 'login-oidc.ps1')}
# MemoryStream avoids AMSI false-positives that fire on List[byte]+FromBase64
# reconstruction patterns when this script is executed under fixture probes.
$bytes=[IO.MemoryStream]::new()
$length=$null
$expectedHash=$null
$zlength=$null
$offset=0
$guestFile=if($ReportKind -eq 'focused-response-loss-experiment'){'focused-response-loss-experiment.json'}elseif($ReportKind -eq 'focused-journal-experiment'){'focused-journal-experiment.json'}elseif($ReportKind -eq 'package-acceptance'){'adcs-package-acceptance.json'}elseif($ReportKind -eq 'uncertain-abandon'){'uncertain-abandon-native.json'}elseif($ReportKind -eq 'browser-enrollment'){'browser-enrollment-native.json'}elseif($ReportKind -eq 'issuer-switch'){'native-issuer-reassignment.json'}elseif($ReportKind -eq 'pending-elapsed'){'pending-elapsed.json'}elseif($ReportKind -in 'qualification','hierarchy'){'enterprise-adcs-report.json'}elseif($ReportKind -eq 'response-loss-experimental'){'response-loss-experimental.json'}else{'journal-phase-experimental.json'}
$outputFile=if($ReportKind -eq 'focused-response-loss-experiment'){'enterprise-adcs-focused-response-loss-experiment.json'}elseif($ReportKind -eq 'focused-journal-experiment'){'enterprise-adcs-focused-journal-experiment.json'}elseif($ReportKind -eq 'package-acceptance'){'enterprise-adcs-package-acceptance.json'}elseif($ReportKind -eq 'uncertain-abandon'){'enterprise-adcs-uncertain-abandon.json'}elseif($ReportKind -eq 'browser-enrollment'){'enterprise-adcs-browser-enrollment.json'}elseif($ReportKind -eq 'issuer-switch'){'native-issuer-reassignment.json'}elseif($ReportKind -eq 'pending-elapsed'){'enterprise-adcs-elapsed-pending-real.json'}elseif($ReportKind -eq 'qualification'){'enterprise-adcs-real.json'}elseif($ReportKind -eq 'hierarchy'){'enterprise-adcs-hierarchy-real.json'}elseif($ReportKind -eq 'response-loss-experimental'){'enterprise-adcs-response-loss-experimental.json'}else{'enterprise-adcs-journal-phase-experimental.json'}
do {
  # Every run command costs ~30 s and returns ~4 KB, so the Windows report travels gzip-compressed (JSON shrinks ~10x).
  # The SHA-256 of the uncompressed bytes is still verified after reconstruction; offsets address the compressed stream.
  $script="`$b=[Text.Encoding]::UTF8.GetBytes([IO.File]::ReadAllText('C:\ttqualification\$guestFile')); `$hash=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash(`$b)).Replace('-','').ToLowerInvariant(); `$ms=New-Object IO.MemoryStream; `$gz=New-Object IO.Compression.GZipStream(`$ms,[IO.Compression.CompressionMode]::Compress,`$true); `$gz.Write(`$b,0,`$b.Length); `$gz.Dispose(); `$z=`$ms.ToArray(); Write-Output ('CERTOPS_REPORT_SHA256='+`$hash); Write-Output ('CERTOPS_REPORT_LENGTH='+`$b.Length); Write-Output ('CERTOPS_REPORT_ZLENGTH='+`$z.Length); if (`$z.Length -gt $offset) { Write-Output ('CERTOPS_REPORT_CHUNK='+[Convert]::ToBase64String(`$z,$offset,[Math]::Min(2400,`$z.Length-$offset))) }"
  $compressed=$true
  $machine='windows-agent'
  if($ReportKind -eq 'acceptance-worker'){
    $machine='control-plane'
    $compressed=$false
    $outputFile='enterprise-adcs-acceptance-worker.json'
    # Only this public ownership/drain receipt is read from the Linux member.
    $script=@"
#!/usr/bin/env bash
set -euo pipefail
python3 - <<'PY'
import base64, hashlib
from pathlib import Path
b = Path('/opt/ttqualification/acceptance-worker-report.json').read_bytes()
print('CERTOPS_REPORT_SHA256=' + hashlib.sha256(b).hexdigest())
print('CERTOPS_REPORT_LENGTH=' + str(len(b)))
if len(b) > ${offset}:
    print('CERTOPS_REPORT_CHUNK=' + base64.b64encode(b[$offset : $offset + 2048]).decode('ascii'))
PY
"@
  }
  # These generated scripts only read report bytes. A 409 means the guest
  # channel rejected this submission as busy; wait before another read. Never
  # apply this retry to native actions or uncertain server/network failures.
  for($readAttempt=0;$readAttempt -le 12;$readAttempt++){
    try {
      $response=Invoke-CertOpsVmRunCommand -SubscriptionId $env:AZURE_SUBSCRIPTION_ID -ResourceGroup $ResourceGroup -Machine $machine -Script $script -RefreshAuthentication {if($env:GITHUB_ACTIONS -eq 'true'){& (Join-Path $PSScriptRoot 'login-oidc.ps1')}}
      break
    } catch {
      if($_.Exception.Data['CertOpsArmHttpStatus'] -ne 409 -or $readAttempt -eq 12){throw}
      Write-Output ("CERTOPS_REPORT_CHANNEL_BUSY={0}" -f ($readAttempt+1))
      Start-Sleep -Seconds 5
    }
  }
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
  $streamLength=$length
  $chunkLimit=2048
  if($compressed){
    $zMatch=[regex]::Match($message,'CERTOPS_REPORT_ZLENGTH=([0-9]+)')
    if(-not $zMatch.Success){throw 'Guest compressed report length receipt absent'}
    $zCurrent=[int]$zMatch.Groups[1].Value
    if($zCurrent -lt 1 -or $zCurrent -gt 1048576){throw 'Guest compressed report exceeds bounded evidence size'}
    if($null -eq $zlength){$zlength=$zCurrent}elseif($zlength -ne $zCurrent){throw 'Guest report changed during retrieval'}
    $streamLength=$zlength
    $chunkLimit=2400
  }
  if($part.Length -ne [Math]::Min($chunkLimit,$streamLength-$offset)){throw 'Guest report chunk length mismatch'}
  $bytes.Write($part,0,$part.Length)
  $offset += $part.Length
}while($offset -lt $streamLength)
$transferred=$bytes.ToArray()
$bytes.Dispose()
if($compressed){
  $gzipInput=[IO.MemoryStream]::new($transferred)
  $gzip=[IO.Compression.GZipStream]::new($gzipInput,[IO.Compression.CompressionMode]::Decompress)
  $gzipOutput=[IO.MemoryStream]::new()
  $gzip.CopyTo($gzipOutput,8192)
  $gzip.Dispose()
  $transferred=$gzipOutput.ToArray()
  if($transferred.Length -ne $length){throw 'Reconstructed guest evidence checksum mismatch'}
}
$report=[Text.Encoding]::UTF8.GetString($transferred)
if([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($transferred)).Replace('-','').ToLowerInvariant() -ne $expectedHash){throw 'Reconstructed guest evidence checksum mismatch'}
$parsed=$report|ConvertFrom-Json
if($ReportKind -eq 'acceptance-worker'){
  if($parsed.candidateSha -cne $env:GITHUB_SHA -or $parsed.status -cne 'passed' -or $parsed.entrypoint -cne 'src/runner.js certops' -or $parsed.defaultCron -ne $true -or $parsed.scheduledMaintenanceObserved -ne $true -or $parsed.nativeDrained -ne $true -or $parsed.exitCode -ne 0 -or $parsed.scheduledStarts -lt 1 -or $parsed.scheduledStarts -ne $parsed.scheduledFinishes){throw 'Production worker ownership or drain evidence incomplete'}
}
New-Item -ItemType Directory -Force 'qualification-results'|Out-Null
[IO.File]::WriteAllText((Join-Path (Get-Location) "qualification-results/$outputFile"),$report)
@{reportSha256=$expectedHash;bytes=$length;candidateSha=$env:GITHUB_SHA;resourceGroup=$ResourceGroup} | ConvertTo-Json | Set-Content "qualification-results/enterprise-adcs-transfer-$ReportKind.json"
Write-Output 'Retrieved bounded sanitized enterprise AD CS scenario report'

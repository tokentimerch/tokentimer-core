"use strict";
// Exercise the real PowerShell transport with bounded HTTP/auth doubles. Each
// poll must obtain a fresh credential and never resubmit a guest operation.
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path"),{spawnSync}=require("node:child_process");
function run(t,mode){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),"certops-arm-"));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const file=path.join(dir,"probe.ps1");
 fs.writeFileSync(file,String.raw`
$ErrorActionPreference='Stop'
. $env:CERTOPS_ARM_HELPER
$global:certopsEpoch=0
$global:certopsRequests=[Collections.Generic.List[string]]::new()
$subscription='11111111-1111-4111-8111-111111111111'
$base="https://management.azure.com/subscriptions/$subscription/providers/Microsoft.Compute/locations/swedencentral/operations"
function az {
 if(($args -join ' ') -notmatch '^account get-access-token '){throw 'Unexpected Azure command'}
 $global:LASTEXITCODE=0
 "fixture-token-$global:certopsEpoch"
}
function Start-Sleep { param($Seconds) }
function Invoke-WebRequest {
 param($Uri,$Method,$Headers,$Body,$TimeoutSec,$MaximumRedirection,$ErrorAction,[switch]$UseBasicParsing)
 if($Headers.Authorization -ne "Bearer fixture-token-$global:certopsEpoch"){throw 'Credential mismatch'}
 if($global:certopsEpoch -ne $global:certopsRequests.Count+1){throw 'Expired federation assertion was reused'}
 $global:certopsRequests.Add($Method)
 if($Method -eq 'POST'){
   $bodyObject=$Body|ConvertFrom-Json
   if($bodyObject.parameters[0].value -ne 'fixture-private-value'){throw 'Guest parameter changed'}
   $poll=if($env:CERTOPS_ARM_MODE -eq 'foreign'){'https://attacker.invalid/steal'}else{"$base/progress?api-version=2024-07-01"}
   return [pscustomobject]@{StatusCode=202;Headers=@{'Azure-AsyncOperation'=$poll;Location="$base/result?api-version=2024-07-01"};Content=''}
 }
 if($env:CERTOPS_ARM_MODE -eq 'malformed'){return [pscustomobject]@{StatusCode=200;Headers=@{};Content='{fixture-private-value'}}
 if($env:CERTOPS_ARM_MODE -eq 'failed'){
   return [pscustomobject]@{StatusCode=200;Headers=@{};Content='{"status":"Failed","error":{"message":"fixture-private-value"}}'}
 }
 if($global:certopsRequests.Count -eq 2){return [pscustomobject]@{StatusCode=200;Headers=@{};Content='{"status":"InProgress"}'}}
 if($global:certopsRequests.Count -eq 3){return [pscustomobject]@{StatusCode=200;Headers=@{};Content='{"status":"Succeeded"}'}}
 [pscustomobject]@{StatusCode=200;Headers=@{};Content='{"value":[{"message":"CERTOPS_STAGE=probe-passed"}]}'}
}
$failed=$false
try {
 $result=Invoke-CertOpsVmRunCommand -SubscriptionId $subscription -ResourceGroup tt-certops-123-1 -Machine domain-ca -Script 'Write-Output fixture' -Parameters @('Secret=fixture-private-value','journal_phase=none') -RefreshAuthentication {$global:certopsEpoch++}
}catch{
 $failed=$true
 if($_.Exception.Message.Contains('fixture-private-value')){throw 'Private error escaped'}
}
if($env:CERTOPS_ARM_MODE -eq 'success'){
 if($failed -or $result.value[0].message -ne 'CERTOPS_STAGE=probe-passed'){throw 'Fresh polling did not return guest receipt'}
 if(($global:certopsRequests -join ',') -ne 'POST,GET,GET,GET'){throw 'Unexpected submit/poll sequence'}
 if($global:certopsEpoch -ne 4){throw 'Credential was not refreshed at each boundary'}
}else{
 if(-not $failed){throw 'Unsafe operation passed'}
 if(@($global:certopsRequests|Where-Object {$_ -eq 'POST'}).Count -ne 1){throw 'Guest action was replayed'}
 if($env:CERTOPS_ARM_MODE -eq 'foreign' -and $global:certopsRequests.Count -ne 1){throw 'Credential sent to foreign poll host'}
}
Write-Output 'ARM_BOUNDARY_PROBE_PASSED'
`);
 const result=spawnSync("pwsh",["-NoProfile","-NonInteractive","-File",file],{encoding:"utf8",windowsHide:true,timeout:15000,env:{...process.env,CERTOPS_ARM_HELPER:path.resolve(__dirname,"../infra/certops-adcs/arm-operation.ps1"),CERTOPS_ARM_MODE:mode}});
 assert.equal(result.status,0,result.stdout+result.stderr);assert.match(result.stdout,/ARM_BOUNDARY_PROBE_PASSED/);assert.ok(!result.stdout.includes("fixture-private-value"));
}
test("long guest operations refresh authentication at every poll without replay",t=>run(t,"success"));
test("failed ARM polls withhold private error bodies and never resubmit",t=>run(t,"failed"));
test("foreign ARM polling URLs are rejected before sending credentials",t=>run(t,"foreign"));
test("malformed ARM responses cannot print private content or replay the action",t=>run(t,"malformed"));

function reportTransfer(t, mode) {
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),"certops-report-transfer-"));
 t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const file=path.join(dir,"probe.ps1");
 fs.writeFileSync(file,String.raw`
$ErrorActionPreference='Stop'
$global:requests=0
$global:waits=0
function az {$global:LASTEXITCODE=0;'fixture-token'}
function Start-Sleep {param($Seconds) $global:waits++}
function Invoke-WebRequest {
 param($Uri,$Method,$Headers,$Body,$TimeoutSec,$MaximumRedirection,$ErrorAction,[switch]$UseBasicParsing)
 if($Method -ne 'POST'){throw 'Unexpected HTTP method'}
 $global:requests++
 $guest=($Body|ConvertFrom-Json).script[0]
 if($guest -notmatch 'ReadAllText' -or $guest -notmatch 'enterprise-adcs-report.json'){throw 'Report transfer must remain read-only'}
 if($env:REPORT_TRANSFER_MODE -ne 'busy-then-success' -or $global:requests -le 2){
  $status=if($env:REPORT_TRANSFER_MODE -eq 'server-error'){503}else{409}
  $fixtureFailure=[Exception]::new('fixture-private-value')
  $fixtureFailure|Add-Member -NotePropertyName Response -NotePropertyValue ([pscustomobject]@{StatusCode=$status})
  throw $fixtureFailure
 }
 $text='{"status":"failed","suite":"native-transfer-fixture","scenarios":[]}'
 $bytes=[Text.Encoding]::UTF8.GetBytes($text)
 $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
 $stream=[IO.MemoryStream]::new()
 $gzip=[IO.Compression.GZipStream]::new($stream,[IO.Compression.CompressionMode]::Compress,$true)
 $gzip.Write($bytes,0,$bytes.Length);$gzip.Dispose();$compressed=$stream.ToArray()
 $message="CERTOPS_REPORT_SHA256=$hash"+"\nCERTOPS_REPORT_LENGTH="+$bytes.Length+"\nCERTOPS_REPORT_ZLENGTH="+$compressed.Length+"\nCERTOPS_REPORT_CHUNK="+[Convert]::ToBase64String($compressed)
 $content=@{value=@(@{message=$message})}|ConvertTo-Json -Depth 4 -Compress
 [pscustomobject]@{StatusCode=200;Headers=@{};Content=$content}
}
$failed=$false
try {& $env:CERTOPS_REPORT_READER -ResourceGroup tt-certops-123-1} catch {
 $failed=$true
 if($_.Exception.Message.Contains('fixture-private-value')){throw 'Private response escaped'}
}
$output=Join-Path (Get-Location) 'qualification-results/enterprise-adcs-real.json'
if($env:REPORT_TRANSFER_MODE -eq 'busy-then-success'){
 if($failed -or $global:requests -ne 3 -or $global:waits -ne 2){throw 'Busy channel did not recover through read-only retries'}
 if((Get-Content $output -Raw|ConvertFrom-Json).status -ne 'failed'){throw 'Failed native report was promoted or lost'}
}else{
 if(-not $failed -or (Test-Path $output)){throw 'Failed transfer produced evidence'}
 if($env:REPORT_TRANSFER_MODE -eq 'server-error' -and $global:requests -ne 1){throw 'Uncertain POST was replayed'}
 if($env:REPORT_TRANSFER_MODE -eq 'busy-exhausted' -and ($global:requests -ne 13 -or $global:waits -ne 12)){throw 'Busy-channel retry bound changed'}
}
Write-Output 'READONLY_REPORT_TRANSFER_PROBE_PASSED'
`);
 const result=spawnSync("pwsh",["-NoProfile","-NonInteractive","-File",file],{cwd:dir,encoding:"utf8",windowsHide:true,timeout:20000,env:{...process.env,GITHUB_ACTIONS:"false",AZURE_SUBSCRIPTION_ID:"11111111-1111-4111-8111-111111111111",CERTOPS_REPORT_READER:path.resolve(__dirname,"../infra/certops-adcs/read-report.ps1"),REPORT_TRANSFER_MODE:mode}});
 assert.equal(result.status,0,result.stdout+result.stderr);
 assert.match(result.stdout,/READONLY_REPORT_TRANSFER_PROBE_PASSED/);
 assert.ok(!result.stdout.includes("fixture-private-value"));
}
test("read-only native report transfer waits for a busy channel and preserves failed reports",t=>reportTransfer(t,"busy-then-success"));
test("read-only native report transfer bounds busy-channel retries",t=>reportTransfer(t,"busy-exhausted"));
test("native report transfer does not replay an uncertain server-error submission",t=>reportTransfer(t,"server-error"));

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

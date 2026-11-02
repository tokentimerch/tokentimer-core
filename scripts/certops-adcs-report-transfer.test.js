"use strict";
// End-to-end collector transport checks run in the workflow's Linux host.
// The Windows guest and cross-platform ARM boundary have separate suites.
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path"),{spawnSync}=require("node:child_process");
const collectorHost = process.platform === "win32" ? {skip:"The report collector runs on the Linux workflow host; Windows guest operations have their own suite"} : {};
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
test("read-only native report transfer waits for a busy channel and preserves failed reports",collectorHost,t=>reportTransfer(t,"busy-then-success"));
test("read-only native report transfer bounds busy-channel retries",collectorHost,t=>reportTransfer(t,"busy-exhausted"));
test("native report transfer does not replay an uncertain server-error submission",collectorHost,t=>reportTransfer(t,"server-error"));

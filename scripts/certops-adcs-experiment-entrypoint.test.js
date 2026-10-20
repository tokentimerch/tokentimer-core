"use strict";
// Execute canonical guest orchestration with a node-command double; no native
// operation or report is synthesized as qualification by this portable check.
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path"),{spawnSync}=require("node:child_process");
function invoke(t,response,phase,scope="experiment"){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),"adcs-experiment-entry-"));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));const wrapper=path.join(dir,"probe.ps1");
 fs.writeFileSync(wrapper,String.raw`
$ErrorActionPreference='Stop';$global:calls=[Collections.Generic.List[string]]::new()
function Get-CimInstance {param($ClassName)[pscustomobject]@{Domain='lab.certops.test'}}
function Get-Content {
 param($Path,[switch]$Raw)
 if($Path -cne 'C:\ttqualification\runtime.json'){throw 'Unexpected private input read'}
 @{path=$env:PATH;candidateSha=('a'*40);source=$env:ENTRY_DIR;node='Invoke-FixtureNode';windowsVersion='2022'}|ConvertTo-Json
}
function Invoke-FixtureNode {$global:calls.Add(($args -join '|'));$global:LASTEXITCODE=0}
$failed=$false
try{& $env:ENTRY_SCRIPT -Scope $env:ENTRY_SCOPE -DomainPassword 'fixture-only-private' -ResponseLossExperiment $env:ENTRY_RESPONSE -JournalPhaseExperiment $env:ENTRY_PHASE}catch{$failed=$true}
if($env:ENTRY_EXPECT -eq 'passed'){
 if($failed -or $global:calls.Count -ne 2){throw 'Expected one standalone execution and verification'}
 if($global:calls[0] -cne 'tests/e2e/certops-adcs-focused-experiment.cjs'){throw 'Unexpected baseline execution'}
 $expected=if($env:ENTRY_RESPONSE -eq '1'){'C:\ttqualification\focused-response-loss-experiment.json'}else{'C:\ttqualification\focused-journal-experiment.json'}
 if($global:calls[1] -cne ('tests/e2e/certops-adcs-focused-experiment.cjs|verify|'+$expected)){throw 'Report verification mode mismatch'}
 if($env:CERTOPS_ADCS_OFFICER_PASSWORD){throw 'Private operator credential retained'}
}else{if(-not $failed -or $global:calls.Count){throw 'Invalid mode reached native entrypoint'}}
Write-Output 'ENTRY_FIXTURE_PASSED'
`);
 const valid=scope==="experiment"&&((response==="1"&&phase==="none")||(response==="0"&&["issued","submitting"].includes(phase)));
 return spawnSync(process.platform==="win32"?"powershell.exe":"pwsh",["-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",wrapper],{encoding:"utf8",windowsHide:true,timeout:10000,env:{...process.env,ENTRY_SCRIPT:path.resolve(__dirname,"../infra/certops-adcs/run-windows-tests.ps1"),ENTRY_DIR:dir,ENTRY_RESPONSE:response,ENTRY_PHASE:phase,ENTRY_SCOPE:scope,ENTRY_EXPECT:valid?"passed":"failed"}});
}
test("standalone response loss and each supported journal phase select only their own verified report",t=>{
 for(const [response,phase]of [["1","none"],["0","issued"],["0","submitting"]]){const result=invoke(t,response,phase);assert.equal(result.status,0,result.stderr+result.stdout);assert.match(result.stdout,/ENTRY_FIXTURE_PASSED/);assert.doesNotMatch(result.stdout,/real-enterprise-adcs-tests-passed/);}
});
test("missing, mixed and unsupported fault modes never reach baseline or experiment execution",t=>{
 for(const [response,phase,scope]of [["0","none"],["1","issued"],["1","submitting"],["0","installing"],["1","none","acceptance"]]){const result=invoke(t,response,phase,scope);assert.equal(result.status,0,result.stderr+result.stdout);}
});
test("response loss collector uses distinct bounded guest and output report names",()=>{
 const source=fs.readFileSync(path.resolve(__dirname,"../infra/certops-adcs/read-report.ps1"),"utf8");
 assert.match(source,/\$ReportKind -eq 'focused-response-loss-experiment'\)\{'focused-response-loss-experiment\.json'\}/);
 assert.match(source,/\$ReportKind -eq 'focused-response-loss-experiment'\)\{'enterprise-adcs-focused-response-loss-experiment\.json'\}/);
 assert.match(source,/Reconstructed guest evidence checksum mismatch/);
});

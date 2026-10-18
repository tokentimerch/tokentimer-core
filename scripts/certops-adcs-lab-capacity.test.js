"use strict";
// Exercise the paid-lab preflight with a read-only Azure CLI double; no resource
// creation is permitted by the double. Real subscription eligibility stays live.
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path"),{spawnSync}=require("node:child_process");
const script=path.resolve(__dirname,"../infra/certops-adcs/assert-lab-capacity.ps1");
function fixture(){return {skus:[{name:"Standard_D2s_v5",family:"standardDSv5Family",restrictions:[]}],usage:[{name:{value:"cores"},currentValue:0,limit:6},{name:{value:"standardDSv5Family"},currentValue:0,limit:6}]};}
function run(t,input,location="northeurope"){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),"certops-adcs-capacity-"));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const data=path.join(dir,"fixture.json"),wrapper=path.join(dir,"probe.ps1");fs.writeFileSync(data,JSON.stringify(input));
 fs.writeFileSync(wrapper,`$ErrorActionPreference='Stop'
$fixture=Get-Content -Raw -LiteralPath $env:CERTOPS_CAPACITY_FIXTURE | ConvertFrom-Json
function global:az {
 $command=$args -join ' '
 $global:LASTEXITCODE=0
 if($fixture.failQuery){$global:LASTEXITCODE=1;return '{}'}
 if($command.StartsWith('vm list-skus ')){return ConvertTo-Json -InputObject @($fixture.skus) -Depth 10}
 if($command.StartsWith('vm list-usage ')){return ConvertTo-Json -InputObject @($fixture.usage) -Depth 10}
 throw 'Preflight attempted an unexpected or mutating Azure command'
}
& $env:CERTOPS_CAPACITY_SCRIPT -Location $env:CERTOPS_CAPACITY_LOCATION -VmSize Standard_D2s_v5
`);
 return spawnSync(process.platform==="win32"?"powershell.exe":"pwsh",["-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",wrapper],{encoding:"utf8",windowsHide:true,timeout:30000,env:{...process.env,CERTOPS_CAPACITY_FIXTURE:data,CERTOPS_CAPACITY_SCRIPT:script,CERTOPS_CAPACITY_LOCATION:location}});
}
test("lab preflight admits available size with six regional and family vCPUs",t=>{const result=run(t,fixture());assert.equal(result.status,0,result.stderr);assert.match(result.stdout,/preflight passed/);});
test("lab preflight rejects subscription restrictions, missing size, insufficient or missing quota, and CLI failure",t=>{
 const blocked=fixture();blocked.skus[0].restrictions=[{type:"Location",values:["northeurope"],reasonCode:"NotAvailableForSubscription"}];
 const regional=fixture();regional.usage[0].currentValue=1;
 const family=fixture();family.usage[1].limit=5;
 for(const value of [blocked,{...fixture(),skus:[]},regional,family,{...fixture(),usage:[]},{...fixture(),failQuery:true}]){const result=run(t,value);assert.notEqual(result.status,0,result.stdout);}
});
test("lab preflight ignores zone-only restrictions for this non-zonal lab and rejects malformed locations",t=>{
 const value=fixture();value.skus[0].restrictions=[{type:"Zone",values:["northeurope"],restrictionInfo:{zones:["1"]}}];const result=run(t,value);assert.equal(result.status,0,result.stderr);
 assert.notEqual(run(t,fixture(),"northeurope;ignored").status,0);
});

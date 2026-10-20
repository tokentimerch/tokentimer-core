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

test("guest stage failures expose only bounded template diagnostics and still require their receipt", t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),"certops-stage-receipt-"));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const wrapper=path.join(dir,"probe.ps1");
 fs.writeFileSync(wrapper,`$ErrorActionPreference='Stop'
$ast=[Management.Automation.Language.Parser]::ParseFile($env:CERTOPS_PROVISION_SCRIPT,[ref]$null,[ref]$null)
$definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-Stage'},$true)
. ([scriptblock]::Create($definition.Extent.Text))
function Refresh-LabAuthentication {}
function Invoke-CertOpsVmRunCommand { return [pscustomobject]@{value=@([pscustomobject]@{message=$env:CERTOPS_STAGE_RESPONSE})} }
$ResourceGroup='tt-certops-123-1'
$receipts=[Collections.Generic.List[string]]::new()
$publicStageData=@{}
Invoke-Stage 'domain-ca' $env:CERTOPS_TEMPLATE_SCRIPT 'CERTOPS_STAGE=isolated-template-matrix-published'
`);
 const invoke=message=>spawnSync(process.platform==="win32"?"powershell.exe":"pwsh",["-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",wrapper],{encoding:"utf8",timeout:15000,windowsHide:true,env:{...process.env,CERTOPS_PROVISION_SCRIPT:path.resolve(__dirname,"../infra/certops-adcs/provision-lab.ps1"),CERTOPS_TEMPLATE_SCRIPT:path.resolve(__dirname,"../infra/certops-adcs/templates.ps1"),CERTOPS_STAGE_RESPONSE:message}});
 const failed=invoke("private-credential-needle\nCERTOPS_TEMPLATE_FAILURE=directory:42:-2147467259\n");
 assert.notEqual(failed.status,0);assert.match(failed.stdout,/CERTOPS_TEMPLATE_FAILURE=directory:42:-2147467259/,failed.stderr);assert.match(failed.stderr,/templates.ps1/);assert.doesNotMatch(failed.stdout+failed.stderr,/private-credential-needle/);
 const unsafe=invoke("CERTOPS_TEMPLATE_FAILURE=directory:42:-1 private-credential-needle");
 assert.notEqual(unsafe.status,0);assert.doesNotMatch(unsafe.stdout+unsafe.stderr,/private-credential-needle/);
 const member=invoke("private-credential-needle\nCERTOPS_MEMBER_FAILURE=domain-join:25:-2147467259\n");
 assert.notEqual(member.status,0);assert.match(member.stdout,/CERTOPS_MEMBER_FAILURE=domain-join:25:-2147467259/);assert.doesNotMatch(member.stdout+member.stderr,/private-credential-needle/);
 for(const message of ["CERTOPS_MEMBER_FAILURE=domain-join:25:-1 private-credential-needle","CERTOPS_MEMBER_FAILURE=private-credential-needle:25:-1"]){
  const rejected=invoke(message);assert.notEqual(rejected.status,0);assert.doesNotMatch(rejected.stdout+rejected.stderr,/private-credential-needle/);
 }
 const passed=invoke("private-credential-needle\nCERTOPS_STAGE=isolated-template-matrix-published");
 assert.equal(passed.status,0,passed.stderr);assert.equal(passed.stdout.trim(),"CERTOPS_STAGE=isolated-template-matrix-published");
});

test("template stage transports the complete large descriptor inside the script, with only the password on argv", t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),"certops-template-stage-"));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const template=path.join(dir,"template.ps1"),descriptor=path.join(dir,"safety.json"),generated=path.join(dir,"generated.ps1"),wrapper=path.join(dir,"probe.ps1");
 const bytes=fs.readFileSync(path.resolve(__dirname,"../infra/certops-adcs/safety-cases.json"));
 assert.ok(bytes.toString("base64").length>8191,"Exercise the actual oversized descriptor");fs.writeFileSync(descriptor,bytes);
 fs.writeFileSync(template,`param([Parameter(Mandatory)][string]$DomainPassword,[Parameter(Mandatory)][string]$SafetyCasesBase64)
if($DomainPassword -ne $env:CERTOPS_EXPECTED_PASSWORD){throw 'Credential parameter was not forwarded'}
$bytes=[Convert]::FromBase64String($SafetyCasesBase64)
Write-Output ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes)).Replace('-','').ToLowerInvariant())
`);
 fs.writeFileSync(wrapper,`$ErrorActionPreference='Stop'
$ast=[Management.Automation.Language.Parser]::ParseFile($env:CERTOPS_PROVISION_SCRIPT,[ref]$null,[ref]$null)
$definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'New-TemplateStageScript'},$true)
. ([scriptblock]::Create($definition.Extent.Text))
New-TemplateStageScript $env:CERTOPS_TEST_TEMPLATE $env:CERTOPS_TEST_DESCRIPTOR $env:CERTOPS_TEST_GENERATED
& $env:CERTOPS_TEST_GENERATED -DomainPassword 'fixture-only'
`);
 const result=spawnSync(process.platform==="win32"?"powershell.exe":"pwsh",["-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",wrapper],{encoding:"utf8",windowsHide:true,timeout:15000,env:{...process.env,CERTOPS_PROVISION_SCRIPT:path.resolve(__dirname,"../infra/certops-adcs/provision-lab.ps1"),CERTOPS_TEST_TEMPLATE:template,CERTOPS_TEST_DESCRIPTOR:descriptor,CERTOPS_TEST_GENERATED:generated,CERTOPS_EXPECTED_PASSWORD:"fixture-only"}});
 assert.equal(result.status,0,result.stderr);assert.equal(result.stdout.trim(),require("node:crypto").createHash("sha256").update(bytes).digest("hex"));
 assert.doesNotMatch(fs.readFileSync(generated,"utf8"),/fixture-only/);
});

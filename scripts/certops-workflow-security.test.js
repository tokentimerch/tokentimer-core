/**
 * Regression coverage: trusted read-only qualification with failure cleanup passes.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const test=require("node:test"),assert=require("node:assert/strict");const {validateWorkflow}=require("./certops-workflow-security");
const baseline=()=>({name:"CertOps / Fixture",on:{workflow_dispatch:null},permissions:{contents:"read"},jobs:{qualify:{if:"github.ref == 'refs/heads/main'","timeout-minutes":30,steps:[{uses:"actions/checkout@"+"a".repeat(40),with:{"persist-credentials":false}},{run:"docker compose -f owned.yml up -d"},{if:"always()",run:"docker compose -f owned.yml down -v"},{if:"always()",uses:"actions/upload-artifact@"+"b".repeat(40),with:{path:"qualification-results/report.json"}}]}}});

// CodeQL analysis is the explicit exception to the public PR execution policy.
test("only CodeQL permits automatic pull-request analysis",()=>{
 const fs=require("node:fs"),path=require("node:path");
 const yaml=require("node:module").createRequire(require.resolve("../node_modules/mocha/package.json"))("js-yaml");
 const directory=path.resolve(__dirname,"../.github/workflows");
 for(const name of fs.readdirSync(directory).filter(value=>/\.ya?ml$/.test(value))){
  const workflow=yaml.load(fs.readFileSync(path.join(directory,name),"utf8"));
  const events=typeof workflow.on==="string"?[workflow.on]:Array.isArray(workflow.on)?workflow.on:Object.keys(workflow.on||{});
  if(name==="codeql.yml"){
   assert.deepEqual(workflow.on.pull_request,{branches:["main"]});
   for(const event of ["pull_request_target","pull_request_review","pull_request_review_comment"]){assert.equal(events.includes(event),false,`${name}: forbidden ${event} trigger`);}
   continue;
  }
  for(const event of ["pull_request","pull_request_target","pull_request_review","pull_request_review_comment"]){assert.equal(events.includes(event),false,`${name}: forbidden ${event} trigger`);}
 }
});
test("trusted read-only qualification with failure cleanup passes",()=>assert.deepEqual(validateWorkflow(baseline()),[]));
test("untrusted PR triggers, refs and write credentials fail",()=>{for(const alter of [w=>w.on={pull_request:{}},w=>w.jobs.qualify.if="always()",w=>w.permissions.contents="write",w=>w.jobs.qualify.steps[0].with["persist-credentials"]=true]){const w=baseline();alter(w);assert.ok(validateWorkflow(w).length);}});
test("mutable actions, input injection and broad artifact paths fail",()=>{for(const alter of [w=>w.jobs.qualify.steps[0].uses="actions/checkout@main",w=>w.jobs.qualify.steps[1].run="echo ${{ inputs.payload }}",w=>w.jobs.qualify.steps[3].with.path=".",w=>w.jobs.qualify.steps[3].with.path="qualification-results/../../secret"]){const w=baseline();alter(w);assert.ok(validateWorkflow(w).length);}});
test("missing interruption cleanup and unprotected OIDC fail",()=>{for(const alter of [w=>w.jobs.qualify.steps[2].if="success()",w=>w.permissions["id-token"]="write",w=>w.jobs.qualify["timeout-minutes"]=0]){const w=baseline();alter(w);assert.ok(validateWorkflow(w).length);}});
test("independent AD CS expiry cleanup cannot share approval-gated lab environment",()=>{
  const workflow=baseline();workflow.on={schedule:[{cron:"17 * * * *"}],workflow_dispatch:null};workflow.permissions["id-token"]="write";
  workflow.jobs.qualify.environment="certops-adcs-lab";
  assert.ok(validateWorkflow(workflow,"certops-adcs-lab-janitor.yml").some(error=>error.includes("dedicated unattended environment")));
  workflow.jobs.qualify.environment="certops-adcs-cleanup";
  workflow.jobs.qualify.if=require("./certops-azure-scope-policy").LIFECYCLE_IF;
  assert.deepEqual(validateWorkflow(workflow,"certops-adcs-lab-janitor.yml"),[]);
});

test("selective lanes narrow only exact trusted main with their committed dependency output",()=>{
 const w=baseline();w.jobs={windows:{...w.jobs.qualify,needs:"selection",if:"github.ref == 'refs/heads/main' && needs.selection.outputs.windows == 'true'"}};
 assert.deepEqual(validateWorkflow(w,"certops-qualification.yml"),[]);
 for(const alter of [value=>{value.jobs.windows.if="github.ref == 'refs/heads/main' || needs.selection.outputs.windows == 'true'";},value=>{value.jobs.windows.if="github.ref == 'refs/heads/main' && needs.selection.outputs.stack == 'true'";},value=>{value.jobs.windows.needs="untrusted";},value=>{value.jobs.windows.if="github.ref == 'refs/heads/main' && true";},value=>{value.jobs.windows.if="github.ref == 'refs/heads/main'";}]){const value=structuredClone(w);alter(value);assert.ok(validateWorkflow(value,"certops-qualification.yml").length);}
 assert.ok(validateWorkflow(w,"certops-paid-fixture.yml").length,"Other workflows cannot borrow selector exceptions");
});

test("DNS cleanup uses only enrolled provider matrix and its independent unattended environment",()=>{
 const w=baseline();w.on={schedule:[{cron:"17 * * * *"}]};w.jobs={cleanup:{...w.jobs.qualify,needs:"enrollment",if:"github.ref == 'refs/heads/main' && needs.enrollment.outputs.enabled == 'true'",environment:"certops-dns-cleanup-${{ matrix.provider }}",strategy:{matrix:{provider:"${{ fromJSON(needs.enrollment.outputs.providers) }}"}}}};
 assert.deepEqual(validateWorkflow(w,"certops-dns-fixture-janitor.yml"),[]);
 for(const change of [value=>{value.jobs.cleanup.environment="certops-dns-${{ matrix.provider }}";},value=>{value.jobs.cleanup.strategy.matrix.provider=["cloudflare","route53"];},value=>{value.jobs.cleanup.if="github.ref == 'refs/heads/main' || needs.enrollment.outputs.enabled == 'true'";},value=>{value.jobs.cleanup.needs="foreign";}]){const value=structuredClone(w);change(value);assert.ok(validateWorkflow(value,"certops-dns-fixture-janitor.yml").length);}
});

test("only complete original-artifact-first resident handoff may retain a successful lab",()=>{
 const fs=require("node:fs"),path=require("node:path"),{createRequire}=require("node:module");
 const yaml=createRequire(require.resolve(path.resolve(__dirname,"../node_modules/mocha/package.json")))("js-yaml");
 const workflow=()=>yaml.load(fs.readFileSync(path.resolve(__dirname,"../.github/workflows/certops-retention24h-prepare.yml"),"utf8"));
 const name="certops-retention24h-prepare.yml";assert.deepEqual(validateWorkflow(workflow(),name),[]);
 const find=(w,fragment)=>w.jobs.prepare.steps.findIndex(step=>(step.run||step.with?.path||"").includes(fragment));
 for(const fragment of ["provision-lab.ps1","-azure.js seal","retention24h-original.json","-azure.js handoff","retention24h-ownership.json","-azure.js abort"]){const w=workflow();w.jobs.prepare.steps.splice(find(w,fragment),1);assert.ok(validateWorkflow(w,name).length,fragment);}
 for(const change of [w=>{const steps=w.jobs.prepare.steps,a=find(w,"retention24h-original.json"),b=find(w,"-azure.js handoff");[steps[a],steps[b]]=[steps[b],steps[a]];},w=>w.jobs.prepare.steps[find(w,"-azure.js handoff")].if="always()",w=>w.jobs.prepare.steps[find(w,"-azure.js seal")].if="always()",w=>w.jobs.prepare.steps[find(w,"provision-lab.ps1")].if="always()",w=>w.jobs.prepare.steps[find(w,"retention24h-original.json")].with["if-no-files-found"]="warn",w=>w.jobs.prepare.steps[find(w,"-azure.js abort")].if="failure()",w=>w.concurrency["cancel-in-progress"]=true,w=>w.jobs.prepare.environment="certops-adcs-cleanup",w=>w.on.schedule=[{cron:"0 * * * *"}],w=>w.jobs.prepare.if="always()",w=>w.jobs.prepare.steps.push({run:"echo late failure"})]){const w=workflow();change(w);assert.ok(validateWorkflow(w,name).length);}
 assert.ok(validateWorkflow(workflow(),"certops-unrelated-paid-lab.yml").some(error=>error.includes("independent always cleanup")),"Other labs cannot borrow retained-resource exception");
});

test("resident finalizer and janitor require unattended cleanup and fixed serialization",()=>{
 const fs=require("node:fs"),path=require("node:path"),{createRequire}=require("node:module");const yaml=createRequire(require.resolve(path.resolve(__dirname,"../node_modules/mocha/package.json")))("js-yaml");
 for(const mode of ["finalize","janitor"]){const name=`certops-retention24h-${mode}.yml`,w=yaml.load(fs.readFileSync(path.resolve(__dirname,"../.github/workflows",name),"utf8"));assert.deepEqual(validateWorkflow(w,name),[]);w.jobs[mode].environment="certops-adcs-lab";assert.ok(validateWorkflow(w,name).some(error=>error.includes("dedicated unattended")));w.jobs[mode].environment="certops-adcs-cleanup";w.concurrency.group="foreign";assert.ok(validateWorkflow(w,name).length);}
});

test("unsupported ARM full-host notice exception admits only exact credential-free failure",()=>{
 const fs=require("node:fs"),path=require("node:path"),{createRequire}=require("node:module"),yaml=createRequire(require.resolve(path.resolve(__dirname,"../node_modules/mocha/package.json")))("js-yaml");
 const name="certops-windows-arm64-host.yml",baseline=yaml.load(fs.readFileSync(path.resolve(__dirname,"../.github/workflows",name),"utf8"));assert.deepEqual(validateWorkflow(baseline,name),[]);
 assert.ok(validateWorkflow(baseline,"certops-other.yml").length);
 for(const change of [w=>w.permissions.contents="read",w=>w.permissions["id-token"]="write",w=>w.on.push={branches:["main"]},w=>w.jobs["unsupported-full-host"].if="github.ref == 'refs/heads/main'",w=>w.jobs["unsupported-full-host"]["runs-on"]="windows-11-arm",w=>w.jobs["unsupported-full-host"].steps.push({uses:"actions/checkout@"+"a".repeat(40)}),w=>w.jobs["unsupported-full-host"].steps[0].run="echo ignored\nexit 0\n",w=>w.jobs["unsupported-full-host"].steps[0].shell="pwsh",w=>w.env={TOKEN:"secret"},w=>w.jobs["unsupported-full-host"].steps[0].env={TOKEN:"secret"}]){const w=structuredClone(baseline);change(w);assert.ok(validateWorkflow(w,name).length);}
});

test("approval-pending retention prepare never occupies cleanup queue and cannot outlive initial lease",()=>{
 const fs=require("node:fs"),path=require("node:path"),{createRequire}=require("node:module"),yaml=createRequire(require.resolve(path.resolve(__dirname,"../node_modules/mocha/package.json")))("js-yaml");
 const read=name=>yaml.load(fs.readFileSync(path.resolve(__dirname,"../.github/workflows",name),"utf8"));
 const name="certops-retention24h-prepare.yml",value=read(name),initial=require("./certops-retention24h-contract").INITIAL;
 assert.deepEqual(validateWorkflow(value,name),[]);
 assert.equal(value.jobs.prepare["timeout-minutes"],180);
 assert.ok(value.jobs.prepare["timeout-minutes"]*60000+5*60000<initial,"Whole job plus cancellation grace must end before earliest provision-start lease expiry");
 for(const queue of ["certops-retention24h-owned-azure-lifecycle","certops-retention24h-prepare-${{ github.run_id }}","certops-retention24h-prepare-${{ github.run_attempt }}","foreign"]){const altered=structuredClone(value);altered.concurrency.group=queue;assert.ok(validateWorkflow(altered,name).length);}
 for(const timeout of [181,240,"180",null]){const altered=structuredClone(value);altered.jobs.prepare["timeout-minutes"]=timeout;assert.ok(validateWorkflow(altered,name).length);}
 for(const other of ["certops-retention24h-finalize.yml","certops-retention24h-janitor.yml","certops-adcs-lab-janitor.yml"]){const cleanup=read(other);assert.equal(cleanup.concurrency.group,"certops-retention24h-owned-azure-lifecycle");assert.equal(cleanup.concurrency["cancel-in-progress"],false);assert.notEqual(cleanup.concurrency.group,value.concurrency.group);for(const job of Object.values(cleanup.jobs))assert.equal(job.environment,"certops-adcs-cleanup");}
});

test("only complete separate ADCS TTL original-artifact-first handoff may retain a successful lab",()=>{
 const fs=require("node:fs"),path=require("node:path"),{createRequire}=require("node:module");
 const yaml=createRequire(require.resolve(path.resolve(__dirname,"../node_modules/mocha/package.json")))("js-yaml");
 const workflow=()=>yaml.load(fs.readFileSync(path.resolve(__dirname,"../.github/workflows/certops-adcs-ttl24h-prepare.yml"),"utf8"));
 const name="certops-adcs-ttl24h-prepare.yml";assert.deepEqual(validateWorkflow(workflow(),name),[]);
 const find=(w,fragment)=>w.jobs.prepare.steps.findIndex(step=>(step.run||step.with?.path||"").includes(fragment));
 for(const fragment of ["provision-lab.ps1","-azure.js seal","adcs-ttl24h-original.json","-azure.js handoff","adcs-ttl24h-ownership.json","-azure.js abort"]){const w=workflow();w.jobs.prepare.steps.splice(find(w,fragment),1);assert.ok(validateWorkflow(w,name).length,fragment);}
 for(const change of [w=>{const steps=w.jobs.prepare.steps,a=find(w,"adcs-ttl24h-original.json"),b=find(w,"-azure.js handoff");[steps[a],steps[b]]=[steps[b],steps[a]];},w=>w.jobs.prepare.steps[find(w,"-azure.js handoff")].if="always()",w=>w.jobs.prepare.steps[find(w,"-azure.js seal")].if="always()",w=>w.jobs.prepare.steps[find(w,"provision-lab.ps1")].if="always()",w=>w.jobs.prepare.steps[find(w,"adcs-ttl24h-original.json")].with["if-no-files-found"]="warn",w=>w.jobs.prepare.steps[find(w,"-azure.js abort")].if="failure()",w=>w.concurrency["cancel-in-progress"]=true,w=>w.jobs.prepare.environment="certops-adcs-cleanup",w=>w.on.schedule=[{cron:"0 * * * *"}],w=>w.jobs.prepare.if="always()",w=>w.jobs.prepare.steps.push({run:"echo late failure"})]){const w=workflow();change(w);assert.ok(validateWorkflow(w,name).length);}
 assert.ok(validateWorkflow(workflow(),"certops-unrelated-paid-lab.yml").some(error=>error.includes("independent always cleanup")),"Other labs cannot borrow retained-resource exception");
});


test("ADCS TTL approval queues cannot delay cleanup and active preparation ends before initialexpiry",()=>{
 const fs=require("node:fs"),path=require("node:path"),{createRequire}=require("node:module"),yaml=createRequire(require.resolve(path.resolve(__dirname,"../node_modules/mocha/package.json")))("js-yaml");
 const read=name=>yaml.load(fs.readFileSync(path.resolve(__dirname,"../.github/workflows",name),"utf8")),name="certops-adcs-ttl24h-prepare.yml",value=read(name),initial=require("./certops-adcs-ttl24h-contract").INITIAL;
 assert.deepEqual(validateWorkflow(value,name),[]);assert.equal(value.jobs.prepare["timeout-minutes"],180);assert.ok(value.jobs.prepare["timeout-minutes"]*60000+5*60000<initial);
 for(const alteredGroup of ["certops-adcs-ttl24h-cleanup","foreign","certops-adcs-ttl24h-prepare-${{ github.run_id }}"]){const bad=structuredClone(value);bad.concurrency.group=alteredGroup;assert.ok(validateWorkflow(bad,name).length);}
 for(const mode of ["finalize","janitor"]){const name=`certops-adcs-ttl24h-${mode}.yml`,workflow=read(name);assert.deepEqual(validateWorkflow(workflow,name),[]);assert.notEqual(value.concurrency.group,workflow.concurrency.group);workflow.jobs[mode].environment="certops-adcs-lab";assert.ok(validateWorkflow(workflow,name).length);}
});

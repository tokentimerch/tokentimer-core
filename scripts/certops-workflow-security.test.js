/**
 * Regression coverage: trusted read-only qualification with failure cleanup passes.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const test=require("node:test"),assert=require("node:assert/strict");const {validateWorkflow}=require("./certops-workflow-security");
const baseline=()=>({name:"CertOps / Fixture",on:{workflow_dispatch:null},permissions:{contents:"read"},jobs:{qualify:{if:"github.ref == 'refs/heads/main'","timeout-minutes":30,steps:[{uses:"actions/checkout@"+"a".repeat(40),with:{"persist-credentials":false}},{run:"docker compose -f owned.yml up -d"},{if:"always()",run:"docker compose -f owned.yml down -v"},{if:"always()",uses:"actions/upload-artifact@"+"b".repeat(40),with:{path:"qualification-results/report.json"}}]}}});

test("early AD CS failure evidence is sanitized and cannot replace cleanup",()=>{
 const fs=require("node:fs"),path=require("node:path");
 const yaml=require("node:module").createRequire(require.resolve("../node_modules/mocha/package.json"))("js-yaml");
 const workflow=yaml.load(fs.readFileSync(path.resolve(__dirname,"../.github/workflows/certops-enterprise-adcs-qualification.yml"),"utf8"));
 const steps=workflow.jobs.lab.steps,early=steps.findIndex(step=>step.name==="Publish sanitized failure report before resource cleanup"),cleanup=steps.findIndex(step=>step.name==="Destroy owned temporary resources");
 assert.ok(early>=0 && cleanup>early);assert.equal(steps[early].if,"failure() && !inputs.debug_mode");
 assert.equal(steps[early].with.path,"qualification-results/enterprise-adcs-real.json");assert.equal(steps[early]["continue-on-error"],true);
 assert.equal(steps[cleanup].if,"always()");
 const name="certops-enterprise-adcs-qualification.yml";
 assert.deepEqual(validateWorkflow(workflow,name),[]);
 for(const change of [w=>w.jobs.lab.steps[early].with.path="qualification-results/other.json",w=>w.jobs.lab.steps[early].if="failure()",w=>w.jobs.lab.steps[early]["continue-on-error"]=false,w=>w.jobs.lab.steps[early]["timeout-minutes"]=3,w=>w.jobs.lab.steps.find(s=>s.with?.path==="qualification-results/enterprise-adcs-*.json").if="success()"]){const altered=structuredClone(workflow);change(altered);assert.ok(validateWorkflow(altered,name).length);}
 assert.ok(validateWorkflow(workflow,"certops-other.yml").length);
});

test("Vault summary preserves main restriction while collecting failed cohort results",()=>{
 const fs=require("node:fs"),path=require("node:path");
 const yaml=require("node:module").createRequire(require.resolve("../node_modules/mocha/package.json"))("js-yaml");
 const workflow=yaml.load(fs.readFileSync(path.resolve(__dirname,"../.github/workflows/certops-distribution-qualification.yml"),"utf8"));
 const name="certops-distribution-qualification.yml";
 assert.deepEqual(validateWorkflow(workflow,name),[]);
 for(const alter of [job=>job.if="always()",job=>job.if="${{ always() }}",job=>job.needs=["postgres"],job=>job.if="${{ always() && github.ref != 'refs/heads/main' }}"]){
  const changed=structuredClone(workflow);alter(changed.jobs["functional-summary"]);
  assert.ok(validateWorkflow(changed,name).length);
 }
 assert.ok(validateWorkflow(workflow,"certops-unrelated.yml").length);
});

test("shared Linux setup refuses mutable actions, credential hooks and extra commands",()=>{
 const fs=require("node:fs"),path=require("node:path");
 const yaml=require("node:module").createRequire(require.resolve("../node_modules/mocha/package.json"))("js-yaml");
 const {validateNodeSetup}=require("./certops-workflow-security");
 const action=yaml.load(fs.readFileSync(path.resolve(__dirname,"../.github/actions/certops-node-setup/action.yml"),"utf8"));
 assert.deepEqual(validateNodeSetup(action),[]);
 for(const alter of [a=>a.runs.steps[0].uses="pnpm/action-setup@main",a=>a.runs.steps[1].with["node-version"]="22",a=>a.runs.steps[2].run="pnpm install",a=>a.runs.steps[2].env={TOKEN:"fixture"},a=>a.runs.steps.push({run:"echo extra",shell:"bash"}),a=>a.inputs={command:{}},a=>a.runs.using="node24"]){
  const bad=structuredClone(action);alter(bad);assert.ok(validateNodeSetup(bad).length);
 }
 for(const step of [{uses:"./.github/actions/unreviewed"},{uses:"./.github/actions/certops-node-setup",with:{command:"extra"}},{uses:"./.github/actions/certops-node-setup",env:{TOKEN:"fixture"}}]){
  const workflow=baseline();workflow.jobs.qualify.steps.splice(1,0,step);assert.ok(validateWorkflow(workflow).length);
 }
});

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
test("IIS access isolates the protected verifier and backup operations and their receipt", () => {
  const fs = require("node:fs");
  const yaml = require("node:module").createRequire(require.resolve("../node_modules/mocha/package.json"))("js-yaml");
  const name = "certops-iis-lab-access.yml";
  const workflow = yaml.load(fs.readFileSync(require("node:path").join(__dirname, "../.github/workflows", name), "utf8"));
  assert.deepEqual(validateWorkflow(workflow, name), []);
  assert.ok(validateWorkflow(workflow, "certops-other.yml").some(error => error.includes("lifecycle inventory")));
  for (const alter of [
    w => { w.on.push = { branches: ["main"] }; },
    w => { w.on.workflow_dispatch.inputs.operation.default = "delete-owned-group"; },
    w => { w.jobs.verifier.if = "github.ref == 'refs/heads/main'"; },
    w => { w.jobs.verifier.environment = w.jobs.cleanup.environment; },
    w => { w.jobs.cleanup.env.TT_IIS_CLIENT_ID = "${{ vars.AZURE_CLIENT_ID }}"; },
    w => { w.jobs.cleanup.steps[0].with.ref = "untrusted"; },
    w => { w.jobs.cleanup.steps[3].if = "inputs.operation == 'check-cleanup'"; },
    w => { delete w.jobs.cleanup.steps[3].env; },
    w => { delete w.jobs.cleanup.steps[3].env.TT_IIS_EXPIRES_AT; },
    w => { w.jobs.cleanup.steps[4].if = "always()"; },
    w => { w.jobs.verifier.steps[3].with.path = "qualification-results/"; },
  ]) {
    const altered = structuredClone(workflow);
    alter(altered);
    assert.ok(validateWorkflow(altered, name).length);
  }
});
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

test("Windows tooling shares only the trusted tooling selection and cannot borrow native or foreign outputs",()=>{
 const w=baseline();w.jobs={"tooling-windows":{...w.jobs.qualify,needs:"selection",if:"github.ref == 'refs/heads/main' && needs.selection.outputs.tooling == 'true'"}};
 assert.deepEqual(validateWorkflow(w,"certops-qualification.yml"),[]);
 for(const value of ["github.ref == 'refs/heads/main' || needs.selection.outputs.tooling == 'true'","github.ref == 'refs/heads/main' && needs.selection.outputs.windows == 'true'","github.ref == 'refs/heads/main' && needs.selection.outputs.stack == 'true'"]){const bad=structuredClone(w);bad.jobs["tooling-windows"].if=value;assert.ok(validateWorkflow(bad,"certops-qualification.yml").length);}
 assert.ok(validateWorkflow(w,"certops-other.yml").length);
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

test("scheduled janitor remains enabled when new lab provisioning is disabled",()=>{
 const fs=require("node:fs"),path=require("node:path"),yaml=require("node:module").createRequire(require.resolve("mocha/package.json"))("js-yaml"),azure=require("./certops-azure-scope-policy");
 const name="certops-adcs-lab-janitor.yml",workflow=yaml.load(fs.readFileSync(path.resolve(__dirname,"../.github/workflows",name),"utf8"));
 assert.ok(workflow.on.schedule.length);assert.equal(workflow.jobs.cleanup.if,"github.ref == 'refs/heads/main'");assert.equal(workflow.jobs.cleanup.environment,"certops-adcs-cleanup");assert.deepEqual(azure.validate(name,workflow),[]);assert.deepEqual(validateWorkflow(workflow,name),[]);
 for(const condition of [azure.PROVISION_IF,"always()","github.ref == 'refs/heads/main' && vars.CERTOPS_ADCS_LAB_ENABLED == 'true'"]){const bad=structuredClone(workflow);bad.jobs.cleanup.if=condition;assert.ok(azure.validate(name,bad).length);}
 assert.match(azure.PROVISION_IF,/CERTOPS_ADCS_LAB_ENABLED/);assert.doesNotMatch(azure.LIFECYCLE_IF,/CERTOPS_ADCS_LAB_ENABLED/);
});
test("distribution selectors retain exact main, manual dispatch and bounded failure evidence",()=>{
 const fs=require("node:fs"),path=require("node:path"),yaml=require("node:module").createRequire(require.resolve("mocha/package.json"))("js-yaml");
 const name="certops-distribution-qualification.yml",w=yaml.load(fs.readFileSync(path.resolve(__dirname,"../.github/workflows",name),"utf8"));
 assert.deepEqual(validateWorkflow(w,name),[]);
 const unsupported=structuredClone(w);
 unsupported.on.workflow_dispatch.inputs.native_cleanup_provider.options.push("azure-key-vault");
 assert.match(validateWorkflow(unsupported,name).join("\n"), /exact KV v2 provider choices/);
 const stagedByDefault=structuredClone(w);
 stagedByDefault.on.workflow_dispatch.inputs.native_linux_staging.default=true;
 assert.match(validateWorkflow(stagedByDefault,name).join("\n"), /exact staging selector/);
 for(const id of ["postgres","agent-lab","functional-summary","native-vault-cleanup"]){
  for(const condition of ["github.ref == 'refs/heads/main'", "github.ref == 'refs/heads/main' || true", "always()"]){const bad=structuredClone(w);bad.jobs[id].if=condition;assert.ok(validateWorkflow(bad,name).length,id);}
 }
 for(const change of [x=>{x.on.push={branches:["main"]};},x=>{x.on.workflow_dispatch.inputs.native_vault_cleanup.default=true;},x=>{x.jobs.extra=structuredClone(x.jobs.postgres);},x=>{x.jobs["native-vault-cleanup"].steps.find(s=>s.name==="Preserve the bounded native failure report").with.path="qualification-results/../foreign";},x=>{x.jobs["native-vault-cleanup"].steps.find(s=>s.name==="Preserve the bounded native failure report").if="success()";},x=>{x.jobs["native-vault-cleanup"].steps.find(s=>s.name==="Preserve the bounded native failure report").if="always()";}]){const bad=structuredClone(w);change(bad);assert.ok(validateWorkflow(bad,name).length);}
});
test("release distribution requires four isolated jobs consuming the one verified main artifact", () => {
  const fs = require("node:fs"), path = require("node:path");
  const yaml = require("node:module").createRequire(require.resolve("mocha/package.json"))("js-yaml");
  const name = "certops-distribution-qualification.yml";
  const workflow = yaml.load(fs.readFileSync(path.resolve(__dirname, "../.github/workflows", name), "utf8"));
  assert.deepEqual(validateWorkflow(workflow, name), []);
  for (const change of [
    jobs => { delete jobs["release-native-linux-staging-openbao"]; },
    jobs => { jobs["release-distribution-candidate"].steps.find(step => step.name === "Require the exact trusted main dispatch SHA").run = "true"; },
    jobs => { delete jobs["release-distribution-candidate"].steps.find(step => step.id === "package").env.EXPECTED_PACKAGE_SHA256; },
    jobs => { const step = jobs["release-distribution-candidate"].steps.find(step => step.id === "package");
      step.run = step.run.replace("verify-release-distribution-candidate", "skip-verification"); },
    jobs => { jobs["release-native-vault-cleanup"].needs = "postgres"; },
    jobs => { jobs["release-native-linux-staging-openbao"].env.NATIVE_MODE = "--native-staging"; },
    jobs => { jobs["release-native-linux-staging-vault"].steps.find(step => step.uses?.startsWith("actions/download-artifact@")).with["artifact-ids"] = "1"; },
    jobs => { jobs["release-native-openbao-cleanup"].steps.find(step => step.name === "Verify teardown of only the owned host and containers").if = "success()"; },
  ]) {
    const bad = structuredClone(workflow);
    change(bad.jobs);
    assert.ok(validateWorkflow(bad, name).length);
  }
});
test("manual qualification cannot bypass the trusted main reference",()=>{
 const workflow=baseline();
 for(const name of ["certops-qualification.yml","certops-distribution-qualification.yml","certops-enterprise-adcs-qualification.yml"]){
  workflow.jobs.qualify.if="(github.ref == 'refs/heads/main' || (github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/review'))";
  assert.ok(validateWorkflow(workflow,name).length);
 }
});

test("no-IIS preparation retains only the independently verified run and bounds failure cleanup", () => {
 const fs=require("node:fs"),path=require("node:path");
 const yaml=require("node:module").createRequire(require.resolve("../node_modules/mocha/package.json"))("js-yaml");
 const name="certops-adcs-store-noiis-prepare.yml";
 const workflow=yaml.load(fs.readFileSync(path.resolve(__dirname,"../.github/workflows",name),"utf8"));
 const azure=require("./certops-azure-scope-policy");
 assert.ok(azure.PROVISION.includes(name));
 assert.deepEqual(azure.validate(name,workflow),[]);
 assert.deepEqual(validateWorkflow(workflow,name),[]);
 const altered=[
  ["untrusted trigger",w=>w.on.schedule=[{cron:"0 * * * *"}]],
  ["mutable target",w=>w.jobs.register.steps[0].with.ref="untrusted"],
  ["default working directory",w=>w.defaults={run:{"working-directory":"other"}}],
  ["shared cleanup queue",w=>w.concurrency.group="certops-retention24h-owned-azure-lifecycle"],
  ["untrusted resource scope",w=>w.env.STORE_GROUP="shared"],
  ["verification role",w=>w.jobs.verify.environment="certops-adcs-lab"],
  ["required manual proof",w=>w.on.workflow_dispatch.inputs.manual_janitor_run_id.required=true],
  ["default manual proof",w=>w.on.workflow_dispatch.inputs.manual_janitor_run_id.default="1234"],
  ["default recovery infrastructure",w=>w.on.workflow_dispatch.inputs.prepare_recovery_infrastructure.default=true],
  ["constant recovery selector",w=>w.jobs.prepare.env.STORE_RECOVERY_INFRASTRUCTURE="1"],
  ["recovery selector outside preparation",w=>w.jobs.register.env.STORE_RECOVERY_INFRASTRUCTURE=w.jobs.prepare.env.STORE_RECOVERY_INFRASTRUCTURE],
  ["substituted manual proof",w=>w.jobs.verify.env.STORE_MANUAL_JANITOR_RUN_ID="1234"],
  ["manual proof outside verify",w=>w.jobs.prepare.env.STORE_MANUAL_JANITOR_RUN_ID=w.jobs.verify.env.STORE_MANUAL_JANITOR_RUN_ID],
  ["verification mutation",w=>w.jobs.verify.steps[2].run=w.jobs.register.steps[2].run],
  ["failure evidence",w=>delete w.jobs.verify.steps[3].if],
  ["registration evidence path",w=>w.jobs.verify.steps[3].with.path="qualification-results/"],
  ["successful verify without evidence",w=>w.jobs.verify.steps[3].with["if-no-files-found"]="warn"],
  ["registration handoff",w=>w.jobs.prepare.needs=["register"]],
  ["untrusted approval digest",w=>w.jobs.prepare.env.STORE_REGISTRATION_SHA256="test"],
  ["unsupported preparation mode",w=>w.jobs.prepare.steps[2].run=w.jobs.prepare.steps[2].run.replace("-StoreNoIisPrepare 1","-StoreNoIisPrepare 0")],
  ["unbounded preparation",w=>w.jobs.prepare["timeout-minutes"]=181],
  ["cleanup of successful preparations",w=>w.jobs["cleanup-failed"].if=w.jobs["cleanup-failed"].if.replace(" != 'success'"," == 'success'")],
  ["cleanup without exact activation equality",w=>w.jobs["cleanup-failed"].if=w.jobs["cleanup-failed"].if.replace(" && needs.prepare.outputs.cleanup_activation == needs.verify.outputs.receipt_sha256","")],
  ["cleanup for another owner",w=>w.jobs["cleanup-failed"].env.STORE_REGISTRATION="foreign"],
  ["cleanup evidence",w=>delete w.jobs["cleanup-failed"].steps[3].if],
 ];
 for(const id of ["register","verify","prepare","cleanup-failed"])altered.push([id+" main guard",w=>w.jobs[id].if="always()"]);
 for(const [description,change] of altered){
  const candidate=structuredClone(workflow);
  change(candidate);
  assert.ok(azure.validate(name,candidate).length,description);
  assert.ok(validateWorkflow(candidate,name).length,description);
 }
 const unrelated=validateWorkflow(workflow,"certops-unrelated-paid-lab.yml");
 assert.ok(unrelated.some(error=>error.includes("lifecycle inventory")));
 assert.ok(unrelated.some(error=>error.includes("independent always cleanup")));
});

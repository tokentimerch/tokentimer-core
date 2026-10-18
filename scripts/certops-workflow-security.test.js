"use strict";

const test=require("node:test"),assert=require("node:assert/strict");

const {validateWorkflow}=require("./certops-workflow-security");

const baseline=()=>({name:"CertOps / Fixture",on:{workflow_dispatch:null},permissions:{contents:"read"},jobs:{qualify:{if:"github.ref == 'refs/heads/main'","timeout-minutes":30,steps:[{uses:"actions/checkout@"+"a".repeat(40),with:{"persist-credentials":false}},{run:"docker compose -f owned.yml up -d"},{if:"always()",run:"docker compose -f owned.yml down -v"},{if:"always()",uses:"actions/upload-artifact@"+"b".repeat(40),with:{path:"qualification-results/report.json"}}]}}});

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

test("scheduled janitor remains enabled when new lab provisioning is disabled",()=>{
 const fs=require("node:fs"),path=require("node:path"),yaml=require("node:module").createRequire(require.resolve("mocha/package.json"))("js-yaml"),azure=require("./certops-azure-scope-policy");
 const name="certops-adcs-lab-janitor.yml",workflow=yaml.load(fs.readFileSync(path.resolve(__dirname,"../.github/workflows",name),"utf8"));
 assert.ok(workflow.on.schedule.length);assert.equal(workflow.jobs.cleanup.if,"github.ref == 'refs/heads/main'");assert.equal(workflow.jobs.cleanup.environment,"certops-adcs-cleanup");assert.deepEqual(azure.validate(name,workflow),[]);assert.deepEqual(validateWorkflow(workflow,name),[]);
 for(const condition of [azure.PROVISION_IF,"always()","github.ref == 'refs/heads/main' && vars.CERTOPS_ADCS_LAB_ENABLED == 'true'"]){const bad=structuredClone(workflow);bad.jobs.cleanup.if=condition;assert.ok(azure.validate(name,bad).length);}
 assert.match(azure.PROVISION_IF,/CERTOPS_ADCS_LAB_ENABLED/);assert.doesNotMatch(azure.LIFECYCLE_IF,/CERTOPS_ADCS_LAB_ENABLED/);
});

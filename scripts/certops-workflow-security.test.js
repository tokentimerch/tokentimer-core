"use strict";
const test=require("node:test"),assert=require("node:assert/strict");const {validateWorkflow}=require("./certops-workflow-security");
const baseline=()=>({on:{workflow_dispatch:null},permissions:{contents:"read"},jobs:{qualify:{if:"github.ref == 'refs/heads/main'","timeout-minutes":30,steps:[{uses:"actions/checkout@"+"a".repeat(40),with:{"persist-credentials":false}},{run:"docker compose -f owned.yml up -d"},{if:"always()",run:"docker compose -f owned.yml down -v"},{if:"always()",uses:"actions/upload-artifact@"+"b".repeat(40),with:{path:"qualification-results/report.json"}}]}}});
test("trusted read-only qualification with failure cleanup passes",()=>assert.deepEqual(validateWorkflow(baseline()),[]));
test("untrusted PR triggers, refs and write credentials fail",()=>{for(const alter of [w=>w.on={pull_request:{}},w=>w.jobs.qualify.if="always()",w=>w.permissions.contents="write",w=>w.jobs.qualify.steps[0].with["persist-credentials"]=true]){const w=baseline();alter(w);assert.ok(validateWorkflow(w).length);}});
test("mutable actions, input injection and broad artifact paths fail",()=>{for(const alter of [w=>w.jobs.qualify.steps[0].uses="actions/checkout@main",w=>w.jobs.qualify.steps[1].run="echo ${{ inputs.payload }}",w=>w.jobs.qualify.steps[3].with.path=".",w=>w.jobs.qualify.steps[3].with.path="qualification-results/../../secret"]){const w=baseline();alter(w);assert.ok(validateWorkflow(w).length);}});
test("missing interruption cleanup and unprotected OIDC fail",()=>{for(const alter of [w=>w.jobs.qualify.steps[2].if="success()",w=>w.permissions["id-token"]="write",w=>w.jobs.qualify["timeout-minutes"]=0]){const w=baseline();alter(w);assert.ok(validateWorkflow(w).length);}});
test("independent AD CS expiry cleanup cannot share approval-gated lab environment",()=>{
  const workflow=baseline();workflow.on={schedule:[{cron:"17 * * * *"}],workflow_dispatch:null};workflow.permissions["id-token"]="write";
  workflow.jobs.qualify.environment="certops-adcs-lab";
  assert.ok(validateWorkflow(workflow,"certops-adcs-lab-janitor.yml").some(error=>error.includes("dedicated unattended environment")));
  workflow.jobs.qualify.environment="certops-adcs-cleanup";
  assert.deepEqual(validateWorkflow(workflow,"certops-adcs-lab-janitor.yml"),[]);
});

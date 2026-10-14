/**
 * Regression coverage: trusted read-only qualification with failure cleanup passes.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const test=require("node:test"),assert=require("node:assert/strict");const {validateWorkflow}=require("./certops-workflow-security");
const baseline=()=>({name:"CertOps / Fixture",on:{workflow_dispatch:null},permissions:{contents:"read"},jobs:{qualify:{if:"github.ref == 'refs/heads/main'","timeout-minutes":30,steps:[{uses:"actions/checkout@"+"a".repeat(40),with:{"persist-credentials":false}},{run:"docker compose -f owned.yml up -d"},{if:"always()",run:"docker compose -f owned.yml down -v"},{if:"always()",uses:"actions/upload-artifact@"+"b".repeat(40),with:{path:"qualification-results/report.json"}}]}}});
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

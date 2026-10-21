/**
 * Qualification notes: Public CA capacity admission qualification
 * `ca-capacity-api` covers concurrent public issuance admission. Six simultaneous public issuance
 * requests admit exactly five pending approval jobs under the default per-CA cap; the sixth receives
 * the documented capacity conflict. Idempotency still resolves the existing job at capacity. Canonical
 * endpoint variations cannot split one bucket, a different CA remains independently eligible, and an
 * actual requester rejection releases capacity for another request. Failed reservations preserve job,
 * certificate and outbox counts.
 *
 * Shared execution and evidence policy: docs/certops/e2e-qualification.md.
 */
/**
 * Supporting API/PostgreSQL qualification: public issuance shares race-safe CA admission and terminal release.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * Public requests and persisted rows are the oracle; prerequisite state is isolated.
 * Native certificate deployment is qualified separately; strict reports and cleanup apply. */
"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),crypto=require("node:crypto");
const {createApiFixture}=require("./helpers/certops-api-fixture"),{createHostGate}=require("../../packages/agent/scripts/host-gate");
const scenarios=["capacity-public-concurrent-reservation","capacity-public-idempotency-at-cap","capacity-public-refusal-atomic","capacity-public-distinct-ca","capacity-public-rejection-releases","capacity-public-cleanup"];
test("public issuance shares race-safe CA admission and terminal release",{timeout:120000},async t=>{
 const baseUrl=process.env.CERTOPS_CSR_API_URL;if(!baseUrl&&process.env.CERTOPS_E2E_REQUIRED!=="1"){
  // skip-reason: no-host - requires disposable API PostgreSQL with default per-CA cap five
  t.skip("Disposable API and PostgreSQL required");return;
 }
 assert.ok(baseUrl);const fixture=await createApiFixture(baseUrl);let ready=false,failure;const gate=createHostGate({suite:"ca-capacity-api",evidenceLevel:"integration",strict:true,reportPath:process.env.CERTOPS_CA_CAPACITY_REPORT,requiredCapabilities:["api","postgres"],fixtureSource:{file:"tests/e2e/certops-ca-capacity-e2e.test.js",sha256:crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex")},probeCapabilities:()=>({api:{available:true},postgres:{available:true}})});gate.report.executionScope="Actual public pending-approval issuance admission under default cap five; no CA requests, native execution, fake terminal results or scheduler capacity claims";
 const prefix=`/api/v1/workspaces/${fixture.workspaceId}/certops`,requests=[],jobs=[];
 const counts=async()=>(await fixture.pool.query("SELECT (SELECT count(*)::int FROM certificate_jobs WHERE workspace_id=$1) jobs,(SELECT count(*)::int FROM managed_certificates WHERE workspace_id=$1) certificates,(SELECT count(*)::int FROM certops_outbox WHERE workspace_id=$1) intents",[fixture.workspaceId])).rows[0];
 function input(index,endpoint="https://ca-capacity.invalid/directory"){return{operation:"issue",idempotencyKey:crypto.randomUUID(),payload:{sans:[`capacity-${index}.example.test`],target:{type:"domain",reference:`capacity-${index}.example.test`},certPath:`/owned-qualification/capacity-${index}.crt`,commandRef:"certbot",caEndpoint:endpoint,acmeKind:"certbot",dnsProvider:"cloudflare",dnsZone:"example.test"}};}
 try{assert.equal(await gate.preflight(),true);ready=true;assert.equal((await fixture.request(`${prefix}/settings`,"PUT",{certOpsRequireApprovalAlways:true,reason:"Owned public capacity admission fixture"})).status,200);
 await gate.scenario(scenarios[0],async()=>{for(let i=0;i<6;i++)requests.push(input(i));const outcomes=await Promise.all(requests.map(body=>fixture.request(`${prefix}/jobs`,"POST",body)));assert.equal(outcomes.filter(row=>row.status===201).length,5);assert.equal(outcomes.filter(row=>row.status===409&&row.body.code==="CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED").length,1);for(let i=0;i<outcomes.length;i++)if(outcomes[i].status===201){jobs.push({input:requests[i],job:outcomes[i].body.job});assert.equal(outcomes[i].body.job.status,"pending_approval");}assert.equal((await counts()).jobs,5);});
 await gate.scenario(scenarios[1],async()=>{const before=await counts(),replayed=await fixture.request(`${prefix}/jobs`,"POST",jobs[0].input);assert.equal(replayed.status,201);assert.equal(replayed.body.job.id,jobs[0].job.id);assert.deepEqual(await counts(),before);});
 await gate.scenario(scenarios[2],async()=>{const before=await counts(),denied=await fixture.request(`${prefix}/jobs`,"POST",input(10,"https://CA-CAPACITY.invalid/directory/"));assert.equal(denied.status,409);assert.equal(denied.body.code,"CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED");assert.deepEqual(await counts(),before);});
 await gate.scenario(scenarios[3],async()=>{const created=await fixture.request(`${prefix}/jobs`,"POST",input(11,"https://different-ca.invalid/directory"));assert.equal(created.status,201);assert.equal(created.body.job.status,"pending_approval");assert.equal((await counts()).jobs,6);});
 await gate.scenario(scenarios[4],async()=>{const rejected=await fixture.request(`${prefix}/jobs/${jobs[0].job.id}/reject`,"POST",{reason:"Owned requester withdraws pending issuance"});assert.equal(rejected.status,200);assert.equal((await fixture.pool.query("SELECT status FROM certificate_jobs WHERE id=$1",[jobs[0].job.id])).rows[0].status,"rejected");const created=await fixture.request(`${prefix}/jobs`,"POST",input(12));assert.equal(created.status,201);assert.equal(created.body.job.status,"pending_approval");assert.equal((await counts()).jobs,7);});
 }catch(error){failure=error;}
 finally{try{if(ready){await gate.scenario(scenarios.at(-1),fixture.cleanup);await gate.finish({requiredScenarios:scenarios});}else await fixture.cleanup();}catch(error){failure=failure?new AggregateError([failure,error],"Public capacity and cleanup failed"):error;}if(failure)throw failure;}
});

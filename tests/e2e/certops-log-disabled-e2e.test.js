/**
 * Supporting API/PostgreSQL qualification: missing log capability produces explicit disabled offer without inventing job completion.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * The registered fixture sends genuine machine-protocol requests; it does not run
 * an installed native agent. Named strict reports and owned cleanup are mandatory. */
"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),crypto=require("node:crypto");
const {createApiFixture}=require("./helpers/certops-api-fixture"),{createRegisteredAgent}=require("./helpers/certops-registered-agent"),{createHostGate}=require("../../packages/agent/scripts/host-gate");
test("missing log capability produces explicit disabled offer without inventing job completion",{timeout:120000},async t=>{
 const baseUrl=process.env.CERTOPS_CSR_API_URL;
 if(!baseUrl&&process.env.CERTOPS_E2E_REQUIRED!=="1"){
  // skip-reason: no-host - requires disposable API PostgreSQL and genuine agent claim negotiation
  t.skip("Disposable API URL required");return;
 }
 assert.ok(baseUrl);const fixture=await createApiFixture(baseUrl);let ready=false,failure;
 const scenarios=["log-disabled-offer","log-disabled-ingest","log-disabled-truthful-state","log-disabled-new-capability-offer","log-disabled-old-attempt-stays-disabled","log-disabled-cleanup"];
 const gate=createHostGate({suite:"agent-log-disabled-api",evidenceLevel:"integration",strict:process.env.CERTOPS_E2E_REQUIRED==="1",reportPath:process.env.CERTOPS_LOG_DISABLED_REPORT,requiredCapabilities:["api","postgres"],fixtureSource:{file:"tests/e2e/certops-log-disabled-e2e.test.js",sha256:crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex")},probeCapabilities:()=>({api:{available:true},postgres:{available:true}})});
 try{
  assert.equal(await gate.preflight(),true);ready=true;const agent=await createRegisteredAgent(fixture,baseUrl);const prefix=`/api/v1/workspaces/${fixture.workspaceId}/certops`;
  const create=async()=>{const created=await fixture.request(`${prefix}/jobs`,"POST",{operation:"noop"});assert.equal(created.status,201);const claim=await agent.machine("jobs/claim","claim",{maxJobs:1,supportedActions:["noop"]});assert.equal(claim.status,200);const job=claim.body.jobs.find(item=>(item.jobId||item.id)===created.body.job.id);assert.ok(job);return{jobId:created.body.job.id,claimId:String(job.claimId),offer:claim.body.logStreams[0]};};
  let first,second;
  const send=item=>agent.machine(`jobs/${item.jobId}/logs`,"log",{jobId:item.jobId,claimId:item.claimId,final:false,firstSeq:1,lines:[{seq:1,ts:new Date().toISOString(),level:"info",step:"verify",message:"Public disabled-stream diagnostic"}]});
  const read=item=>fixture.request(`${prefix}/jobs/${item.jobId}/agent-log`);
  await gate.scenario(scenarios[0],async()=>{first=await create();assert.equal(first.offer.enabled,false);});
  await gate.scenario(scenarios[1],async()=>{const response=await send(first);assert.equal(response.status,200);assert.equal(response.body.streamDisabled,true);assert.equal(response.body.newlyStored,0);assert.deepEqual((await read(first)).body.items,[]);});
  await gate.scenario(scenarios[2],async()=>{const response=await read(first);assert.equal(response.body.jobStatus,"claimed");assert.equal(response.body.logsComplete,false);assert.equal(response.body.storageEnabled,true);assert.equal(response.body.streams.length,1);assert.equal(response.body.streams[0].status,"disabled");assert.equal(response.body.streams[0].streamingEnabled,false);},{oracle:"Actual claimed noop remains incomplete while its optional log stream is disabled; storage availability and execution state are independent"});
  await gate.scenario(scenarios[3],async()=>{assert.equal((await agent.machine("heartbeat","heartbeat",{agentVersion:"1.0.0",declaredCapabilities:["job-log-stream-v1"]})).status,200);second=await create();assert.equal(second.offer.enabled,true);const response=await send(second);assert.equal(response.status,200);assert.equal(response.body.newlyStored,1);assert.equal((await read(second)).body.items.length,1);});
  await gate.scenario(scenarios[4],async()=>{const response=await send(first);assert.equal(response.status,200);assert.equal(response.body.streamDisabled,true);assert.deepEqual((await read(first)).body.items,[]);assert.equal((await read(first)).body.jobStatus,"claimed");assert.equal((await read(second)).body.items.length,1);});
 }catch(error){failure=error;throw error;}
 finally{try{if(ready){await gate.scenario(scenarios.at(-1),fixture.cleanup);await gate.finish({requiredScenarios:scenarios});}else await fixture.cleanup();}catch(error){if(failure)throw new AggregateError([failure,error],"Disabled log negotiation and cleanup failed");throw error;}}
});

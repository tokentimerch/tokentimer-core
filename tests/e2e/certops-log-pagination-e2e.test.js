/**
 * Supporting API/PostgreSQL qualification: agent log cursor polling preserves live append and reconnect order.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * The registered fixture sends genuine machine-protocol requests; it does not run
 * an installed native agent. Named strict reports and owned cleanup are mandatory. */
"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),crypto=require("node:crypto");
const {createApiFixture}=require("./helpers/certops-api-fixture"),{createRegisteredAgent}=require("./helpers/certops-registered-agent"),{createHostGate}=require("../../packages/agent/scripts/host-gate");
test("agent log cursor polling preserves live append and reconnect order",{timeout:120000},async t=>{
 const baseUrl=process.env.CERTOPS_CSR_API_URL;
 if(!baseUrl&&process.env.CERTOPS_E2E_REQUIRED!=="1"){
  // skip-reason: no-host - requires disposable API PostgreSQL and actual agent log protocol
  t.skip("Disposable API URL required");return;
 }
 assert.ok(baseUrl);const fixture=await createApiFixture(baseUrl);let ready=false,failure;
 const scenarios=["log-page-initial","log-page-tail","log-page-empty-reconnect","log-page-live-append","log-page-closed-replay","log-page-cleanup"];
 const gate=createHostGate({suite:"agent-log-pagination-api",evidenceLevel:"integration",strict:process.env.CERTOPS_E2E_REQUIRED==="1",reportPath:process.env.CERTOPS_LOG_PAGINATION_REPORT,requiredCapabilities:["api","postgres"],fixtureSource:{file:"tests/e2e/certops-log-pagination-e2e.test.js",sha256:crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex")},probeCapabilities:()=>({api:{available:true},postgres:{available:true}})});
 try{
  assert.equal(await gate.preflight(),true);ready=true;const agent=await createRegisteredAgent(fixture,baseUrl,["job-log-stream-v1"]);const {jobId,claimId}=await agent.claimNoop();
  const lines=Array.from({length:6},(_,index)=>({seq:index+1,ts:new Date().toISOString(),level:"info",step:"verify",message:`Public pagination line ${index+1}`}));
  const send=(batch,final=false)=>agent.machine(`jobs/${jobId}/logs`,"log",{jobId,claimId,lines:batch,final,...(batch.length?{firstSeq:batch[0].seq}:{})});
  const read=cursor=>fixture.request(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs/${jobId}/agent-log?limit=2${cursor?`&cursor=${encodeURIComponent(cursor)}`:""}`);
  let cursor;
  const initialBatch = await send(lines.slice(0,3)); assert.equal(initialBatch.status,200,`${initialBatch.body.code || "refused"}: ${initialBatch.body.error || "validation failed"}`);
  await gate.scenario(scenarios[0],async()=>{const page=await read();assert.equal(page.status,200);assert.deepEqual(page.body.items.map(item=>item.seq),[1,2]);assert.equal(page.body.hasMore,true);assert.ok(page.body.nextCursor);cursor=page.body.nextCursor;});
  await gate.scenario(scenarios[1],async()=>{const page=await read(cursor);assert.deepEqual(page.body.items.map(item=>item.seq),[3]);assert.equal(page.body.hasMore,false);assert.notEqual(page.body.nextCursor,cursor);cursor=page.body.nextCursor;});
  await gate.scenario(scenarios[2],async()=>{for(let index=0;index<2;index++){const page=await read(cursor);assert.deepEqual(page.body.items,[]);assert.equal(page.body.nextCursor,cursor);assert.equal(page.body.hasMore,false);}});
  await gate.scenario(scenarios[3],async()=>{assert.equal((await send(lines.slice(3))).status,200);const first=await read(cursor);assert.deepEqual(first.body.items.map(item=>item.seq),[4,5]);assert.equal(first.body.hasMore,true);const second=await read(first.body.nextCursor);assert.deepEqual(second.body.items.map(item=>item.seq),[6]);assert.equal(second.body.hasMore,false);cursor=second.body.nextCursor;assert.equal((await fixture.pool.query("SELECT status FROM certificate_jobs WHERE id=$1",[jobId])).rows[0].status,"claimed");},{oracle:"Fresh authenticated HTTP polls reuse the returned opaque cursor across empty pages and actual newly ingested batches; no browser transport or process logs are simulated as execution"});
  await gate.scenario(scenarios[4],async()=>{const replay=await send(lines);assert.equal(replay.status,200);assert.equal(replay.body.newlyStored,0);assert.equal((await send([],true)).status,200);const page=await read(cursor);assert.deepEqual(page.body.items,[]);assert.equal(page.body.nextCursor,cursor);assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certops_agent_job_log WHERE workspace_id=$1 AND job_id=$2",[fixture.workspaceId,jobId])).rows[0].count,6);});
 }catch(error){failure=error;throw error;}
 finally{try{if(ready){await gate.scenario(scenarios.at(-1),fixture.cleanup);await gate.finish({requiredScenarios:scenarios});}else await fixture.cleanup();}catch(error){if(failure)throw new AggregateError([failure,error],"Log pagination and cleanup failed");throw error;}}
});

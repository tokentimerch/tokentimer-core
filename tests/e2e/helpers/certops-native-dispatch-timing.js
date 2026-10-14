"use strict";
/* Real Linux agent timing qualification for certops-native-agent-e2e.test.js.
 * An owned transport delays a genuine claim signed by the production signer
 * with an explicit two-second fixture lifetime. Actual monotonic/host/database
 * clocks advance normally; no persisted dates, journal phases or successful
 * outcomes are rewritten. This does not qualify stock long-lived dispatches,
 * host clock changes, or Windows SCM timing. The parent owns child/API cleanup. */
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const SCENARIO="native-agent-real-elapsed-dispatch-expiry";
function verifyTimingFacts(facts){
 assert.equal(facts.fixtureLifetimeSeconds,2);assert.equal(facts.localToleranceMs,1);assert.ok(Number.isFinite(facts.heldMonotonicMs)&&facts.heldMonotonicMs>=5000&&facts.heldMonotonicMs<=60000);assert.ok(Number.isFinite(facts.originalDispatchLifetimeSeconds)&&facts.originalDispatchLifetimeSeconds>2&&facts.originalDispatchLifetimeSeconds<=86400);
 for(const field of ["issuedAt","expiresAt","releasedAt"])assert.ok(Number.isFinite(Date.parse(facts[field])));
 assert.equal(Date.parse(facts.expiresAt)-Date.parse(facts.issuedAt),2000);assert.ok(Date.parse(facts.releasedAt)>Date.parse(facts.expiresAt)+1000);
 assert.equal(facts.clocks,"actual-host-monotonic-and-database");assert.equal(facts.fixture,"production-signer-short-lifetime-and-delayed-HTTP-delivery");assert.equal(facts.databaseDatesRewritten,false);assert.equal(facts.journalRewritten,false);
 for(const field of ["nativeClockRefusalObserved","executionSuccessAbsent","nonceUnconsumed","freshClaimRecoverySucceeded","credentialAndPinUnchanged"])assert.equal(facts[field],true);
 assert.equal(facts.leaseCallsBeforeRefusal,0);assert.equal(facts.expiredNonceResultStatus,409);assert.equal(facts.expiredNonceResultCode,"CERTOPS_AGENT_RESULT_NONCE_REJECTED");assert.equal(facts.actualServerJobState,"claimed");assert.equal(facts.actualRejectedOutbox,"dead-letter");assert.equal(facts.qualificationScope,"native-Linux-shortened-dispatch-fixture-not-stock-TTL-or-Windows-SCM");return true;
}
function decode(envelope){return envelope.envelopeVersion===2?JSON.parse(Buffer.from(envelope.payloadB64,"base64").toString("utf8")):envelope;}
function createNativeDispatchTiming(context){
 const {fixture,agentRow,configDir,stop,start,wait,row,create,counters,getClockRejections}=context;
 let armed=false,proof=null,resultRefusal=null,transportFailure=null,stage="idle";
 function observedReply(url,request,status,bytes){
  if(proof&&url.endsWith("/results")&&request.messageType==="result"&&request.body?.jobId===proof.jobId){
   const response=JSON.parse(bytes.toString("utf8"));resultRefusal={status,code:response.code};
  }
 }
 async function replied(url,status,bytes,respond){
  if(!armed||!url.endsWith("/claim")||status!==200)return false;
  const envelope=JSON.parse(bytes.toString("utf8"));if(!envelope.jobs?.length)return false;assert.equal(envelope.jobs.length,1);armed=false;
  stage="claimed";const original=envelope.jobs[0],payload=decode(original);assert.equal(payload.action,"noop");
  const agent=await agentRow();assert.ok(agent?.id);
  stage="signing";const signed=await require("../../../apps/api/services/certops/jobSigning").signJobForDispatch({client:fixture.pool,job:payload,workspaceId:fixture.workspaceId,agentId:agent.id,nonceTtlSeconds:2,envelopeVersion:original.envelopeVersion===2?2:1});
  stage="signed";const current=decode(signed);for(const field of ["jobId","claimId","attemptId","agentId","action"])assert.equal(current[field],payload[field]);
  assert.equal(Date.parse(current.expiresAt)-Date.parse(current.issuedAt),2000);
  const persisted=(await fixture.pool.query("SELECT expires_at,consumed_at FROM certops_consumed_nonces WHERE workspace_id=$1 AND job_id=$2 AND nonce=$3",[fixture.workspaceId,current.jobId,current.nonce])).rows[0];assert.ok(persisted);assert.equal(persisted.expires_at instanceof Date?persisted.expires_at.getTime():Date.parse(persisted.expires_at),Date.parse(current.expiresAt));assert.equal(persisted.consumed_at,null);
  stage="holding";const started=process.hrtime.bigint();await new Promise(resolve=>setTimeout(resolve,5000));
  const elapsedMs=Number(process.hrtime.bigint()-started)/1e6,releasedAt=new Date().toISOString();assert.ok(elapsedMs>=5000);assert.ok(Date.parse(releasedAt)>Date.parse(current.expiresAt)+1000);
  proof={jobId:current.jobId,nonce:current.nonce,heldMonotonicMs:elapsedMs,signedLifetimeSeconds:2,originalDispatchLifetimeSeconds:(Date.parse(payload.expiresAt)-Date.parse(payload.issuedAt))/1000,issuedAt:current.issuedAt,expiresAt:current.expiresAt,releasedAt};
  stage="delivered";envelope.jobs=[signed];respond(status,Buffer.from(JSON.stringify(envelope)),{date:new Date().toUTCString()});return true;
 }
 async function qualify(gate){
  await gate.scenario(SCENARIO,async()=>{
   assert.equal(process.platform,"linux");assert.equal(process.env.CERTOPS_NATIVE_AGENT_DISPOSABLE_STACK,"1");
   const configPath=path.join(configDir,"config.json"),original=fs.readFileSync(configPath),hash=file=>crypto.createHash("sha256").update(fs.readFileSync(path.join(configDir,file))).digest("hex");
   const identity=["credential","signing-key-pin.json"].map(hash),before=getClockRejections();let id,primary;
   try{
    await stop();const config=JSON.parse(original);config.execution.clockDriftToleranceMs=1;fs.writeFileSync(configPath,JSON.stringify(config),{mode:0o600});start();await wait(async()=>Boolean(await agentRow()));
    armed=true;stage="armed";id=await create();await wait(()=>{if(transportFailure)throw new Error(`Native timing transport failed at ${stage}: ${transportFailure}`);return proof?.jobId===id;},30000);await wait(()=>getClockRejections()>before,30000);
    await wait(()=>resultRefusal?.status===409&&resultRefusal.code==="CERTOPS_AGENT_RESULT_NONCE_REJECTED",30000);
    const {listDeadLetterEntries}=require("../../../packages/agent/src/outbox");let cached;
    await wait(()=>{cached=listDeadLetterEntries(path.join(configDir,"outbox")).find(entry=>entry.result.jobId===id);return Boolean(cached);},60000);
    assert.equal(cached.result.status,"rejected");assert.equal(cached.result.rejectionReason,"clock_drift_suspected");assert.equal(counters.get(id)?.leases||0,0);
    const observed=await row(id);assert.equal(observed.status,"claimed");assert.equal(observed.attempt_count,1);
    const evidence=(await fixture.pool.query("SELECT evidence_type FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2",[fixture.workspaceId,id])).rows;assert.ok(evidence.every(item=>item.evidence_type==="policy.checked"));
    const replayPath=path.join(configDir,"replay-store.json");if(fs.existsSync(replayPath))assert.equal(JSON.parse(fs.readFileSync(replayPath,"utf8")).entries.some(entry=>entry.jobId===id),false);
    const nonce=(await fixture.pool.query("SELECT consumed_at,expires_at<NOW() AS actually_expired FROM certops_consumed_nonces WHERE workspace_id=$1 AND job_id=$2 AND nonce=$3",[fixture.workspaceId,id,proof.nonce])).rows[0];assert.equal(nonce.actually_expired,true);assert.equal(nonce.consumed_at,null);
   }catch(error){gate.report.nativeDispatchTimingDiagnostics={stage,transportFailure,proofDelivered:Boolean(proof),clockRefusals:getClockRejections()-before,resultRefusalStatus:resultRefusal?.status||null,resultRefusalCode:resultRefusal?.code||null};primary=error;throw error;}finally{
    armed=false;try{await stop();fs.writeFileSync(configPath,original,{mode:0o600});start();}catch(error){if(primary)throw new AggregateError([primary,error],"Native timing case and exact configuration restoration failed");throw error;}
   }
   const recovery=await create();await wait(async()=>(await row(recovery)).status==="succeeded",60000);assert.deepEqual(["credential","signing-key-pin.json"].map(hash),identity);
   gate.report.nativeDispatchTiming={fixtureLifetimeSeconds:2,localToleranceMs:1,heldMonotonicMs:proof.heldMonotonicMs,originalDispatchLifetimeSeconds:proof.originalDispatchLifetimeSeconds,issuedAt:proof.issuedAt,expiresAt:proof.expiresAt,releasedAt:proof.releasedAt,clocks:"actual-host-monotonic-and-database",fixture:"production-signer-short-lifetime-and-delayed-HTTP-delivery",databaseDatesRewritten:false,journalRewritten:false,nativeClockRefusalObserved:true,leaseCallsBeforeRefusal:0,executionSuccessAbsent:true,expiredNonceResultStatus:409,expiredNonceResultCode:resultRefusal.code,actualServerJobState:"claimed",actualRejectedOutbox:"dead-letter",nonceUnconsumed:true,freshClaimRecoverySucceeded:true,credentialAndPinUnchanged:true,qualificationScope:"native-Linux-shortened-dispatch-fixture-not-stock-TTL-or-Windows-SCM"};
   verifyTimingFacts(gate.report.nativeDispatchTiming);
   const file="tests/e2e/helpers/certops-native-dispatch-timing.js";gate.report.fixtureSources??=[];gate.report.fixtureSources.push({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex")});
  },{evidenceLevel:"e2e",oracle:"actual signed expiry and monotonic transport delay; native clock rejection before lease/execution, real expired-nonce HTTP409/dead-letter and fresh same-identity recovery"});
 }
 return {replied,observedReply,qualify,failed:error=>{if(armed||stage!=="idle")transportFailure=/^[A-Z0-9_]{1,96}$/.test(error?.code||"")?error.code:"UNCLASSIFIED";}};
}
module.exports={SCENARIO,createNativeDispatchTiming,verifyTimingFacts};

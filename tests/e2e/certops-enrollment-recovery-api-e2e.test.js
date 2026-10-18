/**
 * Supporting API/PostgreSQL qualification: AD CS installation retry through real API and PostgreSQL.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * Public requests and persisted rows are the oracle; prerequisite state is isolated.
 * Native certificate deployment is qualified separately; strict reports and cleanup apply. */
"use strict";
const {test}=require("node:test");
const assert=require("node:assert/strict");
const crypto=require("node:crypto");
const fs=require("node:fs");
const {createApiFixture}=require("./helpers/certops-api-fixture");
const {createHostGate}=require("../../packages/agent/scripts/host-gate");
const {freezeSnapshot}=require("../../apps/api/services/certops/enrollmentLifecycle");
const required=["adcs-install-retry-api-boundaries","adcs-install-retry-api-concurrent-provenance","adcs-install-retry-api-approval-policy",
  "adcs-orphan-recovery-api-acknowledgement","adcs-orphan-recovery-api-concurrent-provenance","adcs-orphan-recovery-api-approval-and-rbac","adcs-orphan-recovery-api-terminal-refusal","adcs-install-retry-api-cleanup","adcs-original-enrollment-api-requester-approval","adcs-recovery-api-worker-principal-refused"];
test("AD CS installation retry through real API and PostgreSQL",{timeout:120000},async t=>{
  const url=process.env.CERTOPS_CSR_API_URL;
  if(!url&&process.env.CERTOPS_E2E_REQUIRED!=="1"){
    // skip-reason: no-host - requires isolated real API and PostgreSQL
    t.skip("Disposable API URL required");return;
  }
  assert.ok(url);const fixture=await createApiFixture(url);let primaryError;
  const gate=createHostGate({suite:"adcs-installation-recovery-api",strict:process.env.CERTOPS_E2E_REQUIRED==="1",
    reportPath:process.env.CERTOPS_ADCS_INSTALL_RECOVERY_API_REPORT,evidenceLevel:"integration",requiredCapabilities:["api","postgres"],probeCapabilities:()=>({api:{available:true},postgres:{available:true}}),
    fixtureSource:{file:"tests/e2e/certops-enrollment-recovery-api-e2e.test.js",sha256:crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex")}});
  gate.report.fixtureTraffic="Seeded confirmed issuer, failed-installation/orphaned-job server prerequisites and protocol-only Windows registration; no native CA, CNG, SCM or certificate execution claim";
  const api=`/api/v1/workspaces/${fixture.workspaceId}/certops`;let issuerId,agentDbId;
  const seed=[];
  async function failedEnrollment(){
    const id=crypto.randomUUID(),certificateId=crypto.randomUUID();const frozen=freezeSnapshot({issuerId,issuerVersion:1,caConfig:"ca.invalid\\API fixture",caKeySha256:"ab".repeat(32),template:"APIOnly",authorizedDnsNames:["retry.api.example.test"],keyAlgorithm:"rsa",keySize:2048});
    const target={type:"windows-iis",reference:"retry.api.example.test",store:"My",binding:{site:"API-only fixture",port:443}};
    await fixture.pool.query(`INSERT INTO certificate_enrollments(id,workspace_id,certificate_id,issuer_id,issuer_version,agent_id,state,attempt,snapshot_bytes,snapshot_sha256,deploy_target,request_id)
      VALUES($1,$2,$3,$4,1,$5,'install_failed',1,$6,$7,$8::jsonb,42)`,[id,fixture.workspaceId,certificateId,issuerId,agentDbId,frozen.bytes,frozen.sha256,JSON.stringify(target)]);
    seed.push(id);return {id,certificateId,frozen,target};
  }
  async function orphanedEnrollment(state="issued"){
    const row=await failedEnrollment();
    const admitted=await fixture.request(`${api}/enrollments/${row.id}/retry-installation`,"POST",{});assert.equal(admitted.status,201);
    // This is an explicit real API/DB boundary fixture, not native crash proof.
    await fixture.pool.query("UPDATE certificate_jobs SET status='orphaned_unknown_effect',needs_operator_reconciliation=true WHERE id=$1",[admitted.body.jobId]);
    await fixture.pool.query("UPDATE certificate_enrollments SET state=$2 WHERE id=$1",[row.id,state]);
    return {...row,orphanedJobId:admitted.body.jobId};
  }
  const recoveryBody=row=>({orphanedJobId:row.orphanedJobId,acknowledgeUnknownEffect:true,reason:"Operator inspected this isolated API prerequisite; resume only its frozen enrollment"});
  try{
    await gate.preflight();
    const issuer=await fixture.request(`${api}/issuers`,"POST",{kind:"adcs",name:"API retry fixture"});assert.equal(issuer.status,201);issuerId=issuer.body.issuer.id;
    await fixture.pool.query("INSERT INTO certificate_issuer_versions(workspace_id,issuer_id,version,ca_config,template,ca_key_sha256,confirmed_at) VALUES($1,$2,1,$3,'APIOnly',$4,NOW())",[fixture.workspaceId,issuerId,"ca.invalid\\API fixture","ab".repeat(32)]);
    await fixture.pool.query("UPDATE certificate_issuers SET current_version=1 WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,issuerId]);
    const bootstrap=await fixture.request(`${api}/agent-bootstrap-tokens`,"POST",{name:"Protocol-only retry API prerequisite",expiresAt:new Date(Date.now()+3600000).toISOString()});assert.equal(bootstrap.status,201);
    const agentId=crypto.randomUUID();const registered=await fetch(new URL("/api/v1/certops/agent/register",url),{method:"POST",signal:AbortSignal.timeout(15000),headers:{"content-type":"application/json",authorization:`Bearer ${bootstrap.body.plaintextToken}`},body:JSON.stringify({schemaVersion:1,protocolVersion:"1.0.0",messageType:"register",agentId,sentAt:new Date().toISOString(),body:{bootstrapTokenId:bootstrap.body.token.id,registrationId:crypto.randomUUID(),hostname:"api-prerequisite-only",platform:"win32",agentVersion:"1.0.0",declaredCapabilities:[]}})});assert.equal(registered.status,201);
    agentDbId=(await fixture.pool.query("SELECT id FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",[fixture.workspaceId,agentId])).rows[0].id;
    await gate.scenario(required[8],async()=>{
      await fixture.pool.query("UPDATE workspaces SET certops_require_approval_always=true WHERE id=$1",[fixture.workspaceId]);
      try{
        const admitted=await fixture.request(`${api}/enrollments`,"POST",{issuerId,certificateId:crypto.randomUUID(),agentId:agentDbId,
          target:{type:"windows-iis",reference:"retry.api.example.test",store:"My",binding:{site:"API-only fixture",port:443}},authorizedDnsNames:["retry.api.example.test"],keyAlgorithm:"rsa",keySize:2048});
        assert.equal(admitted.status,201,`Original enrollment API status ${admitted.status}: ${admitted.body.code||"unknown"}`);seed.push(admitted.body.enrollmentId);
        const job=(await fixture.pool.query("SELECT operation,status,source,requested_by_user_id FROM certificate_jobs WHERE id=$1",[admitted.body.jobId])).rows[0];
        assert.equal(job.operation,"renew");assert.equal(job.source,"api");assert.equal(job.status,"pending_approval");assert.equal(String(job.requested_by_user_id),String(fixture.userId));
        const refused=await fixture.request(`${api}/jobs/${admitted.body.jobId}/approve`,"POST",{});assert.ok(refused.status>=400,"Original enrollment requester must not approve their own job");
      }finally{await fixture.pool.query("UPDATE workspaces SET certops_require_approval_always=false WHERE id=$1",[fixture.workspaceId]);}
    });
    await gate.scenario(required[0],async()=>{
      const row=await failedEnrollment();const route=`${api}/enrollments/${row.id}/retry-installation`;
      const bad=await fixture.request(route,"POST",{agentId:crypto.randomUUID()});assert.equal(bad.status,400);assert.equal(bad.body.code,"CERTOPS_SNAPSHOT_INVALID");
      assert.equal((await fixture.request(`${api}/enrollments/${crypto.randomUUID()}/retry-installation`,"POST",{})).status,404);
      await fixture.pool.query("UPDATE workspaces SET certops_paused=true WHERE id=$1",[fixture.workspaceId]);
      try{const paused=await fixture.request(route,"POST",{});assert.equal(paused.status,400);assert.equal(paused.body.code,"CERTOPS_WORKSPACE_PAUSED");}finally{await fixture.pool.query("UPDATE workspaces SET certops_paused=false WHERE id=$1",[fixture.workspaceId]);}
      await fixture.pool.query("UPDATE workspace_memberships SET role='viewer' WHERE workspace_id=$1 AND user_id=$2",[fixture.workspaceId,fixture.userId]);
      try{assert.equal((await fixture.request(route,"POST",{})).status,403);}finally{await fixture.pool.query("UPDATE workspace_memberships SET role='admin' WHERE workspace_id=$1 AND user_id=$2",[fixture.workspaceId,fixture.userId]);}
      assert.equal(Number((await fixture.pool.query("SELECT count(*)::int AS n FROM certificate_jobs WHERE enrollment_id=$1",[row.id])).rows[0].n),0);
    });
    await gate.scenario(required[1],async()=>{
      const row=await failedEnrollment();const results=await Promise.all(Array.from({length:4},()=>fixture.request(`${api}/enrollments/${row.id}/retry-installation`,"POST",{})));
      assert.equal(results.filter(result=>result.status===201).length,1);for(const result of results)assert.ok([200,201].includes(result.status),`Unexpected retry API status ${result.status}: ${result.body.code||"unknown"}`);
      const jobId=results.find(result=>result.status===201).body.jobId;assert.ok(results.every(result=>result.body.jobId===jobId));
      const jobs=(await fixture.pool.query("SELECT source,requested_by_user_id,assigned_agent_id,payload,status FROM certificate_jobs WHERE workspace_id=$1 AND enrollment_id=$2",[fixture.workspaceId,row.id])).rows;assert.equal(jobs.length,1);
      assert.equal(jobs[0].source,"api");assert.equal(String(jobs[0].requested_by_user_id),String(fixture.userId));assert.equal(jobs[0].assigned_agent_id,agentDbId);assert.deepEqual(jobs[0].payload.target,row.target);
      const enrollment=(await fixture.pool.query("SELECT state,attempt,snapshot_bytes,snapshot_sha256,request_id FROM certificate_enrollments WHERE id=$1",[row.id])).rows[0];assert.equal(enrollment.state,"install_failed");assert.equal(enrollment.attempt,2);assert.deepEqual(enrollment.snapshot_bytes,row.frozen.bytes);assert.equal(enrollment.snapshot_sha256,row.frozen.sha256);assert.equal(String(enrollment.request_id),"42");
      const audit=(await fixture.pool.query("SELECT actor_user_id,metadata FROM audit_events WHERE workspace_id=$1 AND action='certops.enrollment.installation_retry_requested' AND metadata->>'enrollmentId'=$2",[fixture.workspaceId,row.id])).rows;assert.equal(audit.length,1);assert.equal(String(audit[0].actor_user_id),String(fixture.userId));assert.equal(audit[0].metadata.jobId,jobId);
    });
    await gate.scenario(required[2],async()=>{
      await fixture.pool.query("UPDATE workspaces SET certops_require_approval_always=true WHERE id=$1",[fixture.workspaceId]);const row=await failedEnrollment();
      const result=await fixture.request(`${api}/enrollments/${row.id}/retry-installation`,"POST",{});assert.equal(result.status,201,`Retry approval API returned ${result.body.code||result.status}`);
      const job=(await fixture.pool.query("SELECT status,requested_by_user_id FROM certificate_jobs WHERE id=$1",[result.body.jobId])).rows[0];assert.equal(job.status,"pending_approval");assert.equal(String(job.requested_by_user_id),String(fixture.userId));
      const selfApproval=await fixture.request(`${api}/jobs/${result.body.jobId}/approve`,"POST",{});assert.ok(selfApproval.status>=400,"Requester must not approve their own gated retry");
    });
    await gate.scenario(required[3],async()=>{
      const row=await orphanedEnrollment();const route=`${api}/enrollments/${row.id}/recover`;
      for(const body of [{...recoveryBody(row),acknowledgeUnknownEffect:false},{...recoveryBody(row),reason:""},{...recoveryBody(row),reason:"x".repeat(501)},{...recoveryBody(row),agentId:crypto.randomUUID()}])assert.equal((await fixture.request(route,"POST",body)).status,400);
      await fixture.pool.query("UPDATE certificate_jobs SET needs_operator_reconciliation=false WHERE id=$1",[row.orphanedJobId]);
      try{assert.equal((await fixture.request(route,"POST",recoveryBody(row))).status,400);}finally{await fixture.pool.query("UPDATE certificate_jobs SET needs_operator_reconciliation=true WHERE id=$1",[row.orphanedJobId]);}
      assert.equal((await fixture.request(route,"POST",{...recoveryBody(row),orphanedJobId:crypto.randomUUID()})).status,400);
      assert.equal(Number((await fixture.pool.query("SELECT count(*)::int AS n FROM certificate_jobs WHERE enrollment_id=$1",[row.id])).rows[0].n),1);
    });
    await gate.scenario(required[4],async()=>{
      const row=await orphanedEnrollment();const body=recoveryBody(row);
      const results=await Promise.all(Array.from({length:4},()=>fixture.request(`${api}/enrollments/${row.id}/recover`,"POST",body)));
      assert.equal(results.filter(result=>result.status===201).length,1);for(const result of results)assert.ok([200,201].includes(result.status),`Recovery API status ${result.status}: ${result.body.code||"unknown"}`);
      const jobId=results.find(result=>result.status===201).body.jobId;assert.ok(results.every(result=>result.body.jobId===jobId));
      const job=(await fixture.pool.query("SELECT operation,source,requested_by_user_id,assigned_agent_id,enrollment_id,payload FROM certificate_jobs WHERE id=$1",[jobId])).rows[0];
      assert.equal(job.operation,"continue-enrollment");assert.equal(job.source,"api");assert.equal(String(job.requested_by_user_id),String(fixture.userId));assert.equal(job.assigned_agent_id,agentDbId);assert.equal(job.enrollment_id,row.id);assert.deepEqual(job.payload.target,row.target);
      const original=(await fixture.pool.query("SELECT status,needs_operator_reconciliation FROM certificate_jobs WHERE id=$1",[row.orphanedJobId])).rows[0];assert.equal(original.status,"orphaned_unknown_effect");assert.equal(original.needs_operator_reconciliation,true);
      const enrollment=(await fixture.pool.query("SELECT snapshot_bytes,snapshot_sha256,request_id FROM certificate_enrollments WHERE id=$1",[row.id])).rows[0];assert.deepEqual(enrollment.snapshot_bytes,row.frozen.bytes);assert.equal(enrollment.snapshot_sha256,row.frozen.sha256);assert.equal(String(enrollment.request_id),"42");
      const audit=(await fixture.pool.query("SELECT actor_user_id,metadata FROM audit_events WHERE workspace_id=$1 AND action='certops.enrollment.recovery_requested' AND metadata->>'enrollmentId'=$2",[fixture.workspaceId,row.id])).rows;assert.equal(audit.length,1);assert.equal(audit[0].metadata.orphanedJobId,row.orphanedJobId);assert.equal(audit[0].metadata.acknowledgeUnknownEffect,true);assert.equal(String(audit[0].actor_user_id),String(fixture.userId));
    });
    await gate.scenario(required[5],async()=>{
      const row=await orphanedEnrollment();const route=`${api}/enrollments/${row.id}/recover`;
      await fixture.pool.query("UPDATE workspace_memberships SET role='viewer' WHERE workspace_id=$1 AND user_id=$2",[fixture.workspaceId,fixture.userId]);
      try{assert.equal((await fixture.request(route,"POST",recoveryBody(row))).status,403);}finally{await fixture.pool.query("UPDATE workspace_memberships SET role='admin' WHERE workspace_id=$1 AND user_id=$2",[fixture.workspaceId,fixture.userId]);}
      await fixture.pool.query("UPDATE workspaces SET certops_paused=true WHERE id=$1",[fixture.workspaceId]);
      try{const paused=await fixture.request(route,"POST",recoveryBody(row));assert.equal(paused.status,400);assert.equal(paused.body.code,"CERTOPS_WORKSPACE_PAUSED");}finally{await fixture.pool.query("UPDATE workspaces SET certops_paused=false WHERE id=$1",[fixture.workspaceId]);}
      const result=await fixture.request(route,"POST",recoveryBody(row));assert.equal(result.status,201);
      assert.equal((await fixture.pool.query("SELECT status FROM certificate_jobs WHERE id=$1",[result.body.jobId])).rows[0].status,"pending_approval");
      assert.ok((await fixture.request(`${api}/jobs/${result.body.jobId}/approve`,"POST",{})).status>=400);
    });
    await gate.scenario(required[6],async()=>{
      for(const state of ["installed","cancelled","expired","denied","install_failed"]){const row=await orphanedEnrollment(state);const result=await fixture.request(`${api}/enrollments/${row.id}/recover`,"POST",recoveryBody(row));assert.equal(result.status,400);assert.equal(result.body.code,"CERTOPS_ENROLLMENT_TRANSITION_INVALID");}
    });
    await gate.scenario(required[9],async()=>{
      const key=process.env.CERTOPS_API_WORKER_FIXTURE_KEY;assert.ok(typeof key==="string"&&key.length,"Explicit disposable API worker-key prerequisite required");
      const failed=await failedEnrollment();const orphan=await orphanedEnrollment();
      for(const [route,body] of [[`${api}/enrollments/${failed.id}/retry-installation`,{}],[`${api}/enrollments/${orphan.id}/recover`,recoveryBody(orphan)]]){
        const denied=await fixture.request(route,"POST",body,{authorization:`Bearer ${key}`});
        assert.equal(denied.status,403);assert.equal(denied.body.code,"INSUFFICIENT_ROLE");
      }
      assert.equal(Number((await fixture.pool.query("SELECT count(*)::int AS n FROM certificate_jobs WHERE enrollment_id=$1",[failed.id])).rows[0].n),0);
      assert.equal(Number((await fixture.pool.query("SELECT count(*)::int AS n FROM certificate_jobs WHERE enrollment_id=$1",[orphan.id])).rows[0].n),1);
    });
  }catch(error){primaryError=error;throw error;}finally{
    try{await gate.scenario(required[7],async()=>{for(const id of seed)await fixture.pool.query("DELETE FROM certificate_jobs WHERE enrollment_id=$1",[id]);await fixture.cleanup();});await gate.finish({requiredScenarios:required});}
    catch(error){if(primaryError)throw new AggregateError([primaryError,error],"Recovery API fixture and finalization failed");throw error;}
  }
});

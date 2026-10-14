/**
 * Supporting API/PostgreSQL qualification: public AD CS enrollment policy bounds and immutable snapshots.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * The registered fixture sends genuine machine-protocol requests; it does not run
 * an installed native agent. Named strict reports and owned cleanup are mandatory. */
"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict"),crypto=require("node:crypto"),fs=require("node:fs");
const {createApiFixture}=require("./helpers/certops-api-fixture");
const {createRegisteredAgent}=require("./helpers/certops-registered-agent");
const {createHostGate}=require("../../packages/agent/scripts/host-gate");
const IDS=["adcs-policy-api-immutable-defaults","adcs-policy-api-bounded-options","adcs-policy-api-invalid-atomic","adcs-policy-api-cancel-preserves-snapshot","adcs-policy-api-cleanup","adcs-policy-api-native-request-id-distinct-from-operator-hint"];
test("public AD CS enrollment policy bounds and immutable snapshots",{timeout:120000},async t=>{
  const url=process.env.CERTOPS_CSR_API_URL;if(!url&&process.env.CERTOPS_E2E_REQUIRED!=="1"){
    // skip-reason: no-host - requires isolated authenticated API and PostgreSQL
    t.skip("Disposable API URL required");return;
  }
  assert.ok(url);const fixture=await createApiFixture(url);let primaryError;
  const gate=createHostGate({suite:"adcs-enrollment-policy-api",evidenceLevel:"integration",strict:process.env.CERTOPS_E2E_REQUIRED==="1",reportPath:process.env.CERTOPS_ADCS_POLICY_API_REPORT,fixtureSource:{file:"tests/e2e/certops-enrollment-policy-api-e2e.test.js",sha256:crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex")},requiredCapabilities:["api","postgres"],probeCapabilities:()=>({api:{available:true},postgres:{available:true}})});
  gate.report.fixtureTraffic="Seeded confirmed issuer and protocol-only Windows identity prerequisites; actual public enrollment/admission/cancellation and PostgreSQL snapshots, no native CA/CNG/SCM claim";
  const api=`/api/v1/workspaces/${fixture.workspaceId}/certops`;let issuerId,agentDbId,selected;
  const input=()=>({issuerId,certificateId:crypto.randomUUID(),agentId:agentDbId,target:{type:"windows-iis",reference:"policy.api.example.test",store:"My",binding:{site:"API policy-only fixture",port:443}},authorizedDnsNames:["policy.api.example.test"],keyAlgorithm:"rsa",keySize:2048});
  const stored=async id=>(await fixture.pool.query("SELECT state,snapshot_bytes,snapshot_sha256,current_job_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,id])).rows[0];
  const counts=async()=>({enrollments:Number((await fixture.pool.query("SELECT count(*) AS n FROM certificate_enrollments WHERE workspace_id=$1",[fixture.workspaceId])).rows[0].n),jobs:Number((await fixture.pool.query("SELECT count(*) AS n FROM certificate_jobs WHERE workspace_id=$1",[fixture.workspaceId])).rows[0].n)});
  try{
    await gate.preflight();const createdIssuer=await fixture.request(`${api}/issuers`,"POST",{kind:"adcs",name:"Policy API prerequisite"});assert.equal(createdIssuer.status,201);issuerId=createdIssuer.body.issuer.id;
    await fixture.pool.query("INSERT INTO certificate_issuer_versions(workspace_id,issuer_id,version,ca_config,template,ca_key_sha256,confirmed_at) VALUES($1,$2,1,$3,'PolicyAPIOnly',$4,NOW())",[fixture.workspaceId,issuerId,"ca.invalid\\API policy fixture","ab".repeat(32)]);await fixture.pool.query("UPDATE certificate_issuers SET current_version=1 WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,issuerId]);
    const agent=await createRegisteredAgent(fixture,url,[],{platform:"win32"});agentDbId=(await fixture.pool.query("SELECT id FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",[fixture.workspaceId,agent.agentId])).rows[0].id;
    await gate.scenario(IDS[0],async()=>{const admitted=await fixture.request(`${api}/enrollments`,"POST",input());assert.equal(admitted.status,201);const row=await stored(admitted.body.enrollmentId),snapshot=JSON.parse(row.snapshot_bytes);assert.equal(snapshot.pollInterval,900);assert.equal(snapshot.pendingTimeout,1209600);assert.equal(snapshot.minimumRemainingValidity,0);assert.equal(snapshot.requireLaterNotAfter,false);assert.equal(row.snapshot_sha256,admitted.body.snapshotSha256);assert.equal(crypto.createHash("sha256").update(row.snapshot_bytes).digest("hex"),row.snapshot_sha256);});
    await gate.scenario(IDS[1],async()=>{assert.equal((await fixture.request(`${api}/settings`,"PUT",{certOpsRequireApprovalAlways:true,reason:"Policy request approval provenance"})).status,200);const options={pollInterval:60,pendingTimeout:3600,minimumRemainingValidity:86400,requireLaterNotAfter:true};const admitted=await fixture.request(`${api}/enrollments`,"POST",{...input(),...options});assert.equal(admitted.status,201);selected={id:admitted.body.enrollmentId,row:await stored(admitted.body.enrollmentId)};const snapshot=JSON.parse(selected.row.snapshot_bytes);for(const [field,value] of Object.entries(options))assert.equal(snapshot[field],value);assert.equal(selected.row.snapshot_sha256,admitted.body.snapshotSha256);const job=(await fixture.pool.query("SELECT status,source,requested_by_user_id,assigned_agent_id,enrollment_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,admitted.body.jobId])).rows[0];assert.equal(job.status,"pending_approval");assert.equal(job.source,"api");assert.equal(String(job.requested_by_user_id),String(fixture.userId));assert.equal(job.assigned_agent_id,agentDbId);assert.equal(job.enrollment_id,selected.id);assert.equal((await fixture.request(`${api}/jobs/${admitted.body.jobId}/approve`,"POST",{reason:"Self approval refused"})).status,403);});
    await gate.scenario(IDS[2],async()=>{const before=await counts();for(const options of [{pollInterval:0},{pollInterval:59},{pollInterval:86401},{pollInterval:60.5},{pollInterval:"900"},{pollInterval:null},{pendingTimeout:3599},{pendingTimeout:7776001},{pendingTimeout:null},{minimumRemainingValidity:-1},{minimumRemainingValidity:31536001},{minimumRemainingValidity:"0"},{minimumRemainingValidity:null},{requireLaterNotAfter:"true"},{requireLaterNotAfter:1},{requireLaterNotAfter:null}]){const refused=await fixture.request(`${api}/enrollments`,"POST",{...input(),...options});assert.equal(refused.status,400);assert.equal(refused.body.code,"CERTOPS_SNAPSHOT_INVALID");}assert.deepEqual(await counts(),before);});
    await gate.scenario(IDS[5],async()=>{
      // Exercise the real persistence service with explicit protocol-only
      // result fixtures; no CA or installed-agent execution is claimed here.
      const service=require("../../apps/api/services/certops/certificateEnrollments");
      const make=async()=>{const admitted=await fixture.request(`${api}/enrollments`,"POST",input());assert.equal(admitted.status,201);const job=(await fixture.pool.query("SELECT id,enrollment_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,admitted.body.jobId])).rows[0];return {id:admitted.body.enrollmentId,job};};
      const record=async(row,state,requestId)=>service.recordEnrollmentResult(fixture.pool,{workspaceId:fixture.workspaceId,job:row.job,enrollmentResult:{enrollmentId:row.id,attempt:1,state,...(requestId===undefined?{}:{requestId})}});
      const ids=async row=>(await fixture.pool.query("SELECT state,request_id,operator_request_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,row.id])).rows[0];
      const normal=await make();for(const state of ["prepared","submitting"])await record(normal,state);await record(normal,"pending_issuance",42);
      assert.deepEqual(await ids(normal),{state:"pending_issuance",request_id:"42",operator_request_id:null});
      const nativeSource=fs.readFileSync(require.resolve("./helpers/certops-adcs-pending-elapsed"),"utf8");
      const actualOracle=nativeSource.match(/fixture\.pool\.query\("(SELECT [^"]+ FROM certificate_enrollments[^"]+)"/);assert.ok(actualOracle,"Actual native pending helper query must be independently exercised");
      const observed=(await fixture.pool.query(actualOracle[1],[fixture.workspaceId,normal.id])).rows[0];assert.equal(observed.request_id,"42","The real native first-wait oracle must read the CA-reported ID, not an unset operator hint");
      const wrongOracle=actualOracle[1].replace("state,request_id,","state,operator_request_id AS request_id,");assert.notEqual(wrongOracle,actualOracle[1]);assert.equal((await fixture.pool.query(wrongOracle,[fixture.workspaceId,normal.id])).rows[0].request_id,null,"A semantically wrong but SQL-valid alias cannot represent the reported native request ID");

      const uncertain=await make();for(const state of ["prepared","submitting","submission_uncertain"])await record(uncertain,state);
      assert.equal((await fixture.request(`${api}/enrollments/${uncertain.id}/reconcile`,"POST",{requestId:99})).status,204);
      assert.deepEqual(await ids(uncertain),{state:"submission_uncertain",request_id:null,operator_request_id:"99"});
      await record(uncertain,"issued",42);
      assert.deepEqual(await ids(uncertain),{state:"issued",request_id:"42",operator_request_id:"99"});
      gate.report.requestIdentityQualification={persistence:"actual-production-service-and-postgresql",operatorHint:"actual-public-reconcile-route",reportedNativeRequestId:42,operatorCandidateRequestId:99,distinctColumnsVerified:true,nativeExecution:false};
    });
    await gate.scenario(IDS[3],async()=>{assert.equal((await fixture.request(`${api}/enrollments/${selected.id}/cancel`,"POST",{})).status,204);const after=await stored(selected.id);assert.equal(after.state,"cancelled");assert.ok(after.snapshot_bytes.equals(selected.row.snapshot_bytes));assert.equal(after.snapshot_sha256,selected.row.snapshot_sha256);assert.equal(after.current_job_id,selected.row.current_job_id);assert.equal((await fixture.pool.query("SELECT status FROM certificate_jobs WHERE id=$1",[after.current_job_id])).rows[0].status,"cancelled");});
  }catch(error){primaryError=error;throw error;}finally{try{await gate.scenario(IDS[4],()=>fixture.cleanup());await gate.finish({requiredScenarios:IDS});}catch(error){if(primaryError)throw new AggregateError([primaryError,error],"Enrollment policy API and cleanup failed");throw error;}}
});

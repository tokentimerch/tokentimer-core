"use strict";
const test=require("node:test"),assert=require("node:assert/strict"),crypto=require("node:crypto");
assert.equal(process.env.DB_HOST,"127.0.0.1");assert.match(process.env.DB_NAME || "",/^distribution_lifecycle_[a-f0-9]+_test$/);assert.equal(process.env.NODE_ENV,"test");
const {pool}=require("../../apps/api/db/database"),{fixture}=require("../helpers/distribution-lifecycle-fixture.cjs");
const operations=require("../../apps/api/services/certops/distributionOperations"),cleanup=require("../../apps/api/services/certops/materialCleanup"),lifecycle=require("../../apps/api/services/certops/distributionLifecycle");
const {approveJob}=require("../../apps/api/services/certops/jobApprovals"),material=require("../../apps/api/services/certops/materialDistribution");
test.after(()=>pool.end());
async function setup(t){
  const previous=process.env.CERTOPS_MATERIAL_CLEANUP_ENABLED;process.env.CERTOPS_MATERIAL_CLEANUP_ENABLED="true";
  t.after(()=>{if(previous===undefined)delete process.env.CERTOPS_MATERIAL_CLEANUP_ENABLED;else process.env.CERTOPS_MATERIAL_CLEANUP_ENABLED=previous;});
  const f=await fixture();
  await pool.query("UPDATE certops_agents SET declared_capabilities=declared_capabilities||'[\"material-cleanup-vault-kv2-v1\"]'::jsonb,supported_operations=supported_operations||'[\"cleanup-from-store\"]'::jsonb,declared_target_selectors=declared_target_selectors||$2::jsonb WHERE id=$1",[f.issuer,JSON.stringify([f.groupId])]);
  const group=(await pool.query("SELECT * FROM certops_distribution_groups WHERE id=$1",[f.groupId])).rows[0],old=[];
  for(let n=0;n<3;n++){
    const id=crypto.randomUUID(),job=(await pool.query("INSERT INTO certificate_jobs(workspace_id,operation,status,source,subject_type,subject_id,assigned_agent_id,management_period_id) VALUES($1,'renew','succeeded','api','managed_certificate',$2,$3,$4) RETURNING id",[f.workspaceId,f.certificateId,f.issuer,group.management_period_id])).rows[0];
    await pool.query(`INSERT INTO certops_material_versions(id,workspace_id,group_id,management_period_id,publishing_job_id,profile_revision,state,provider_version,certificate_identity_id,fingerprint_sha256,valid_to,published_at,publishing_claim_id,created_at)
      VALUES($1,$2,$3,$4,$5,1,'published',1,$6,$7,clock_timestamp()+interval '30 days',clock_timestamp()-($8*interval '1 day'),$9,clock_timestamp()-($8*interval '1 day'))`,[id,f.workspaceId,f.groupId,group.management_period_id,job.id,f.identity,f.fingerprint,100+n,crypto.randomUUID()]);old.push(id);
  }
  const policy=structuredClone(lifecycle.DEFAULT_POLICY);Object.assign(policy.retention,{minimumSeconds:86400,minimumVersions:2,rollbackSeconds:86400,cleanupEnabled:true,reportOnly:false});
  const saved=await lifecycle.putPolicy({...f,policy,expectedRevision:0,actorUserId:f.actor});
  return {...f,old,revision:saved.revision};
}
async function request(f,version=f.old[2]){return cleanup.requestCleanup({...f,materialVersionId:version,expectedRevision:f.revision,actorUserId:f.actor});}
async function jobFor(f,id){return (await pool.query("SELECT * FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[f.workspaceId,id])).rows[0];}
function resolve(f,job){return operations.transaction(client=>cleanup.resolveCleanupDefaults({client,workspaceId:f.workspaceId,operation:job.operation,subjectId:job.subject_id,assignedAgentId:job.assigned_agent_id,payload:job.payload,jobId:job.id}));}

test("cleanup requires genuine independent approval, creates a permanent exact-version fence and preserves public history",async t=>{
  const f=await setup(t),requested=await request(f);assert.equal(requested.status,"pending_approval");
  const unapproved=await jobFor(f,requested.jobId);await assert.rejects(()=>resolve(f,unapproved),{code:"CERTOPS_MATERIAL_CLEANUP_APPROVAL_REQUIRED"});
  await approveJob({workspaceId:f.workspaceId,jobId:requested.jobId,approverUserId:f.approver});let job=await jobFor(f,requested.jobId);await resolve(f,job);
  assert.equal((await pool.query("SELECT state FROM certops_material_cleanups WHERE id=$1",[requested.cleanupId])).rows[0].state,"fenced");
  await assert.rejects(()=>operations.requestRollout({...f,materialVersionId:f.old[2],actorUserId:f.actor}),{code:"CERTOPS_ROLLOUT_VERSION_INVALID"});
  await assert.rejects(()=>pool.query("INSERT INTO certificate_jobs(workspace_id,operation,status,source,payload) VALUES($1,'noop','pending','api',$2)",[f.workspaceId,{distributionRollout:{groupId:f.groupId,materialVersionId:f.old[2]}}]),{code:"23514"});
  await assert.rejects(()=>pool.query("UPDATE certops_material_cleanups SET state='planned' WHERE id=$1",[requested.cleanupId]),{code:"23514"});
  const claim=crypto.randomUUID();job=(await pool.query("UPDATE certificate_jobs SET status='claimed',claim_id=$2,claimed_by_agent_id=assigned_agent_id,lease_expires_at=clock_timestamp()+interval '5 minutes' WHERE id=$1 RETURNING *",[job.id,claim])).rows[0];
  const receipt={schemaVersion:1,workspaceId:f.workspaceId,cleanupId:requested.cleanupId,groupId:f.groupId,materialVersionId:f.old[2],providerVersion:1,method:"vault-kv2-soft-delete",softDeleted:true,observedAt:new Date().toISOString()};
  await operations.transaction(client=>cleanup.acceptCleanupReceipt({client,workspaceId:f.workspaceId,agentId:f.issuer,job,receipt}));
  assert.equal((await pool.query("SELECT state FROM certops_material_cleanups WHERE id=$1",[requested.cleanupId])).rows[0].state,"soft_deleted");
  assert.equal((await pool.query("SELECT state FROM certops_material_versions WHERE id=$1",[f.old[2]])).rows[0].state,"published","Secret-store cleanup never erases public history");
});
test("concurrent rollout admission and cleanup authorization cannot both reference and delete a version",async t=>{
  const f=await setup(t),requested=await request(f);await approveJob({workspaceId:f.workspaceId,jobId:requested.jobId,approverUserId:f.approver});const job=await jobFor(f,requested.jobId);
  const results=await Promise.allSettled([resolve(f,job),operations.requestRollout({...f,materialVersionId:f.old[2],actorUserId:f.actor})]);
  assert.equal(results.filter(r=>r.status==="fulfilled").length,1);assert.equal(results.filter(r=>r.status==="rejected").length,1);
  const rejected=results.find(r=>r.status==="rejected");assert.ok(["CERTOPS_ROLLOUT_VERSION_INVALID","CERTOPS_MATERIAL_CLEANUP_PROTECTED"].includes(rejected.reason.code));
});
test("concurrent cleanup plans re-evaluate the remaining minimum-version count at execution",async t=>{
  const f=await setup(t),requests=await Promise.all([request(f,f.old[2]),request(f,f.old[1])]);
  for(const row of requests)await approveJob({workspaceId:f.workspaceId,jobId:row.jobId,approverUserId:f.approver});
  await Promise.all(requests.map(async row=>resolve(f,await jobFor(f,row.jobId))));
  await assert.rejects(()=>request(f,f.old[0]),{code:"CERTOPS_MATERIAL_CLEANUP_PROTECTED"});
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM certops_material_cleanups WHERE workspace_id=$1 AND state='fenced'",[f.workspaceId])).rows[0].n,2);
});
test("policy changes, revoked reviewers, missing qualification and current references refuse cleanup",async t=>{
  const f=await setup(t),requested=await request(f);await approveJob({workspaceId:f.workspaceId,jobId:requested.jobId,approverUserId:f.approver});const job=await jobFor(f,requested.jobId);
  await pool.query("UPDATE workspace_memberships SET role='viewer' WHERE workspace_id=$1 AND user_id=$2",[f.workspaceId,f.approver]);
  await assert.rejects(()=>resolve(f,job),{code:"CERTOPS_MATERIAL_CLEANUP_AUTHORIZATION_STALE"});
  await assert.rejects(()=>request(f,f.materialVersionId),{code:"CERTOPS_MATERIAL_CLEANUP_PROTECTED"});
  delete process.env.CERTOPS_MATERIAL_CLEANUP_ENABLED;await assert.rejects(()=>request(f,f.old[0]),{code:"CERTOPS_MATERIAL_CLEANUP_DISABLED"});
});
test("uncertain cleanup retry retains the fence and cannot silently reauthorize a changed intent",async t=>{
  const f=await setup(t),requested=await request(f);await approveJob({workspaceId:f.workspaceId,jobId:requested.jobId,approverUserId:f.approver});await resolve(f,await jobFor(f,requested.jobId));
  await pool.query("UPDATE certificate_jobs SET status='orphaned_unknown_effect',attempt_count=1 WHERE id=$1",[requested.jobId]);
  assert.equal((await operations.retryDistributionJob({workspaceId:f.workspaceId,jobId:requested.jobId,actorUserId:f.actor})).status,"pending");
  assert.equal((await pool.query("SELECT state FROM certops_material_cleanups WHERE id=$1",[requested.cleanupId])).rows[0].state,"fenced");
  await assert.rejects(()=>operations.transaction(client=>material.assertDeployableVersion(client,f.workspaceId,f.groupId,f.old[2])),{code:"CERTOPS_ROLLOUT_VERSION_INVALID"});
});
test("explicit workspace deletion clears new lifecycle leaves without touching another workspace",async t=>{
  const f=await setup(t),other=await fixture();await request(f);
  await operations.transaction(client=>require("../../apps/api/services/workspaceDeletion").deleteWorkspaces(client,[f.workspaceId]));
  assert.equal((await pool.query("SELECT 1 FROM workspaces WHERE id=$1",[f.workspaceId])).rowCount,0);
  assert.equal((await pool.query("SELECT 1 FROM workspaces WHERE id=$1",[other.workspaceId])).rowCount,1);
});
test("explicit fresh review replaces stale cleanup authority without clearing an uncertain job or releasing its fence",async t=>{
  const f=await setup(t),requested=await request(f);await approveJob({workspaceId:f.workspaceId,jobId:requested.jobId,approverUserId:f.approver});const original=await jobFor(f,requested.jobId);await resolve(f,original);
  await pool.query("UPDATE certificate_jobs SET status='orphaned_unknown_effect',needs_operator_reconciliation=true WHERE id=$1",[original.id]);
  await pool.query("UPDATE workspace_memberships SET role='viewer' WHERE workspace_id=$1 AND user_id=$2",[f.workspaceId,f.approver]);
  const other=await fixture();await pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES($1,$2,'workspace_manager')",[f.workspaceId,other.approver]);
  const stale=await request(f);assert.equal(stale.requiresReauthorization,true);assert.equal(stale.jobId,original.id);
  const fresh=await cleanup.requestCleanup({...f,materialVersionId:f.old[2],expectedRevision:f.revision,actorUserId:f.actor,reauthorize:true});assert.notEqual(fresh.jobId,original.id);assert.equal(fresh.status,"pending_approval");
  await approveJob({workspaceId:f.workspaceId,jobId:fresh.jobId,approverUserId:other.approver});await resolve(f,await jobFor(f,fresh.jobId));
  const historical=await jobFor(f,original.id);assert.equal(historical.status,"orphaned_unknown_effect");assert.equal(historical.needs_operator_reconciliation,true);
  await assert.rejects(()=>resolve(f,original),{code:"CERTOPS_MATERIAL_CLEANUP_AUTHORIZATION_STALE"});
  assert.equal((await pool.query("SELECT state FROM certops_material_cleanups WHERE id=$1",[fresh.cleanupId])).rows[0].state,"fenced");
});
test("cleanup uses real signed dispatch, claim-bound receipts and the existing single-use nonce ledger",async t=>{
  const f=await setup(t),requested=await request(f),dispatch=require("../../apps/api/services/certops/agentDispatch"),signing=require("../../apps/api/services/certops/jobSigning");
  const row=(await pool.query("SELECT agent_id,agent_version,protocol_version FROM certops_agents WHERE id=$1",[f.issuer])).rows[0];
  const agent={id:f.issuer,workspaceId:f.workspaceId,agentId:row.agent_id,agentVersion:row.agent_version,protocolVersion:row.protocol_version,status:"active"};
  await signing.ensureActiveSigningKey();const pin=await signing.getActiveSigningKeyPublicInfo();
  assert.equal((await dispatch.claimJobs({agent,envelope:{sequence:1},body:{maxJobs:1,supportedActions:["cleanup-from-store"]}})).jobs.length,0);
  await approveJob({workspaceId:f.workspaceId,jobId:requested.jobId,approverUserId:f.approver});
  const claimed=await dispatch.claimJobs({agent,envelope:{sequence:2},body:{maxJobs:1,supportedActions:["cleanup-from-store"]}});assert.equal(claimed.jobs.length,1);
  const verified=require("../../packages/agent/src/signing").verifyJobEnvelope({claimed:claimed.jobs[0],publicKeyPem:pin.publicKeyPem,pinnedSigningKeyId:pin.signingKeyId});
  assert.equal(verified.allowed,true);assert.equal(verified.job.action,"cleanup-from-store");assert.equal(verified.job.materialCleanup.materialVersionId,f.old[2]);
  const contract=require("../../packages/contracts/certops/validate-signed-job.cjs").validateSignedJob(verified.job);assert.equal(contract.valid,true,JSON.stringify(contract.errors));
  assert.doesNotMatch(JSON.stringify(verified.job),/PRIVATE KEY|tokenFile|credential|X-Vault-Token/);
  const job=await jobFor(f,requested.jobId),receipt={schemaVersion:1,workspaceId:f.workspaceId,cleanupId:requested.cleanupId,groupId:f.groupId,materialVersionId:f.old[2],providerVersion:1,method:"vault-kv2-soft-delete",softDeleted:true,observedAt:new Date().toISOString()};
  const body={jobId:job.id,claimId:job.claim_id,attemptId:job.claim_id,nonce:verified.job.nonce,status:"succeeded",cleanupReceipt:receipt};
  await assert.rejects(()=>dispatch.ingestResult({agent,envelope:{sequence:3},body:{...body,cleanupReceipt:{...receipt,materialVersionId:f.materialVersionId}}}),{code:"CERTOPS_MATERIAL_CLEANUP_RECEIPT_MISMATCH"});
  await dispatch.ingestResult({agent,envelope:{sequence:3},body});
  assert.equal((await jobFor(f,job.id)).status,"succeeded");
  assert.equal((await dispatch.ingestResult({agent,envelope:{sequence:4},body})).duplicate,true,"Lost result acknowledgements reuse the existing committed outcome");
  await assert.rejects(()=>dispatch.ingestResult({agent,envelope:{sequence:5},body:{...body,status:"failed",cleanupReceipt:undefined}}),{code:"CERTOPS_AGENT_RESULT_NONCE_REJECTED"});
});

"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
assert.equal(process.env.DB_HOST,"127.0.0.1");
assert.match(process.env.DB_NAME || "",/^distribution_lifecycle_[a-f0-9]+_test$/);
assert.equal(process.env.NODE_ENV,"test");
const {pool}=require("../../apps/api/db/database");
const operations=require("../../apps/api/services/certops/distributionOperations");
const lifecycle=require("../../apps/api/services/certops/distributionLifecycle");
const {approveJob}=require("../../apps/api/services/certops/jobApprovals");
const {fixture}=require("../helpers/distribution-lifecycle-fixture.cjs");
test.after(()=>pool.end());
function publish(f,revision){return operations.transaction(client=>lifecycle.onMaterialPublished({client,workspaceId:f.workspaceId,
  payload:{groupId:f.groupId,materialVersionId:f.materialVersionId,policyRevision:revision}}));}
async function configure(f,mode){const policy=structuredClone(lifecycle.DEFAULT_POLICY);policy.mode=mode;
  if(mode==="preauthorized")policy.authorizationExpiresAt=new Date(Date.now()+86400000).toISOString();
  return lifecycle.putPolicy({workspaceId:f.workspaceId,groupId:f.groupId,policy,expectedRevision:0,actorUserId:f.actor});}
async function approve(f,jobId){await approveJob({workspaceId:f.workspaceId,jobId,approverUserId:f.approver});
  return operations.transaction(client=>operations.processDistributionIntent({client,row:{workspace_id:f.workspaceId,event_type:"distribution_approval_granted"},payload:{jobId}}));}
test("manual publication is durable metadata and never creates a rollout",async()=>{
  const f=await fixture();await publish(f,0);await publish(f,0);
  assert.equal((await pool.query("SELECT 1 FROM certops_distribution_rollouts WHERE workspace_id=$1",[f.workspaceId])).rowCount,0);
  assert.equal((await pool.query("SELECT 1 FROM certops_distribution_automations WHERE workspace_id=$1",[f.workspaceId])).rowCount,1);
});
test("concurrent/restarted publication handling creates exactly one genuine pending approval for the exact version",async()=>{
  const f=await fixture(),policy=await configure(f,"approval_request");
  await Promise.all(Array.from({length:5},()=>publish(f,policy.revision)));
  const jobs=(await pool.query("SELECT * FROM certificate_jobs WHERE workspace_id=$1 AND payload ? 'distributionRollout'",[f.workspaceId])).rows;
  assert.equal(jobs.length,1);assert.equal(jobs[0].status,"pending_approval");assert.equal(jobs[0].approved_payload_hash,null);
  assert.equal(jobs[0].payload.distributionRollout.materialVersionId,f.materialVersionId);
  await approve(f,jobs[0].id);await publish(f,policy.revision);
  assert.equal((await pool.query("SELECT 1 FROM certops_distribution_rollouts WHERE workspace_id=$1",[f.workspaceId])).rowCount,1);
});
test("preauthorized mode needs a real bounded policy review; workspace mandatory approval cannot be bypassed",async()=>{
  for(const requireApproval of [false,true]){
    const f=await fixture({requireApproval}),policy=await configure(f,"preauthorized");
    await approve(f,policy.approval_job_id);const result=await publish(f,policy.revision);
    assert.equal(result.reason,requireApproval?"authorization_stale":"authorized");
    const rollouts=(await pool.query("SELECT * FROM certops_distribution_rollouts WHERE workspace_id=$1",[f.workspaceId])).rows;
    assert.equal(rollouts.length,requireApproval?0:1);
    assert.equal((await pool.query("SELECT 1 FROM certops_job_approvals WHERE workspace_id=$1 AND decision='approved'",[f.workspaceId])).rowCount,1,"Automation never manufactures a human approval");
  }
});
test("membership changes and changed policy revisions refuse old standing authority and delayed events",async()=>{
  const f=await fixture(),policy=await configure(f,"preauthorized");await approve(f,policy.approval_job_id);
  await operations.putBinding({...f,binding:{...f.binding,wave:1},actorUserId:f.actor});
  assert.equal((await publish(f,policy.revision)).reason,"authorization_stale");
  const second=await fixture();await configure(second,"approval_request");
  assert.equal((await publish(second,0)).reason,"policy_changed");
});
test("policy updates use optimistic revisions and are isolated by workspace",async()=>{
  const f=await fixture();const policy=await configure(f,"manual");
  await assert.rejects(()=>lifecycle.putPolicy({...f,actorUserId:f.actor,policy:{...policy.policy,maxParallel:2},expectedRevision:0}),{code:"CERTOPS_LIFECYCLE_POLICY_REVISION_CHANGED"});
  const other=await fixture();assert.equal(await lifecycle.loadPolicy(pool,other.workspaceId,f.groupId),null);
});

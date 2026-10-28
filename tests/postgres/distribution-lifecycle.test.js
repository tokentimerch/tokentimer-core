"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
assert.equal(process.env.DB_HOST,"127.0.0.1");
assert.match(process.env.DB_NAME || "",/^distribution_lifecycle_[a-f0-9]+_test$/);
assert.equal(process.env.NODE_ENV,"test");
const {pool}=require("../../apps/api/db/database");
const operations=require("../../apps/api/services/certops/distributionOperations");
const lifecycle=require("../../apps/api/services/certops/distributionLifecycle");
const {approveJob}=require("../../apps/api/services/certops/jobApprovals");
const {fixture,proveConsumer}=require("../helpers/distribution-lifecycle-fixture.cjs");
const maintenance=require("../../apps/api/services/certops/distributionMaintenance");
const scheduler=require("../../apps/api/services/certops/distributionScheduler");
const monitoring=require("../../apps/api/services/certops/distributionMonitoring");
const administration=require("../../apps/api/services/certops/distributionAdministration");
const discovery=require("../../apps/api/services/certops/consumerDiscovery");
const request=require("supertest");
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
    const review=(await pool.query("SELECT payload FROM certificate_jobs WHERE id=$1",[policy.approval_job_id])).rows[0].payload.distributionPolicyApproval;
    assert.equal(review.scope.bindings[0].bindingId,f.bindingId);assert.equal(review.scope.bindings[0].activationClass,"reload");
    assert.equal(review.scope.policy.maxParallel,1);assert.equal(review.scope.rolloutBehavior.requiredFailure,"pause");
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
test("disruptive activation requires genuine approval, waits outside its window and freezes policy revisions",async()=>{
  const f=await fixture();
  const policy={method:"reload",disruptive:true,requiresApproval:true,timezone:"UTC",windows:[],blackouts:[],validUntil:null,emergency:null};
  await maintenance.putConsumerPolicy({...f,policy,expectedAuthorizationRevision:1,actorUserId:f.actor});
  const job=await operations.requestRollout({...f,actorUserId:f.actor});
  assert.equal(job.status,"pending_approval");await approve(f,job.id);
  const rollout=(await pool.query("SELECT * FROM certops_distribution_rollouts WHERE workspace_id=$1",[f.workspaceId])).rows[0];
  await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,rollout.id));
  assert.equal((await pool.query("SELECT 1 FROM certificate_jobs WHERE workspace_id=$1 AND operation='deploy-from-store'",[f.workspaceId])).rowCount,0);
  assert.equal((await pool.query("SELECT activation_policy FROM certops_consumer_deployments WHERE rollout_id=$1",[rollout.id])).rows[0].activation_policy.method,"reload");
  await assert.rejects(()=>maintenance.putConsumerPolicy({...f,policy:{...policy,emergency:{start:new Date().toISOString(),end:new Date(Date.now()+3600000).toISOString(),reference:"change248"}},expectedAuthorizationRevision:2,actorUserId:f.actor}),{code:"CERTOPS_EMERGENCY_AUTHORIZATION_REQUIRED"});
});
test("concurrent recurring schedulers create one read-only exact desired-version rollout and honor workspace approval",async()=>{
  for(const requireApproval of [false,true]){
    const f=await fixture({requireApproval});
    const initial=await operations.requestRollout({...f,actorUserId:f.actor});
    if(requireApproval)await approve(f,initial.id);
    const rollout=(await pool.query("SELECT * FROM certops_distribution_rollouts WHERE workspace_id=$1",[f.workspaceId])).rows[0];
    await pool.query("UPDATE certops_distribution_rollouts SET state='verified' WHERE id=$1",[rollout.id]);
    const policy=structuredClone(lifecycle.DEFAULT_POLICY);policy.verification.enabled=true;
    await lifecycle.putPolicy({...f,policy,expectedRevision:0,actorUserId:f.actor});
    const results=await Promise.all(Array.from({length:4},()=>operations.transaction(client=>scheduler.scheduleGroup({client,workspaceId:f.workspaceId,groupId:f.groupId}))));
    assert.equal(results.filter(result=>result.scheduled).length,1);
    const job=(await pool.query("SELECT * FROM certificate_jobs WHERE workspace_id=$1 AND idempotency_key LIKE 'verification:%'",[f.workspaceId])).rows[0];
    assert.equal(job.payload.distributionRollout.verificationOnly,true);assert.equal(job.payload.distributionRollout.materialVersionId,f.materialVersionId);
    assert.equal(job.status,requireApproval?"pending_approval":"succeeded");
  }
});
test("offline recurring verification backs off without creating jobs or stealing live work",async()=>{
  const f=await fixture();const initial=await operations.requestRollout({...f,actorUserId:f.actor});
  await pool.query("UPDATE certops_distribution_rollouts SET state='verified' WHERE approval_job_id=$1",[initial.id]);
  const policy=structuredClone(lifecycle.DEFAULT_POLICY);policy.verification.enabled=true;
  await lifecycle.putPolicy({...f,policy,expectedRevision:0,actorUserId:f.actor});
  await pool.query("UPDATE certops_agents SET last_seen_at=NOW()-interval '1 day' WHERE id=$1",[f.consumer]);
  assert.equal((await operations.transaction(client=>scheduler.scheduleGroup({client,workspaceId:f.workspaceId,groupId:f.groupId}))).reason,"required_agent_offline");
  const schedule=(await pool.query("SELECT * FROM certops_distribution_schedules WHERE workspace_id=$1",[f.workspaceId])).rows[0];
  assert.equal(schedule.failures,1);assert.ok(new Date(schedule.next_run_at).getTime()>Date.now()+3600000);
});
test("consumer incidents deduplicate, survive source publication, and resolve only on fresh consumer proof",async()=>{
  const f=await fixture();await operations.requestRollout({...f,actorUserId:f.actor});await proveConsumer(f);
  const policy=structuredClone(lifecycle.DEFAULT_POLICY);policy.alerts.enabled=true;
  await lifecycle.putPolicy({...f,policy,expectedRevision:0,actorUserId:f.actor});
  await pool.query("UPDATE certops_agents SET status='offline' WHERE id=$1",[f.consumer]);
  const monitor=()=>operations.transaction(client=>monitoring.monitorGroup({client,workspaceId:f.workspaceId,groupId:f.groupId}));
  await monitor();await monitor();
  const incidents=(await pool.query("SELECT * FROM certops_distribution_incidents WHERE workspace_id=$1",[f.workspaceId])).rows;
  assert.equal(incidents.length,1);assert.equal(incidents[0].code,"required_consumer_offline");assert.equal(incidents[0].revision,1);
  await pool.query("UPDATE certops_agents SET status='active',last_seen_at=clock_timestamp() WHERE id=$1",[f.consumer]);
  await monitor();assert.equal((await pool.query("SELECT resolved_at FROM certops_distribution_incidents WHERE id=$1",[incidents[0].id])).rows[0].resolved_at,null,"Old proof cannot resolve a newly opened incident");
  await operations.requestRollout({...f,verificationOnly:true,actorUserId:f.actor});await proveConsumer(f);
  await pool.query("UPDATE certops_agents SET status='offline' WHERE id=$1",[f.consumer]);await monitor();
  await pool.query("UPDATE certops_agents SET status='active',last_seen_at=clock_timestamp() WHERE id=$1",[f.consumer]);await monitor();
  assert.equal((await pool.query("SELECT resolved_at FROM certops_distribution_incidents WHERE id=$1",[incidents[0].id])).rows[0].resolved_at,null,"Proof before the latest incident condition must not resolve it after heartbeat recovery");
  await operations.requestRollout({...f,verificationOnly:true,actorUserId:f.actor});await proveConsumer(f);await monitor();
  assert.ok((await pool.query("SELECT resolved_at FROM certops_distribution_incidents WHERE id=$1",[incidents[0].id])).rows[0].resolved_at);
});
test("a failed publishing job opens an incident while its exact material allocation remains unresolved",async()=>{
  const f=await fixture({published:false}),policy=structuredClone(lifecycle.DEFAULT_POLICY);policy.alerts.enabled=true;
  await lifecycle.putPolicy({...f,policy,expectedRevision:0,actorUserId:f.actor});
  await pool.query("UPDATE certificate_jobs SET status='failed',completed_at=clock_timestamp() WHERE id=(SELECT publishing_job_id FROM certops_material_versions WHERE workspace_id=$1 AND id=$2)",[f.workspaceId,f.materialVersionId]);
  await operations.transaction(client=>monitoring.monitorGroup({client,workspaceId:f.workspaceId,groupId:f.groupId}));
  const incident=(await pool.query("SELECT code,evidence FROM certops_distribution_incidents WHERE workspace_id=$1",[f.workspaceId])).rows[0];
  assert.equal(incident.code,"publication_failed");assert.equal(incident.evidence.materialVersionId,f.materialVersionId);
  assert.equal((await pool.query("SELECT state FROM certops_material_versions WHERE id=$1",[f.materialVersionId])).rows[0].state,"allocated");
});

test("stable discovered consumers survive fingerprint rotation, stale observations and tenant boundaries",async()=>{
  const f=await fixture(),other=await fixture();
  const observation={workspaceId:f.workspaceId,agentRowId:f.consumer,targetHost:"web",locationKind:"iis_binding",locationSlot:"default:443",
    locationRef:"iis://Default:443",windowsFields:{storeLocation:"LocalMachine",storeName:"My"},fingerprintSha256:f.fingerprint,observedAt:new Date().toISOString()};
  const id=await discovery.recordConsumerObservation(pool,observation,{id:f.certificateId});
  assert.equal(await discovery.recordConsumerObservation(pool,{...observation,fingerprintSha256:"b".repeat(64),observedAt:new Date(Date.now()+100).toISOString()},{id:f.certificateId}),id);
  await discovery.recordConsumerObservation(pool,{...observation,observedAt:"2025-01-01T00:00:00Z"},{id:f.certificateId});
  assert.equal((await pool.query("SELECT observed_fingerprint_sha256 FROM certops_discovered_consumers WHERE id=$1",[id])).rows[0].observed_fingerprint_sha256,"b".repeat(64));
  assert.equal(await discovery.recordConsumerObservation(pool,{...observation,locationKind:"windows_store"},{id:f.certificateId}),null);
  assert.equal((await pool.query("SELECT 1 FROM certops_discovered_consumers WHERE workspace_id=$1 AND id=$2",[other.workspaceId,id])).rowCount,0);
});
test("management/preflight/retention reads are non-mutating and do not expose credentials",async()=>{
  const f=await fixture();await operations.requestRollout({...f,actorUserId:f.actor});
  const count=(await pool.query("SELECT count(*) AS count FROM certificate_jobs WHERE workspace_id=$1",[f.workspaceId])).rows[0].count;
  const view=await administration.overview({client:pool,workspaceId:f.workspaceId,groupId:f.groupId});
  assert.equal(view.discoveryCoverage,"partial");assert.equal(view.consumers[0].binding_id,f.bindingId);
  const preflight=await administration.preflight({client:pool,workspaceId:f.workspaceId,groupId:f.groupId});
  assert.equal(preflight.nonMutating,true);assert.equal(preflight.consumers[0].ready,false);
  assert.equal(preflight.consumers[0].publicIntent.materialVersionId,f.materialVersionId);assert.equal(preflight.consumers[0].publicIntent.bindingId,f.bindingId);
  const retention=await administration.retentionPreview({client:pool,workspaceId:f.workspaceId,groupId:f.groupId});
  assert.equal(retention.cleanupAvailable,false);assert.ok(retention.versions[0].retainedReasons.includes("desired_consumer_version"));
  assert.equal((await pool.query("SELECT count(*) AS count FROM certificate_jobs WHERE workspace_id=$1",[f.workspaceId])).rows[0].count,count);
  assert.doesNotMatch(JSON.stringify({view,preflight,retention}),/credential_hash|credential_prefix|PRIVATE KEY|privateKeyPem/);
  const other=await fixture();await assert.rejects(()=>administration.overview({client:pool,workspaceId:other.workspaceId,groupId:f.groupId}),{code:"CERTOPS_DISTRIBUTION_NOT_FOUND"});
});
test("revoking a policy reviewer invalidates previously approved automatic rollout authority",async()=>{
  const f=await fixture(),policy=await configure(f,"preauthorized");await approve(f,policy.approval_job_id);
  await pool.query("UPDATE workspace_memberships SET role='viewer' WHERE workspace_id=$1 AND user_id=$2",[f.workspaceId,f.approver]);
  assert.equal((await publish(f,policy.revision)).reason,"authorization_stale");
});
test("unchanged configuration can obtain a fresh policy review after consumer authorization changes",async()=>{
  const f=await fixture(),policy=await configure(f,"preauthorized");await approve(f,policy.approval_job_id);
  await operations.putBinding({...f,binding:{...f.binding,wave:1},actorUserId:f.actor});
  const next=await lifecycle.putPolicy({...f,policy:policy.policy,expectedRevision:policy.revision,actorUserId:f.actor});
  assert.equal(next.revision,policy.revision+1);assert.notEqual(next.approval_job_id,policy.approval_job_id);
  assert.equal((await pool.query("SELECT status FROM certificate_jobs WHERE id=$1",[next.approval_job_id])).rows[0].status,"pending_approval");
});
test("cancelled approval requests close their notification without creating a rollout",async()=>{
  const f=await fixture(),policy=await configure(f,"preauthorized");
  assert.equal((await pool.query("SELECT 1 FROM operational_notifications WHERE workspace_id=$1 AND resolved_at IS NULL",[f.workspaceId])).rowCount,1);
  await pool.query("UPDATE certificate_jobs SET status='cancelled' WHERE workspace_id=$1 AND id=$2",[f.workspaceId,policy.approval_job_id]);
  assert.equal((await pool.query("SELECT 1 FROM operational_notifications WHERE workspace_id=$1 AND resolved_at IS NULL",[f.workspaceId])).rowCount,0);
  assert.equal((await pool.query("SELECT 1 FROM certops_distribution_rollouts WHERE workspace_id=$1",[f.workspaceId])).rowCount,0);
});
test("retry refuses changed consumer authorization without clearing the original uncertain stage",async()=>{
  const f=await fixture(),parent=await operations.requestRollout({...f,actorUserId:f.actor});
  const rollout=(await pool.query("SELECT id FROM certops_distribution_rollouts WHERE approval_job_id=$1",[parent.id])).rows[0];
  await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,rollout.id));
  const job=(await pool.query("SELECT job_id FROM certops_consumer_deployments WHERE workspace_id=$1 AND binding_id=$2",[f.workspaceId,f.bindingId])).rows[0];
  await pool.query("UPDATE certificate_jobs SET status='orphaned_unknown_effect',attempt_count=1 WHERE id=$1",[job.job_id]);
  await pool.query("UPDATE certops_consumer_deployments SET stage='orphaned_unknown_effect' WHERE job_id=$1",[job.job_id]);
  await operations.putBinding({...f,binding:{...f.binding,wave:2},actorUserId:f.actor});
  await assert.rejects(()=>operations.retryDistributionJob({workspaceId:f.workspaceId,jobId:job.job_id,actorUserId:f.actor}),{code:"CERTOPS_MATERIAL_RETRY_AUTHORIZATION_STALE"});
  assert.equal((await pool.query("SELECT stage FROM certops_consumer_deployments WHERE job_id=$1",[job.job_id])).rows[0].stage,"orphaned_unknown_effect");
});
test("historical canary success with expired proof cannot authorize later waves or complete a rollout",async()=>{
  const f=await fixture();await operations.requestRollout({...f,actorUserId:f.actor});const proof=await proveConsumer(f);
  await pool.query("UPDATE certops_distribution_rollouts SET state='deploying' WHERE id=$1",[proof.rollout.id]);
  await pool.query("UPDATE certops_consumer_deployments SET observed_at=clock_timestamp()-interval '2 hours' WHERE rollout_id=$1",[proof.rollout.id]);
  const result=await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,proof.rollout.id));
  assert.equal(result.reason,"consumer_verification_stale");
  assert.equal((await pool.query("SELECT state FROM certops_distribution_rollouts WHERE id=$1",[proof.rollout.id])).rows[0].state,"paused");
});
test("real HTTP routes preserve session, manager, emergency-admin, tenant and private-material boundaries",async()=>{
  const f=await fixture(),other=await fixture(),express=require("../../apps/api/node_modules/express"),app=express();
  app.use(express.json());app.use((req,_res,next)=>{const id=Number(req.get("X-Test-Session"));if([f.actor,f.approver,other.actor].includes(id)){req.user={id,auth_method:"local"};req.isAuthenticated=()=>true;}next();});
  const auth=require("../../apps/api/middleware/auth"),rbac=require("../../apps/api/services/rbac");
  app.use("/api/v1/workspaces/:id",auth.requireAuth,rbac.loadWorkspace,rbac.requireWorkspaceMembership);app.use(require("../../apps/api/routes/certops"));
  const base=`/api/v1/workspaces/${f.workspaceId}/certops/distribution-groups/${f.groupId}`;
  assert.equal((await request(app).get(`${base}/management`).set("X-Test-Session",String(f.actor))).status,200);
  assert.equal((await request(app).get(`${base}/management`).set("X-Test-Session",String(other.actor))).status,403);
  const saved=await request(app).put(`${base}/policy`).set("X-Test-Session",String(f.approver)).send({policy:structuredClone(lifecycle.DEFAULT_POLICY),expectedRevision:0});
  assert.equal(saved.status,200,JSON.stringify(saved.body));
  assert.equal((await request(app).post(`${base}/cleanups`).set("X-Test-Session",String(f.approver)).send({materialVersionId:f.materialVersionId,expectedRevision:1})).status,403,"Cleanup requests require an administrator, independently of manager access");
  assert.equal((await request(app).post(`${base}/cleanups`).set("X-Test-Session",String(f.actor)).send({materialVersionId:f.materialVersionId,expectedRevision:1,token:"forbidden-field"})).status,422);
  assert.equal((await request(app).post(`${base}/cleanups`).set("X-Test-Session",String(f.actor)).send({materialVersionId:f.materialVersionId,expectedRevision:1})).status,409,"Disabled cleanup never creates an executable operation");
  const emergency={method:"reload",disruptive:true,requiresApproval:true,timezone:"UTC",windows:[],blackouts:[],validUntil:null,
    emergency:{start:new Date().toISOString(),end:new Date(Date.now()+3600000).toISOString(),reference:"change248"}};
  assert.equal((await request(app).post(`${base}/consumers/${f.bindingId}/emergency`).set("X-Test-Session",String(f.approver)).send({policy:emergency,expectedAuthorizationRevision:1})).status,403);
  const granted=await request(app).post(`${base}/consumers/${f.bindingId}/emergency`).set("X-Test-Session",String(f.actor)).send({policy:emergency,expectedAuthorizationRevision:1});
  assert.equal(granted.status,200,JSON.stringify(granted.body));
  // Detection fixture only; no actual key is generated or included.
  const refused=await request(app).put(`${base}/policy`).set("X-Test-Session",String(f.actor)).send({policy:{...structuredClone(lifecycle.DEFAULT_POLICY),privateKeyPem:"synthetic-forbidden-field"},expectedRevision:1});
  assert.equal(refused.status,422);
  await pool.query("UPDATE workspace_memberships SET role='viewer' WHERE workspace_id=$1 AND user_id=$2",[f.workspaceId,f.approver]);
  assert.equal((await request(app).put(`${base}/policy`).set("X-Test-Session",String(f.approver)).send({policy:structuredClone(lifecycle.DEFAULT_POLICY),expectedRevision:1})).status,403);
});
test("pending retained-version approvals protect an otherwise eligible old material version",async()=>{
  const f=await fixture(),crypto=require("node:crypto"),{createCertificateJob}=require("../../apps/api/services/certops/jobs");
  const policy=structuredClone(lifecycle.DEFAULT_POLICY);policy.retention.minimumVersions=2;
  await lifecycle.putPolicy({...f,policy,expectedRevision:0,actorUserId:f.actor});
  let old;
  for(const days of [100,101]){
    const job=await createCertificateJob({workspaceId:f.workspaceId,operation:"noop",source:"api",subjectType:"managed_certificate",subjectId:f.certificateId});
    const id=crypto.randomUUID();await pool.query(`INSERT INTO certops_material_versions(id,workspace_id,group_id,management_period_id,publishing_job_id,
      profile_revision,state,certificate_identity_id,provider_version,fingerprint_sha256,valid_to,published_at,created_at,publishing_claim_id)
      SELECT $1,$2,$3,management_period_id,$4,profile_revision,'published',$5,1,$6,clock_timestamp()+interval '30 days',
        clock_timestamp()-$7*interval '1 day',clock_timestamp()-$7*interval '1 day',$8 FROM certops_distribution_groups WHERE workspace_id=$2 AND id=$3`,
      [id,f.workspaceId,f.groupId,job.id,f.identity,f.fingerprint,days,crypto.randomUUID()]);old=id;
  }
  const before=await administration.retentionPreview({client:pool,workspaceId:f.workspaceId,groupId:f.groupId});
  assert.equal(before.versions.find(row=>row.id===old).metadataEligible,true);
  const rollback=await operations.requestRollout({...f,materialVersionId:old,actorUserId:f.actor});assert.equal(rollback.status,"pending_approval");
  const after=await administration.retentionPreview({client:pool,workspaceId:f.workspaceId,groupId:f.groupId});
  assert.ok(after.versions.find(row=>row.id===old).retainedReasons.includes("job_or_pending_approval"));assert.equal(after.cleanupAvailable,false);
});

// Public database fixtures only. Advancing due timestamps exercises durable
// scheduling without sleeping through production backoff intervals.
async function verificationTick(f){
  return operations.transaction(client=>scheduler.scheduleGroup({client,workspaceId:f.workspaceId,groupId:f.groupId}));
}
async function verificationDue(f){
  await pool.query("UPDATE certops_distribution_schedules SET next_run_at=clock_timestamp()-interval '1 second' WHERE workspace_id=$1 AND group_id=$2",[f.workspaceId,f.groupId]);
}
async function verificationSchedule(f){
  return (await pool.query("SELECT * FROM certops_distribution_schedules WHERE workspace_id=$1 AND group_id=$2",[f.workspaceId,f.groupId])).rows[0];
}
async function verificationRollout(f){
  return (await pool.query("SELECT * FROM certops_distribution_rollouts WHERE workspace_id=$1 AND group_id=$2 ORDER BY generation DESC LIMIT 1",[f.workspaceId,f.groupId])).rows[0];
}
async function verificationJobs(f){
  return (await pool.query("SELECT * FROM certificate_jobs WHERE workspace_id=$1 AND idempotency_key LIKE 'verification:%' ORDER BY created_at",[f.workspaceId])).rows;
}
async function proveVerification(f,{skipBindingIds=[]}={}){
  const material=require("../../apps/api/services/certops/materialDistribution"),crypto=require("node:crypto");
  const rollout=await verificationRollout(f);
  await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,rollout.id));
  const children=(await pool.query("SELECT d.*,j.status AS job_status FROM certops_consumer_deployments d JOIN certificate_jobs j ON j.workspace_id=d.workspace_id AND j.id=d.job_id WHERE d.workspace_id=$1 AND d.rollout_id=$2",[f.workspaceId,rollout.id])).rows;
  assert.ok(children.length);
  const version=(await pool.query("SELECT * FROM certops_material_versions WHERE workspace_id=$1 AND id=$2",[f.workspaceId,rollout.material_version_id])).rows[0];
  for(const child of children){
    if(skipBindingIds.includes(child.binding_id))continue;
    if(child.job_status==="pending_approval")await approveJob({workspaceId:f.workspaceId,jobId:child.job_id,approverUserId:f.approver});
    const job=(await pool.query("UPDATE certificate_jobs SET status='claimed',claim_id=$2,claimed_by_agent_id=assigned_agent_id,lease_expires_at=clock_timestamp()+interval '5 minutes',attempt_count=1 WHERE workspace_id=$1 AND id=$3 RETURNING *",[f.workspaceId,crypto.randomUUID(),child.job_id])).rows[0];
    const receipt={schemaVersion:1,workspaceId:f.workspaceId,groupId:f.groupId,bindingId:child.binding_id,materialVersionId:version.id,
      generation:Number(rollout.generation),fetched:true,installed:true,bound:child.verification_policy!=="installed",
      servedVerified:child.verification_policy!=="installed",trustValidated:child.verification_policy==="trust",
      fingerprintSha256:version.fingerprint_sha256,validTo:new Date(version.valid_to).toISOString(),observedAt:new Date().toISOString()};
    await operations.transaction(client=>material.acceptDeploymentReceipt({client,workspaceId:f.workspaceId,agentId:child.assigned_agent_id,job,receipt,jobStatus:"succeeded"}));
    await pool.query("UPDATE certificate_jobs SET status='succeeded',completed_at=clock_timestamp() WHERE id=$1",[job.id]);
  }
  await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,rollout.id));
  return rollout;
}
async function prepareVerification({requireApproval=false,method="served",optional=false,secondRequired=false,alerts=false,configuredBy="actor"}={}){
  const f=await fixture({requireApproval});
  if(method!=="served"){f.binding={...f.binding,verificationPolicy:method};await operations.putBinding({...f,binding:f.binding,actorUserId:f.actor});}
  if(optional){
    f.optionalBindingId=require("node:crypto").randomUUID();
    await operations.putBinding({...f,bindingId:f.optionalBindingId,binding:{...f.binding,agentId:f.issuer,deploymentProfileRef:"optional_web",required:secondRequired},actorUserId:f.actor});
  }
  const initial=await operations.requestRollout({...f,maxParallel:optional?2:1,actorUserId:f.actor});
  if(initial.status==="pending_approval")await approve(f,initial.id);
  await proveVerification(f);
  const policy=structuredClone(lifecycle.DEFAULT_POLICY);
  policy.maxParallel=optional?2:1;Object.assign(policy.verification,{enabled:true,intervalSeconds:300,maxBackoffSeconds:1200,failureThreshold:2});
  policy.alerts.enabled=alerts;
  await lifecycle.putPolicy({...f,policy,expectedRevision:0,actorUserId:f[configuredBy]});
  return f;
}
async function failVerification(f,{advance=true,status="failed",reconciliation=false}={}){
  const rollout=await verificationRollout(f);
  await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,rollout.id));
  const child=(await pool.query("SELECT * FROM certops_consumer_deployments WHERE workspace_id=$1 AND rollout_id=$2 AND binding_id=$3",[f.workspaceId,rollout.id,f.bindingId])).rows[0];
  const original=(await pool.query("SELECT status FROM certificate_jobs WHERE id=$1",[child.job_id])).rows[0];
  if(original.status==="pending_approval")await approveJob({workspaceId:f.workspaceId,jobId:child.job_id,approverUserId:f.approver});
  await pool.query("UPDATE certificate_jobs SET status=$2,attempt_count=1,error_code='CERTOPS_VERIFICATION_FAILED',error_message='Synthetic listener mismatch',completed_at=clock_timestamp(),needs_operator_reconciliation=$3 WHERE id=$1",[child.job_id,status,reconciliation]);
  await pool.query("UPDATE certops_consumer_deployments SET stage=$2,failure_code='material_listener_mismatch' WHERE workspace_id=$1 AND job_id=$3",[f.workspaceId,status==="orphaned_unknown_effect"?"orphaned_unknown_effect":"failed",child.job_id]);
  const result=advance?await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,rollout.id)):null;
  return {rollout,child,result};
}

test("required recurring verification recovers automatically with fresh installed, served and trust proof and preserved failure history",async()=>{
  for(const method of ["installed","served","trust"]){
    const f=await prepareVerification({method});
    assert.equal((await verificationTick(f)).scheduled,true);
    const failed=await failVerification(f);assert.equal(failed.result.reason,"recurring_verification_failed");
    assert.equal((await verificationRollout(f)).state,"degraded");
    const oldJob=(await pool.query("SELECT * FROM certificate_jobs WHERE id=$1",[failed.child.job_id])).rows[0];
    const oldChild=(await pool.query("SELECT * FROM certops_consumer_deployments WHERE job_id=$1",[failed.child.job_id])).rows[0];
    await verificationDue(f);
    assert.equal((await verificationTick(f)).reason,"verification_backoff");
    const backedOff=await verificationSchedule(f);assert.equal(backedOff.failures,1);assert.equal(backedOff.last_job_id,null);
    assert.ok(new Date(backedOff.next_run_at).getTime()>Date.now()+590000);
    assert.equal((await verificationTick(f)).reason,"not_due");
    const audits=(await pool.query("SELECT * FROM audit_events WHERE workspace_id=$1 ORDER BY id",[f.workspaceId])).rows;
    await verificationDue(f);
    const recovery=await Promise.all(Array.from({length:5},()=>verificationTick(f)));
    assert.equal(recovery.filter(result=>result.scheduled).length,1);
    const parent=(await verificationJobs(f)).at(-1),latest=await verificationRollout(f);
    assert.equal(parent.payload.distributionRollout.verificationOnly,true);
    assert.equal(parent.payload.distributionRollout.materialVersionId,f.materialVersionId);
    assert.ok(Number(latest.generation)>Number(failed.rollout.generation));
    await proveVerification(f);
    const row=(await require("../../apps/api/services/certops/materialDistribution").consumerMatrix({client:pool,workspaceId:f.workspaceId,groupId:f.groupId}))[0];
    assert.equal(row.converged,true);assert.equal(row.verification_method,method);
    const newChild=(await pool.query("SELECT j.payload FROM certops_consumer_deployments d JOIN certificate_jobs j ON j.id=d.job_id WHERE d.rollout_id=$1",[latest.id])).rows[0];
    assert.equal(newChild.payload.materialDeployment.verificationOnly,true);
    assert.equal(newChild.payload.materialDeployment.authorizationRevision,oldChild.authorization_revision);
    assert.deepEqual((await pool.query("SELECT * FROM certificate_jobs WHERE id=$1",[failed.child.job_id])).rows[0],oldJob);
    assert.deepEqual((await pool.query("SELECT * FROM certops_consumer_deployments WHERE job_id=$1",[failed.child.job_id])).rows[0],oldChild);
    const after=(await pool.query("SELECT * FROM audit_events WHERE workspace_id=$1 ORDER BY id",[f.workspaceId])).rows;
    assert.deepEqual(after.filter(event=>audits.some(old=>old.id===event.id)),audits);
  }
});
test("repeated recurring failures consume each outcome once, cap exponential backoff and reset after fresh success",async()=>{
  const f=await prepareVerification();assert.equal((await verificationTick(f)).scheduled,true);
  for(const expectedFailures of [1,2,3]){
    const failed=await failVerification(f);
    assert.equal((await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,failed.rollout.id))).reason,"rollout_inactive");
    await verificationDue(f);
    const outcomes=await Promise.all(Array.from({length:4},()=>verificationTick(f)));
    assert.equal(outcomes.filter(result=>result.reason==="verification_backoff").length,1);
    const schedule=await verificationSchedule(f),seconds=Math.min(1200,300*2**expectedFailures);
    assert.equal(schedule.failures,expectedFailures);assert.equal(Number(schedule.sequence),expectedFailures);
    assert.ok(Math.abs(new Date(schedule.next_run_at).getTime()-Date.now()-seconds*1000)<2000);
    assert.equal((await verificationJobs(f)).length,expectedFailures);
    await verificationDue(f);
    const retried=await Promise.all(Array.from({length:4},()=>verificationTick(f)));
    assert.equal(retried.filter(result=>result.scheduled).length,1);
    assert.ok(Math.abs(new Date((await verificationSchedule(f)).next_run_at).getTime()-Date.now()-300000)<2000);
  }
  await proveVerification(f);await verificationDue(f);await verificationTick(f);
  assert.equal((await verificationSchedule(f)).failures,0);
});
test("active deployments and manually requested paused verification stay protected from recurring recovery",async()=>{
  for(const verificationOnly of [false,true]){
    const f=await prepareVerification();
    await operations.requestRollout({...f,verificationOnly,actorUserId:f.actor});
    const rollout=await verificationRollout(f);
    assert.equal((await verificationTick(f)).reason,"rollout_in_progress");
    await failVerification(f);
    assert.equal((await verificationRollout(f)).state,"paused");
    await verificationDue(f);assert.equal((await verificationTick(f)).scheduled,false);
    assert.equal((await verificationJobs(f)).length,0);
    assert.equal((await pool.query("SELECT state FROM certops_distribution_rollouts WHERE id=$1",[rollout.id])).rows[0].state,"paused");
  }
});
test("an explicit or legacy ambiguous pause is never automatically resumed, even when its verification jobs failed",async()=>{
  for(const legacy of [false,true]){
    const f=await prepareVerification();await verificationTick(f);const failed=await failVerification(f,{advance:false});
    if(legacy)await pool.query("UPDATE certops_distribution_rollouts SET state='paused' WHERE id=$1",[failed.rollout.id]);
    else await operations.setRolloutState({...f,rolloutId:failed.rollout.id,state:"paused",actorUserId:f.actor});
    await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,failed.rollout.id));
    await verificationDue(f);assert.equal((await verificationTick(f)).scheduled,false);
    assert.equal((await verificationRollout(f)).state,"paused");assert.equal((await verificationJobs(f)).length,1);
    // Explicit operator resume re-enters normal admission; it can then settle
    // the old failed cycle and hand subsequent attempts back to the scheduler.
    await operations.setRolloutState({...f,rolloutId:failed.rollout.id,state:"deploying",actorUserId:f.actor});
    assert.equal((await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,failed.rollout.id))).reason,"recurring_verification_failed");
    await verificationDue(f);assert.equal((await verificationTick(f)).reason,"verification_backoff");
  }
});
test("failed recurring cycles wait for already-created optional claims and do not start additional work",async()=>{
  const f=await prepareVerification({optional:true});await verificationTick(f);
  const failed=await failVerification(f,{advance:false});
  const optional=(await pool.query("SELECT job_id FROM certops_consumer_deployments WHERE rollout_id=$1 AND binding_id=$2",[failed.rollout.id,f.optionalBindingId])).rows[0];
  const claim=require("node:crypto").randomUUID();
  await pool.query("UPDATE certificate_jobs SET status='claimed',claim_id=$2,claimed_by_agent_id=assigned_agent_id,lease_expires_at=clock_timestamp()+interval '5 minutes' WHERE id=$1",[optional.job_id,claim]);
  const result=await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,failed.rollout.id));
  assert.equal(result.reason,"waiting_for_verification_children");assert.equal(result.deferred,true);
  await verificationDue(f);assert.equal((await verificationTick(f)).scheduled,false);
  assert.equal((await pool.query("SELECT claim_id FROM certificate_jobs WHERE id=$1",[optional.job_id])).rows[0].claim_id,claim);
  assert.equal((await verificationJobs(f)).length,1);
  await pool.query("UPDATE certificate_jobs SET status='failed',completed_at=clock_timestamp() WHERE id=$1",[optional.job_id]);
  await pool.query("UPDATE certops_consumer_deployments SET stage='failed' WHERE job_id=$1",[optional.job_id]);
  assert.equal((await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,failed.rollout.id))).reason,"recurring_verification_failed");
});
test("optional failure remains degraded and does not acquire a required-failure recovery gate",async()=>{
  const f=await prepareVerification({optional:true});await verificationTick(f);
  const rollout=await proveVerification(f,{skipBindingIds:[f.optionalBindingId]});
  const optional=(await pool.query("SELECT job_id FROM certops_consumer_deployments WHERE rollout_id=$1 AND binding_id=$2",[rollout.id,f.optionalBindingId])).rows[0];
  // Model the settled optional failure before normal rollout completion.
  await pool.query("UPDATE certificate_jobs SET status='failed',completed_at=clock_timestamp() WHERE id=$1",[optional.job_id]);
  await pool.query("UPDATE certops_consumer_deployments SET stage='failed',failure_code='material_optional_probe_failed' WHERE job_id=$1",[optional.job_id]);
  assert.equal((await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,rollout.id))).reason,"rollout_completed");
  assert.equal((await verificationRollout(f)).state,"degraded");
  await verificationDue(f);assert.equal((await verificationTick(f)).scheduled,true);
  assert.equal((await verificationSchedule(f)).failures,0);
});
test("uncertain effects and reconciliation fences never become automatic verification failures",async()=>{
  for(const facts of [{status:"orphaned_unknown_effect"},{status:"failed",reconciliation:true}]){
    const f=await prepareVerification();await verificationTick(f);
    const failed=await failVerification(f,facts);
    assert.equal(failed.result.reason,"required_consumer_failed");
    assert.equal((await verificationRollout(f)).state,"paused");
    const before=(await pool.query("SELECT * FROM certificate_jobs WHERE id=$1",[failed.child.job_id])).rows[0];
    await verificationDue(f);assert.equal((await verificationTick(f)).scheduled,false);
    assert.equal((await verificationJobs(f)).length,1);
    assert.deepEqual((await pool.query("SELECT * FROM certificate_jobs WHERE id=$1",[failed.child.job_id])).rows[0],before);
  }
});
test("binding authorization changes fence failed cycles and reject stale original execution",async()=>{
  const f=await prepareVerification();await verificationTick(f);const failed=await failVerification(f,{advance:false});
  await operations.putBinding({...f,binding:{...f.binding,wave:1},actorUserId:f.actor});
  assert.equal((await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,failed.rollout.id))).reason,"required_consumer_failed");
  await verificationDue(f);assert.equal((await verificationTick(f)).scheduled,false);
  const job=(await pool.query("SELECT * FROM certificate_jobs WHERE id=$1",[failed.child.job_id])).rows[0];
  await assert.rejects(()=>operations.transaction(client=>require("../../apps/api/services/certops/materialDistribution").resolveDistributionJobDefaults({
    client,workspaceId:f.workspaceId,operation:job.operation,subjectId:job.subject_id,assignedAgentId:job.assigned_agent_id,payload:job.payload,jobId:job.id})),{code:"CERTOPS_DEPLOYMENT_INTENT_MISMATCH"});
  assert.equal((await verificationJobs(f)).length,1);
});
test("offline agents, revoked configuration owners and paused workspaces defer fresh recovery attempts",async()=>{
  for(const condition of ["offline","revoked","paused"]){
    const f=await prepareVerification({configuredBy:condition==="revoked"?"approver":"actor"});
    await verificationTick(f);await failVerification(f);await verificationDue(f);await verificationTick(f);
    if(condition==="offline")await pool.query("UPDATE certops_agents SET last_seen_at=clock_timestamp()-interval '1 day' WHERE id=$1",[f.consumer]);
    if(condition==="revoked")await pool.query("UPDATE workspace_memberships SET role='viewer' WHERE workspace_id=$1 AND user_id=$2",[f.workspaceId,f.approver]);
    if(condition==="paused")await pool.query("UPDATE workspaces SET certops_paused=true WHERE id=$1",[f.workspaceId]);
    await verificationDue(f);
    if(condition==="paused")await assert.rejects(()=>verificationTick(f),{code:"CERTOPS_WORKSPACE_PAUSED"});
    else assert.equal((await verificationTick(f)).reason,condition==="offline"?"required_agent_offline":"verification_authorization_stale");
    assert.equal((await verificationJobs(f)).length,1);
  }
});
test("each recovery cycle still requires real workspace approval and pending approvals prevent duplicate attempts",async()=>{
  const f=await prepareVerification({requireApproval:true});
  const first=await verificationTick(f);assert.equal(first.scheduled,true);
  let parent=(await verificationJobs(f))[0];assert.equal(parent.status,"pending_approval");assert.equal(parent.approved_by_user_id,null);
  await verificationDue(f);assert.equal((await verificationTick(f)).reason,"verification_approval_pending");
  await approve(f,parent.id);
  const rollout=await verificationRollout(f);await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,rollout.id));
  const child=(await pool.query("SELECT j.* FROM certops_consumer_deployments d JOIN certificate_jobs j ON j.id=d.job_id WHERE d.rollout_id=$1",[rollout.id])).rows[0];
  assert.equal(child.status,"pending_approval");
  await verificationDue(f);assert.equal((await verificationTick(f)).scheduled,false);
  await failVerification(f);await verificationDue(f);assert.equal((await verificationTick(f)).reason,"verification_backoff");
  await verificationDue(f);
  const attempts=await Promise.all(Array.from({length:4},()=>verificationTick(f)));assert.equal(attempts.filter(result=>result.scheduled).length,1);
  parent=(await verificationJobs(f)).at(-1);assert.equal(parent.status,"pending_approval");assert.equal(parent.approved_by_user_id,null);
  assert.equal((await pool.query("SELECT 1 FROM certops_distribution_rollouts WHERE approval_job_id=$1",[parent.id])).rowCount,0);
});
test("recovery incidents retain failed evidence and resolve only after fresh current consumer proof",async()=>{
  const f=await prepareVerification({alerts:true,method:"installed"});await verificationTick(f);await failVerification(f);
  const monitor=()=>operations.transaction(client=>monitoring.monitorGroup({client,workspaceId:f.workspaceId,groupId:f.groupId}));
  await monitor();
  const incident=(await pool.query("SELECT * FROM certops_distribution_incidents WHERE workspace_id=$1 AND code='verification_failed' AND binding_id=$2",[f.workspaceId,f.bindingId])).rows[0];
  assert.ok(incident);
  await verificationDue(f);await verificationTick(f);await monitor();
  assert.equal((await pool.query("SELECT resolved_at FROM certops_distribution_incidents WHERE id=$1",[incident.id])).rows[0].resolved_at,null);
  await verificationDue(f);await verificationTick(f);await monitor();
  assert.equal((await pool.query("SELECT resolved_at FROM certops_distribution_incidents WHERE id=$1",[incident.id])).rows[0].resolved_at,null,"Creating a fresh cycle is not successful verification");
  await proveVerification(f);await monitor();
  assert.ok((await pool.query("SELECT resolved_at FROM certops_distribution_incidents WHERE id=$1",[incident.id])).rows[0].resolved_at);
  assert.equal((await pool.query("SELECT state FROM certops_distribution_rollouts WHERE workspace_id=$1 AND state='degraded'",[f.workspaceId])).rowCount,1);
});
test("fresh later proof cannot clear an older job's unresolved operator reconciliation fence",async()=>{
  const f=await prepareVerification();await verificationTick(f);
  const failed=await failVerification(f,{status:"orphaned_unknown_effect",reconciliation:true});
  await operations.setRolloutState({...f,rolloutId:failed.rollout.id,state:"retired",actorUserId:f.actor});
  await operations.requestRollout({...f,verificationOnly:true,actorUserId:f.actor});await proveVerification(f);
  await verificationDue(f);assert.equal((await verificationTick(f)).reason,"unresolved_uncertain_effects");
  const original=(await pool.query("SELECT status,needs_operator_reconciliation FROM certificate_jobs WHERE id=$1",[failed.child.job_id])).rows[0];
  assert.equal(original.status,"orphaned_unknown_effect");assert.equal(original.needs_operator_reconciliation,true);
  assert.equal((await verificationJobs(f)).length,1);
});
test("recovery pins the current authorized desired version rather than an unapproved newer publication",async()=>{
  const f=await prepareVerification();await verificationTick(f);await failVerification(f);await verificationDue(f);await verificationTick(f);
  const before=await administration.retentionPreview({client:pool,workspaceId:f.workspaceId,groupId:f.groupId});
  assert.ok(before.versions.find(row=>row.id===f.materialVersionId).retainedReasons.includes("uncertain_or_reconcilable_deployment"));
  const id=require("node:crypto").randomUUID();
  const publishing=await require("../../apps/api/services/certops/jobs").createCertificateJob({workspaceId:f.workspaceId,operation:"noop",source:"api",subjectType:"managed_certificate",subjectId:f.certificateId});
  await pool.query("INSERT INTO certops_material_versions(id,workspace_id,group_id,management_period_id,publishing_job_id,profile_revision,state,certificate_identity_id,provider_version,fingerprint_sha256,valid_to,published_at,publishing_claim_id) SELECT $1,workspace_id,group_id,management_period_id,$2,profile_revision,'published',certificate_identity_id,1,fingerprint_sha256,valid_to,clock_timestamp(),$3 FROM certops_material_versions WHERE workspace_id=$4 AND id=$5",
    [id,publishing.id,require("node:crypto").randomUUID(),f.workspaceId,f.materialVersionId]);
  await pool.query("UPDATE certops_distribution_groups SET latest_material_version_id=$3 WHERE workspace_id=$1 AND id=$2",[f.workspaceId,f.groupId,id]);
  await verificationDue(f);await verificationTick(f);
  assert.equal((await verificationJobs(f)).at(-1).payload.distributionRollout.materialVersionId,f.materialVersionId);
  await proveVerification(f);
  await operations.requestRollout({...f,materialVersionId:id,actorUserId:f.actor});await proveVerification(f);
  await verificationDue(f);await verificationTick(f);
  assert.equal((await verificationJobs(f)).at(-1).payload.distributionRollout.materialVersionId,id);
  const after=await administration.retentionPreview({client:pool,workspaceId:f.workspaceId,groupId:f.groupId});
  assert.ok(after.versions.find(row=>row.id===f.materialVersionId).retainedReasons.includes("uncertain_or_reconcilable_deployment"));
});
test("required verification escalation counts failed cycles even though every fresh job has only one attempt",async()=>{
  const f=await prepareVerification({alerts:true});await verificationTick(f);
  let incidentId;
  for(const count of [1,2]){
    await failVerification(f);await verificationDue(f);await verificationTick(f);
    await operations.transaction(client=>monitoring.monitorGroup({client,workspaceId:f.workspaceId,groupId:f.groupId}));
    const incident=(await pool.query("SELECT * FROM certops_distribution_incidents WHERE workspace_id=$1 AND binding_id=$2 AND code='verification_failed' AND resolved_at IS NULL",[f.workspaceId,f.bindingId])).rows[0];
    assert.equal(incident.evidence.failureCount,count);
    if(incidentId)assert.equal(incident.id,incidentId);else incidentId=incident.id;
    if(count<2){await verificationDue(f);await verificationTick(f);}
  }
});

async function finishConsumerCycle(f,outcomes={}){
  const rollout=await proveVerification(f,{skipBindingIds:Object.keys(outcomes)});
  for(const [bindingId,status] of Object.entries(outcomes)){
    const child=(await pool.query("SELECT * FROM certops_consumer_deployments WHERE rollout_id=$1 AND binding_id=$2",[rollout.id,bindingId])).rows[0];
    assert.ok(child.job_id,"The selected wave must have created this consumer's job");
    const uncertain=status==="orphaned_unknown_effect" || status==="uncertain_failed";
    const storedStatus=status==="uncertain_failed"?"failed":status;
    await pool.query("UPDATE certificate_jobs SET status=$2,attempt_count=1,completed_at=CASE WHEN $2 IN ('pending','claimed','running','pending_approval') THEN NULL ELSE clock_timestamp() END,needs_operator_reconciliation=$3,error_code='CERTOPS_VERIFICATION_FAILED' WHERE id=$1",[child.job_id,storedStatus,uncertain]);
    if(!["pending","pending_approval","claimed","running"].includes(status))
      await pool.query("UPDATE certops_consumer_deployments SET stage=$2,failure_code='material_listener_mismatch' WHERE job_id=$1",[child.job_id,status==="orphaned_unknown_effect"?status:"failed"]);
  }
  await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,rollout.id));
  return rollout;
}
async function startNextConsumerCycle(f){
  await verificationDue(f);
  let result=await verificationTick(f);
  if(result.reason==="verification_backoff"){await verificationDue(f);result=await verificationTick(f);}
  assert.equal(result.scheduled,true);
  return result;
}
async function consumerFailureSummary(f){
  return monitoring.verificationFailureCounts(pool,f.workspaceId,f.groupId);
}
async function monitorConsumers(f,service=monitoring){
  return operations.transaction(client=>service.monitorGroup({client,workspaceId:f.workspaceId,groupId:f.groupId}));
}
async function enableFixtureNotificationQueue(f){
  // Disposable queue eligibility only: no delivery worker or real recipient.
  await pool.query("INSERT INTO workspace_settings(workspace_id,contact_groups,default_contact_group_id,email_alerts_enabled) VALUES($1,$2,'verification_fixture',true) ON CONFLICT(workspace_id) DO UPDATE SET contact_groups=EXCLUDED.contact_groups,default_contact_group_id=EXCLUDED.default_contact_group_id,email_alerts_enabled=true",
    [f.workspaceId,JSON.stringify([{id:"verification_fixture",name:"Fixture only",email_contact_ids:[require("node:crypto").randomUUID()]}])]);
}
test("consumer A's two verification failures cannot make consumer B's first failure notification-eligible",async()=>{
  const f=await prepareVerification({optional:true,secondRequired:true,alerts:true});await enableFixtureNotificationQueue(f);
  await verificationTick(f);await finishConsumerCycle(f,{[f.bindingId]:"failed"});await monitorConsumers(f);
  let counts=await consumerFailureSummary(f);assert.equal(counts.get(f.bindingId).failures,1);assert.equal(counts.get(f.optionalBindingId).failures,0);
  await startNextConsumerCycle(f);await finishConsumerCycle(f,{[f.bindingId]:"failed",[f.optionalBindingId]:"failed"});
  await Promise.all(Array.from({length:4},()=>monitorConsumers(f)));
  counts=await consumerFailureSummary(f);assert.equal(counts.get(f.bindingId).failures,2);assert.equal(counts.get(f.optionalBindingId).failures,1);
  const incidents=(await pool.query("SELECT * FROM certops_distribution_incidents WHERE workspace_id=$1 AND code='verification_failed' AND resolved_at IS NULL",[f.workspaceId])).rows;
  assert.equal(incidents.find(row=>row.binding_id===f.bindingId).evidence.failureCount,2);
  assert.ok(incidents.find(row=>row.binding_id===f.bindingId).last_notified_at);
  assert.equal(incidents.find(row=>row.binding_id===f.optionalBindingId).evidence.failureCount,1);
  assert.equal(incidents.find(row=>row.binding_id===f.optionalBindingId).last_notified_at,null);
  const queued=(await pool.query("SELECT metadata FROM alert_queue WHERE metadata->>'groupId'=$1 AND metadata->>'code'='verification_failed'",[f.groupId])).rows;
  assert.equal(queued.length,1);assert.equal(queued[0].metadata.evidence.bindingId,f.bindingId);
});
test("required and optional consumer failures form independent streaks across consecutive cycles",async()=>{
  const f=await prepareVerification({optional:true,alerts:true});await enableFixtureNotificationQueue(f);await verificationTick(f);
  await finishConsumerCycle(f,{[f.bindingId]:"failed"});
  let counts=await consumerFailureSummary(f);assert.equal(counts.get(f.bindingId).failures,1);assert.equal(counts.get(f.optionalBindingId).failures,0);
  await startNextConsumerCycle(f);await finishConsumerCycle(f,{[f.bindingId]:"blocked",[f.optionalBindingId]:"failed"});
  counts=await consumerFailureSummary(f);assert.equal(counts.get(f.bindingId).failures,2);assert.equal(counts.get(f.optionalBindingId).failures,1);
  await monitorConsumers(f);
  let optional=(await pool.query("SELECT last_notified_at,evidence FROM certops_distribution_incidents WHERE workspace_id=$1 AND binding_id=$2 AND code='verification_failed' AND resolved_at IS NULL",[f.workspaceId,f.optionalBindingId])).rows[0];
  assert.equal(optional.evidence.failureCount,1);assert.equal(optional.last_notified_at,null);
  await startNextConsumerCycle(f);await finishConsumerCycle(f,{[f.optionalBindingId]:"failed"});
  counts=await consumerFailureSummary(f);assert.equal(counts.get(f.bindingId).failures,0);assert.equal(counts.get(f.optionalBindingId).failures,2);
  await monitorConsumers(f);
  optional=(await pool.query("SELECT last_notified_at,evidence FROM certops_distribution_incidents WHERE workspace_id=$1 AND binding_id=$2 AND code='verification_failed' AND resolved_at IS NULL",[f.workspaceId,f.optionalBindingId])).rows[0];
  assert.equal(optional.evidence.failureCount,2);assert.ok(optional.last_notified_at);
});
test("fresh successful verification resets only that binding's streak and resolves its incident before the next first failure",async()=>{
  const f=await prepareVerification({optional:true,secondRequired:true,alerts:true});await enableFixtureNotificationQueue(f);await verificationTick(f);
  for(const count of [1,2]){
    await finishConsumerCycle(f,{[f.bindingId]:"failed"});await monitorConsumers(f);
    assert.equal((await consumerFailureSummary(f)).get(f.bindingId).failures,count);
    await startNextConsumerCycle(f);
  }
  const incident=(await pool.query("SELECT * FROM certops_distribution_incidents WHERE workspace_id=$1 AND binding_id=$2 AND code='verification_failed' AND resolved_at IS NULL",[f.workspaceId,f.bindingId])).rows[0];
  await monitorConsumers(f);
  assert.equal((await pool.query("SELECT resolved_at FROM certops_distribution_incidents WHERE id=$1",[incident.id])).rows[0].resolved_at,null,"Pending work is not a successful reset");
  await finishConsumerCycle(f);await monitorConsumers(f);
  assert.equal((await consumerFailureSummary(f)).get(f.bindingId).failures,0);
  assert.ok((await pool.query("SELECT resolved_at FROM certops_distribution_incidents WHERE id=$1",[incident.id])).rows[0].resolved_at);
  await startNextConsumerCycle(f);await finishConsumerCycle(f,{[f.bindingId]:"failed"});await monitorConsumers(f);
  const next=(await pool.query("SELECT * FROM certops_distribution_incidents WHERE workspace_id=$1 AND binding_id=$2 AND code='verification_failed' AND resolved_at IS NULL",[f.workspaceId,f.bindingId])).rows[0];
  assert.notEqual(next.id,incident.id);assert.equal(next.evidence.failureCount,1);assert.equal(next.last_notified_at,null);
});
test("restarts, repeated job attempts and concurrent monitors cannot double-count one failed verification cycle",async()=>{
  const f=await prepareVerification({alerts:true});await verificationTick(f);const rollout=await finishConsumerCycle(f,{[f.bindingId]:"failed"});
  const child=(await pool.query("SELECT job_id FROM certops_consumer_deployments WHERE rollout_id=$1 AND binding_id=$2",[rollout.id,f.bindingId])).rows[0];
  for(const status of ["pending","failed","failed"])await pool.query("UPDATE certificate_jobs SET status=$2,attempt_count=attempt_count+1 WHERE id=$1",[child.job_id,status]);
  assert.equal((await consumerFailureSummary(f)).get(f.bindingId).failures,1);
  const script="const {pool}=require('./apps/api/db/database');require('./apps/api/services/certops/distributionMonitoring').verificationFailureCounts(pool,process.argv[1],process.argv[2]).then(c=>{process.stdout.write('restart-count:'+JSON.stringify([...c])+'\\n');return pool.end()}).catch(()=>{process.exitCode=1;pool.end()});";
  const restarted=require("node:child_process").spawnSync(process.execPath,["-e",script,f.workspaceId,f.groupId],{cwd:require("node:path").resolve(__dirname,"../.."),env:process.env,encoding:"utf8",timeout:30000,windowsHide:true});
  assert.equal(restarted.status,0,restarted.stderr);
  const marker=restarted.stdout.split("\n").find(line=>line.startsWith("restart-count:"));
  assert.equal(new Map(JSON.parse(marker.slice("restart-count:".length))).get(f.bindingId).failures,1);
  await verificationDue(f);
  await Promise.all([...Array.from({length:4},()=>monitorConsumers(f)),...Array.from({length:4},()=>verificationTick(f))]);
  assert.equal((await consumerFailureSummary(f)).get(f.bindingId).failures,1);
  assert.equal((await pool.query("SELECT count(*)::int AS count FROM certops_consumer_verification_outcomes WHERE workspace_id=$1 AND rollout_id=$2 AND binding_id=$3",[f.workspaceId,rollout.id,f.bindingId])).rows[0].count,1);
});
test("pending approvals and live verification jobs do not create failure outcomes",async()=>{
  const f=await prepareVerification({requireApproval:true,alerts:true});const scheduled=await verificationTick(f);
  await monitorConsumers(f);assert.equal((await consumerFailureSummary(f)).get(f.bindingId).failures,0);
  await approve(f,scheduled.jobId);const rollout=await verificationRollout(f);
  await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,rollout.id));
  const child=(await pool.query("SELECT job_id FROM certops_consumer_deployments WHERE rollout_id=$1 AND binding_id=$2",[rollout.id,f.bindingId])).rows[0];
  await monitorConsumers(f);assert.equal((await consumerFailureSummary(f)).get(f.bindingId).failures,0);
  await approveJob({workspaceId:f.workspaceId,jobId:child.job_id,approverUserId:f.approver});
  for(const status of ["pending","claimed","running"]){
    await pool.query("UPDATE certificate_jobs SET status=$2 WHERE id=$1",[child.job_id,status]);
    await monitorConsumers(f);assert.equal((await consumerFailureSummary(f)).get(f.bindingId).failures,0);
  }
  assert.equal((await pool.query("SELECT 1 FROM certops_consumer_verification_outcomes WHERE workspace_id=$1 AND rollout_id=$2",[f.workspaceId,rollout.id])).rowCount,0);
});
test("concurrent consumer results and retries count each cycle once without acquiring the group's scheduler lock",async()=>{
  const f=await prepareVerification({optional:true,alerts:true});await verificationTick(f);
  const rollout=await verificationRollout(f);
  await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,rollout.id));
  const children=(await pool.query("SELECT job_id FROM certops_consumer_deployments WHERE workspace_id=$1 AND rollout_id=$2 ORDER BY binding_id",[f.workspaceId,rollout.id])).rows;
  assert.equal(children.length,2);
  const groupLock=await pool.connect();
  try{
    await groupLock.query("BEGIN");
    await groupLock.query("SELECT id FROM certops_distribution_groups WHERE workspace_id=$1 AND id=$2 FOR UPDATE",[f.workspaceId,f.groupId]);
    const updates=await Promise.allSettled([...children,children[0]].map(child=>operations.transaction(async client=>{
      await client.query("SET LOCAL statement_timeout='5s'");
      await client.query("UPDATE certificate_jobs SET status='failed',completed_at=clock_timestamp() WHERE workspace_id=$1 AND id=$2",[f.workspaceId,child.job_id]);
    })));
    for(const result of updates)assert.equal(result.status,"fulfilled",result.reason?.message);
  }finally{await groupLock.query("ROLLBACK");groupLock.release();}
  const counts=await consumerFailureSummary(f);
  assert.equal(counts.get(f.bindingId).failures,1);assert.equal(counts.get(f.optionalBindingId).failures,1);
  assert.equal((await pool.query("SELECT count(*)::int AS count FROM certops_consumer_verification_outcomes WHERE workspace_id=$1 AND rollout_id=$2",[f.workspaceId,rollout.id])).rows[0].count,2);
  // Reclassification after a late reconciliation flag removes this cycle
  // from ordinary failures while the original failed job remains preserved.
  await pool.query("UPDATE certificate_jobs SET needs_operator_reconciliation=true WHERE id=$1",[children[0].job_id]);
  const uncertain=(await pool.query("SELECT d.binding_id,j.status FROM certops_consumer_deployments d JOIN certificate_jobs j ON j.id=d.job_id WHERE d.job_id=$1",[children[0].job_id])).rows[0];
  assert.equal((await consumerFailureSummary(f)).get(uncertain.binding_id).failures,0);
  assert.equal(uncertain.status,"failed");
  await monitorConsumers(f);
  assert.equal((await pool.query("SELECT 1 FROM certops_distribution_incidents WHERE workspace_id=$1 AND binding_id=$2 AND code='uncertain_effects' AND resolved_at IS NULL",[f.workspaceId,uncertain.binding_id])).rowCount,1);
});
test("rejected verification counts once but offline, uncertainty and manual deployment failures retain their own semantics",async()=>{
  for(const status of ["blocked","rejected","cancelled"]){
    const f=await prepareVerification({alerts:true});await verificationTick(f);await finishConsumerCycle(f,{[f.bindingId]:status});
    await monitorConsumers(f);assert.equal((await consumerFailureSummary(f)).get(f.bindingId).failures,1);
  }
  for(const status of ["orphaned_unknown_effect","uncertain_failed"]){
    const f=await prepareVerification({alerts:true});await verificationTick(f);await finishConsumerCycle(f,{[f.bindingId]:status});await monitorConsumers(f);
    assert.equal((await consumerFailureSummary(f)).get(f.bindingId).failures,0);
    const incidents=(await pool.query("SELECT code FROM certops_distribution_incidents WHERE workspace_id=$1 AND resolved_at IS NULL",[f.workspaceId])).rows.map(row=>row.code);
    assert.ok(incidents.includes("uncertain_effects"));assert.ok(!incidents.includes("verification_failed"));
    await verificationDue(f);assert.equal((await verificationTick(f)).scheduled,false);
  }
  const f=await prepareVerification({alerts:true});
  await pool.query("UPDATE certops_agents SET status='offline' WHERE id=$1",[f.consumer]);await monitorConsumers(f);
  assert.equal((await consumerFailureSummary(f)).get(f.bindingId).failures,0);
  assert.equal((await pool.query("SELECT 1 FROM certops_distribution_incidents WHERE workspace_id=$1 AND code='required_consumer_offline'",[f.workspaceId])).rowCount,1);
  await pool.query("UPDATE certops_agents SET status='active' WHERE id=$1",[f.consumer]);
  await operations.requestRollout({...f,actorUserId:f.actor});await finishConsumerCycle(f,{[f.bindingId]:"failed"});await monitorConsumers(f);
  assert.equal((await consumerFailureSummary(f)).get(f.bindingId).failures,0);
  const incident=(await pool.query("SELECT last_notified_at,evidence FROM certops_distribution_incidents WHERE workspace_id=$1 AND binding_id=$2 AND code='verification_failed' AND resolved_at IS NULL",[f.workspaceId,f.bindingId])).rows[0];
  assert.equal(incident.last_notified_at,null);assert.equal(incident.evidence.failureCount,0);
});
test("changed binding authorization or replacement membership cannot inherit an older target's failures",async()=>{
  const f=await prepareVerification();await verificationTick(f);await finishConsumerCycle(f,{[f.bindingId]:"failed"});
  assert.equal((await consumerFailureSummary(f)).get(f.bindingId).failures,1);
  await operations.putBinding({...f,binding:{...f.binding,deploymentProfileRef:"reviewed_new_profile",profileRevision:2},actorUserId:f.actor});
  assert.equal((await consumerFailureSummary(f)).get(f.bindingId).failures,0);
  await startNextConsumerCycle(f);await finishConsumerCycle(f,{[f.bindingId]:"failed"});
  assert.equal((await consumerFailureSummary(f)).get(f.bindingId).failures,1);
  const replacement=require("node:crypto").randomUUID();
  await operations.putBinding({...f,bindingId:replacement,binding:{...f.binding,deploymentProfileRef:"another_consumer"},actorUserId:f.actor});
  assert.equal((await consumerFailureSummary(f)).get(replacement).failures,0);
});
test("consumers in later waves are counted only when their own verification actually settles",async()=>{
  const f=await prepareVerification({optional:true,secondRequired:true});
  await operations.putBinding({...f,bindingId:f.optionalBindingId,binding:{...f.binding,agentId:f.issuer,deploymentProfileRef:"optional_web",wave:1},actorUserId:f.actor});
  await verificationTick(f);await finishConsumerCycle(f,{[f.bindingId]:"failed"});
  let counts=await consumerFailureSummary(f);assert.equal(counts.get(f.bindingId).failures,1);assert.equal(counts.get(f.optionalBindingId).failures,0);
  await startNextConsumerCycle(f);await finishConsumerCycle(f,{[f.optionalBindingId]:"failed"});
  counts=await consumerFailureSummary(f);assert.equal(counts.get(f.bindingId).failures,0);assert.equal(counts.get(f.optionalBindingId).failures,1);
});
test("consumer streaks remain exact beyond the alert threshold rather than truncating a history scan",async()=>{
  const f=await prepareVerification();await verificationTick(f);
  for(const count of [1,2,3,4,5]){
    await finishConsumerCycle(f,{[f.bindingId]:"failed"});
    assert.equal((await consumerFailureSummary(f)).get(f.bindingId).failures,count);
    if(count<5)await startNextConsumerCycle(f);
  }
});
test("late fresh proof from an older generation cannot erase a newer generation's failed verification",async()=>{
  const f=await prepareVerification();await verificationTick(f);
  const old=await verificationRollout(f);await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,old.id));
  const oldChild=(await pool.query("SELECT * FROM certops_consumer_deployments WHERE rollout_id=$1 AND binding_id=$2",[old.id,f.bindingId])).rows[0];
  const job=(await pool.query("UPDATE certificate_jobs SET status='claimed',claim_id=$2,claimed_by_agent_id=assigned_agent_id,lease_expires_at=clock_timestamp()+interval '5 minutes' WHERE id=$1 RETURNING *",[oldChild.job_id,require("node:crypto").randomUUID()])).rows[0];
  await operations.requestRollout({...f,verificationOnly:true,actorUserId:f.actor});await finishConsumerCycle(f,{[f.bindingId]:"failed"});
  assert.equal((await consumerFailureSummary(f)).get(f.bindingId).failures,1);
  const version=(await pool.query("SELECT * FROM certops_material_versions WHERE workspace_id=$1 AND id=$2",[f.workspaceId,f.materialVersionId])).rows[0];
  const receipt={schemaVersion:1,workspaceId:f.workspaceId,groupId:f.groupId,bindingId:f.bindingId,materialVersionId:f.materialVersionId,
    generation:Number(old.generation),fetched:true,installed:true,bound:true,servedVerified:true,trustValidated:false,
    fingerprintSha256:version.fingerprint_sha256,validTo:new Date(version.valid_to).toISOString(),observedAt:new Date().toISOString()};
  const accepted=await operations.transaction(client=>require("../../apps/api/services/certops/materialDistribution").acceptDeploymentReceipt({client,workspaceId:f.workspaceId,agentId:f.consumer,job,receipt,jobStatus:"succeeded"}));
  assert.equal(accepted.historicalOnly,true);
  await pool.query("UPDATE certificate_jobs SET status='succeeded',completed_at=clock_timestamp() WHERE id=$1",[job.id]);
  assert.equal((await consumerFailureSummary(f)).get(f.bindingId).failures,1);
  assert.equal((await require("../../apps/api/services/certops/materialDistribution").consumerMatrix({client:pool,workspaceId:f.workspaceId,groupId:f.groupId}))[0].converged,false);
});
test("success without sufficiently fresh verification evidence cannot reset a consumer's failure streak",async()=>{
  const f=await prepareVerification();await verificationTick(f);await finishConsumerCycle(f,{[f.bindingId]:"failed"});
  await startNextConsumerCycle(f);const rollout=await verificationRollout(f);
  await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,rollout.id));
  const child=(await pool.query("SELECT job_id FROM certops_consumer_deployments WHERE rollout_id=$1 AND binding_id=$2",[rollout.id,f.bindingId])).rows[0];
  await pool.query("UPDATE certops_consumer_deployments SET stage='served_verified',observed_fingerprint_sha256=$2,observed_at=clock_timestamp()-interval '2 hours',observed_valid_to=clock_timestamp()+interval '1 day' WHERE job_id=$1",[child.job_id,f.fingerprint]);
  await pool.query("UPDATE certificate_jobs SET status='succeeded',completed_at=clock_timestamp() WHERE id=$1",[child.job_id]);
  assert.equal((await consumerFailureSummary(f)).get(f.bindingId).failures,1);
  assert.equal((await pool.query("SELECT 1 FROM certops_consumer_verification_outcomes WHERE workspace_id=$1 AND rollout_id=$2",[f.workspaceId,rollout.id])).rowCount,0);
});

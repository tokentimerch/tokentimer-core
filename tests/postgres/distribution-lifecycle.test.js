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

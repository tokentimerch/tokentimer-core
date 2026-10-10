"use strict";
// Public metadata orchestration. This module has no customer network client.
const crypto = require("node:crypto");
const { pool } = require("../../db/database");
const material = require("./materialDistribution");
const { createCertificateJob, getCertificateJobById, assertSafePublicValue } = require("./jobs");
const { assertDistributionPolicy: lockWorkspaceForCertOpsSideEffect } = require("./distributionPolicy");

function fail(code, statusCode = 409) { const e = new Error(code); e.code = code; e.statusCode = statusCode; throw e; }
async function transaction(work, dbPool = pool) {
  const client = await dbPool.connect();
  try { await client.query("BEGIN"); const value = await work(client); await client.query("COMMIT"); return value; }
  catch (e) { await client.query("ROLLBACK"); throw e; }
  finally { client.release(); }
}
async function putBinding({ workspaceId, groupId, bindingId = crypto.randomUUID(), binding, actorUserId }) {
  material.validateDistributionContract("consumerBinding", binding);
  groupId = material.normalizeDistributionId(groupId);
  bindingId = material.normalizeDistributionId(bindingId);
  binding = {...binding,agentId:binding.agentId.toLowerCase()};
  return transaction(async (client) => {
    await lockWorkspaceForCertOpsSideEffect({client,workspaceId});
    await material.lockGroup(client, workspaceId, groupId);
    const old = (await client.query(`SELECT * FROM certops_consumer_bindings WHERE workspace_id=$1 AND id=$2 FOR UPDATE`, [workspaceId, bindingId])).rows[0];
    if (old && old.group_id !== groupId) fail("CERTOPS_BINDING_GROUP_IMMUTABLE");
    // Compare validated typed values while holding the group and binding locks.
    // An identical PUT must preserve approvals, proofs and local authorization.
    const authorization = { assigned_agent_id: binding.agentId, deployment_profile_ref: binding.deploymentProfileRef,
      profile_revision: binding.profileRevision, required: binding.required, wave: binding.wave,
      verification_policy: binding.verificationPolicy, freshness_seconds: binding.freshnessSeconds, state: binding.state };
    if (old && Object.entries(authorization).every(([key,value]) => old[key] === value)) return old;
    const row = (await client.query(`INSERT INTO certops_consumer_bindings(id,workspace_id,group_id,assigned_agent_id,deployment_profile_ref,
      profile_revision,required,wave,verification_policy,freshness_seconds,state)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      ON CONFLICT(id) DO UPDATE SET assigned_agent_id=EXCLUDED.assigned_agent_id,
      deployment_profile_ref=EXCLUDED.deployment_profile_ref,profile_revision=EXCLUDED.profile_revision,
      required=EXCLUDED.required,wave=EXCLUDED.wave,verification_policy=EXCLUDED.verification_policy,
      freshness_seconds=EXCLUDED.freshness_seconds,state=EXCLUDED.state,
      authorization_revision=certops_consumer_bindings.authorization_revision+1
      WHERE certops_consumer_bindings.workspace_id=EXCLUDED.workspace_id RETURNING *`,
    [bindingId,workspaceId,groupId,binding.agentId,binding.deploymentProfileRef,binding.profileRevision,
      binding.required,binding.wave,binding.verificationPolicy,binding.freshnessSeconds,binding.state])).rows[0];
    if (!row) fail("CERTOPS_BINDING_NOT_FOUND",404);
    await require("../audit").writeAudit({ client, actorUserId, workspaceId, action: "CERTOPS_CONSUMER_BINDING_CHANGED",
      targetType: "certops_consumer_binding", targetId: bindingId, metadata: { groupId, authorizationRevision: row.authorization_revision } });
    return row;
  });
}
async function requestRollout({ workspaceId, groupId, materialVersionId, maxParallel = 1, verificationOnly = false, actorUserId, idempotencyKey }) {
  workspaceId = material.normalizeDistributionId(workspaceId);
  groupId = material.normalizeDistributionId(groupId);
  materialVersionId = material.normalizeDistributionId(materialVersionId);
  if (idempotencyKey !== undefined && idempotencyKey !== null) {
    if (typeof idempotencyKey !== "string" || idempotencyKey.trim().length > 128) fail("CERTOPS_JOB_INVALID",422);
    idempotencyKey = idempotencyKey.trim() || null;
    if (idempotencyKey) assertSafePublicValue(idempotencyKey);
  }
  const requestHash = rolloutRequestHash({groupId,materialVersionId,maxParallel,verificationOnly,actorUserId});
  return transaction(async (client) => {
    await lockWorkspaceForCertOpsSideEffect({client,workspaceId});
    if (idempotencyKey) {
      // Serialize even an initially absent key, across groups in this tenant.
      // Resolve before checking mutable membership, generation or validity.
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))",[JSON.stringify([workspaceId,idempotencyKey])]);
      const existing = (await client.query(`SELECT id,payload,requested_by_user_id,distribution_request_hash
        FROM certificate_jobs WHERE workspace_id=$1 AND idempotency_key=$2`,[workspaceId,idempotencyKey])).rows[0];
      if (existing) {
        const prior=existing.payload?.distributionRollout;
        const priorHash=existing.distribution_request_hash || (prior && rolloutRequestHash({...prior,actorUserId:existing.requested_by_user_id}));
        if (!prior || priorHash !== requestHash) fail("CERTOPS_JOB_IDEMPOTENCY_CONFLICT");
        return getCertificateJobById({client,workspaceId,jobId:existing.id});
      }
    }
    const { group, intent } = await material.buildRolloutIntent({ client, workspaceId, groupId, materialVersionId, maxParallel, verificationOnly });
    const job = await createCertificateJob({ client, workspaceId, operation: "noop", source: "control-plane",
      subjectType: "managed_certificate", subjectId: group.managed_certificate_id,
      assignedAgentId: group.issuer_agent_id, requestedByUserId: actorUserId, requiresApproval: true,
      idempotencyKey, payload: { distributionRollout: intent } });
    await client.query("UPDATE certificate_jobs SET distribution_request_hash=$3 WHERE workspace_id=$1 AND id=$2",[workspaceId,job.id,requestHash]);
    return job;
  });
}
function rolloutRequestHash({groupId,materialVersionId,maxParallel=1,verificationOnly=false,actorUserId}) {
  return material.hashIntent({groupId:groupId.toLowerCase(),materialVersionId:materialVersionId.toLowerCase(),maxParallel,verificationOnly,actorUserId:actorUserId==null?null:String(actorUserId)});
}
async function setRolloutState({ workspaceId, groupId, rolloutId, state, actorUserId }) {
  if (!["paused","deploying","retired"].includes(state)) fail("CERTOPS_ROLLOUT_STATE_INVALID",422);
  groupId = material.normalizeDistributionId(groupId);
  rolloutId = material.normalizeDistributionId(rolloutId);
  return transaction(async (client) => {
    if(state==="deploying")await lockWorkspaceForCertOpsSideEffect({client,workspaceId});
    await material.lockGroup(client,workspaceId,groupId);
    const row = (await client.query(`UPDATE certops_distribution_rollouts SET state=$4
      WHERE workspace_id=$1 AND group_id=$2 AND id=$3 AND state<>'retired' RETURNING *`, [workspaceId,groupId,rolloutId,state])).rows[0];
    if (!row) fail("CERTOPS_ROLLOUT_NOT_FOUND",404);
    if (state === "deploying") await material.enqueueDistributionEvent(client,workspaceId,"distribution_rollout_requested",`${rolloutId}:resume:${crypto.randomUUID()}`,{ groupId,rolloutId });
    await require("../audit").writeAudit({ client,actorUserId,workspaceId,action:"CERTOPS_ROLLOUT_STATE_CHANGED",
      targetType:"certops_distribution_rollout",targetId:rolloutId,metadata:{ groupId,state } });
    return row;
  });
}
async function advanceRollout(client, workspaceId, groupId, rolloutId) {
  await lockWorkspaceForCertOpsSideEffect({client,workspaceId});
  // Read inactive groups under the same locks solely to retire stale work.
  // Admission/dispatch continue to require an active group and valid version.
  const group = await material.lockGroup(client,workspaceId,groupId,{allowInactive:true});
  const rollout = (await client.query(`SELECT r.*,v.provider_version,v.fingerprint_sha256,v.valid_to FROM certops_distribution_rollouts r
    JOIN certops_material_versions v ON v.workspace_id=r.workspace_id AND v.id=r.material_version_id
    WHERE r.workspace_id=$1 AND r.group_id=$2 AND r.id=$3 FOR UPDATE OF r`,[workspaceId,groupId,rolloutId])).rows[0];
  if (!rollout || ["retired","verified"].includes(rollout.state)) return { queued: false,reason:"rollout_inactive" };
  let stale = group.state !== "active" || !!group.ended_at || Number(group.generation)!==Number(rollout.generation);
  if (!stale) {
    try { await material.assertDeployableVersion(client,workspaceId,groupId,rollout.material_version_id); }
    catch (error) {
      if (error.code !== "CERTOPS_ROLLOUT_VERSION_INVALID") throw error;
      stale = true;
    }
  }
  if (stale) {
    await client.query(`UPDATE certops_distribution_rollouts SET state='retired' WHERE workspace_id=$1 AND id=$2`,[workspaceId,rolloutId]);
    return { queued:false,reason:"rollout_superseded" };
  }
  if (rollout.state === "paused") return {queued:false,reason:"rollout_inactive"};
  const rows = (await client.query(`SELECT d.*,j.status AS job_status,b.state AS binding_state,b.authorization_revision AS current_revision
    FROM certops_consumer_deployments d LEFT JOIN certificate_jobs j ON j.workspace_id=d.workspace_id AND j.id=d.job_id
    JOIN certops_consumer_bindings b ON b.workspace_id=d.workspace_id AND b.id=d.binding_id
    WHERE d.workspace_id=$1 AND d.rollout_id=$2 ORDER BY d.wave,d.binding_id FOR UPDATE OF d`,[workspaceId,rolloutId])).rows;
  const done = (d) => d.stage === "trust_validated" || d.stage === "served_verified" && d.verification_policy === "served";
  const failed = (d) => ["failed","blocked","cancelled","rejected","orphaned_unknown_effect"].includes(d.job_status) || d.binding_state !== "active" || d.current_revision !== d.authorization_revision;
  if (rows.some((d)=>d.required && failed(d))) {
    await client.query(`UPDATE certops_distribution_rollouts SET state='paused' WHERE workspace_id=$1 AND id=$2`,[workspaceId,rolloutId]);
    return { queued:false,reason:"required_consumer_failed" };
  }
  const outstanding = rows.filter((d)=>!done(d) && !failed(d));
  if (!outstanding.length) {
    await client.query(`UPDATE certops_distribution_rollouts SET state=$3 WHERE workspace_id=$1 AND id=$2`,[workspaceId,rolloutId,rows.every(done)?"verified":"degraded"]);
    return { queued:true,reason:"rollout_completed" };
  }
  const wave = Math.min(...outstanding.map((d)=>d.wave));
  const active = outstanding.filter((d)=>d.job_id).length;
  let capacity = Math.max(0,rollout.max_parallel-active);
  for (const d of outstanding.filter((d)=>d.wave===wave && !d.job_id)) {
    if (!capacity--) break;
    const job = await createCertificateJob({ client, workspaceId, operation:"deploy-from-store",source:"control-plane",
      subjectType:"managed_certificate",subjectId:group.managed_certificate_id,assignedAgentId:d.assigned_agent_id,
      idempotencyKey:`distribution:${rolloutId}:${d.binding_id}`,payload:{ keyMode:"vault-managed",
        target:{ type:"endpoint",reference:d.binding_id },materialDeployment:{ bindingId:d.binding_id,
          rolloutId,groupId,materialVersionId:rollout.material_version_id,materialStoreRef:group.material_store_ref,
          providerVersion:rollout.provider_version,fingerprintSha256:rollout.fingerprint_sha256,generation:Number(rollout.generation),
          deploymentProfileRef:d.deployment_profile_ref,profileRevision:d.profile_revision,
          authorizationRevision:d.authorization_revision,verificationPolicy:d.verification_policy,
          ...(rollout.verification_only?{verificationOnly:true}:{}) } } });
    await client.query(`UPDATE certops_consumer_deployments SET job_id=$4 WHERE workspace_id=$1 AND rollout_id=$2 AND binding_id=$3 AND job_id IS NULL`,[workspaceId,rolloutId,d.binding_id,job.id]);
  }
  await client.query(`UPDATE certops_distribution_rollouts SET state='deploying' WHERE workspace_id=$1 AND id=$2`,[workspaceId,rolloutId]);
  return { deferred:true,retryInMs:15000,reason:"waiting_for_consumers" };
}

async function handleDistributionIntent({ dbPool = pool, row, claimId, payload }) {
  return transaction(async (client) => {
    const owner = await client.query(`SELECT id FROM certops_outbox WHERE id=$1 AND claim_id=$2 AND claimed_until>clock_timestamp() FOR UPDATE`,[row.id,claimId]);
    if (!owner.rowCount) return { queued:false,reason:"outbox_claim_lost" };
    return processDistributionIntent({client,row,payload});
  },dbPool);
}

// Variant workers may hold the outbox row in their caller-owned transaction.
// Keep expansion and its acknowledgement atomic on that same connection.
async function processDistributionIntent({client,row,payload}) {
    if (row.event_type === "material_published") {
      const v = await client.query(`SELECT 1 FROM certops_material_versions WHERE workspace_id=$1 AND group_id=$2 AND id=$3 AND state='published'`,[row.workspace_id,payload.groupId,payload.materialVersionId]);
      return { queued:!!v.rowCount,reason:"publication_available_for_approved_rollout" };
    }
    if (row.event_type === "distribution_approval_granted") {
      await lockWorkspaceForCertOpsSideEffect({client,workspaceId:row.workspace_id});
      const job = (await client.query(`SELECT * FROM certificate_jobs WHERE workspace_id=$1 AND id=$2 FOR UPDATE`,[row.workspace_id,payload.jobId])).rows[0];
      if (!job?.payload?.distributionRollout || !["pending","succeeded"].includes(job.status)) return { queued:false,reason:"approval_no_longer_active" };
      const intent=job.payload.distributionRollout;
      try {
        await material.createRolloutSnapshot({ client,workspaceId:row.workspace_id,groupId:intent.groupId,
          materialVersionId:intent.materialVersionId,maxParallel:intent.maxParallel,verificationOnly:intent.verificationOnly,approvalJobId:job.id,approvedIntentHash:material.hashIntent(intent) });
      } catch (error) {
        // These logical precondition failures occur before snapshot writes.
        // A fresh request/approval is required; never rewrite the frozen intent
        // or retry it against changed membership, validity or generation.
        if (job.status !== "pending" || !["CERTOPS_ROLLOUT_APPROVAL_MISMATCH","CERTOPS_ROLLOUT_VERSION_INVALID",
          "CERTOPS_ROLLOUT_POLICY_INVALID","CERTOPS_DISTRIBUTION_INACTIVE"].includes(error.code)) throw error;
        await client.query(`UPDATE certificate_jobs SET status='failed',error_code='CERTOPS_ROLLOUT_APPROVAL_STALE',
          error_message='Rollout authorization changed; request a new rollout approval',completed_at=clock_timestamp(),updated_at=clock_timestamp(),
          approved_by_user_id=NULL,approved_at=NULL,approved_payload_hash=NULL,approved_canonical_intent_hash=NULL
          WHERE workspace_id=$1 AND id=$2`,[row.workspace_id,job.id]);
        await client.query(`INSERT INTO certops_job_approvals(workspace_id,job_id,decision,payload_hash,reason)
          VALUES($1,$2,'invalidated',$3,$4)`,[row.workspace_id,job.id,job.approved_payload_hash,error.code]);
        await require("./jobs").appendCertificateJobLog({client,workspaceId:row.workspace_id,jobId:job.id,
          eventType:"approval.invalidated",status:"failed",message:"Rollout approval is stale; request a new rollout",
          metadata:{reason:error.code}});
        return {queued:false,reason:"rollout_approval_stale"};
      }
      await client.query(`UPDATE certificate_jobs SET status='succeeded',completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE workspace_id=$1 AND id=$2 AND status='pending'`,[row.workspace_id,job.id]);
      return { queued:true,reason:"approved_rollout_created" };
    }
    return advanceRollout(client,row.workspace_id,payload.groupId,payload.rolloutId);

}

async function retryDistributionJob({ workspaceId,jobId,actorUserId }) {
  jobId = material.normalizeDistributionId(jobId);
  return transaction(async(client)=>{
    await lockWorkspaceForCertOpsSideEffect({client,workspaceId});
    const job=(await client.query(`SELECT * FROM certificate_jobs WHERE workspace_id=$1 AND id=$2 FOR UPDATE`,[workspaceId,jobId])).rows[0];
    if(!job || !(job.payload?.publication || job.payload?.materialDeployment))fail("CERTOPS_MATERIAL_JOB_NOT_FOUND",404);
    const intent=job.payload.publication||job.payload.materialDeployment;
    await material.lockGroup(client,workspaceId,intent.groupId);
    if(!["failed","blocked","orphaned_unknown_effect"].includes(job.status) || job.attempt_count>=3)fail("CERTOPS_MATERIAL_RETRY_UNAVAILABLE");
    // The payload/version/approval/consumer membership remain unchanged.
    // An uncertain local deployment still needs read-only reconciliation.
    const workspace=(await client.query(`SELECT certops_require_approval_always FROM workspaces WHERE id=$1 FOR SHARE`,[workspaceId])).rows[0];
    const status=workspace.certops_require_approval_always&&!job.approved_payload_hash?"pending_approval":"pending";
    await client.query(`UPDATE certificate_jobs SET status=$3,claim_id=NULL,claimed_by_agent_id=NULL,lease_expires_at=NULL,
      lease_renewed_at=NULL,completed_at=NULL,started_at=NULL,next_attempt_at=NULL,error_code=NULL,error_message=NULL,updated_at=clock_timestamp()
      WHERE workspace_id=$1 AND id=$2`,[workspaceId,jobId,status]);
    if(job.payload.materialDeployment)await client.query(`UPDATE certops_consumer_deployments SET stage='pending',failure_code=NULL
      WHERE workspace_id=$1 AND job_id=$2`,[workspaceId,jobId]);
    await require("../audit").writeAudit({client,workspaceId,actorUserId,action:"CERTOPS_MATERIAL_JOB_RETRY_REQUESTED",targetType:"certificate_job",targetId:jobId,metadata:{materialVersionId:intent.materialVersionId,status}});
    return {jobId,status,materialVersionId:intent.materialVersionId};
  });
}

module.exports={ transaction,putBinding,requestRollout,setRolloutState,advanceRollout,handleDistributionIntent,processDistributionIntent,retryDistributionJob };

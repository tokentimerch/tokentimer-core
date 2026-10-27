"use strict";
// Control-plane public metadata only. Never connects to a customer store.
const crypto=require("node:crypto");
const material=require("./materialDistribution");
const lifecycle=require("./distributionLifecycle");
const {assertDistributionPolicy}=require("./distributionPolicy");
const {writeAudit}=require("../audit");
const {hasFreshCapability}=require("./agentJobEligibility");
function fail(code,statusCode=409){const e=new Error(code);e.code=code;e.statusCode=statusCode;throw e;}
const CAPABILITY="material-cleanup-vault-kv2-v1";
async function availability({client,workspaceId,group,env=process.env}){
  if(env.CERTOPS_MATERIAL_CLEANUP_ENABLED!=="true")return {available:false,code:"CERTOPS_MATERIAL_CLEANUP_DISABLED"};
  const agent=(await client.query("SELECT status,last_seen_at,declared_capabilities,capabilities_updated_at,supported_operations FROM certops_agents WHERE workspace_id=$1 AND id=$2",[workspaceId,group.issuer_agent_id])).rows[0];
  const available=agent?.status==="active" && Date.now()-new Date(agent.last_seen_at).getTime()<900000 &&
    agent.supported_operations?.includes("cleanup-from-store") && hasFreshCapability({declaredCapabilities:agent.declared_capabilities,capabilitiesUpdatedAt:agent.capabilities_updated_at,capability:CAPABILITY});
  return {available:Boolean(available),code:available?null:"CERTOPS_MATERIAL_CLEANUP_NOT_QUALIFIED"};
}
async function context(client,workspaceId,groupId){
  await assertDistributionPolicy({client,workspaceId});
  const group=await material.lockGroup(client,workspaceId,groupId);
  const policy=await lifecycle.loadPolicy(client,workspaceId,group.id);
  if(!policy?.policy.retention.cleanupEnabled || policy.policy.retention.reportOnly || !policy.policy.retention.requiresApproval)fail("CERTOPS_MATERIAL_CLEANUP_DISABLED");
  const readiness=await availability({client,workspaceId,group});if(!readiness.available)fail(readiness.code);
  const scope=await lifecycle.authorizationScope(client,workspaceId,group,policy.policy);
  return {group,policy,scope};
}
async function requestCleanup({workspaceId,groupId,materialVersionId,actorUserId,expectedRevision,reauthorize=false}){
  materialVersionId=material.normalizeDistributionId(materialVersionId);
  return require("./distributionOperations").transaction(async client=>{
    const {group,policy,scope}=await context(client,workspaceId,groupId);
    if(expectedRevision!==policy.revision)fail("CERTOPS_LIFECYCLE_POLICY_REVISION_CHANGED");
    const existing=(await client.query("SELECT c.*,j.status AS job_status,j.payload->'materialCleanup'->>'expiresAt' AS authority_expires_at FROM certops_material_cleanups c LEFT JOIN certificate_jobs j ON j.workspace_id=c.workspace_id AND j.id=c.job_id WHERE c.workspace_id=$1 AND c.group_id=$2 AND c.material_version_id=$3 FOR UPDATE OF c",[workspaceId,group.id,materialVersionId])).rows[0];
    const current=existing && existing.scope_hash===scope.hash && existing.policy_revision===policy.revision && Date.parse(existing.authority_expires_at)>Date.now() && ["pending_approval","pending","claimed","running"].includes(existing.job_status);
    if(existing && (existing.state==="soft_deleted" || current || !reauthorize))return {cleanupId:existing.id,jobId:existing.job_id,status:existing.job_status,state:existing.state,duplicate:true,requiresReauthorization:!current && existing.state!=="soft_deleted"};
    if(existing && ["claimed","running"].includes(existing.job_status))fail("CERTOPS_MATERIAL_CLEANUP_LIVE_CLAIM");
    const preview=await require("./distributionAdministration").retentionPreview({client,workspaceId,groupId:group.id});
    const candidate=preview.versions.find(v=>v.id===materialVersionId);
    if(!candidate || candidate.profile_revision!==group.profile_revision || !candidate.metadataEligible && existing?.state!=="fenced")fail("CERTOPS_MATERIAL_CLEANUP_PROTECTED");
    const id=existing?.id || crypto.randomUUID();
    const intent={type:"vault-kv2-soft-delete",cleanupId:id,groupId:group.id,managementPeriodId:group.management_period_id,
      materialVersionId,materialStoreRef:group.material_store_ref,profileRevision:group.profile_revision,
      providerVersion:candidate.provider_version,policyRevision:policy.revision,scopeHash:scope.hash,
      retentionPolicy:policy.policy.retention,expiresAt:new Date(Date.now()+86400000).toISOString()};
    material.validateDistributionContract("materialCleanup",intent);
    if(existing){
      // Pending authority may be superseded explicitly; uncertain history is
      // preserved. A permanent version fence is never released for re-review.
      await client.query("UPDATE certificate_jobs SET status='cancelled',completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE workspace_id=$1 AND id=$2 AND status IN ('pending_approval','pending')",[workspaceId,existing.job_id]);
      await client.query("UPDATE certops_material_cleanups SET job_id=NULL,policy_revision=$3,scope_hash=$4 WHERE workspace_id=$1 AND id=$2",[workspaceId,id,policy.revision,scope.hash]);
    }else await client.query("INSERT INTO certops_material_cleanups(id,workspace_id,group_id,material_version_id,policy_revision,scope_hash,created_by_user_id) VALUES($1,$2,$3,$4,$5,$6,$7)",[id,workspaceId,group.id,materialVersionId,policy.revision,scope.hash,actorUserId]);
    const job=await require("./jobs").createCertificateJob({client,workspaceId,operation:"cleanup-from-store",subjectType:"managed_certificate",subjectId:group.managed_certificate_id,
      assignedAgentId:group.issuer_agent_id,requestedByUserId:actorUserId,requiresApproval:true,mode:"real",source:"api",idempotencyKey:`material-cleanup:${id}:${crypto.randomUUID()}`,
      payload:{schemaVersion:1,keyMode:"vault-managed",target:{type:"endpoint",reference:group.id},materialCleanup:intent}});
    await client.query("UPDATE certops_material_cleanups SET job_id=$3 WHERE workspace_id=$1 AND id=$2",[workspaceId,id,job.id]);
    await lifecycle.notifyApproval(client,workspaceId,job);
    await writeAudit({client,workspaceId,actorUserId,action:existing?"CERTOPS_MATERIAL_CLEANUP_REAUTHORIZED":"CERTOPS_MATERIAL_CLEANUP_REQUESTED",targetType:"certops_material_cleanup",targetId:id,metadata:{materialVersionId,jobId:job.id,previousJobId:existing?.job_id || null,policyRevision:policy.revision}});
    return {cleanupId:id,jobId:job.id,status:job.status,state:existing?.state || "planned",duplicate:false};
  });
}
async function resolveCleanupDefaults({client,workspaceId,operation,subjectId,payload,assignedAgentId,jobId}){
  const intent=material.validateDistributionContract("materialCleanup",payload.materialCleanup);
  const {group,policy,scope}=await context(client,workspaceId,intent.groupId);
  const request=(await client.query("SELECT * FROM certops_material_cleanups WHERE workspace_id=$1 AND id=$2 FOR UPDATE",[workspaceId,intent.cleanupId])).rows[0];
    const version=(await client.query("SELECT provider_version,profile_revision FROM certops_material_versions WHERE workspace_id=$1 AND group_id=$2 AND id=$3",[workspaceId,group.id,intent.materialVersionId])).rows[0];
  if(operation!=="cleanup-from-store" || subjectId!==group.managed_certificate_id || assignedAgentId!==group.issuer_agent_id ||
    !request || request.group_id!==group.id || request.material_version_id!==intent.materialVersionId || request.state==="soft_deleted" ||
    (jobId?request.job_id!==jobId:request.job_id!==null) || request.scope_hash!==scope.hash || intent.scopeHash!==scope.hash ||
    intent.policyRevision!==policy.revision || request.policy_revision!==policy.revision || intent.managementPeriodId!==group.management_period_id ||
    intent.profileRevision!==group.profile_revision || version?.profile_revision!==group.profile_revision || intent.materialStoreRef!==group.material_store_ref || intent.providerVersion!==version?.provider_version ||
    Date.parse(intent.expiresAt)<=Date.now() || material.hashIntent(intent.retentionPolicy)!==material.hashIntent(policy.policy.retention))fail("CERTOPS_MATERIAL_CLEANUP_AUTHORIZATION_STALE");
  if(request.state==="planned"){
    const preview=await require("./distributionAdministration").retentionPreview({client,workspaceId,groupId:group.id});
    if(!preview.versions.find(v=>v.id===intent.materialVersionId)?.metadataEligible)fail("CERTOPS_MATERIAL_CLEANUP_PROTECTED");
  }
  if(jobId){
    const job=(await client.query("SELECT * FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[workspaceId,jobId])).rows[0];
    if(!job?.approved_by_user_id || !job.approved_at || !job.approved_payload_hash ||
      require("./jobApprovals").computeJobPayloadApprovalHash(job.payload)!==job.approved_payload_hash ||
      require("./jobApprovals").computeCanonicalIntentHash({operation:job.operation,subjectType:job.subject_type,subjectId:job.subject_id,payload:job.payload})!==job.approved_canonical_intent_hash)fail("CERTOPS_MATERIAL_CLEANUP_APPROVAL_REQUIRED");
    if(request.state==="planned" && job.mode!=="dry_run"){
      // Atomic with claim. This permanent fence survives lease loss, cancellation
      // and uncertain effects; SQL triggers prohibit all later material reuse.
      await client.query("UPDATE certops_material_cleanups SET state='fenced',fenced_at=clock_timestamp() WHERE workspace_id=$1 AND id=$2",[workspaceId,request.id]);
      await writeAudit({client,workspaceId,action:"CERTOPS_MATERIAL_CLEANUP_FENCED",targetType:"certops_material_cleanup",targetId:request.id,metadata:{materialVersionId:intent.materialVersionId,jobId}});
    }
  }
  return {autoAssignedAgentId:assignedAgentId};
}
async function acceptCleanupReceipt({client,workspaceId,agentId,job,receipt}){
  material.validateDistributionContract("cleanupReceipt",receipt);
  const intent=job.payload.materialCleanup;
  await material.lockGroup(client,workspaceId,intent.groupId,{allowInactive:true});
  const request=(await client.query("SELECT * FROM certops_material_cleanups WHERE workspace_id=$1 AND id=$2 FOR UPDATE",[workspaceId,intent.cleanupId])).rows[0];
  const live=await client.query("SELECT 1 FROM certificate_jobs WHERE workspace_id=$1 AND id=$2 AND claim_id=$3 AND lease_expires_at>clock_timestamp()",[workspaceId,job.id,job.claim_id]);
  if(job.mode!=="real" || !request || request.job_id!==job.id || !["fenced","soft_deleted"].includes(request.state) || !live.rowCount || job.claimed_by_agent_id!==agentId || job.assigned_agent_id!==agentId ||
    receipt.workspaceId!==workspaceId || receipt.cleanupId!==request.id || receipt.groupId!==request.group_id || receipt.materialVersionId!==request.material_version_id ||
    receipt.providerVersion!==intent.providerVersion || receipt.method!=="vault-kv2-soft-delete" || receipt.softDeleted!==true ||
    Date.parse(receipt.observedAt)>Date.now()+30000 || Date.now()-Date.parse(receipt.observedAt)>300000)fail("CERTOPS_MATERIAL_CLEANUP_RECEIPT_MISMATCH");
  if(request.state==="soft_deleted")return {duplicate:true};
  await client.query("UPDATE certops_material_cleanups SET state='soft_deleted',completed_at=clock_timestamp(),receipt=$3 WHERE workspace_id=$1 AND id=$2",[workspaceId,request.id,receipt]);
  await writeAudit({client,workspaceId,action:"CERTOPS_MATERIAL_CLEANUP_COMPLETED",targetType:"certops_material_cleanup",targetId:request.id,metadata:receipt});
  return {duplicate:false};
}
module.exports={CAPABILITY,availability,requestCleanup,resolveCleanupDefaults,acceptCleanupReceipt};

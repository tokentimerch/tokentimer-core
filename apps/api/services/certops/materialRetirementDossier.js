"use strict";

// Human review records an advisory dossier, never a claim that the external
// evidence is true or that an uncertain operation succeeded.
const crypto=require("crypto");
const material=require("./materialDistribution");
const {assertDistributionPolicy}=require("./distributionPolicy");
const {transaction}=require("./distributionOperations");

function fail(code,statusCode=409){const e=new Error(code);e.code=code;e.statusCode=statusCode;throw e;}
const kinds=["writerInventory","writerIsolation","destinationIsolation","replacementReadback"];
function validateEvidence(evidence){
  if(!evidence || typeof evidence!=="object" || Array.isArray(evidence) ||
    Object.keys(evidence).length!==kinds.length || kinds.some(k=>typeof evidence[k]!=="string" || !/^sha256:[a-f0-9]{64}$/.test(evidence[k])))
    fail("CERTOPS_RETIREMENT_EVIDENCE_INVALID",422);
  return Object.fromEntries(kinds.map(k=>[k,evidence[k]]));
}
async function authority(client,workspaceId,actor){
  if(!actor)fail("CERTOPS_RETIREMENT_AUTHORITY_STALE");
  const w=(await client.query("SELECT created_by,certops_paused,certops_distribution_authorization_revision FROM workspaces WHERE id=$1 FOR SHARE",[workspaceId])).rows[0];
  if(!w || w.certops_paused)fail("CERTOPS_RETIREMENT_AUTHORITY_STALE");
  const members=(await client.query("SELECT user_id FROM workspace_memberships WHERE workspace_id=$1 AND role IN ('admin','workspace_manager')",[workspaceId])).rows;
  const active=new Set([w.created_by,...members.map(x=>x.user_id)].filter(Boolean).map(String));
  if(!active.has(String(actor)))fail("CERTOPS_RETIREMENT_AUTHORITY_STALE");
  return {active,revision:String(w.certops_distribution_authorization_revision)};
}
async function snapshot(client,workspaceId,jobId){
  jobId=material.normalizeDistributionId(jobId);
  const hint=(await client.query("SELECT payload FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[workspaceId,jobId])).rows[0];
  const intent=hint?.payload?.materialDeployment;
  if(!intent)fail("CERTOPS_RETIREMENT_UNAVAILABLE",404);
  const group=await material.lockGroup(client,workspaceId,intent.groupId);
  const old=(await client.query("SELECT * FROM certificate_jobs WHERE workspace_id=$1 AND id=$2 FOR UPDATE",[workspaceId,jobId])).rows[0];
  if(!old?.needs_operator_reconciliation || material.hashIntent(old.payload.materialDeployment)!==material.hashIntent(intent) ||
    !["rejected","failed","blocked","orphaned_unknown_effect"].includes(old.status) || Number(group.generation)<=intent.generation)
    fail("CERTOPS_RETIREMENT_STALE");
  const binding=(await client.query("SELECT state,assigned_agent_id,authorization_revision FROM certops_consumer_bindings WHERE workspace_id=$1 AND group_id=$2 AND id=$3 FOR UPDATE",[workspaceId,intent.groupId,intent.bindingId])).rows[0];
  const current=(await client.query("SELECT desired_generation,desired_material_version_id FROM certops_consumer_current_state WHERE workspace_id=$1 AND binding_id=$2 FOR UPDATE",[workspaceId,intent.bindingId])).rows[0];
  if(!binding || !current)fail("CERTOPS_RETIREMENT_STALE");
  return {originalJobId:old.id,assignedAgentId:old.assigned_agent_id,groupId:intent.groupId,bindingId:intent.bindingId,
    originalGeneration:intent.generation,currentGeneration:Number(group.generation),intentHash:material.hashIntent(intent),
    bindingState:binding.state,currentAgentId:binding.assigned_agent_id,bindingAuthorizationRevision:String(binding.authorization_revision),
    desiredGeneration:Number(current.desired_generation),desiredMaterialVersionId:current.desired_material_version_id,
    history:"unknown"};
}
async function request({workspaceId,jobId,actorUserId,evidence}){
  evidence=validateEvidence(evidence);
  return transaction(async client=>{
    await assertDistributionPolicy({client,workspaceId});
    const auth=await authority(client,workspaceId,actorUserId),scope=await snapshot(client,workspaceId,jobId);
    scope.workspaceAuthorizationRevision=auth.revision;
    const dossierHash=material.hashIntent({workspaceId,scope,evidence,requestedBy:String(actorUserId)});
    const id=crypto.randomUUID();
    await client.query(`INSERT INTO certops_material_retirement_dossiers
      (id,workspace_id,original_job_id,scope,evidence,dossier_hash,requested_by,status)
      VALUES($1,$2,$3,$4::jsonb,$5::jsonb,$6,$7,'pending_review')`,
      [id,workspaceId,scope.originalJobId,JSON.stringify(scope),JSON.stringify(evidence),dossierHash,actorUserId]);
    await require("../audit").writeAudit({client,workspaceId,actorUserId,action:"CERTOPS_RETIREMENT_DOSSIER_REQUESTED",targetType:"certificate_job",targetId:scope.originalJobId,metadata:{dossierId:id,dossierHash}});
    return {id,scope,evidence,dossierHash,status:"pending_review",history:"unknown",evidenceVerified:false};
  });
}
async function review({workspaceId,dossierId,actorUserId,dossierHash}){
  dossierId=material.normalizeDistributionId(dossierId);
  return transaction(async client=>{
    await assertDistributionPolicy({client,workspaceId});
    const auth=await authority(client,workspaceId,actorUserId);
    const hint=(await client.query("SELECT original_job_id FROM certops_material_retirement_dossiers WHERE workspace_id=$1 AND id=$2",[workspaceId,dossierId])).rows[0];
    if(!hint)fail("CERTOPS_RETIREMENT_UNAVAILABLE",404);
    const current=await snapshot(client,workspaceId,hint.original_job_id);
    const d=(await client.query("SELECT * FROM certops_material_retirement_dossiers WHERE workspace_id=$1 AND id=$2 FOR UPDATE",[workspaceId,dossierId])).rows[0];
    current.workspaceAuthorizationRevision=auth.revision;
    if(!d || d.status!=="pending_review" || !auth.active.has(String(d.requested_by)) || String(d.requested_by)===String(actorUserId) ||
      d.dossier_hash!==dossierHash || material.hashIntent({workspaceId,scope:current,evidence:validateEvidence(d.evidence),requestedBy:String(d.requested_by)})!==d.dossier_hash)
      fail("CERTOPS_RETIREMENT_REVIEW_STALE");
    await client.query("UPDATE certops_material_retirement_dossiers SET status='reviewed_history_unknown',reviewed_by=$3,reviewed_at=clock_timestamp() WHERE workspace_id=$1 AND id=$2",[workspaceId,dossierId,actorUserId]);
    await require("../audit").writeAudit({client,workspaceId,actorUserId,action:"CERTOPS_RETIREMENT_DOSSIER_REVIEWED",targetType:"certificate_job",targetId:hint.original_job_id,metadata:{dossierId,dossierHash,history:"unknown",evidenceVerified:false}});
    return {id:dossierId,status:"reviewed_history_unknown",history:"unknown",evidenceVerified:false,reconciliationCleared:false};
  });
}
async function get({workspaceId,dossierId}){
  dossierId=material.normalizeDistributionId(dossierId);
  return transaction(async client=>{
    const d=(await client.query("SELECT id,original_job_id,scope,evidence,dossier_hash,status,requested_by,reviewed_by,created_at,reviewed_at FROM certops_material_retirement_dossiers WHERE workspace_id=$1 AND id=$2",[workspaceId,dossierId])).rows[0];
    if(!d)fail("CERTOPS_RETIREMENT_UNAVAILABLE",404);
    let scopeCurrent=false;
    try {
      const current=await snapshot(client,workspaceId,d.original_job_id);
      const w=(await client.query("SELECT certops_distribution_authorization_revision FROM workspaces WHERE id=$1",[workspaceId])).rows[0];
      current.workspaceAuthorizationRevision=String(w.certops_distribution_authorization_revision);
      scopeCurrent=material.hashIntent(current)===material.hashIntent(d.scope);
    } catch(e) { if(!["CERTOPS_RETIREMENT_STALE","CERTOPS_RETIREMENT_UNAVAILABLE","CERTOPS_DISTRIBUTION_NOT_FOUND"].includes(e.code))throw e; }
    return {...d,scopeStatus:scopeCurrent?"current":"stale",history:"unknown",evidenceVerified:false,reconciliationCleared:false};
  });
}
module.exports={request,review,get,validateEvidence};

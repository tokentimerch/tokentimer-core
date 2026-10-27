"use strict";
const crypto=require("node:crypto");
const {pool}=require("../../apps/api/db/database");
const operations=require("../../apps/api/services/certops/distributionOperations");
const {createCertificateIssuanceJob}=require("../../apps/api/services/certops/issuance");
async function fixture({requireApproval=false}={}) {
  const workspaceId=crypto.randomUUID();
  async function user(){return (await pool.query(`INSERT INTO users(email,display_name,password_hash,auth_method)
    VALUES($1,'Lifecycle fixture','synthetic-test-only','local') RETURNING id`,[`${crypto.randomUUID()}@example.test`])).rows[0].id;}
  const actor=await user(),approver=await user();
  await pool.query(`INSERT INTO workspaces(id,name,created_by,plan,certops_require_approval_always)
    VALUES($1,'Isolated lifecycle test',$2,'oss',$3)`,[workspaceId,actor,requireApproval]);
  await pool.query(`INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES($1,$2,'workspace_manager')`,[workspaceId,approver]);
  async function agent(){return (await pool.query(`INSERT INTO certops_agents(workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash,
    supported_operations,declared_capabilities,declared_target_selectors,supported_dns_providers,declared_command_profile_names,capabilities_updated_at,last_seen_at)
    VALUES($1,$2,'0.18.1','1.0.0',$3,$4,'["renew","deploy-from-store"]',
      '["material-store-vault-kv2-v1","certificate-publication-v1","deploy-from-store-v1","evidence-claim-binding-v1","signed-payload-b64-v1"]',
      '["shared.example.test"]','["cloudflare"]','["certbot"]',NOW(),NOW()) RETURNING id`,
    [workspaceId,crypto.randomUUID(),`ttagent_${crypto.randomBytes(8).toString("hex")}`,crypto.randomBytes(32).toString("hex")])).rows[0].id;}
  const issuer=await agent(),consumer=await agent();
  const issued=await operations.transaction(client=>createCertificateIssuanceJob({client,workspaceId,requestedByUserId:actor,assignedAgentId:issuer,
    idempotencyKey:crypto.randomUUID(),payload:{target:{type:"domain",reference:"shared.example.test"},sans:["shared.example.test"],
      caEndpoint:"https://acme.example.test/directory",commandRef:"certbot",dnsProvider:"cloudflare",dnsZone:"example.test",keyAlgorithm:"rsa",keySize:2048,
      publicationDestination:{materialStoreRef:"customer",issuanceProfileRef:"shared",profileRevision:1}}}));
  const {groupId,materialVersionId}=issued.job.payload.publication;
  const fingerprint=crypto.randomBytes(32).toString("hex");
  const identity=(await pool.query(`INSERT INTO certops_certificate_identities(workspace_id,fingerprint_sha256) VALUES($1,$2) RETURNING id`,[workspaceId,fingerprint])).rows[0].id;
  // Public synthetic receipt metadata only; no service execution is claimed.
  await pool.query(`UPDATE certops_material_versions SET state='published',certificate_identity_id=$2,provider_version=1,
    fingerprint_sha256=$3,valid_to=clock_timestamp()+interval '30 days',published_at=clock_timestamp(),publishing_claim_id=$4 WHERE id=$1`,
    [materialVersionId,identity,fingerprint,crypto.randomUUID()]);
  await pool.query(`UPDATE certops_distribution_groups SET latest_material_version_id=$3 WHERE workspace_id=$1 AND id=$2`,[workspaceId,groupId,materialVersionId]);
  await pool.query(`UPDATE certificate_jobs SET status='succeeded',completed_at=NOW() WHERE id=$1`,[issued.job.id]);
  const bindingId=crypto.randomUUID(),binding={agentId:consumer,deploymentProfileRef:"web",profileRevision:1,required:true,wave:0,verificationPolicy:"served",freshnessSeconds:3600,state:"active"};
  await operations.putBinding({workspaceId,groupId,bindingId,binding,actorUserId:actor});
  return {workspaceId,actor,approver,issuer,consumer,groupId,materialVersionId,bindingId,binding,certificateId:issued.job.subjectId,identity,fingerprint};
}
async function proveConsumer(f){
  const material=require("../../apps/api/services/certops/materialDistribution");
  const rollout=(await pool.query(`SELECT * FROM certops_distribution_rollouts WHERE workspace_id=$1 AND group_id=$2 ORDER BY generation DESC LIMIT 1`,[f.workspaceId,f.groupId])).rows[0];
  await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,rollout.id));
  const claimId=crypto.randomUUID();
  const job=(await pool.query(`UPDATE certificate_jobs SET status='claimed',claim_id=$2,claimed_by_agent_id=assigned_agent_id,
    lease_expires_at=clock_timestamp()+interval '5 minutes',attempt_count=1 WHERE id=(SELECT job_id FROM certops_consumer_deployments
    WHERE workspace_id=$1 AND rollout_id=$3 AND binding_id=$4) RETURNING *`,[f.workspaceId,claimId,rollout.id,f.bindingId])).rows[0];
  const version=(await pool.query(`SELECT * FROM certops_material_versions WHERE workspace_id=$1 AND id=$2`,[f.workspaceId,rollout.material_version_id])).rows[0];
  const receipt={schemaVersion:1,workspaceId:f.workspaceId,groupId:f.groupId,bindingId:f.bindingId,materialVersionId:version.id,
    generation:Number(rollout.generation),fetched:true,installed:true,bound:true,servedVerified:true,trustValidated:false,
    fingerprintSha256:version.fingerprint_sha256,validTo:new Date(version.valid_to).toISOString(),observedAt:new Date().toISOString()};
  await operations.transaction(client=>material.acceptDeploymentReceipt({client,workspaceId:f.workspaceId,agentId:f.consumer,job,receipt,jobStatus:"succeeded"}));
  await pool.query(`UPDATE certificate_jobs SET status='succeeded',completed_at=clock_timestamp() WHERE id=$1`,[job.id]);
  await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,rollout.id));
  return {job,receipt,rollout};
}
module.exports={fixture,proveConsumer};

"use strict";
const test=require("node:test");
const assert=require("node:assert/strict");
const crypto=require("node:crypto");
const fs=require("node:fs");
const path=require("node:path");
// Hard fence: no default environment/database and no root .env loader.
assert.equal(process.env.DB_HOST,"127.0.0.1");assert.equal(process.env.DB_PORT,"57470");
assert.match(process.env.DB_NAME||"",/^wildcard_candidate_/);
process.env.ENFORCE_CERTOPS_LIMITS="true";
const apiRoot=process.env.TT_WILDCARD_API_ROOT || path.resolve(__dirname,"../../apps/api");
const {pool}=require(path.join(apiRoot,"db/database"));
const material=require(path.join(apiRoot,"services/certops/materialDistribution"));
const operations=require(path.join(apiRoot,"services/certops/distributionOperations"));
const {createCertificateIssuanceJob}=require(path.join(apiRoot,"services/certops/issuance"));
const {approveJob}=require(path.join(apiRoot,"services/certops/jobApprovals"));
const {parsePublicCertificateMaterial}=require(path.join(apiRoot,"services/certops/parser"));
const certificatePem=fs.readFileSync(path.join(__dirname,"../../packages/agent/src/verify/fixtures/leaf.crt.pem"),"utf8");
const cert=parsePublicCertificateMaterial(certificatePem)[0];
test.after(()=>pool.end());

test("real PostgreSQL publication, immutable identities, approvals, frozen waves, stale results and scope",async()=>{
  const workspaceId=crypto.randomUUID();
  const actor=(await pool.query(`INSERT INTO users(email,display_name,password_hash,auth_method) VALUES($1,'Distribution fixture','fixture-only','local') RETURNING id`,[`${workspaceId}@example.test`])).rows[0].id;
  const approver=(await pool.query(`INSERT INTO users(email,display_name,password_hash,auth_method) VALUES($1,'Approver fixture','fixture-only','local') RETURNING id`,[`approver-${workspaceId}@example.test`])).rows[0].id;
  await pool.query(`INSERT INTO workspaces(id,name,created_by,plan) VALUES($1,'Isolated distribution',$2,$3)`,[workspaceId,actor,process.env.TT_WILDCARD_API_ROOT?"pro":"oss"]);
  async function agent(){return (await pool.query(`INSERT INTO certops_agents(workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash)
    VALUES($1,$2,'0.1.0','1.0.0',$3,$4) RETURNING id`,[workspaceId,crypto.randomUUID(),`ttagent_${crypto.randomBytes(8).toString("hex")}`,crypto.randomBytes(32).toString("hex")])).rows[0].id;}
  const issuer=await agent(),consumerA=await agent(),consumerB=await agent();
  const request={workspaceId,...(process.env.TT_WILDCARD_API_ROOT?{workspacePlan:"pro"}:{}),requestedByUserId:actor,assignedAgentId:issuer,idempotencyKey:`issue-${workspaceId}`,
    payload:{target:{type:"domain",reference:cert.commonName},sans:cert.subjectAltNames,
      caEndpoint:"https://pebble:14000/dir",commandRef:"certbot",dnsProvider:"pebble-challtestsrv",dnsZone:"example.com",keyAlgorithm:"rsa",keySize:2048,keyRotation:true,
      publicationDestination:{materialStoreRef:"customer",issuanceProfileRef:"wildcard",profileRevision:1}}};
  if(process.env.TT_WILDCARD_API_ROOT) {
    await assert.rejects(operations.transaction(client=>createCertificateIssuanceJob({...request,workspacePlan:"free",client})),{code:"CERTOPS_MANAGED_CERT_LIMIT"});
    assert.equal((await pool.query("SELECT COUNT(*)::int n FROM managed_certificates WHERE workspace_id=$1",[workspaceId])).rows[0].n,0);
  }
  const first=await operations.transaction(client=>createCertificateIssuanceJob({...request,client}));
  assert.equal(first.created,true);
  const replay=await operations.transaction(client=>createCertificateIssuanceJob({...request,client}));assert.equal(replay.job.id,first.job.id);
  const jobId=first.job.id;
  const job=(await pool.query(`UPDATE certificate_jobs SET status='running',claim_id=gen_random_uuid(),claimed_by_agent_id=$2,lease_expires_at=clock_timestamp()+interval '5 minutes'
    WHERE id=$1 RETURNING *`,[jobId,issuer])).rows[0];
  const intent=job.payload.publication,groupId=intent.groupId,materialVersionId=intent.materialVersionId;
  const receipt={schemaVersion:1,workspaceId,groupId,materialVersionId,materialStoreRef:"customer",providerVersion:1,fingerprintSha256:cert.fingerprintSha256,validTo:cert.notAfter};
  await operations.transaction(async client=>{
    const result=await material.acceptPublicationReceipt({client,workspaceId,agentId:issuer,job,receipt,certificatePem});assert.equal(result.duplicate,false);
    assert.equal((await material.acceptPublicationReceipt({client,workspaceId,agentId:issuer,job,receipt,certificatePem})).duplicate,true);
    await client.query(`UPDATE certificate_jobs SET status='succeeded',completed_at=clock_timestamp() WHERE id=$1`,[jobId]);
  });
  assert.equal((await pool.query(`SELECT COUNT(*)::int n FROM certops_outbox WHERE workspace_id=$1 AND event_type='material_published'`,[workspaceId])).rows[0].n,1);
  assert.ok((await pool.query(`SELECT profile_id FROM managed_certificates WHERE id=$1`,[job.subject_id])).rows[0].profile_id);
  await assert.rejects(pool.query(`UPDATE certops_material_versions SET provider_version=2 WHERE id=$1`,[materialVersionId]),/immutable/);
  await assert.rejects(operations.transaction(client=>material.resolveDistributionJobDefaults({client,workspaceId:crypto.randomUUID(),operation:"renew",subjectId:job.subject_id,payload:job.payload,assignedAgentId:issuer})),{code:"CERTOPS_DISTRIBUTION_NOT_FOUND"});
  const bindingA=crypto.randomUUID(),bindingB=crypto.randomUUID();
  for(const [bindingId,agentId,wave] of [[bindingA,consumerA,0],[bindingB,consumerB,1]])await operations.putBinding({workspaceId,groupId,bindingId,actorUserId:actor,
    binding:{agentId,deploymentProfileRef:`web${wave}`,profileRevision:1,required:true,wave,verificationPolicy:"served",freshnessSeconds:3600,state:"active"}});
  const approval=await operations.requestRollout({workspaceId,groupId,materialVersionId,actorUserId:actor,idempotencyKey:`rollout-${workspaceId}`});
  assert.equal(approval.status,"pending_approval");
  await assert.rejects(approveJob({workspaceId,jobId:approval.id,approverUserId:actor}),{code:"CERTOPS_APPROVAL_SELF_APPROVAL_FORBIDDEN"});
  await approveJob({workspaceId,jobId:approval.id,approverUserId:approver});
  const approvalIntent=approval.payload.distributionRollout;
  const snapshot=await operations.transaction(client=>material.createRolloutSnapshot({client,workspaceId,groupId,materialVersionId,approvalJobId:approval.id,approvedIntentHash:material.hashIntent(approvalIntent)}));
  assert.equal(snapshot.generation,1);
  assert.equal((await operations.transaction(client=>material.createRolloutSnapshot({client,workspaceId,groupId,materialVersionId,approvalJobId:approval.id,approvedIntentHash:material.hashIntent(approvalIntent)}))).rolloutId,snapshot.rolloutId);
  await assert.rejects(pool.query(`UPDATE certops_consumer_deployments SET assigned_agent_id=$2 WHERE rollout_id=$1`,[snapshot.rolloutId,issuer]),/immutable/);
  if(process.env.TT_WILDCARD_API_ROOT) {
    const {pathToFileURL}=require("node:url");
    const worker=await import(pathToFileURL(path.resolve(apiRoot,"../worker/src/certops-scheduler-placeholder.js")));
    await worker.drainMaterialDistributionOutbox({maxRows:20});
    assert.equal((await pool.query("SELECT status FROM certificate_jobs WHERE id=$1",[approval.id])).rows[0].status,"succeeded");
    assert.equal((await pool.query("SELECT COUNT(*)::int n FROM certops_distribution_rollouts WHERE workspace_id=$1",[workspaceId])).rows[0].n,1);
  }
  await operations.transaction(client=>operations.advanceRollout(client,workspaceId,groupId,snapshot.rolloutId));
  const rows=(await pool.query(`SELECT * FROM certops_consumer_deployments WHERE rollout_id=$1 ORDER BY wave`,[snapshot.rolloutId])).rows;
  assert.ok(rows[0].job_id);assert.equal(rows[1].job_id,null);
  const dispatch=require(path.join(apiRoot,"services/certops/agentDispatch"));
  const signing=require(path.join(apiRoot,"services/certops/jobSigning"));
  const {verifyJobEnvelope}=require("../../packages/agent/src/signing");
  process.env.CERTOPS_SIGNING_ENCRYPTION_KEY=crypto.randomBytes(32).toString("hex");
  const signingKey=await signing.ensureActiveSigningKey();
  const consumerRow=(await pool.query("SELECT agent_id FROM certops_agents WHERE id=$1",[consumerA])).rows[0];
  const agentInfo={id:consumerA,workspaceId,agentId:consumerRow.agent_id,status:"active",protocolVersion:"1.0.0",agentVersion:"0.17.3"};
  await pool.query("UPDATE certops_agents SET declared_target_selectors=$2::jsonb,declared_capabilities='[]'::jsonb,capabilities_updated_at=clock_timestamp() WHERE id=$1",[consumerA,JSON.stringify([bindingA])]);
  const poll={agent:agentInfo,body:{supportedActions:["deploy-from-store"],maxJobs:1}};
  assert.equal((await dispatch.claimJobs(poll)).jobs.length,0,"unqualified capability must not claim");
  await pool.query("UPDATE certops_agents SET declared_capabilities=$2::jsonb,capabilities_updated_at=clock_timestamp() WHERE id=$1",[consumerA,JSON.stringify(["material-store-vault-kv2-v1","deploy-from-store-v1","evidence-claim-binding-v1","signed-payload-b64-v1"])]);
  const claimed=await dispatch.claimJobs(poll);assert.equal(claimed.jobs.length,1);
  const signed=claimed.jobs[0];const verified=verifyJobEnvelope({claimed:signed,...signingKey,pinnedSigningKeyId:signingKey.signingKeyId});assert.equal(verified.allowed,true);
  const decoded=verified.job;assert.equal(decoded.agentId,agentInfo.agentId);assert.equal(decoded.materialDeployment.materialVersionId,materialVersionId);
  const changed={...signed,payloadB64:Buffer.from(JSON.stringify({...decoded,materialDeployment:{...decoded.materialDeployment,generation:99}})).toString("base64")};
  assert.equal(verifyJobEnvelope({claimed:changed,...signingKey,pinnedSigningKeyId:signingKey.signingKeyId}).allowed,false);
  const child=(await pool.query("SELECT * FROM certificate_jobs WHERE id=$1",[rows[0].job_id])).rows[0];
  await assert.rejects(operations.transaction(client=>material.resolveDistributionJobDefaults({client,workspaceId,operation:"deploy-from-store",subjectId:child.subject_id,payload:child.payload,assignedAgentId:consumerA,jobId:crypto.randomUUID()})),{code:"CERTOPS_DEPLOYMENT_INTENT_MISMATCH"});
  const deployed={schemaVersion:1,workspaceId,groupId,bindingId:bindingA,materialVersionId,generation:1,fetched:true,installed:true,bound:true,servedVerified:true,trustValidated:false,
    fingerprintSha256:cert.fingerprintSha256,validTo:cert.notAfter,observedAt:new Date().toISOString()};
  await assert.rejects(operations.transaction(client=>material.acceptDeploymentReceipt({client,workspaceId,agentId:consumerA,job:child,receipt:{...deployed,servedVerified:false},jobStatus:"succeeded"})),{code:"CERTOPS_DEPLOYMENT_ASSURANCE_MISSING"});
  const resultBody={jobId:child.id,claimId:child.claim_id,nonce:decoded.nonce,status:"succeeded",deploymentReceipt:deployed};
  await assert.rejects(dispatch.ingestResult({agent:agentInfo,body:{...resultBody,claimId:crypto.randomUUID()}}),{code:"CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH"});
  if(process.env.TT_WILDCARD_API_ROOT) {
    await pool.query("UPDATE workspaces SET is_frozen=true,plan='free' WHERE id=$1",[workspaceId]);
    await assert.rejects(operations.requestRollout({workspaceId,groupId,materialVersionId,actorUserId:actor,idempotencyKey:"frozen-check"}),{code:"WORKSPACE_FROZEN"});
  }
  assert.equal((await dispatch.ingestResult({agent:agentInfo,body:resultBody})).ok,true);
  assert.equal((await dispatch.ingestResult({agent:agentInfo,body:resultBody})).duplicate,true);
  if(process.env.TT_WILDCARD_API_ROOT)await pool.query("UPDATE workspaces SET is_frozen=false,plan='pro' WHERE id=$1",[workspaceId]);
  await operations.transaction(client=>operations.advanceRollout(client,workspaceId,groupId,snapshot.rolloutId));
  const matrix=await material.consumerMatrix({client:pool,workspaceId,groupId});assert.equal(matrix.find(r=>r.binding_id===bindingA).converged,true);assert.equal(matrix.find(r=>r.binding_id===bindingB).observed_material_version_id,null);
  await operations.setRolloutState({workspaceId,groupId,rolloutId:snapshot.rolloutId,state:"paused",actorUserId:actor});
  await assert.rejects(operations.transaction(client=>material.resolveDistributionJobDefaults({client,workspaceId,operation:"deploy-from-store",subjectId:child.subject_id,payload:child.payload,assignedAgentId:consumerA})),{code:"CERTOPS_DEPLOYMENT_INTENT_MISMATCH"});
  const checkJob=await operations.requestRollout({workspaceId,groupId,materialVersionId,actorUserId:actor,idempotencyKey:`verify-${workspaceId}`,verificationOnly:true});
  await approveJob({workspaceId,jobId:checkJob.id,approverUserId:approver});
  const checkSnapshot=await operations.transaction(client=>material.createRolloutSnapshot({client,workspaceId,groupId,materialVersionId,approvalJobId:checkJob.id,approvedIntentHash:material.hashIntent(checkJob.payload.distributionRollout),verificationOnly:true}));
  await operations.transaction(client=>operations.advanceRollout(client,workspaceId,groupId,checkSnapshot.rolloutId));
  const checked=await dispatch.claimJobs(poll);assert.equal(checked.jobs.length,1);
  const checkedIntent=verifyJobEnvelope({claimed:checked.jobs[0],...signingKey,pinnedSigningKeyId:signingKey.signingKeyId}).job;
  assert.equal(checkedIntent.materialDeployment.verificationOnly,true);
  assert.equal(checkedIntent.materialDeployment.generation,2);
  await dispatch.ingestResult({agent:agentInfo,body:{jobId:checkedIntent.jobId,claimId:checkedIntent.claimId,nonce:checkedIntent.nonce,status:"failed",errorMessage:"material_drift_detected"}});
  const failedProof=(await pool.query("SELECT stage,failure_code,job_id FROM certops_consumer_deployments WHERE rollout_id=$1 AND binding_id=$2",[checkSnapshot.rolloutId,bindingA])).rows[0];
  assert.equal(failedProof.stage,"failed");assert.equal(failedProof.failure_code,"agent_result_failed");
  const retry=await operations.retryDistributionJob({workspaceId,jobId:failedProof.job_id,actorUserId:actor});
  assert.equal(retry.materialVersionId,materialVersionId);
  assert.equal((await material.consumerMatrix({client:pool,workspaceId,groupId})).find(r=>r.binding_id===bindingA).converged,false);
  await operations.transaction(async client=>{await client.query(`UPDATE certops_management_periods SET ended_at=clock_timestamp(),ended_reason='retired' WHERE workspace_id=$1 AND id=$2`,[workspaceId,intent.managementPeriodId]);});
  await assert.rejects(operations.transaction(client=>material.acceptPublicationReceipt({client,workspaceId,agentId:issuer,job,receipt,certificatePem})),{code:"CERTOPS_DISTRIBUTION_INACTIVE"});
});

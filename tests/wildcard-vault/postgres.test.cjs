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
// Public-only renewal identity fixture. The separate native lifecycle scenario
// obtains both actual certificates from Pebble; no key enters this API test.
const renewedPem=fs.readFileSync(path.join(__dirname,"renewed-public.crt.pem"),"utf8");
const renewedCert=parsePublicCertificateMaterial(renewedPem)[0];
test.after(()=>pool.end());

test("real PostgreSQL publication, renewal identities, approvals, frozen waves, stale results and scope",async()=>{
  const workspaceId=crypto.randomUUID();
  const actor=(await pool.query(`INSERT INTO users(email,display_name,password_hash,auth_method) VALUES($1,'Distribution fixture','fixture-only','local') RETURNING id`,[`${workspaceId}@example.test`])).rows[0].id;
  const approver=(await pool.query(`INSERT INTO users(email,display_name,password_hash,auth_method) VALUES($1,'Approver fixture','fixture-only','local') RETURNING id`,[`approver-${workspaceId}@example.test`])).rows[0].id;
  await pool.query(`INSERT INTO workspaces(id,name,created_by,plan) VALUES($1,'Isolated distribution',$2,$3)`,[workspaceId,actor,process.env.TT_WILDCARD_API_ROOT?"pro":"oss"]);
  // The Cloud candidate advances its Core baseline. Exercise its real upgraded
  // inventory name constraint as well as the material tables below.
  const nameInsert="INSERT INTO tokens(user_id,workspace_id,created_by,name,expiration,type,category) VALUES($1,$2,$1,$3,'2027-01-01','other','general') RETURNING name";
  for(const name of ["x","x".repeat(255)]) assert.equal((await pool.query(nameInsert,[actor,workspaceId,name])).rows[0].name,name);
  await assert.rejects(pool.query(nameInsert,[actor,workspaceId," \t\n "]),{code:"23514"});
  await assert.rejects(pool.query(nameInsert,[actor,workspaceId,"x".repeat(256)]),{code:"22001"});
  if(process.env.TT_WILDCARD_API_ROOT) {
    const {migrations,applyMigrationSql,applyPostCommitSql}=require(path.join(apiRoot,"migrations/migrate.js"));
    const nameMigration=migrations.find(row=>row.version===85),upgrade=await pool.connect();
    assert.equal(nameMigration.name,"inventory_name_length");
    try {
      await upgrade.query("BEGIN");
      await upgrade.query("CREATE TEMP TABLE tokens(name VARCHAR(100) NOT NULL CONSTRAINT tokens_name_check CHECK(length(name)>=3)) ON COMMIT PRESERVE ROWS");
      assert.equal((await upgrade.query("SELECT 'tokens'::regclass::oid IN (SELECT oid FROM pg_class WHERE relnamespace=pg_my_temp_schema()) owned")).rows[0].owned,true);
      await upgrade.query("INSERT INTO pg_temp.tokens(name) VALUES('   '),(' padded ') ");
      await applyMigrationSql(upgrade,nameMigration);
      await upgrade.query("COMMIT");
      await applyPostCommitSql(upgrade,nameMigration);
      await applyPostCommitSql(upgrade,nameMigration);
      assert.deepEqual((await upgrade.query("SELECT name FROM pg_temp.tokens ORDER BY name")).rows.map(row=>row.name),[" padded ","unnamed"]);
      assert.equal((await upgrade.query("SELECT convalidated FROM pg_constraint WHERE conrelid='pg_temp.tokens'::regclass AND conname='tokens_name_check'")).rows[0].convalidated,true);
    } finally {
      await upgrade.query("ROLLBACK");
      await upgrade.query("DROP TABLE IF EXISTS pg_temp.tokens");
      upgrade.release();
    }
  }
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
  const rolloutRequest={workspaceId,groupId,materialVersionId,actorUserId:actor,idempotencyKey:`rollout-${workspaceId}`};
  assert.equal((await operations.requestRollout(rolloutRequest)).id,approval.id,"retry before approval");
  const sameBinding={agentId:consumerA,deploymentProfileRef:"web0",profileRevision:1,required:true,wave:0,verificationPolicy:"served",freshnessSeconds:3600,state:"active"};
  const puts=await Promise.all(Array.from({length:3},()=>operations.putBinding({workspaceId,groupId,bindingId:bindingA,actorUserId:actor,binding:sameBinding})));
  assert.ok(puts.every(b=>b.authorization_revision===1),"concurrent identical PUTs retain authorization");
  assert.equal((await operations.putBinding({workspaceId,groupId:groupId.toUpperCase(),bindingId:bindingA,actorUserId:actor,binding:{...sameBinding,agentId:consumerA.toUpperCase()}})).authorization_revision,1,"UUID normalization preserves authorization");
  assert.equal((await pool.query("SELECT COUNT(*)::int n FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_CONSUMER_BINDING_CHANGED'",[workspaceId])).rows[0].n,2,"no-op PUTs emit no change audit");
  assert.equal(approval.status,"pending_approval");
  await assert.rejects(approveJob({workspaceId,jobId:approval.id,approverUserId:actor}),{code:"CERTOPS_APPROVAL_SELF_APPROVAL_FORBIDDEN"});
  await approveJob({workspaceId,jobId:approval.id,approverUserId:approver});
  const approvalIntent=approval.payload.distributionRollout;
  const snapshot=await operations.transaction(client=>material.createRolloutSnapshot({client,workspaceId,groupId,materialVersionId,approvalJobId:approval.id,approvedIntentHash:material.hashIntent(approvalIntent)}));
  assert.equal(snapshot.generation,1);
  assert.equal((await operations.requestRollout(rolloutRequest)).id,approval.id,"retry after expansion preserves original generation");
  assert.deepEqual((await Promise.all(Array.from({length:3},()=>operations.requestRollout(rolloutRequest)))).map(j=>j.id),[approval.id,approval.id,approval.id]);
  await assert.rejects(operations.requestRollout({...rolloutRequest,maxParallel:2}),{code:"CERTOPS_JOB_IDEMPOTENCY_CONFLICT"});
  await assert.rejects(operations.requestRollout({...rolloutRequest,actorUserId:approver}),{code:"CERTOPS_JOB_IDEMPOTENCY_CONFLICT"});
  const legacy=await operations.transaction(client=>require(path.join(apiRoot,"services/certops/jobs")).createCertificateJob({client,workspaceId,operation:"noop",source:"control-plane",subjectType:"managed_certificate",subjectId:job.subject_id,assignedAgentId:issuer,requestedByUserId:actor,requiresApproval:true,idempotencyKey:`legacy-${workspaceId}`,payload:{distributionRollout:approval.payload.distributionRollout}}));
  assert.equal((await operations.requestRollout({...rolloutRequest,idempotencyKey:`legacy-${workspaceId}`})).id,legacy.id,"pre-migration requests derive stable identity from frozen payload");
  await assert.rejects(pool.query("UPDATE certificate_jobs SET distribution_request_hash=repeat('0',64) WHERE workspace_id=$1 AND id=$2",[workspaceId,approval.id]),/immutable/);
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
  assert.equal((await operations.putBinding({workspaceId,groupId,bindingId:bindingA,actorUserId:actor,binding:sameBinding})).authorization_revision,1);
  assert.equal((await material.consumerMatrix({client:pool,workspaceId,groupId})).find(r=>r.binding_id===bindingA).converged,true,"identical PUT preserves deployment proof");
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
  // Exercise the production scheduler against the profile persisted by the
  // publication receipt. Renewal has the same source/issuer/store scope but
  // allocates a distinct immutable material object; consumers add no sources.
  const scheduler=require(path.join(apiRoot,process.env.TT_WILDCARD_API_ROOT?"services/certops/renewalSchedulerSweep":"services/certops/renewalScheduler"));
  const swept=await scheduler.runRenewalSchedulerSweep({dbPool:pool,env:{...process.env,CERTOPS_RENEWAL_THRESHOLD_DAYS:"3650"}});
  assert.deepEqual(swept.errors,[]);assert.equal(swept.created,1);
  const renewed=(await pool.query("SELECT * FROM certificate_jobs WHERE workspace_id=$1 AND operation='renew' AND subject_id=$2",[workspaceId,job.subject_id])).rows[0];
  assert.ok(renewed);assert.equal(renewed.assigned_agent_id,issuer);
  assert.equal((await pool.query("SELECT metadata->>'jobId' job_id FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_JOB_CREATED_AUTOMATIC' ORDER BY id DESC LIMIT 1",[workspaceId])).rows[0].job_id,renewed.id);
  assert.equal(renewed.payload.publication.groupId,groupId);
  assert.equal(renewed.payload.publication.materialStoreRef,"customer");
  assert.notEqual(renewed.payload.publication.materialVersionId,materialVersionId);
  const allocated=(await pool.query("SELECT publishing_job_id FROM certops_material_versions WHERE workspace_id=$1 AND id=$2",[workspaceId,renewed.payload.publication.materialVersionId])).rows[0];
  assert.equal(allocated.publishing_job_id,renewed.id);
  assert.equal((await pool.query("SELECT COUNT(*)::int n FROM managed_certificates WHERE workspace_id=$1",[workspaceId])).rows[0].n,1);
  const sweptAgain=await scheduler.runRenewalSchedulerSweep({dbPool:pool,env:{...process.env,CERTOPS_RENEWAL_THRESHOLD_DAYS:"3650"}});
  assert.equal(sweptAgain.created,0);assert.deepEqual(sweptAgain.errors,[]);
  const oldIdentity=(await pool.query("SELECT i.id,i.fingerprint_sha256,i.not_after FROM certops_certificate_identities i JOIN certops_material_versions v ON v.workspace_id=i.workspace_id AND v.certificate_identity_id=i.id WHERE v.workspace_id=$1 AND v.id=$2",[workspaceId,materialVersionId])).rows[0];
  const renewingJob=(await pool.query("UPDATE certificate_jobs SET status='running',claim_id=gen_random_uuid(),claimed_by_agent_id=$2,lease_expires_at=clock_timestamp()+interval '5 minutes' WHERE id=$1 RETURNING *",[renewed.id,issuer])).rows[0];
  const renewedReceipt={...receipt,materialVersionId:renewed.payload.publication.materialVersionId,fingerprintSha256:renewedCert.fingerprintSha256,validTo:renewedCert.notAfter};
  await operations.transaction(async client=>{
    assert.equal((await material.acceptPublicationReceipt({client,workspaceId,agentId:issuer,job:renewingJob,receipt:renewedReceipt,certificatePem:renewedPem})).duplicate,false);
    assert.equal((await material.acceptPublicationReceipt({client,workspaceId,agentId:issuer,job:renewingJob,receipt:renewedReceipt,certificatePem:renewedPem})).duplicate,true);
    await client.query("UPDATE certificate_jobs SET status='succeeded',completed_at=clock_timestamp() WHERE id=$1",[renewed.id]);
  });
  const newVersion=(await pool.query("SELECT certificate_identity_id,fingerprint_sha256 FROM certops_material_versions WHERE workspace_id=$1 AND id=$2",[workspaceId,renewedReceipt.materialVersionId])).rows[0];
  assert.notEqual(newVersion.certificate_identity_id,oldIdentity.id);
  assert.equal(newVersion.fingerprint_sha256,renewedCert.fingerprintSha256);
  assert.deepEqual((await pool.query("SELECT id,fingerprint_sha256,not_after FROM certops_certificate_identities WHERE workspace_id=$1 AND id=$2",[workspaceId,oldIdentity.id])).rows[0],oldIdentity);
  assert.equal((await pool.query("SELECT COUNT(*)::int n FROM certops_certificate_identities WHERE workspace_id=$1",[workspaceId])).rows[0].n,2);
  assert.equal((await pool.query("SELECT latest_material_version_id FROM certops_distribution_groups WHERE workspace_id=$1 AND id=$2",[workspaceId,groupId])).rows[0].latest_material_version_id,renewedReceipt.materialVersionId);
  assert.equal((await pool.query("SELECT COUNT(*)::int n FROM certops_outbox WHERE workspace_id=$1 AND event_type='material_published'",[workspaceId])).rows[0].n,2);
  const afterRenewal=(await material.consumerMatrix({client:pool,workspaceId,groupId})).find(row=>row.binding_id===bindingA);
  assert.equal(afterRenewal.observed_material_version_id,materialVersionId);
  assert.equal(afterRenewal.observed_fingerprint_sha256,cert.fingerprintSha256);
  assert.equal(new Date(afterRenewal.observed_valid_to).toISOString(),cert.notAfter);
  await pool.query("UPDATE certificate_jobs SET status='succeeded' WHERE workspace_id=$1 AND id=$2",[workspaceId,approval.id]);
  const concurrentKey=`concurrent-${workspaceId}`;
  const concurrent=await Promise.all(Array.from({length:3},()=>operations.requestRollout({...rolloutRequest,materialVersionId:renewedReceipt.materialVersionId,idempotencyKey:concurrentKey})));
  assert.ok(concurrent.every(j=>j.id===concurrent[0].id),"concurrent first requests allocate one approval");
  await approveJob({workspaceId,jobId:concurrent[0].id,approverUserId:approver});
  const changedBinding=await operations.putBinding({workspaceId,groupId,bindingId:bindingA,actorUserId:actor,binding:{...sameBinding,freshnessSeconds:3601}});
  assert.equal(changedBinding.authorization_revision,2);
  assert.equal((await operations.putBinding({workspaceId,groupId,bindingId:bindingA,actorUserId:actor,binding:{...sameBinding,freshnessSeconds:3601}})).authorization_revision,2);
  await assert.rejects(operations.transaction(client=>material.createRolloutSnapshot({client,workspaceId,groupId,materialVersionId:renewedReceipt.materialVersionId,approvalJobId:concurrent[0].id,approvedIntentHash:material.hashIntent(concurrent[0].payload.distributionRollout)})),{code:"CERTOPS_ROLLOUT_APPROVAL_MISMATCH"});
  const original=await operations.requestRollout(rolloutRequest);
  assert.equal(original.id,approval.id,"retry after completion/membership change returns original approval");
  assert.deepEqual(original.payload.distributionRollout,approval.payload.distributionRollout);
  // Simulate a withdrawn identity: existing request identity remains replayable,
  // but a fresh rollout must still satisfy current material validity.
  await pool.query("UPDATE certops_certificate_identities SET lifecycle_status='decommissioned' WHERE workspace_id=$1 AND id=$2",[workspaceId,oldIdentity.id]);
  assert.equal((await operations.requestRollout(rolloutRequest)).id,approval.id);
  await assert.rejects(operations.requestRollout({...rolloutRequest,idempotencyKey:`invalid-now-${workspaceId}`}),{code:"CERTOPS_ROLLOUT_VERSION_INVALID"});
  const otherWorkspace=crypto.randomUUID();
  await pool.query("INSERT INTO workspaces(id,name,created_by,plan) VALUES($1,'Other isolated tenant',$2,$3)",[otherWorkspace,actor,process.env.TT_WILDCARD_API_ROOT?"pro":"oss"]);
  await assert.rejects(operations.requestRollout({...rolloutRequest,workspaceId:otherWorkspace}),{code:"CERTOPS_DISTRIBUTION_NOT_FOUND"});
  await assert.rejects(operations.putBinding({workspaceId:otherWorkspace,groupId,bindingId:bindingA,actorUserId:actor,binding:sameBinding}),{code:"CERTOPS_DISTRIBUTION_NOT_FOUND"});
  await operations.transaction(async client=>{await client.query(`UPDATE certops_management_periods SET ended_at=clock_timestamp(),ended_reason='retired' WHERE workspace_id=$1 AND id=$2`,[workspaceId,intent.managementPeriodId]);});
  await assert.rejects(operations.transaction(client=>material.acceptPublicationReceipt({client,workspaceId,agentId:issuer,job,receipt,certificatePem})),{code:"CERTOPS_DISTRIBUTION_INACTIVE"});
});

test("terminal never-executed publications release transactionally; uncertain attempts remain fenced",async()=>{
  const {createCertificateJob,updateCertificateJobStatus}=require(path.join(apiRoot,"services/certops/jobs"));
  const {rejectJob}=require(path.join(apiRoot,"services/certops/jobApprovals"));
  const workspaceId=crypto.randomUUID();
  const actor=(await pool.query("INSERT INTO users(email,display_name,password_hash,auth_method) VALUES($1,'Release fixture','fixture-only','local') RETURNING id",[`${workspaceId}@example.test`])).rows[0].id;
  await pool.query("INSERT INTO workspaces(id,name,created_by,plan,certops_require_approval_always) VALUES($1,'Isolated releases',$2,$3,true)",[workspaceId,actor,process.env.TT_WILDCARD_API_ROOT?"pro":"oss"]);
  const issuer=(await pool.query("INSERT INTO certops_agents(workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash) VALUES($1,$2,'0.17.3','1.0.0',$3,$4) RETURNING id",[workspaceId,crypto.randomUUID(),`ttagent_${crypto.randomBytes(8).toString("hex")}`,crypto.randomBytes(32).toString("hex")])).rows[0].id;
  const first=await operations.transaction(client=>createCertificateIssuanceJob({client,workspaceId,idempotencyKey:`release-${workspaceId}`,...(process.env.TT_WILDCARD_API_ROOT?{workspacePlan:"pro"}:{}),requestedByUserId:actor,assignedAgentId:issuer,
    payload:{target:{type:"domain",reference:cert.commonName},sans:cert.subjectAltNames,caEndpoint:"https://pebble:14000/dir",commandRef:"certbot",dnsProvider:"pebble-challtestsrv",dnsZone:"example.com",keyAlgorithm:"rsa",keySize:2048,
      publicationDestination:{materialStoreRef:"customer",issuanceProfileRef:"wildcard",profileRevision:1}}}));
  const original=first.job,groupId=original.payload.publication.groupId;
  const next=()=>operations.transaction(client=>createCertificateJob({client,workspaceId,operation:"issue",source:"control-plane",subjectType:"managed_certificate",subjectId:original.subjectId,assignedAgentId:issuer,requestedByUserId:actor,requiresApproval:true,
    payload:{...original.payload,publication:{...original.payload.publication,materialVersionId:crypto.randomUUID()}}}));
  const allocation=async id=>(await pool.query("SELECT * FROM certops_material_versions WHERE workspace_id=$1 AND publishing_job_id=$2",[workspaceId,id])).rows[0];
  await assert.rejects(operations.transaction(async client=>{await rejectJob({client,workspaceId,jobId:original.id,approverUserId:actor,reason:"Correct issuer policy"});throw new Error("rollback fixture");}),/rollback fixture/);
  assert.equal((await allocation(original.id)).state,"allocated","release rolls back with rejection");
  await rejectJob({workspaceId,jobId:original.id,approverUserId:actor,reason:"Correct issuer policy"});
  assert.equal((await allocation(original.id)).allocation_release_reason,"rejected_before_execution");
  const corrected=await next();assert.notEqual(corrected.id,original.id);
  await updateCertificateJobStatus({workspaceId,jobId:corrected.id,status:"cancelled"});
  assert.equal((await allocation(corrected.id)).allocation_release_reason,"cancelled_before_execution");
  const stranded=await next();
  await operations.transaction(async client=>{
    // Reproduce the pre-fix persisted state, then execute the migration's real
    // backfill twice. Only this dedicated synthetic database is touched.
    await client.query("ALTER TABLE certificate_jobs DISABLE TRIGGER trg_certops_release_unexecuted_publication");
    await client.query("UPDATE certificate_jobs SET status='cancelled' WHERE workspace_id=$1 AND id=$2",[workspaceId,stranded.id]);
    await client.query("ALTER TABLE certificate_jobs ENABLE TRIGGER trg_certops_release_unexecuted_publication");
    const sql=fs.readFileSync(path.resolve(__dirname,"../../apps/api/migrations/070-certops-distribution-review.sql"),"utf8");
    const repair=sql.slice(sql.indexOf("-- Repair"),sql.indexOf("-- Stable"));
    await client.query(repair);await client.query(repair);
  });
  assert.equal((await allocation(stranded.id)).state,"failed");
  const uncertain=await next();
  await pool.query("UPDATE certificate_jobs SET status='claimed',attempt_count=1,claim_id=gen_random_uuid(),claimed_by_agent_id=$3 WHERE workspace_id=$1 AND id=$2",[workspaceId,uncertain.id,issuer]);
  await updateCertificateJobStatus({workspaceId,jobId:uncertain.id,status:"cancelled"});
  assert.equal((await allocation(uncertain.id)).state,"allocated");
  await assert.rejects(next(),{code:"CERTOPS_PUBLICATION_UNRESOLVED"});
  // Even if claim fields are later cleared, the monotonic attempt count fences
  // this version. A generic failed job is never proof of no ACME effects.
  await pool.query("UPDATE certificate_jobs SET status='failed',claim_id=NULL,claimed_by_agent_id=NULL WHERE workspace_id=$1 AND id=$2",[workspaceId,uncertain.id]);
  await assert.rejects(next(),{code:"CERTOPS_PUBLICATION_UNRESOLVED"});
  assert.equal((await pool.query("SELECT COUNT(*)::int n FROM certops_material_versions WHERE workspace_id=$1",[workspaceId])).rows[0].n,4,"history remains intact");
});

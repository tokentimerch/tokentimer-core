"use strict";

const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const { Pool } = require("pg");
const { lockAutomaticAdcsRenewalForClaim } = require("../../apps/api/services/certops/managementClaim");

describe("automatic AD CS claim admission on PostgreSQL", function () {
  this.timeout(30000);
  const schema = `claim_review_${process.pid}_${Date.now()}`;
  const pool = new Pool({ host: process.env.DB_HOST || "localhost", port: Number(process.env.DB_PORT || 5432),
    user: process.env.DB_USER || "tokentimer", password: process.env.DB_PASSWORD || "password", database: process.env.DB_NAME || "tokentimer" });
  const ids = Object.fromEntries(["workspace", "certificate", "period", "profile", "issuer", "enrollment", "job", "identity", "agent"].map(name => [name, randomUUID()]));
  const target = { type: "windows-iis", reference: "app.example.test", store: "My", binding: { site: "Site", port: 443 } };
  const profile = { target, sanPolicy: { sans: ["app.example.test"] }, keyAlgorithm: "rsa", keySize: 2048 };
  const snapshot = { authorizedDnsNames: ["app.example.test"], keyAlgorithm: "rsa", keySize: 2048 };
  const job = { id: ids.job, status: "pending", source: "automation", operation: "renew", attempt_count: 0,
    enrollment_id: ids.enrollment, subject_type: "managed_certificate", subject_id: ids.certificate, management_period_id: ids.period,certificate_identity_id:ids.identity,assigned_agent_id:ids.agent };
  let claim, writer;
  before(async () => {
    await pool.query(`CREATE SCHEMA ${schema}`);
    claim = await pool.connect(); writer = await pool.connect();
    await claim.query(`SET search_path TO ${schema}`); await writer.query(`SET search_path TO ${schema}`);
    await claim.query(`CREATE TABLE managed_certificates(id uuid, workspace_id uuid, profile_id uuid, not_after timestamptz, fingerprint_sha256 text, deployed_agent_id uuid);
      CREATE TABLE certops_management_periods(id uuid, workspace_id uuid, managed_certificate_id uuid, renewal_profile_id uuid, ended_at timestamptz, automation_enabled boolean, current_identity_id uuid);
      CREATE TABLE certops_certificate_identities(id uuid,workspace_id uuid,fingerprint_sha256 text);
      CREATE TABLE certificate_profiles(id uuid, workspace_id uuid, issuer_id uuid, status text, public_metadata jsonb,renew_before_days integer);
      CREATE TABLE certificate_issuers(id uuid, workspace_id uuid, current_version integer, revalidation_required boolean DEFAULT FALSE);
      CREATE TABLE certificate_enrollments(id uuid, workspace_id uuid, certificate_id uuid, current_job_id uuid, issuer_id uuid, issuer_version integer, snapshot_bytes bytea, deploy_target jsonb,agent_id uuid)`);
    await claim.query("INSERT INTO managed_certificates VALUES($1,$2,$3,NOW()+interval '10 days',$4,$5)",[ids.certificate,ids.workspace,ids.profile,"a".repeat(64),ids.agent]);
    await claim.query("INSERT INTO certops_management_periods VALUES($1,$2,$3,$4,NULL,TRUE,$5)",[ids.period,ids.workspace,ids.certificate,ids.profile,ids.identity]);
    await claim.query("INSERT INTO certops_certificate_identities VALUES($1,$2,$3)",[ids.identity,ids.workspace,"a".repeat(64)]);
    await claim.query("INSERT INTO certificate_profiles VALUES($1,$2,$3,'active',$4::jsonb,30)",[ids.profile,ids.workspace,ids.issuer,JSON.stringify({renewalProfile:profile})]);
    await claim.query("INSERT INTO certificate_issuers(id,workspace_id,current_version) VALUES($1,$2,1)",[ids.issuer,ids.workspace]);
    await claim.query("INSERT INTO certificate_enrollments VALUES($1,$2,$3,$4,$5,1,$6,$7::jsonb,$8)",[ids.enrollment,ids.workspace,ids.certificate,ids.job,ids.issuer,Buffer.from(JSON.stringify(snapshot)),JSON.stringify(target),ids.agent]);
  });
  after(async () => {
    if (claim) { await claim.query("ROLLBACK").catch(()=>{}); claim.release(); }
    if (writer) { await writer.query("ROLLBACK").catch(()=>{}); writer.release(); }
    await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await pool.end();
  });
  const check = () => lockAutomaticAdcsRenewalForClaim({client:claim,job,workspaceId:ids.workspace});
  for (const field of ["profile", "period"]) {
    it(`does not claim while ${field} is being switched off or after it commits`, async () => {
      await writer.query("BEGIN");
      await writer.query(field === "profile" ? "UPDATE certificate_profiles SET status='disabled'" : "UPDATE certops_management_periods SET automation_enabled=FALSE");
      await claim.query("BEGIN"); assert.equal(await check(),false); await claim.query("ROLLBACK");
      await writer.query("COMMIT");
      await claim.query("BEGIN"); assert.equal(await check(),false); await claim.query("ROLLBACK");
      await writer.query(field === "profile" ? "UPDATE certificate_profiles SET status='active'" : "UPDATE certops_management_periods SET automation_enabled=TRUE");
    });
  }
  it("holds policy locks until the claim transaction completes", async () => {
    await claim.query("BEGIN"); assert.equal(await check(),true);
    await writer.query("BEGIN"); await writer.query("SET LOCAL lock_timeout='200ms'");
    await assert.rejects(writer.query("UPDATE certificate_profiles SET status='disabled'"), error => error.code === "55P03");
    await writer.query("ROLLBACK"); await claim.query("ROLLBACK");
  });
  it("revalidates explicit thresholds without applying the API environment to a NULL threshold", async () => {
    await writer.query("UPDATE certificate_profiles SET renew_before_days=1");
    await claim.query("BEGIN"); assert.equal(await check(),false); await claim.query("ROLLBACK");
    await writer.query("UPDATE certificate_profiles SET renew_before_days=NULL");
    await claim.query("BEGIN");
    assert.equal(await lockAutomaticAdcsRenewalForClaim({client:claim,job,workspaceId:ids.workspace,env:{CERTOPS_RENEWAL_THRESHOLD_DAYS:"1"}}),true);
    await claim.query("ROLLBACK");
    await writer.query("UPDATE managed_certificates SET not_after=NULL");
    await claim.query("BEGIN"); assert.equal(await check(),false); await claim.query("ROLLBACK");
    await writer.query("UPDATE managed_certificates SET not_after=NOW()+interval '10 days'");
  });
  it("fences changed fingerprints and requires the owning agent for explicit IP", async () => {
    await writer.query("UPDATE managed_certificates SET fingerprint_sha256=$1",["b".repeat(64)]);
    await claim.query("BEGIN"); assert.equal(await check(),"supersede"); await claim.query("ROLLBACK");
    const explicit={...target,binding:{site:"Site",port:443,address:"192.0.2.1"}};
    await writer.query("UPDATE managed_certificates SET fingerprint_sha256=$1,deployed_agent_id=NULL",["a".repeat(64)]);
    await writer.query("UPDATE certificate_enrollments SET deploy_target=$1::jsonb",[JSON.stringify(explicit)]);
    await writer.query("UPDATE certificate_profiles SET public_metadata=$1::jsonb",[JSON.stringify({renewalProfile:{...profile,target:explicit}})]);
    await claim.query("BEGIN"); assert.equal(await check(),false); await claim.query("ROLLBACK");
    await writer.query("UPDATE managed_certificates SET deployed_agent_id=$1",[randomUUID()]);
    await claim.query("BEGIN"); assert.equal(await check(),"supersede"); await claim.query("ROLLBACK");
    await writer.query("UPDATE managed_certificates SET deployed_agent_id=$1",[ids.agent]);
    await claim.query("BEGIN"); assert.equal(await check(),true); await claim.query("ROLLBACK");
    await writer.query("UPDATE certificate_enrollments SET deploy_target=$1::jsonb",[JSON.stringify(target)]);
    await writer.query("UPDATE certificate_profiles SET public_metadata=$1::jsonb",[JSON.stringify({renewalProfile:profile})]);
  });
  it("rejects stale intent but preserves manual jobs and existing reclaims", async () => {
    await writer.query("UPDATE certificate_profiles SET public_metadata=$1::jsonb", [JSON.stringify({renewalProfile:{...profile,keySize:4096}})]);
    await claim.query("BEGIN"); assert.equal(await check(),"supersede"); await claim.query("ROLLBACK");
    for (const bypass of [{source:"manual"},{status:"claimed",attempt_count:1},{attempt_count:1},{operation:"continue-enrollment"}]) {
      assert.equal(await lockAutomaticAdcsRenewalForClaim({client:claim,job:{...job,...bypass},workspaceId:ids.workspace}),true);
    }
  });
});

describe("automatic AD CS claim dispatch on PostgreSQL", function () {
  this.timeout(60000);
  const { Client, Pool: DatabasePool } = require("pg");
  const connection = {host:process.env.DB_HOST || "localhost",port:Number(process.env.DB_PORT || 5432),user:process.env.DB_USER || "tokentimer",password:process.env.DB_PASSWORD || "password"};
  const database = `claim_dispatch_${process.pid}_${Date.now()}`;
  let db, workspaceId, agentRowId, agentId, issuerId, ownerId, profileId, certificateId, periodId, jobId, expiry;
  const domain="claim.example.test";
  const target={type:"windows-iis",reference:domain,store:"My",binding:{site:"Claim",port:9443,sniHost:domain}};
  const profile={target,sanPolicy:{sans:[domain]},keyAlgorithm:"rsa",keySize:2048};
  before(async () => {
    const admin=new Client({...connection,database:process.env.DB_NAME || "tokentimer"}); await admin.connect();
    await admin.query(`CREATE DATABASE ${database}`); await admin.end();
    db=new DatabasePool({...connection,database});
    const { migrations }=require("../../apps/api/migrations/migrate");
    for (const migration of migrations) await db.query(migration.sql);
    for (const migration of migrations) if (migration.postCommitSql) await db.query(migration.postCommitSql);
    ownerId=(await db.query("INSERT INTO users(email,email_original,display_name,password_hash,auth_method) VALUES('claim@example.test','claim@example.test','Claim','x','local') RETURNING id")).rows[0].id;
    workspaceId=randomUUID(); await db.query("INSERT INTO workspaces(id,name,created_by,plan) VALUES($1,'Claim',$2,'oss')",[workspaceId,ownerId]);
    issuerId=(await db.query("INSERT INTO certificate_issuers(workspace_id,kind,name,current_version,revalidation_required) VALUES($1,'adcs','CA',1,FALSE) RETURNING id",[workspaceId])).rows[0].id;
    await db.query("INSERT INTO certificate_issuer_versions(workspace_id,issuer_id,version,ca_config,template,transport,ca_key_sha256,confirmed_at) VALUES($1,$2,1,'ca.example.test\\CA','Template','dcom',$3,NOW())",[workspaceId,issuerId,"ab".repeat(32)]);
    agentId=`agent-${randomUUID()}`;
    const { _test: caps }=require("./helpers/authenticated-agent-dispatch");
    agentRowId=(await db.query(`INSERT INTO certops_agents(workspace_id,agent_id,name,agent_version,protocol_version,credential_prefix,credential_hash,status,platform,declared_capabilities,capabilities_updated_at,declared_target_selectors)
      VALUES($1,$2,'agent','0.18.0','1.0.0',$3,$4,'active','win32',$5::jsonb,NOW(),$6::jsonb) RETURNING id`,
    [workspaceId,agentId,`ttagent_${require("node:crypto").randomBytes(8).toString("hex")}`,"a".repeat(64),JSON.stringify(["adcs-enroll-v1",caps.EVIDENCE_CLAIM_BINDING_CAPABILITY,caps.SIGNED_PAYLOAD_B64_CAPABILITY]),JSON.stringify([domain])])).rows[0].id;
    certificateId=await require("../e2e/helpers/certops-adcs-local-rules").provisionSurvivorSource({fixture:{workspaceId,pool:db},agentRowId,domain,site:"Claim",port:9443,ownedCertificateIds:[]});
    const fingerprint="a".repeat(64);
    profileId=(await db.query(`INSERT INTO certificate_profiles(workspace_id,name,status,source,source_ref,issuer_id,renew_before_days,key_mode,public_metadata,created_by)
      VALUES($1,'profile','active','manual','claim',$2,30,'os-store-managed',$3::jsonb,$4) RETURNING id`,[workspaceId,issuerId,JSON.stringify({renewalProfile:profile}),ownerId])).rows[0].id;
    await db.query("UPDATE managed_certificates SET status='active',fingerprint_sha256=$2,profile_id=$3,not_after=NOW()+INTERVAL '10 days' WHERE id=$1",[certificateId,fingerprint,profileId]);
    const identity=(await db.query("INSERT INTO certops_certificate_identities(workspace_id,fingerprint_sha256) VALUES($1,$2) ON CONFLICT(workspace_id,fingerprint_sha256) DO UPDATE SET updated_at=NOW() RETURNING id",[workspaceId,fingerprint])).rows[0].id;
    periodId=(await db.query("UPDATE certops_management_periods SET current_identity_id=$2,renewal_profile_id=$3,automation_enabled=TRUE WHERE managed_certificate_id=$1 AND ended_at IS NULL RETURNING id",[certificateId,identity,profileId])).rows[0].id;
    expiry=(await db.query("SELECT not_after FROM managed_certificates WHERE id=$1",[certificateId])).rows[0].not_after;
    const idempotencyKey=require("../../apps/api/services/certops/renewalScheduler").renewalIdempotencyKey(certificateId,expiry);
    // Simulate an older job created before the management period gained an identity.
    await require("./helpers/adcs-ready-agent.cjs").prepareAdcsAgent({db,workspaceId,issuerId,agentId:agentRowId,reference:domain});
    await db.query("UPDATE certops_management_periods SET current_identity_id=NULL WHERE id=$1",[periodId]);
    const created=await require("../../apps/api/services/certops/certificateEnrollments").createEnrollment({client:db,workspaceId,profileId,certificateId,agentId:agentRowId,target,authorizedDnsNames:[domain],keyAlgorithm:"rsa",keySize:2048,source:"automation",idempotencyKey,env:{CERTOPS_ENABLED:"true"}});
    jobId=created.jobId;
    await db.query("UPDATE certops_management_periods SET current_identity_id=$2 WHERE id=$1",[periodId,identity]);
    // Simulate an immutable historical row predating identity attribution.
    // This database is created only for this test and both guards are restored
    // in the same transaction before exercising the real claim path.
    const legacy=await db.connect();
    try {
      await legacy.query("BEGIN");
      await legacy.query("ALTER TABLE certificate_jobs DISABLE TRIGGER trg_certops_a_tag_management_job");
      await legacy.query("ALTER TABLE certificate_jobs DISABLE TRIGGER trg_certops_b_guard_job_identity_start");
      await legacy.query("UPDATE certificate_jobs SET certificate_identity_id=NULL WHERE id=$1",[jobId]);
      await legacy.query("ALTER TABLE certificate_jobs ENABLE TRIGGER trg_certops_b_guard_job_identity_start");
      await legacy.query("ALTER TABLE certificate_jobs ENABLE TRIGGER trg_certops_a_tag_management_job");
      await legacy.query("COMMIT");
    } catch(error) { await legacy.query("ROLLBACK"); throw error; } finally { legacy.release(); }
  });
  after(async () => {
    if(db) await db.end();
    const admin=new Client({...connection,database:process.env.DB_NAME || "tokentimer"}); await admin.connect();
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`); await admin.end();
  });
  async function dispatch(env = {}) {
    return require("./helpers/authenticated-agent-dispatch").claimJobs({dbPool:db,
      agent:{id:agentRowId,workspaceId,agentId,agentVersion:"0.18.0",protocolVersion:"1.0.0",status:"active"},
      envelope:{agentId,protocolVersion:"1.0.0"},body:{supportedActions:["renew","adcs-preflight"],maxJobs:1},env:{CERTOPS_ENABLED:"true",CERTOPS_AGENT_LOG_STORAGE_ENABLED:"false",...env},
      deps:{enforceAgentSequence:async()=>({sequence:1}),signJobForDispatch:async({job,envelopeVersion})=>({...job,envelopeVersion})}});
  }
  it("does not dispatch while concurrent profile or period changes are uncommitted",async()=>{
    for (const field of ["profile","period"]) {
      const writer=await db.connect();
      try {
        await writer.query("BEGIN");
        await writer.query(field === "profile" ? "UPDATE certificate_profiles SET status='disabled' WHERE id=$1" : "UPDATE certops_management_periods SET automation_enabled=FALSE WHERE id=$1",[field === "profile" ? profileId : periodId]);
        assert.equal((await dispatch()).jobs.length,0,field);
        await writer.query("COMMIT");
        assert.equal((await dispatch()).jobs.length,0,field);
      } finally { await writer.query("ROLLBACK").catch(()=>{}); writer.release(); }
      await db.query(field === "profile" ? "UPDATE certificate_profiles SET status='active' WHERE id=$1" : "UPDATE certops_management_periods SET automation_enabled=TRUE WHERE id=$1",[field === "profile" ? profileId : periodId]);
      await db.query("UPDATE certificate_jobs SET next_attempt_at=NULL WHERE id=$1",[jobId]);
    }
  });
  it("does not dispatch a disabled profile or disabled management period",async()=>{
    await db.query("UPDATE certificate_profiles SET status='disabled' WHERE id=$1",[profileId]);
    assert.equal((await dispatch()).jobs.length,0);
    await db.query("UPDATE certificate_profiles SET status='active' WHERE id=$1",[profileId]);
    await db.query("UPDATE certops_management_periods SET automation_enabled=FALSE WHERE id=$1",[periodId]);
    assert.equal((await dispatch()).jobs.length,0);
    await db.query("UPDATE certops_management_periods SET automation_enabled=TRUE WHERE id=$1",[periodId]);
  });
  it("does not let disabled automated work starve a later manual renewal",async()=>{
    await db.query("UPDATE certificate_profiles SET status='disabled' WHERE id=$1",[profileId]);
    const identity=(await db.query("SELECT current_identity_id FROM certops_management_periods WHERE id=$1",[periodId])).rows[0].current_identity_id;
    const manual=(await db.query(`INSERT INTO certificate_jobs(workspace_id,subject_type,subject_id,operation,status,source,executor_kind,assigned_agent_id,management_period_id,certificate_identity_id,payload)
      VALUES($1,'managed_certificate',$2,'renew','pending','api','agent',$3,$4,$5,$6::jsonb) RETURNING id`,
    [workspaceId,certificateId,agentRowId,periodId,identity,JSON.stringify({target})])).rows[0].id;
    const result=await dispatch();
    assert.equal(result.jobs.length,1); assert.equal(String(result.jobs[0].id ?? result.jobs[0].jobId),manual);
    await db.query("UPDATE certificate_jobs SET status='cancelled' WHERE id=$1",[manual]);
    await db.query("UPDATE certificate_profiles SET status='active' WHERE id=$1",[profileId]);
  });
  it("parks a supersession without proof so a later manual renewal is not starved",async()=>{
    const nonce=`nonce-${randomUUID()}`;
    await db.query("INSERT INTO certops_consumed_nonces(nonce,job_id,workspace_id,issued_to_agent_id,expires_at) VALUES($1,$2,$3,$4,NOW()+interval '5 minutes')",[nonce,jobId,workspaceId,agentRowId]);
    assert.equal((await dispatch()).jobs.length,0);
    const parked=(await db.query("SELECT status,next_attempt_at FROM certificate_jobs WHERE id=$1",[jobId])).rows[0];
    assert.equal(parked.status,"pending"); assert.ok(parked.next_attempt_at);
    const identity=(await db.query("SELECT current_identity_id FROM certops_management_periods WHERE id=$1",[periodId])).rows[0].current_identity_id;
    const manual=(await db.query(`INSERT INTO certificate_jobs(workspace_id,subject_type,subject_id,operation,status,source,executor_kind,assigned_agent_id,management_period_id,certificate_identity_id,payload)
      VALUES($1,'managed_certificate',$2,'renew','pending','api','agent',$3,$4,$5,$6::jsonb) RETURNING id`,[workspaceId,certificateId,agentRowId,periodId,identity,JSON.stringify({target})])).rows[0].id;
    const next=await dispatch(); assert.equal(String(next.jobs[0].id ?? next.jobs[0].jobId),manual);
    await db.query("UPDATE certificate_jobs SET status='cancelled' WHERE id=$1",[manual]);
    await db.query("DELETE FROM certops_consumed_nonces WHERE nonce=$1",[nonce]);
    await db.query("UPDATE certificate_jobs SET next_attempt_at=NULL WHERE id=$1",[jobId]);
  });
  it("supersedes stale never-started work, audits it and replans once through the real scheduler",async()=>{
    await db.query("UPDATE certops_agents SET supported_operations='[\"adcs-preflight\",\"renew\",\"continue-enrollment\"]'::jsonb WHERE id=$1",[agentRowId]);
    await db.query(`INSERT INTO certificate_jobs(workspace_id,operation,status,executor_kind,mode,subject_type,subject_id,payload,assigned_agent_id,result_metadata)
      VALUES($1,'adcs-preflight','succeeded','agent','real','external',$2,'{}'::jsonb,$3,$4::jsonb)`,[workspaceId,issuerId,agentRowId,JSON.stringify({preflightVerdict:{templateCheck:"safe",caCheck:"safe",caConfig:"ca.example.test\\CA",template:"Template",caKeySha256s:["ab".repeat(32)]}})]);
    const scheduler=require("../../apps/api/services/certops/renewalScheduler");
    const source=(await db.query("SELECT source,source_ref,fingerprint_sha256,deployed_agent_id FROM managed_certificates WHERE id=$1",[certificateId])).rows[0];
    const schedule=async renewalProfile=>scheduler.createAutomaticAdcsRenewal({dbPool:db,certificate:{...source,id:certificateId,workspace_id:workspaceId,profile_id:profileId,profile_issuer_id:issuerId,management_period_id:periodId,common_name:domain,not_after:expiry,profile_public_metadata:{renewalProfile}},mode:"real",env:{CERTOPS_ENABLED:"true"},auditWriter:async()=>{}});
    async function assertSuperseded(previous) {
      assert.equal((await dispatch()).jobs.length,0);
      const old=(await db.query("SELECT j.status,j.error_code,j.attempt_count,e.state FROM certificate_jobs j JOIN certificate_enrollments e ON e.id=j.enrollment_id WHERE j.id=$1",[previous])).rows[0];
      assert.deepEqual(old,{status:"cancelled",error_code:"CERTOPS_AUTOMATION_SUPERSEDED_BEFORE_CLAIM",attempt_count:0,state:"cancelled"});
      assert.equal((await db.query("SELECT count(*)::int AS n FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_AUTOMATIC_RENEWAL_SUPERSEDED' AND metadata->>'jobId'=$2",[workspaceId,previous])).rows[0].n,1);
    }
    await assertSuperseded(jobId);
    const decision=await scheduler.retryableAdcsRenewalKey(db,workspaceId,scheduler.renewalIdempotencyKey(certificateId,expiry));
    assert.ok(decision.key,`expected a new key: ${JSON.stringify(decision)}`);
    const first=await Promise.all([schedule(profile),schedule(profile)]);
    assert.equal(first.filter(result=>result.created).length,1,JSON.stringify(first));
    jobId=first.find(result=>result.created).job.id;
    const changed={...profile,keySize:4096};
    await db.query("UPDATE certificate_profiles SET public_metadata=$2::jsonb WHERE id=$1",[profileId,JSON.stringify({renewalProfile:changed})]);
    await assertSuperseded(jobId);
    const second=await Promise.all([schedule(changed),schedule(changed)]);
    assert.equal(second.filter(result=>result.created).length,1);
    jobId=second.find(result=>result.created).job.id;
    await db.query("UPDATE certificate_profiles SET renew_before_days=1 WHERE id=$1",[profileId]);
    assert.equal((await dispatch()).jobs.length,0);
    await db.query("UPDATE certificate_profiles SET renew_before_days=NULL WHERE id=$1",[profileId]);
    assert.equal((await dispatch({CERTOPS_RENEWAL_THRESHOLD_DAYS:"1"})).jobs.length,1);
    assert.equal((await db.query("SELECT status FROM certificate_jobs WHERE id=$1",[jobId])).rows[0].status,"claimed");
  });
});

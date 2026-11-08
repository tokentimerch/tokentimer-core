"use strict";

// Own PostgreSQL, real admission services and separate pool connections.
const { before, after, test } = require("node:test");
const assert = require("node:assert/strict");
const { randomUUID, randomBytes } = require("node:crypto");
const { spawnSync } = require("node:child_process");
let pool, enrollments, scheduler, profiles, container;
const name = "tt-core-enrollment-admission-" + randomUUID();
const CA = "ca01.corp.example.com\\Corp Issuing CA 01", TEMPLATE = "TokenTimerWebServer", KEY = "ab".repeat(32);
const TARGET = { type: "windows-iis", reference: "app.example.com", store: "WebHosting", binding: { site: "Shop", port: 443 } };
function docker(args) {
  const result = spawnSync("docker", args, { encoding: "utf8", timeout: 120000 });
  assert.equal(result.status, 0, result.stderr || String(result.error));
  return result.stdout.trim();
}
before(async () => {
  container = docker(["run", "-d", "--name", name, "--label", "tokentimer.test=core-enrollment-admission",
    "--memory=512m", "--cpus=2", "-p", "127.0.0.1::5432", "-e", "POSTGRES_USER=admission_test",
    "-e", "POSTGRES_PASSWORD=isolated-admission-only", "-e", "POSTGRES_DB=certops_admission_ci_test", "postgres:16-alpine"]);
  const port = JSON.parse(docker(["inspect", container]))[0].NetworkSettings.Ports["5432/tcp"][0].HostPort;
  let ready = false;
  for (let i = 0; i < 600; i++) {
    if (spawnSync("docker", ["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "admission_test"], { timeout: 10000 }).status === 0) { ready = true; break; }
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  assert.ok(ready);
  Object.assign(process.env, { NODE_ENV: "test", CERTOPS_ENABLED: "true", DB_HOST: "127.0.0.1", DB_PORT: port,
    DB_NAME: "certops_admission_ci_test", DB_USER: "admission_test", DB_PASSWORD: "isolated-admission-only" });
  // The migrator owns a separate pool. Run it in a child process so it closes
  // before the test removes its temporary PostgreSQL container.
  const migration = spawnSync(process.execPath, ["apps/api/migrations/migrate.js"], { encoding: "utf8", timeout: 120000, env: process.env });
  assert.equal(migration.status, 0, migration.stderr || String(migration.error));
  ({ pool } = require("../../apps/api/db/database"));
  enrollments = require("../../apps/api/services/certops/certificateEnrollments");
  scheduler = require("../../apps/api/services/certops/renewalScheduler");
  profiles = require("../../apps/api/services/certops/renewalProfileAdmin");
}, { timeout: 300000 });
after(async () => {
  if (pool) await pool.end();
  if (container) {
    const info = JSON.parse(docker(["inspect", container]))[0];
    assert.equal(info.Name, "/" + name);
    assert.equal(info.Config.Labels["tokentimer.test"], "core-enrollment-admission");
    docker(["rm", "--force", "--volumes", container]);
  }
});
async function fixture() {
  const email = randomUUID() + "@example.test", workspaceId = randomUUID();
  const actor = (await pool.query("INSERT INTO users(email,email_original,display_name,password_hash,auth_method,email_verified) VALUES($1::text,$1::text,'Admission','x','local',true) RETURNING id", [email])).rows[0].id;
  await pool.query("INSERT INTO workspaces(id,name,created_by,plan) VALUES($1,'Admission',$2,'oss')", [workspaceId, actor]);
  await pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES($1,$2,'workspace_manager') ON CONFLICT DO NOTHING", [workspaceId, actor]);
  const issuerId = (await pool.query("INSERT INTO certificate_issuers(workspace_id,kind,name,current_version,revalidation_required) VALUES($1,'adcs','Admission CA',1,false) RETURNING id", [workspaceId])).rows[0].id;
  await pool.query("INSERT INTO certificate_issuer_versions(workspace_id,issuer_id,version,ca_config,template,transport,ca_key_sha256,confirmed_at) VALUES($1,$2,1,$3,$4,'dcom',$5,NOW())", [workspaceId, issuerId, CA, TEMPLATE, KEY]);
  const agentId = (await pool.query("INSERT INTO certops_agents(workspace_id,agent_id,name,agent_version,protocol_version,credential_prefix,credential_hash,status,declared_target_selectors) VALUES($1,$2,'Admission agent','0.18.0','1.0.0',$3,$4,'active',$5::jsonb) RETURNING id",
    [workspaceId, "agent-" + randomUUID(), "ttagent_" + randomBytes(8).toString("hex"), randomBytes(32).toString("hex"), JSON.stringify([TARGET.reference])])).rows[0].id;
  await pool.query(`UPDATE certops_agents SET platform='win32',declared_capabilities=$2::jsonb,capabilities_updated_at=NOW() WHERE id=$1`,
    [agentId, JSON.stringify(["windows-store-only-adcs-v1", "adcs-enroll-v1", "evidence-claim-binding-v1"])]);
  await pool.query("INSERT INTO certificate_jobs(workspace_id,subject_type,subject_id,operation,status,assigned_agent_id,result_metadata) VALUES($1,'external',$2,'adcs-preflight','succeeded',$3,$4::jsonb)", [workspaceId, issuerId, agentId, JSON.stringify({ preflightVerdict: { templateCheck: "safe", caCheck: "safe", caConfig: CA, template: TEMPLATE, caKeySha256s: [KEY] } })]);
  const profile = await profiles.createAdcsRenewalProfile({ dbPool: pool, workspaceId, actorUserId: actor,
    body: { name: "Admission", issuerId, keyAlgorithm: "rsa", keySize: 2048, target: TARGET } });
  const certificate = (await pool.query("INSERT INTO managed_certificates(workspace_id,source,source_ref,fingerprint_sha256,name,common_name,identity_observed_at,status,not_after,profile_id,key_mode) VALUES($1,'agent_filesystem',$2,$3,'Admission','app.example.com',NOW(),'discovered',NOW()+interval '10 days',$4,'agent-local') RETURNING *", [workspaceId, randomUUID(), randomBytes(32).toString("hex"), profile.id])).rows[0];
  const publicMetadata = (await pool.query("SELECT public_metadata FROM certificate_profiles WHERE id=$1", [profile.id])).rows[0].public_metadata;
  return { workspaceId, issuerId, actor, agentId, certificate, profile, publicMetadata };
}
function manual(f, overrides = {}) {
  return enrollments.createEnrollment({ client: pool, workspaceId: f.workspaceId, issuerId: f.issuerId,
    certificateId: f.certificate.id, agentId: f.agentId, target: TARGET, authorizedDnsNames: [TARGET.reference],
    keyAlgorithm: "rsa", keySize: 2048, actorUserId: f.actor, audit: async () => {}, ...overrides });
}
function automatic(f, dbPool = pool) {
  return scheduler.createAutomaticAdcsRenewal({ dbPool, certificate: { ...f.certificate,
    profile_issuer_id: f.issuerId, profile_public_metadata: f.publicMetadata }, mode: "real",
    env: { CERTOPS_ENABLED: "true" }, auditWriter: async () => {} });
}
async function count(f) {
  return Number((await pool.query("SELECT count(*) FROM certificate_enrollments WHERE workspace_id=$1 AND certificate_id=$2", [f.workspaceId, f.certificate.id])).rows[0].count);
}
test("manual concurrent mixed-case admission creates one enrollment and one job", async () => {
  const f = await fixture();
  const results = await Promise.allSettled([manual(f), manual(f, { workspaceId: f.workspaceId.toUpperCase(), certificateId: f.certificate.id.toUpperCase() })]);
  assert.equal(results.filter(result => result.status === "fulfilled").length, 1);
  assert.equal(results.find(result => result.status === "rejected").reason.code, "CERTOPS_ENROLLMENT_OPEN");
  assert.equal(await count(f), 1);
  assert.equal(Number((await pool.query("SELECT count(*) FROM certificate_jobs WHERE workspace_id=$1 AND operation='renew'", [f.workspaceId])).rows[0].count), 1);
});
test("manual and automatic admissions share the same transaction exclusion", async () => {
  const f = await fixture();
  const results = await Promise.allSettled([manual(f), automatic(f)]);
  for (const result of results) {
    if (result.status === "rejected") assert.equal(result.reason.code, "CERTOPS_ENROLLMENT_OPEN");
  }
  assert.equal(await count(f), 1);
  assert.equal(Number((await pool.query("SELECT count(*) FROM certificate_jobs WHERE workspace_id=$1 AND operation='renew'", [f.workspaceId])).rows[0].count), 1);
});

test("a terminal awaiting_issuer job does not reopen a pending enrollment; cancellation frees admission", async () => {
  const f = await fixture(), first = await manual(f);
  await pool.query("UPDATE certificate_enrollments SET state='pending_issuance' WHERE id=$1", [first.enrollmentId]);
  await pool.query("UPDATE certificate_jobs SET status='awaiting_issuer' WHERE id=$1", [first.jobId]);
  await assert.rejects(manual(f), error => error.code === "CERTOPS_ENROLLMENT_OPEN");
  assert.equal((await automatic(f)).created, false);
  await enrollments.cancelEnrollment({ client: pool, workspaceId: f.workspaceId, enrollmentId: first.enrollmentId, actorUserId: f.actor, audit: async () => {} });
  assert.notEqual((await manual(f)).enrollmentId, first.enrollmentId);
});
test("automatic admission losing its preliminary read race skips the manual winner", async () => {
  const f = await fixture();
  // Pause immediately after the real, empty preliminary read. Admit manual work
  // before automatic creation resumes; the transactional check must see it.
  let intercepted = false;
  const dbPool = { connect: (...args) => pool.connect(...args), get idleCount() { return pool.idleCount; },
    async query(sql, params) {
      const result = await pool.query(sql, params);
      if (!intercepted && sql.includes("FROM certificate_enrollments") && sql.includes("LIMIT 1")) {
        intercepted = true;
        await manual(f);
      }
      return result;
    } };
  const result = await automatic(f, dbPool);
  assert.equal(intercepted, true);
  assert.equal(result.created, false);
  assert.equal(await count(f), 1);
});
test("the enrollment HTTP route returns 409 for an already-open certificate", async () => {
  const f = await fixture();
  await manual(f);
  const express = require("../../apps/api/node_modules/express"), request = require("supertest");
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.user = { id: f.actor }; req.authz = { workspaceRole: "admin" }; req.workspace = { id: f.workspaceId }; req.isAuthenticated = () => true; next(); });
  app.use(require("../../apps/api/routes/certops-enrollments"));
  const response = await request(app).post(`/api/v1/workspaces/${f.workspaceId}/certops/enrollments`).send({ issuerId: f.issuerId, certificateId: f.certificate.id, agentId: f.agentId, target: TARGET, authorizedDnsNames: [TARGET.reference], keyAlgorithm: "rsa", keySize: 2048 });
  assert.equal(response.status, 409, JSON.stringify(response.body));
  assert.equal(response.body.code, "CERTOPS_ENROLLMENT_OPEN");
});

test("store renewal leaves an endpoint's observed certificate and expiry alert intact", async () => {
  const f = await fixture();
  const endpointToken = (await pool.query(`INSERT INTO tokens(user_id,workspace_id,created_by,name,expiration,type,category,issuer,domains)
    VALUES($1,$2,$1,'Endpoint certificate','2026-11-10','ssl_cert','cert','old CA',ARRAY['app.example.com']) RETURNING id`, [f.actor, f.workspaceId])).rows[0].id;
  const monitor = (await pool.query(`INSERT INTO domain_monitors(workspace_id,url,created_by,token_id,ssl_fingerprint,ssl_valid_to)
    VALUES($1,'https://app.example.com',$2,$3,'old-fingerprint','2026-11-10') RETURNING id`, [f.workspaceId, f.actor, endpointToken])).rows[0].id;
  await pool.query(`INSERT INTO alert_queue(user_id,token_id,alert_key,threshold_days,due_date,status)
    VALUES($1,$2,$3,30,'2026-11-01','pending')`, [f.actor, endpointToken, `token_expiry:${endpointToken}:30`]);
  await pool.query("UPDATE managed_certificates SET token_id=$1 WHERE id=$2", [endpointToken, f.certificate.id]);
  const leaf = { commonName: "app.example.com", subjectAltNames: ["app.example.com"], issuer: "new CA", serialNumber: "2", notAfter: new Date("2027-11-10T00:00:00Z") };
  const link = require("../../apps/api/services/certops/inventory").linkReconciledCertificateToken;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await require("../../apps/api/services/certops/inventory").acquireManagedCertificateImportLock(client, f.workspaceId);
    const competing = await pool.connect();
    try {
      await competing.query("BEGIN");
      const probe = await competing.query("SELECT pg_try_advisory_xact_lock(hashtext('certops_managed_cert_quota_' || $1::text)) AS acquired", [f.workspaceId]);
      assert.equal(probe.rows[0].acquired, false);
      await competing.query("ROLLBACK");
    } finally { competing.release(); }
    await client.query("UPDATE managed_certificates SET fingerprint_sha256=$1,not_after=$2 WHERE id=$3", [randomBytes(32).toString("hex"), leaf.notAfter, f.certificate.id]);
    const newToken = await link({ client, workspaceId: f.workspaceId, certificateId: f.certificate.id, certificate: leaf, existingTokenId: endpointToken, isolateFromEndpoint: true });
    assert.notEqual(newToken, endpointToken);
    assert.equal(await link({ client, workspaceId: f.workspaceId, certificateId: f.certificate.id, certificate: leaf, existingTokenId: newToken, isolateFromEndpoint: true }), newToken);
    await client.query("COMMIT");
    const old = (await pool.query("SELECT expiration::text,issuer FROM tokens WHERE id=$1", [endpointToken])).rows[0];
    assert.deepEqual(old, { expiration: "2026-11-10", issuer: "old CA" });
    const served = (await pool.query("SELECT ssl_fingerprint,ssl_valid_to::date::text AS expiry FROM domain_monitors WHERE id=$1", [monitor])).rows[0];
    assert.deepEqual(served, { ssl_fingerprint: "old-fingerprint", expiry: "2026-11-10" });
    assert.equal((await pool.query("SELECT status FROM alert_queue WHERE token_id=$1", [endpointToken])).rows[0].status, "pending");
    assert.equal((await pool.query("SELECT expiration::text FROM tokens WHERE id=$1", [newToken])).rows[0].expiration, "2027-11-10");
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
});

test("store renewal separates tokens linked through targets, instances or other observations", async () => {
  const link = require("../../apps/api/services/certops/inventory").linkReconciledCertificateToken;
  for (const kind of ["target", "instance", "inventory", "other_observation"]) {
    const f = await fixture();
    const oldToken = (await pool.query(`INSERT INTO tokens(user_id,workspace_id,created_by,name,expiration,type,category)
      VALUES($1,$2,$1,'Observed certificate','2026-11-10','ssl_cert','cert') RETURNING id`, [f.actor, f.workspaceId])).rows[0].id;
    if (kind === "other_observation") {
      await pool.query(`INSERT INTO managed_certificates(workspace_id,source,status,name,token_id,fingerprint_sha256)
        VALUES($1,'agent_filesystem','discovered','Other observation',$2,$3)`, [f.workspaceId, oldToken, randomBytes(32).toString("hex")]);
    } else if (kind === "inventory") {
      const monitor = (await pool.query(`INSERT INTO domain_monitors(workspace_id,url,created_by) VALUES($1,'https://inventory.example.com',$2) RETURNING id`, [f.workspaceId, f.actor])).rows[0].id;
      await pool.query(`INSERT INTO managed_certificates(workspace_id,source,source_ref,status,name,token_id,fingerprint_sha256)
        VALUES($1,'endpoint_monitor',$2,'discovered','Endpoint',$3,$4)`, [f.workspaceId, monitor, oldToken, randomBytes(32).toString("hex")]);
    } else {
      const target = (await pool.query(`INSERT INTO certificate_targets(workspace_id,name,target_type,token_id)
        VALUES($1,'Endpoint','domain',$2) RETURNING id`, [f.workspaceId, kind === "target" ? oldToken : null])).rows[0].id;
      if (kind === "instance") await pool.query(`INSERT INTO certificate_instances(workspace_id,managed_certificate_id,target_id,token_id)
        VALUES($1,$2,$3,$4)`, [f.workspaceId, f.certificate.id, target, oldToken]);
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const newToken = await link({ client, workspaceId: f.workspaceId, certificateId: f.certificate.id,
        certificate: { commonName: "app.example.com", notAfter: new Date("2027-11-10T00:00:00Z") }, existingTokenId: oldToken, isolateFromEndpoint: true });
      assert.notEqual(newToken, oldToken, kind);
      await client.query("COMMIT");
      assert.equal((await pool.query("SELECT expiration::text FROM tokens WHERE id=$1", [oldToken])).rows[0].expiration, "2026-11-10", kind);
    } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
  }
});

test("claim-bound store evidence gates renewal and preserves the endpoint alert", async () => {
  const f = await fixture();
  const target = { type: "windows-cert-store", reference: TARGET.reference, store: "My" };
  const oldToken = (await pool.query(`INSERT INTO tokens(user_id,workspace_id,created_by,name,expiration,type,category)
    VALUES($1,$2,$1,'Endpoint certificate','2026-11-10','ssl_cert','cert') RETURNING id`, [f.actor, f.workspaceId])).rows[0].id;
  const monitor = (await pool.query(`INSERT INTO domain_monitors(workspace_id,url,created_by,token_id,ssl_fingerprint,ssl_valid_to)
    VALUES($1,'https://app.example.com',$2,$3,'old','2026-11-10') RETURNING id`, [f.workspaceId, f.actor, oldToken])).rows[0].id;
  await pool.query(`INSERT INTO alert_queue(user_id,token_id,alert_key,threshold_days,due_date,status)
    VALUES($1,$2,$3,30,'2026-11-01','pending')`, [f.actor, oldToken, `token_expiry:${oldToken}:30`]);
  await pool.query("UPDATE managed_certificates SET token_id=$1,deployed_agent_id=$2,key_mode='os-store-managed' WHERE id=$3", [oldToken, f.agentId, f.certificate.id]);
  const enrollment = await manual(f, { target });
  const claim = randomUUID();
  await pool.query("UPDATE certificate_jobs SET claim_id=$1,claimed_by_agent_id=$2 WHERE id=$3", [claim, f.agentId, enrollment.jobId]);
  const job = (await pool.query("SELECT * FROM certificate_jobs WHERE id=$1", [enrollment.jobId])).rows[0];
  const destinationSha256 = require("node:crypto").createHash("sha256").update(JSON.stringify(target)).digest("hex");
  const fingerprint = randomBytes(32).toString("hex");
  const proof = { step: "store-verify", enrollmentId: enrollment.enrollmentId, destinationType: target.type,
    destinationSha256, store: "LocalMachine\\My", keyPossessionVerified: true, machineKey: true, nonExportable: true,
    fingerprintSha256: fingerprint, validTo: "2027-11-10T00:00:00.000Z", issuer: "new CA" };
  const evidence = (await pool.query(`INSERT INTO certificate_evidence(workspace_id,job_id,evidence_type,claim_id,metadata)
    VALUES($1,$2,'validation.passed',$3,$4::jsonb) RETURNING id`, [f.workspaceId, job.id, claim, JSON.stringify({ ...proof, destinationSha256: "00".repeat(32) })])).rows[0].id;
  const refresh = require("../../apps/api/services/certops/agentDispatch")._test.refreshRenewedCertificateEvidence;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const options = { client, workspaceId: f.workspaceId, job, agent: { id: f.agentId }, auditWriter: async () => {} };
    assert.equal((await refresh(options)).refreshed, false);
    assert.equal((await client.query("SELECT fingerprint_sha256 FROM managed_certificates WHERE id=$1", [f.certificate.id])).rows[0].fingerprint_sha256, f.certificate.fingerprint_sha256);
    await client.query("UPDATE certificate_evidence SET metadata=$2::jsonb WHERE id=$1", [evidence, JSON.stringify(proof)]);
    assert.equal((await refresh(options)).refreshed, true);
    const updated = (await client.query("SELECT fingerprint_sha256,token_id FROM managed_certificates WHERE id=$1", [f.certificate.id])).rows[0];
    assert.equal(updated.fingerprint_sha256, fingerprint);
    assert.notEqual(updated.token_id, oldToken);
    await client.query("COMMIT");
    const observed = (await pool.query("SELECT ssl_fingerprint,ssl_valid_to::date::text AS expiry FROM domain_monitors WHERE id=$1", [monitor])).rows[0];
    assert.deepEqual(observed, { ssl_fingerprint: "old", expiry: "2026-11-10" });
    assert.equal((await pool.query("SELECT status FROM alert_queue WHERE token_id=$1", [oldToken])).rows[0].status, "pending");
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
});

test("first store issuance remains tracking-only on proof replay until explicit renewal consent", async () => {
  const f = await fixture();
  // The common fixture has an unrelated due automatic certificate.
  await pool.query("UPDATE managed_certificates SET not_after=NOW()+interval '1 year' WHERE id=$1", [f.certificate.id]);
  const target = { type: "windows-cert-store", reference: TARGET.reference, store: "My" };
  const createIssue = require("../../apps/api/services/certops/issuance").createCertificateIssuanceJob;
  const refresh = require("../../apps/api/services/certops/agentDispatch")._test.reconcileProvisionedCertificate;
  const client = await pool.connect();
  let certificateId, enrollmentId, job;
  try {
    await client.query("BEGIN");
    const created = await createIssue({ client, workspaceId: f.workspaceId, operation: "issue", source: "api", mode: "real",
      idempotencyKey: randomUUID(), assignedAgentId: f.agentId, requestedByUserId: f.actor,
      payload: { issuerId: f.issuerId, target, automationEnabled: false, keyAlgorithm: "rsa", keySize: 2048 } });
    certificateId = created.job.subjectId;
    enrollmentId = created.job.enrollmentId;
    const reality = require("../../apps/api/services/onboarding/certopsReality").loadAdcsReality;
    const requested = await reality(client, f.workspaceId, { issueJobId: created.job.id, agentId: f.agentId, issuerId: f.issuerId });
    assert.equal(requested.storeIssuance.requested, true);
    assert.equal(requested.storeIssuance.installed, false);
    const claim = randomUUID();
    await client.query("UPDATE certificate_jobs SET claim_id=$1,claimed_by_agent_id=$2 WHERE id=$3", [claim, f.agentId, created.job.id]);
    job = (await client.query("SELECT * FROM certificate_jobs WHERE id=$1", [created.job.id])).rows[0];
    const destinationSha256 = require("node:crypto").createHash("sha256").update(JSON.stringify(target)).digest("hex");
    const proof = { step: "store-verify", enrollmentId, destinationType: target.type, destinationSha256,
      store: "LocalMachine\\My", keyPossessionVerified: true, machineKey: true, nonExportable: true,
      fingerprintSha256: randomBytes(32).toString("hex"), validTo: new Date(Date.now() + 86400000).toISOString(), issuer: "AD CS" };
    await client.query(`INSERT INTO certificate_evidence(workspace_id,job_id,evidence_type,claim_id,metadata)
      VALUES($1,$2,'validation.passed',$3,$4::jsonb)`, [f.workspaceId, job.id, claim, JSON.stringify(proof)]);
    const opts = { client, workspaceId: f.workspaceId, job, agent: { id: f.agentId }, auditWriter: async () => {} };
    assert.equal((await refresh(opts)).promoted, true);
    assert.equal(await refresh(opts), null);
    await client.query("UPDATE certificate_enrollments SET state='installed' WHERE id=$1", [enrollmentId]);
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
  const reality = require("../../apps/api/services/onboarding/certopsReality").loadAdcsReality;
  const scoped = { issueJobId: job.id, agentId: f.agentId, issuerId: f.issuerId };
  const installed = await reality(pool, f.workspaceId, scoped);
  assert.equal(installed.storeIssuance.installed, true);
  assert.equal(installed.storeIssuance.served, null);
  assert.equal((await reality(pool, randomUUID(), scoped)).storeIssuance, null);
  assert.equal((await reality(pool, f.workspaceId, { ...scoped, agentId: randomUUID() })).storeIssuance, null);
  assert.equal((await reality(pool, f.workspaceId, { ...scoped, issuerId: randomUUID() })).storeIssuance, null);
  let period = (await pool.query("SELECT * FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL", [f.workspaceId, certificateId])).rows[0];
  assert.ok(period.renewal_profile_id, "derived profile exists");
  assert.equal(period.automation_enabled, false);
  const sweep = () => scheduler.runRenewalSchedulerSweep({ dbPool: pool, env: { CERTOPS_ENABLED: "true" }, auditWriter: async () => {} });
  const automaticJobs = async () => Number((await pool.query("SELECT COUNT(*) FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2::text AND operation='renew' AND source='automation'", [f.workspaceId, certificateId])).rows[0].count);
  await sweep();
  assert.equal(await automaticJobs(), 0);
  const identity = require("../../apps/api/services/certops/certificateIdentity");
  await identity.replaceManagingSource({ client: pool, workspaceId: f.workspaceId, periodId: period.id,
    managedCertificateId: certificateId, renewalProfileId: period.renewal_profile_id, automationEnabled: true, actorUserId: f.actor });
  period = (await pool.query("SELECT * FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL", [f.workspaceId, certificateId])).rows[0];
  assert.equal(period.automation_enabled, true);
  await sweep();
  assert.equal(await automaticJobs(), 1);
  await sweep();
  assert.equal(await automaticJobs(), 1);
});

test("orphaned first store issuance recovers only on its original agent", async () => {
  const f = await fixture();
  const secondAgent = (await pool.query(`INSERT INTO certops_agents(workspace_id,agent_id,name,agent_version,protocol_version,credential_prefix,credential_hash,status,declared_target_selectors)
    VALUES($1,$2,'Other agent','0.18.0','1.0.0',$3,$4,'active',$5::jsonb) RETURNING id`,
    [f.workspaceId, "agent-" + randomUUID(), "ttagent_" + randomBytes(8).toString("hex"), randomBytes(32).toString("hex"), JSON.stringify([TARGET.reference])])).rows[0].id;
  const target = { type: "windows-cert-store", reference: TARGET.reference, store: "My" };
  const client = await pool.connect();
  let created;
  try {
    await client.query("BEGIN");
    created = await require("../../apps/api/services/certops/issuance").createCertificateIssuanceJob({ client,
      workspaceId: f.workspaceId, operation: "issue", source: "api", mode: "real", idempotencyKey: randomUUID(),
      assignedAgentId: f.agentId, requestedByUserId: f.actor, payload: { issuerId: f.issuerId, target, automationEnabled: false } });
    await client.query("UPDATE certificate_jobs SET status='orphaned_unknown_effect',needs_operator_reconciliation=true WHERE id=$1", [created.job.id]);
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
  const options = { client: pool, workspaceId: f.workspaceId, enrollmentId: created.job.enrollmentId,
    orphanedJobId: created.job.id, acknowledgeUnknownEffect: true, reason: "Agent restarted after submission", actorUserId: f.actor,
    env: { CERTOPS_ENABLED: "true" }, audit: async () => {} };
  const recovery = await enrollments.recoverOrphanedEnrollment(options);
  assert.equal(recovery.created, true);
  const continuation = (await pool.query("SELECT assigned_agent_id,operation,enrollment_id FROM certificate_jobs WHERE id=$1", [recovery.jobId])).rows[0];
  assert.equal(continuation.assigned_agent_id, f.agentId);
  assert.notEqual(continuation.assigned_agent_id, secondAgent);
  assert.equal(continuation.operation, "continue-enrollment");
  assert.equal(continuation.enrollment_id, created.job.enrollmentId);
  const replay = await enrollments.recoverOrphanedEnrollment(options);
  assert.deepEqual(replay, { jobId: recovery.jobId, created: false });
});

test("AD CS issue approval binds its persisted enrollment, agent and snapshot", async () => {
  const f = await fixture();
  const target = { type: "windows-cert-store", reference: TARGET.reference, store: "My" };
  const client = await pool.connect();
  let job;
  try {
    await client.query("BEGIN");
    const result = await require("../../apps/api/services/certops/issuance").createCertificateIssuanceJob({ client,
      workspaceId: f.workspaceId, operation: "issue", source: "api", mode: "real", idempotencyKey: randomUUID(),
      assignedAgentId: f.agentId, requestedByUserId: f.actor, requiresApproval: true,
      payload: { issuerId: f.issuerId, target, automationEnabled: false } });
    job = result.job;
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
  const email = randomUUID() + "@example.test";
  const approver = (await pool.query("INSERT INTO users(email,email_original,display_name,password_hash,auth_method,email_verified) VALUES($1::text,$1::text,'Approver','x','local',true) RETURNING id", [email])).rows[0].id;
  const approvals = require("../../apps/api/services/certops/jobApprovals");
  const decision = await approvals.approveJob({ workspaceId: f.workspaceId, jobId: job.id, approverUserId: approver });
  assert.equal(decision.status, "pending");
  assert.equal((await approvals.requestApprovalState({ workspaceId: f.workspaceId, jobId: job.id })).approvalValid, true);
  const stored = (await pool.query("SELECT snapshot_bytes FROM certificate_enrollments WHERE id=$1", [job.enrollmentId])).rows[0];
  const snapshot = JSON.parse(Buffer.from(stored.snapshot_bytes).toString("utf8"));
  snapshot.template = "DifferentTemplate";
  const bytes = Buffer.from(JSON.stringify(snapshot));
  const digest = require("node:crypto").createHash("sha256").update(bytes).digest("hex");
  await pool.query("UPDATE certificate_enrollments SET snapshot_bytes=$2,snapshot_sha256=$3 WHERE id=$1", [job.enrollmentId, bytes, digest]);
  assert.equal((await approvals.requestApprovalState({ workspaceId: f.workspaceId, jobId: job.id })).approvalValid, false);
});

test("an approved store issue and its pending-CA continuation are claimable by the same qualified synthetic agent", async () => {
  const f = await fixture();
  const rawCredential = "synthetic-credential-" + randomUUID();
  const publicId = (await pool.query("UPDATE certops_agents SET credential_hash=$2 WHERE id=$1 RETURNING agent_id", [f.agentId,
    require("node:crypto").createHash("sha256").update(rawCredential).digest("hex")])).rows[0].agent_id;
  await pool.query(`UPDATE certops_agents SET platform='win32',declared_capabilities=$2::jsonb,capabilities_updated_at=NOW()
    WHERE id=$1`, [f.agentId, JSON.stringify(["windows-store-only-adcs-v1", "adcs-enroll-v1", "evidence-claim-binding-v1"])]);
  const target = { type: "windows-cert-store", reference: TARGET.reference, store: "My" };
  const client = await pool.connect();
  let job;
  try {
    await client.query("BEGIN");
    job = (await require("../../apps/api/services/certops/issuance").createCertificateIssuanceJob({ client,
      workspaceId: f.workspaceId, operation: "issue", source: "api", mode: "real", idempotencyKey: randomUUID(),
      assignedAgentId: f.agentId, requestedByUserId: f.actor, requiresApproval: true,
      payload: { issuerId: f.issuerId, target, automationEnabled: false } })).job;
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
  const email = randomUUID() + "@example.test";
  const approver = (await pool.query("INSERT INTO users(email,email_original,display_name,password_hash,auth_method,email_verified) VALUES($1::text,$1::text,'Approver','x','local',true) RETURNING id", [email])).rows[0].id;
  await require("../../apps/api/services/certops/jobApprovals").approveJob({ workspaceId: f.workspaceId, jobId: job.id, approverUserId: approver });
  const claim = () => require("../../apps/api/services/certops/agentDispatch").claimJobs({ dbPool: pool,
    agent: require("../../apps/api/services/certops/agentCredentialFence").bindAuthenticatedCredential({ id: f.agentId, agentId: publicId, workspaceId: f.workspaceId, status: "active", platform: "win32", protocolVersion: "1.0.0", agentVersion: "0.18.1" }, rawCredential),
    body: { maxJobs: 1, supportedActions: ["renew", "continue-enrollment"] }, env: { CERTOPS_ENABLED: "true" },
    deps: { enforceAgentSequence: async () => {}, signJobForDispatch: async ({ job: signed }) => signed } });
  const firstClaim = await claim();
  assert.equal(firstClaim.jobs.length, 1);
  assert.equal(firstClaim.jobs[0].jobId, job.id);
  await pool.query("UPDATE certificate_jobs SET status='awaiting_issuer' WHERE id=$1", [job.id]);
  await pool.query(`UPDATE certificate_enrollments SET state='pending_issuance',request_id=123,pending_since=NOW(),next_poll_at=NOW()-interval '1 minute' WHERE id=$1`, [job.enrollmentId]);
  const scheduled = await enrollments.scheduleDueEnrollments({ client: pool });
  const next = scheduled.find(item => item.enrollmentId === job.enrollmentId);
  assert.ok(next, "the pending CA enrollment schedules its continuation");
  const continued = await claim();
  assert.equal(continued.jobs.length, 1);
  assert.equal(continued.jobs[0].jobId, next.jobId);
  assert.equal((await pool.query("SELECT assigned_agent_id,status FROM certificate_jobs WHERE id=$1", [next.jobId])).rows[0].assigned_agent_id, f.agentId);
  // If the agent disappears after the CA issues the leaf, recovery stays on
  // the original enrollment and does not demand a new human approval.
  await pool.query("UPDATE certificate_jobs SET status='orphaned_unknown_effect',needs_operator_reconciliation=true WHERE id=$1", [next.jobId]);
  await pool.query("UPDATE certificate_enrollments SET state='issued' WHERE id=$1", [job.enrollmentId]);
  const recovery = await enrollments.recoverOrphanedEnrollment({ client: pool, workspaceId: f.workspaceId,
    enrollmentId: job.enrollmentId, orphanedJobId: next.jobId, acknowledgeUnknownEffect: true,
    reason: "Resume issued enrollment", actorUserId: f.actor, env: { CERTOPS_ENABLED: "true" }, audit: async () => {} });
  assert.equal(recovery.created, true);
  const recovered = await claim();
  assert.equal(recovered.jobs.length, 1);
  assert.equal(recovered.jobs[0].jobId, recovery.jobId);
  assert.equal((await pool.query("SELECT assigned_agent_id FROM certificate_jobs WHERE id=$1", [recovery.jobId])).rows[0].assigned_agent_id, f.agentId);
});

test("store issuance requires fresh qualified capability but replay survives capability expiry", async () => {
  const f = await fixture();
  const target = { type: "windows-cert-store", reference: TARGET.reference, store: "My" };
  const idempotencyKey = randomUUID();
  const issue = require("../../apps/api/services/certops/issuance").createCertificateIssuanceJob;
  const options = { workspaceId: f.workspaceId, operation: "issue", source: "api", mode: "real", idempotencyKey,
    assignedAgentId: f.agentId, requestedByUserId: f.actor, payload: { issuerId: f.issuerId, target, automationEnabled: false } };
  const attempt = async () => {
    const client = await pool.connect();
    try { await client.query("BEGIN"); const result = await issue({ ...options, client }); await client.query("COMMIT"); return result; }
    catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
  };
  for (const caps of [[], ["adcs-enroll-v1", "evidence-claim-binding-v1"]]) {
    await pool.query("UPDATE certops_agents SET declared_capabilities=$2::jsonb,capabilities_updated_at=NOW() WHERE id=$1", [f.agentId, JSON.stringify(caps)]);
    await assert.rejects(attempt, /fresh Windows store/);
    assert.equal(Number((await pool.query("SELECT count(*) FROM managed_certificates WHERE workspace_id=$1 AND source_ref=$2", [f.workspaceId, idempotencyKey])).rows[0].count), 0);
  }
  const caps = ["windows-store-only-adcs-v1", "adcs-enroll-v1", "evidence-claim-binding-v1"];
  await pool.query("UPDATE certops_agents SET declared_capabilities=$2::jsonb,capabilities_updated_at=NOW()-interval '2 days' WHERE id=$1", [f.agentId, JSON.stringify(caps)]);
  await assert.rejects(attempt, /fresh Windows store/);
  await pool.query("UPDATE certops_agents SET capabilities_updated_at=NOW() WHERE id=$1", [f.agentId]);
  const first = await attempt();
  assert.equal(first.created, true);
  await pool.query("UPDATE certops_agents SET capabilities_updated_at=NOW()-interval '2 days' WHERE id=$1", [f.agentId]);
  const replay = await attempt();
  assert.equal(replay.created, false);
  assert.equal(replay.job.id, first.job.id);
});

test("server AD CS policy is bounded, frozen and bound to idempotent replay", async () => {
  const f = await fixture();
  const issue = require("../../apps/api/services/certops/issuance").createCertificateIssuanceJob;
  const target = { type: "windows-cert-store", reference: TARGET.reference, store: "My" };
  const options = { workspaceId: f.workspaceId, operation: "issue", source: "api", mode: "real", idempotencyKey: randomUUID(),
    assignedAgentId: f.agentId, requestedByUserId: f.actor, payload: { issuerId: f.issuerId, target },
    adcsEnrollmentPolicy: { pollInterval: 1200, pendingTimeout: 7200 } };
  const run = async (changes = {}) => { const client = await pool.connect(); try { await client.query("BEGIN"); const result = await issue({ ...options, ...changes, client }); await client.query("COMMIT"); return result; } catch (e) { await client.query("ROLLBACK"); throw e; } finally { client.release(); } };
  await assert.rejects(run({ adcsEnrollmentPolicy: { pollInterval: 1 } }), /policy bounds/);
  await assert.rejects(run({ payload: { ...options.payload, pollInterval: 1200 } }), /requires an issuer/);
  const created = await run();
  const snapshot = JSON.parse((await pool.query("SELECT snapshot_bytes FROM certificate_enrollments WHERE id=$1", [created.job.enrollmentId])).rows[0].snapshot_bytes.toString("utf8"));
  assert.equal(snapshot.pollInterval, 1200);
  assert.equal(snapshot.pendingTimeout, 7200);
  assert.equal((await run()).created, false);
  await assert.rejects(run({ adcsEnrollmentPolicy: { pollInterval: 1201, pendingTimeout: 7200 } }), error => error.code === "CERTOPS_JOB_IDEMPOTENCY_CONFLICT");
});

test("retirement or credential rotation wins against already authenticated agent operations", async () => {
  const dispatch = require("../../apps/api/services/certops/agentDispatch");
  const { bindAuthenticatedCredential } = require("../../apps/api/services/certops/agentCredentialFence");
  const crypto = require("node:crypto");
  for (const mutation of ["retire", "rotate"]) {
    const f = await fixture();
    const raw = "synthetic-authenticated-credential-" + randomUUID();
    const agentPublicId = (await pool.query("UPDATE certops_agents SET credential_hash=$2 WHERE id=$1 RETURNING agent_id", [f.agentId, crypto.createHash("sha256").update(raw).digest("hex")])).rows[0].agent_id;
    const agent = bindAuthenticatedCredential({ id: f.agentId, workspaceId: f.workspaceId, agentId: agentPublicId, status: "active", protocolVersion: "1.0.0", agentVersion: "0.18.1" }, raw);
    const writer = await pool.connect();
    try {
      await writer.query("BEGIN");
      if (mutation === "retire") await writer.query("UPDATE certops_agents SET status='retired',retired_at=NOW() WHERE id=$1", [f.agentId]);
      else await writer.query("UPDATE certops_agents SET credential_hash=$2 WHERE id=$1", [f.agentId, crypto.createHash("sha256").update("rotated-" + randomUUID()).digest("hex")]);
      const deps = { enforceAgentSequence: async () => {}, consumeNonce: async () => ({ consumed: true }) };
      const calls = [
        dispatch.recordHeartbeat({ dbPool: pool, agent, envelope: {}, body: {}, deps }),
        dispatch.claimJobs({ dbPool: pool, agent, body: { supportedActions: [] }, deps }),
        dispatch.renewJobLease({ dbPool: pool, agent, jobId: randomUUID(), claimId: randomUUID(), deps }),
        dispatch.ingestResult({ dbPool: pool, agent, body: { jobId: randomUUID(), claimId: randomUUID(), status: "failed" }, deps }),
        require("../../apps/api/services/certops/agentJobLogs").ingestAgentJobLogs({ dbPool: pool, agent, jobId: randomUUID(), body: { claimId: randomUUID() } }),
      ];
      const settled = Promise.allSettled(calls);
      assert.equal(await Promise.race([settled.then(() => "settled"), new Promise(resolve => setTimeout(() => resolve("waiting"), 100))]), "waiting");
      await writer.query("COMMIT");
      const results = await settled;
      assert.ok(results.every(result => result.status === "rejected" && result.reason.code === "CERTOPS_AGENT_CREDENTIAL_INVALID"), JSON.stringify(results));
    } catch (error) { await writer.query("ROLLBACK"); throw error; } finally { writer.release(); }
  }
});

test("terminal enrollment wins a concurrent proof recovery preparation", async () => {
  const f = await fixture();
  const issue = require("../../apps/api/services/certops/issuance").createCertificateIssuanceJob;
  const recovery = require("../../apps/api/services/certops/adcsProofRecovery");
  const target = { type: "windows-cert-store", reference: TARGET.reference, store: "My" };
  const creator = await pool.connect();
  let job;
  try {
    await creator.query("BEGIN");
    job = (await issue({ client: creator, workspaceId: f.workspaceId, operation: "issue", source: "api", mode: "real", idempotencyKey: randomUUID(),
      assignedAgentId: f.agentId, requestedByUserId: f.actor, payload: { issuerId: f.issuerId, target } })).job;
    await creator.query("UPDATE certificate_jobs SET status='orphaned_unknown_effect',needs_operator_reconciliation=true,claim_id=$2,attempt_count=1 WHERE id=$1", [job.id, randomUUID()]);
    await creator.query("COMMIT");
  } catch (error) { await creator.query("ROLLBACK"); throw error; } finally { creator.release(); }
  const writer = await pool.connect(), reader = await pool.connect();
  try {
    await writer.query("BEGIN"); await reader.query("BEGIN");
    await writer.query("UPDATE certificate_enrollments SET state='cancelled' WHERE id=$1", [job.enrollmentId]);
    const result = recovery.prepareAdcsProofRecoveryTx({ client: reader, workspaceId: f.workspaceId, enrollmentId: job.enrollmentId,
      originalJobId: job.id, actorUserId: f.actor, reason: "Inspect uncertain installation", audit: async () => {} });
    const settled = result.then(() => "accepted", () => "rejected");
    assert.equal(await Promise.race([settled, new Promise(resolve => setTimeout(() => resolve("waiting"), 150))]), "waiting");
    await writer.query("COMMIT");
    await assert.rejects(result, { code: "CERTOPS_ADCS_PROOF_INVALID" });
    await reader.query("ROLLBACK");
    const counts = (await pool.query("SELECT count(*)::int AS n FROM certops_adcs_proof_recovery_intents WHERE enrollment_id=$1", [job.enrollmentId])).rows[0];
    assert.equal(counts.n, 0);
  } finally { await writer.query("ROLLBACK").catch(() => {}); await reader.query("ROLLBACK").catch(() => {}); writer.release(); reader.release(); }
});

test("AD CS proof recovery binds the original live identity, verifies installation and preserves workspace deletion", async () => {
  const f = await fixture();
  const crypto = require("node:crypto");
  const rawCredential = "expected-identity-" + randomUUID();
  const publicId = (await pool.query("UPDATE certops_agents SET credential_hash=$2 WHERE id=$1 RETURNING agent_id", [f.agentId, crypto.createHash("sha256").update(rawCredential).digest("hex")])).rows[0].agent_id;
  const agent = require("../../apps/api/services/certops/agentCredentialFence").bindAuthenticatedCredential({ id: f.agentId, workspaceId: f.workspaceId, agentId: publicId }, rawCredential);
  const target = { type: "windows-cert-store", reference: TARGET.reference, store: "My" };
  const issue = require("../../apps/api/services/certops/issuance").createCertificateIssuanceJob;
  const recovery = require("../../apps/api/services/certops/adcsProofRecovery");
  const client = await pool.connect();
  let job, evidenceId;
  try {
    await client.query("BEGIN");
    job = (await issue({ client, workspaceId: f.workspaceId, operation: "issue", source: "api", mode: "real", idempotencyKey: randomUUID(),
      assignedAgentId: f.agentId, requestedByUserId: f.actor, payload: { issuerId: f.issuerId, target } })).job;
    const claim = randomUUID();
    await client.query(`UPDATE certificate_jobs SET status='running',claimed_by_agent_id=$2,claim_id=$3,attempt_count=1,
      lease_expires_at=NOW()+interval '5 minutes' WHERE id=$1`, [job.id, f.agentId, claim]);
    const metadata = { step: "adcs.expected-identity", enrollmentId: job.enrollmentId,
      destinationSha256: crypto.createHash("sha256").update(JSON.stringify(target)).digest("hex"),
      fingerprintSha256: "ab".repeat(32), csrSpkiSha256: "cd".repeat(32), leafSpkiSha256: "cd".repeat(32) };
    evidenceId = (await client.query(`INSERT INTO certificate_evidence(workspace_id,job_id,evidence_type,claim_id,attempt_count,created_by_agent_id,metadata)
      VALUES($1,$2,'validation.passed',$3,1,$4,$5::jsonb) RETURNING id`, [f.workspaceId, job.id, claim, f.agentId, JSON.stringify(metadata)])).rows[0].id;
    // A terminal transition must not discard a valid fact from the still-live
    // original claim, even though proof-only recovery will be unavailable.
    await client.query("SAVEPOINT terminal_receipt");
    await client.query("UPDATE certificate_enrollments SET state='cancelled' WHERE id=$1", [job.enrollmentId]);
    assert.equal((await recovery.recordAdcsExpectedIdentityTx({ client, agent, jobId: job.id, evidenceId })).created, true);
    await client.query("ROLLBACK TO SAVEPOINT terminal_receipt");
    const first = await recovery.recordAdcsExpectedIdentityTx({ client, agent, jobId: job.id, evidenceId });
    assert.equal(first.created, true);
    assert.deepEqual(await recovery.recordAdcsExpectedIdentityTx({ client, agent, jobId: job.id, evidenceId }), { receiptId: first.receiptId, created: false });
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
  await pool.query("UPDATE certificate_jobs SET status='orphaned_unknown_effect',needs_operator_reconciliation=true,lease_expires_at=NOW()-interval '1 minute' WHERE id=$1", [job.id]);
  const afterExpiry = await pool.connect();
  try {
    await afterExpiry.query("BEGIN");
    await assert.rejects(recovery.recordAdcsExpectedIdentityTx({ client: afterExpiry, agent, jobId: job.id, evidenceId }), /claim is no longer admissible/);
    await afterExpiry.query("ROLLBACK");
  } finally { afterExpiry.release(); }
  const resultTx = await pool.connect();
  let proofJobId;
  try {
    await resultTx.query("BEGIN");
    const request = { client: resultTx, workspaceId: f.workspaceId, enrollmentId: job.enrollmentId, originalJobId: job.id,
      actorUserId: f.actor, reason: "Inspect the installed certificate", audit: async () => {} };
    const before = Number((await resultTx.query("SELECT count(*) FROM certificate_jobs WHERE workspace_id=$1", [f.workspaceId])).rows[0].count);
    for (const terminal of ["cancelled", "expired", "abandoned"]) {
      await resultTx.query("SAVEPOINT terminal_before_prepare");
      await resultTx.query("UPDATE certificate_enrollments SET state=$2 WHERE id=$1", [job.enrollmentId, terminal]);
      await assert.rejects(recovery.prepareAdcsProofRecoveryTx(request), { code: "CERTOPS_ADCS_PROOF_INVALID" });
      await resultTx.query("ROLLBACK TO SAVEPOINT terminal_before_prepare");
    }
    const intent = await recovery.prepareAdcsProofRecoveryTx(request);
    assert.equal(intent.state, "transport_unavailable");
    assert.equal(intent.created, true);
    assert.equal((await recovery.prepareAdcsProofRecoveryTx(request)).created, false);
    assert.equal(Number((await resultTx.query("SELECT count(*) FROM certificate_jobs WHERE workspace_id=$1", [f.workspaceId])).rows[0].count), before);
    await resultTx.query(`UPDATE certops_agents SET declared_capabilities=$2::jsonb,capabilities_updated_at=NOW() WHERE id=$1`,
      [f.agentId, JSON.stringify(["windows-store-only-adcs-v1", "adcs-enroll-v1", "evidence-claim-binding-v1", "adcs-store-proof-only-v1"])]);
    for (const terminal of ["cancelled", "expired", "abandoned"]) {
      await resultTx.query("SAVEPOINT terminal_before_queue");
      await resultTx.query("UPDATE certificate_enrollments SET state=$2 WHERE id=$1", [job.enrollmentId, terminal]);
      await assert.rejects(recovery.queueAdcsProofRecoveryTx({ client: resultTx, workspaceId: f.workspaceId, intentId: intent.intentId, actorUserId: f.actor }), { code: "CERTOPS_ADCS_PROOF_INVALID" });
      await resultTx.query("ROLLBACK TO SAVEPOINT terminal_before_queue");
    }
    const queued = await recovery.queueAdcsProofRecoveryTx({ client: resultTx, workspaceId: f.workspaceId, intentId: intent.intentId, actorUserId: f.actor });
    assert.equal(queued.created, true);
    assert.equal(queued.job.operation, "adcs-installation-proof");
    proofJobId = queued.job.id;
    assert.equal((await recovery.queueAdcsProofRecoveryTx({ client: resultTx, workspaceId: f.workspaceId, intentId: intent.intentId, actorUserId: f.actor })).created, false);
    for (const terminal of ["cancelled", "expired", "abandoned"]) {
      await resultTx.query("SAVEPOINT terminal_after_queue");
      await resultTx.query("UPDATE certificate_enrollments SET state=$2 WHERE id=$1", [job.enrollmentId, terminal]);
      await assert.rejects(recovery.queueAdcsProofRecoveryTx({ client: resultTx, workspaceId: f.workspaceId, intentId: intent.intentId, actorUserId: f.actor }), { code: "CERTOPS_ADCS_PROOF_INVALID" });
      assert.equal(await recovery.loadAdcsProofJobBindingTx({ client: resultTx, workspaceId: f.workspaceId, jobId: queued.job.id, agentId: f.agentId }), null);
      await resultTx.query("ROLLBACK TO SAVEPOINT terminal_after_queue");
    }
    const binding = await recovery.loadAdcsProofJobBindingTx({ client: resultTx, workspaceId: f.workspaceId, jobId: queued.job.id, agentId: f.agentId });
    assert.equal(binding.originalJobId, job.id);
    assert.equal(binding.fingerprintSha256, "ab".repeat(32));
    assert.equal(await recovery.loadAdcsProofJobBindingTx({ client: resultTx, workspaceId: f.workspaceId, jobId: queued.job.id, agentId: randomUUID() }), null);
    const terminalWriter = await pool.connect();
    try {
      await terminalWriter.query("BEGIN");
      await terminalWriter.query("SET LOCAL statement_timeout = '5s'");
      const transition = terminalWriter.query("UPDATE certificate_enrollments SET state='cancelled' WHERE id=$1", [job.enrollmentId]);
      const settled = transition.then(() => "updated", () => "rejected");
      assert.equal(await Promise.race([settled, new Promise(resolve => setTimeout(() => resolve("waiting"), 150))]), "waiting");
      await resultTx.query("COMMIT");
      await transition;
      await terminalWriter.query("ROLLBACK");
    } finally { await terminalWriter.query("ROLLBACK").catch(() => {}); terminalWriter.release(); }
  } catch (error) { await resultTx.query("ROLLBACK"); throw error; } finally { resultTx.release(); }
  const claimedProof = await require("../../apps/api/services/certops/agentDispatch").claimJobs({ dbPool: pool,
    agent: require("../../apps/api/services/certops/agentCredentialFence").bindAuthenticatedCredential({ id: f.agentId, agentId: publicId, workspaceId: f.workspaceId, status: "active", platform: "win32", protocolVersion: "1.0.0", agentVersion: "0.18.1" }, rawCredential),
    body: { maxJobs: 1, supportedActions: ["adcs-installation-proof"] }, env: { CERTOPS_ENABLED: "true" },
    deps: { enforceAgentSequence: async () => {}, signJobForDispatch: async ({ job: signed }) => signed } });
  assert.equal(claimedProof.jobs.length, 1);
  assert.equal(claimedProof.jobs[0].jobId, proofJobId);
  assert.equal(claimedProof.jobs[0].adcsProof.originalJobId, job.id);
  assert.equal(claimedProof.jobs[0].caEndpoint, undefined);
  const proofJob = (await pool.query("SELECT * FROM certificate_jobs WHERE id=$1", [proofJobId])).rows[0];
  const signedProof = claimedProof.jobs[0].adcsProof;
  const metadata = { ...signedProof, ownerAgentId: signedProof.agentId, step: "adcs-proof-only", store: "LocalMachine\\My",
    destinationType: "windows-cert-store", keyPossessionVerified: true, machineKey: true, nonExportable: true,
    validTo: "2027-11-10T00:00:00.000Z" };
  delete metadata.agentId;
  const proofEvidence = (await pool.query(`INSERT INTO certificate_evidence(workspace_id,job_id,evidence_type,claim_id,attempt_count,created_by_agent_id,metadata)
    VALUES($1,$2,'validation.passed',$3,$4,$5,$6::jsonb) RETURNING id`, [f.workspaceId, proofJobId, proofJob.claim_id, proofJob.attempt_count, f.agentId, JSON.stringify({ ...metadata, fingerprintSha256: "00".repeat(32) })])).rows[0].id;
  let replay = false;
  const auditEvents = [];
  const submit = () => require("../../apps/api/services/certops/agentDispatch").ingestResult({ dbPool: pool, agent,
    body: { jobId: proofJobId, claimId: proofJob.claim_id, status: "succeeded", nonce: randomUUID() },
    deps: { consumeNonce: async () => replay ? ({ consumed: false, code: "CERTOPS_NONCE_REPLAYED" }) : ({ consumed: true }), enforceAgentSequence: async () => {}, writeAudit: async (event) => { auditEvents.push(event.action); }, enqueueOutboxEvent: async () => {} } });
  // An expired claim must not accept either evidence or result, even before
  // the orphan reaper has transitioned the job.
  await pool.query("UPDATE certificate_jobs SET lease_expires_at=NOW()-interval '1 second' WHERE id=$1", [proofJobId]);
  await assert.rejects(require("../../apps/api/services/certops/agentDispatch").assertEvidenceClaimOwnership({ dbPool: pool, agent, jobId: proofJobId, claimId: proofJob.claim_id }), { code: "CERTOPS_AGENT_LEASE_INVALID" });
  await assert.rejects(submit(), { code: "CERTOPS_AGENT_LEASE_INVALID" });
  assert.equal((await pool.query("SELECT status FROM managed_certificates WHERE id=$1", [job.subjectId])).rows[0].status, "provisioning");
  await pool.query("UPDATE certificate_jobs SET lease_expires_at=NOW()+interval '5 minutes' WHERE id=$1", [proofJobId]);
  await assert.rejects(require("../../apps/api/services/certops/agentDispatch").assertEvidenceClaimOwnership({ dbPool: pool, agent, jobId: proofJobId }), { code: "CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH" });
  await assert.rejects(submit(), /matching claim-bound installation evidence/);
  assert.equal((await pool.query("SELECT status FROM managed_certificates WHERE id=$1", [job.subjectId])).rows[0].status, "provisioning");
  await pool.query("UPDATE certificate_evidence SET metadata=$2::jsonb WHERE id=$1", [proofEvidence, JSON.stringify(metadata)]);
  await submit();
  const recovered = (await pool.query("SELECT status,fingerprint_sha256 FROM managed_certificates WHERE id=$1", [job.subjectId])).rows[0];
  assert.equal(recovered.status, "active");
  assert.equal(recovered.fingerprint_sha256, metadata.fingerprintSha256);
  const originalAfter = (await pool.query("SELECT status,needs_operator_reconciliation,reconciliation_reason FROM certificate_jobs WHERE id=$1", [job.id])).rows[0];
  assert.deepEqual(originalAfter, { status: "orphaned_unknown_effect", needs_operator_reconciliation: false, reconciliation_reason: "installation_verified_by_proof" });
  assert.equal(auditEvents.filter(action => action === "CERTOPS_ADCS_INSTALLATION_PROOF_RECONCILED").length, 1);
  replay = true;
  assert.equal((await submit()).duplicate, true);
  assert.equal(auditEvents.filter(action => action === "CERTOPS_ADCS_INSTALLATION_PROOF_RECONCILED").length, 1);
  const missingTx = await pool.connect();
  let missingJob;
  try {
    await missingTx.query("BEGIN");
    const missing = (await issue({ client: missingTx, workspaceId: f.workspaceId, operation: "issue", source: "api", mode: "real", idempotencyKey: randomUUID(),
      assignedAgentId: f.agentId, requestedByUserId: f.actor, payload: { issuerId: f.issuerId, target } })).job;
    missingJob = missing;
    await missingTx.query("UPDATE certificate_jobs SET status='orphaned_unknown_effect',needs_operator_reconciliation=true,claim_id=$2,attempt_count=1 WHERE id=$1", [missing.id, randomUUID()]);
    const outcome = await recovery.prepareAdcsProofRecoveryTx({ client: missingTx, workspaceId: f.workspaceId, enrollmentId: missing.enrollmentId,
      originalJobId: missing.id, actorUserId: f.actor, reason: "Inspect uncertain installation", audit: async () => {} });
    assert.deepEqual(outcome, { state: "expected_identity_unavailable", created: false });
    const certificate = (await missingTx.query("SELECT reconciliation_reason,fingerprint_sha256 FROM managed_certificates WHERE id=$1", [missing.subjectId])).rows[0];
    assert.equal(certificate.reconciliation_reason, "expected_identity_unavailable");
    assert.equal(certificate.fingerprint_sha256, null);
    await missingTx.query("COMMIT");
  } catch (error) { await missingTx.query("ROLLBACK"); throw error; } finally { missingTx.release(); }
  const express = require("../../apps/api/node_modules/express"), request = require("supertest");
  const app = express(); app.use(express.json());
  app.use((req, _res, next) => { req.user = { id: f.actor }; req.authz = { workspaceRole: "admin" }; req.workspace = { id: f.workspaceId }; req.isAuthenticated = () => true; next(); });
  app.use(require("../../apps/api/routes/certops-enrollments"));
  const route = `/api/v1/workspaces/${f.workspaceId}/certops/enrollments/${missingJob.enrollmentId}/recover-installation-proof`;
  const response = await request(app).post(route).send({ orphanedJobId: missingJob.id, reason: "Inspect uncertain installation" });
  assert.equal(response.status, 200, JSON.stringify(response.body));
  assert.equal(response.body.state, "expected_identity_unavailable");
  const rejected = await request(app).post(route).send({ orphanedJobId: missingJob.id, reason: "Inspect", caEndpoint: "example" });
  assert.equal(rejected.status, 400);
  await pool.query("DELETE FROM workspaces WHERE id=$1", [f.workspaceId]);
  assert.equal(Number((await pool.query("SELECT count(*) FROM certops_adcs_expected_identity_receipts WHERE workspace_id=$1", [f.workspaceId])).rows[0].count), 0);
  assert.equal(Number((await pool.query("SELECT count(*) FROM certops_adcs_proof_recovery_intents WHERE workspace_id=$1", [f.workspaceId])).rows[0].count), 0);
});

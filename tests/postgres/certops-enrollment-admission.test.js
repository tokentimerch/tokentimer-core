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
  for (let i = 0; i < 120; i++) {
    if (spawnSync("docker", ["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "admission_test"], { timeout: 10000 }).status === 0) { ready = true; break; }
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  assert.ok(ready);
  Object.assign(process.env, { NODE_ENV: "test", CERTOPS_ENABLED: "true", DB_HOST: "127.0.0.1", DB_PORT: port,
    DB_NAME: "certops_admission_ci_test", DB_USER: "admission_test", DB_PASSWORD: "isolated-admission-only" });
  ({ pool } = require("../../apps/api/db/database"));
  await require("../../apps/api/migrations/migrate").runMigrations();
  enrollments = require("../../apps/api/services/certops/certificateEnrollments");
  scheduler = require("../../apps/api/services/certops/renewalScheduler");
  profiles = require("../../apps/api/services/certops/renewalProfileAdmin");
}, { timeout: 180000 });
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

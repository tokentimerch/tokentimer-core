"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), Module = require("node:module"), cp = require("node:child_process"), crypto = require("node:crypto");
const root = path.resolve(__dirname, "../..");
const { Pool } = require("pg");
const dispatch = require("../../apps/api/services/certops/agentDispatch");
const observations = require("../../apps/api/services/certops/agentObservations");
const containerName = "tt-store-replay-" + crypto.randomUUID();
let container, pool;
function docker(args) { const result = cp.spawnSync("docker", args, { encoding: "utf8", timeout: 120000 }); assert.equal(result.status, 0, result.stderr || String(result.error)); return result.stdout.trim(); }
const workspaceId = crypto.randomUUID(), agentId = crypto.randomUUID(), certificateId = crypto.randomUUID(), jobId = crypto.randomUUID(), claimId = crypto.randomUUID(), agentPublicId = "agent-" + crypto.randomUUID();
const agent = { id: agentId, workspaceId, agentId: agentPublicId };
const evidence = { evidenceId: "replay:evidence-1", eventType: "validation.passed", observedAt: "2026-11-27T15:00:00Z", summary: "verified", metadata: [{ name: "step", value: "safety" }] };
const args = { agent, jobId, claimId, envelope: {}, evidenceItems: [evidence], deps: { assertCurrentAgentCredential: async () => {}, enforceAgentSequence: async () => {}, assertEvidenceClaimOwnership: dispatch.assertEvidenceClaimOwnership } };
test.before(async () => {
  container = docker(["run", "-d", "--name", containerName, "--label", "tokentimer.test=store-replay", "--memory=512m", "--cpus=2", "-p", "127.0.0.1::5432", "-e", "POSTGRES_USER=replay_fixture", "-e", "POSTGRES_PASSWORD=replay_fixture_only", "-e", "POSTGRES_DB=replay_fixture_only", "postgres:16-alpine"]);
  let ready = false;
  for (let i=0; i<240; i++) { if (cp.spawnSync("docker", ["exec", container, "pg_isready", "-U", "replay_fixture"], { timeout: 10000 }).status === 0) { ready=true; break; } await new Promise(resolve => setTimeout(resolve,250)); }
  assert.ok(ready);
  const inspected = JSON.parse(docker(["inspect", container]))[0];
  assert.equal(inspected.Name, "/" + containerName);
  assert.equal(inspected.Config.Labels["tokentimer.test"], "store-replay");
  const mapping = inspected.NetworkSettings.Ports["5432/tcp"];
  assert.equal(mapping.length, 1); assert.equal(mapping[0].HostIp, "127.0.0.1");
  const env = { ...process.env, NODE_ENV: "test", CERTOPS_ENABLED: "true", CERTOPS_SIGNING_ENCRYPTION_KEY: crypto.randomBytes(32).toString("hex"), DB_HOST: "127.0.0.1", DB_PORT: mapping[0].HostPort, DB_NAME: "replay_fixture_only", DB_USER: "replay_fixture", DB_PASSWORD: "replay_fixture_only" };
  pool = new Pool({ host: env.DB_HOST, port: Number(env.DB_PORT), user: env.DB_USER, password: env.DB_PASSWORD, database: env.DB_NAME });
  args.dbPool = pool;
  assert.equal((await pool.query("SELECT current_database() AS name")).rows[0].name, "replay_fixture_only");
  const migration = cp.spawnSync(process.execPath, ["apps/api/migrations/migrate.js"], { cwd: root, env, encoding: "utf8", timeout: 120000 });
  assert.equal(migration.status, 0, migration.stderr || "Migration failed");
  const user = (await pool.query("INSERT INTO users(email,email_original,display_name,password_hash,auth_method,email_verified) VALUES($1::text,$1::text,'Fixture','x','local',true) RETURNING id", [crypto.randomUUID() + "@example.test"])).rows[0].id;
  await pool.query("INSERT INTO workspaces(id,name,created_by,plan) VALUES($1,'Fixture',$2,'oss')", [workspaceId, user]);
  await pool.query("INSERT INTO managed_certificates(id,workspace_id,common_name) VALUES($1,$2,'app.example.test')", [certificateId, workspaceId]);
  await pool.query("INSERT INTO certops_agents(id,workspace_id,agent_id,name,agent_version,protocol_version,credential_prefix,credential_hash,status) VALUES($1,$2,$3,'Fixture','1','1.0.0',$4,$5,'active')", [agentId, workspaceId, agentPublicId, "ttagent_" + crypto.randomBytes(8).toString("hex"), crypto.randomBytes(32).toString("hex")]);
  await pool.query("INSERT INTO certificate_jobs(id,workspace_id,subject_type,subject_id,operation,status,assigned_agent_id,claimed_by_agent_id,claim_id,attempt_count,lease_expires_at,payload) VALUES($1,$2,'managed_certificate',$3,'issue','running',$4,$4,$5,2,NOW()+INTERVAL '5 minutes',$6::jsonb)", [jobId, workspaceId, certificateId, agentId, claimId, JSON.stringify({ target: { type: "windows-cert-store", reference: "app.example.test", store: "My" } })]);
}, { timeout: 150000 });
test.after(async () => { if (pool) await pool.end(); if (container) { const info = JSON.parse(docker(["inspect",container]))[0]; assert.equal(info.Name,"/"+containerName); assert.equal(info.Config.Labels["tokentimer.test"],"store-replay"); docker(["rm","--force","--volumes",container]); } });
test("production evidence ingestion then terminal replay does not write twice", async () => {
  assert.equal((await observations.persistAgentJobEvidenceBatch(args)).evidenceCount, 1);
  await pool.query("UPDATE certificate_jobs SET status='succeeded',completed_at=now(),lease_expires_at=now()-interval '1 minute' WHERE id=$1", [jobId]);
  assert.equal((await observations.persistAgentJobEvidenceBatch(args)).duplicate, true);
  for (const changed of [{ ...evidence, summary: "different" }, { ...evidence, observedAt: "2026-11-27T15:00:01Z" }, { ...evidence, evidenceId: "missing" }, { ...evidence, metadata: [{ name: "step", value: "adcs.expected-identity" }] }]) await assert.rejects(observations.persistAgentJobEvidenceBatch({ ...args, evidenceItems: [changed] }));
  assert.equal(Number((await pool.query("SELECT count(*) AS n FROM certificate_evidence WHERE job_id=$1", [jobId])).rows[0].n), 1);
}, { timeout: 30000 });

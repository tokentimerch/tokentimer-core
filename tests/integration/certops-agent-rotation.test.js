"use strict";
const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const { Client, Pool } = require("pg");
const { generateAgentCredential, validateAgentCredential } = require("../../apps/api/services/certops/agentCredentials");
const { prepareCredentialRotation, confirmCredentialRotation, acknowledgeCredentialRotation } = require("../../apps/api/services/certops/agentCredentialRotation");
const connection = { host: process.env.DB_HOST || "localhost", port: Number(process.env.DB_PORT || 5432), user: process.env.DB_USER || "tokentimer", password: process.env.DB_PASSWORD || "password" };
const database = `agent_rotation_${process.pid}_${Date.now()}`;
const env = { CERTOPS_AGENT_ROTATION_ALL_API_FENCED: "true" };
const audit = async () => {};
describe("Agent credential rotation on PostgreSQL", function () {
  this.timeout(30000);
  let db;
  before(async () => {
    const admin = new Client({ ...connection, database: process.env.DB_NAME || "tokentimer" });
    await admin.connect(); try { await admin.query(`CREATE DATABASE ${database}`); } finally { await admin.end(); }
    db = new Pool({ ...connection, database });
    await db.query(`CREATE TABLE certops_agents (id uuid PRIMARY KEY, workspace_id uuid, agent_id text, name text,
      credential_prefix text UNIQUE, credential_hash text UNIQUE, status text, protocol_version text,
      agent_version text, pinned_signing_key_id text, last_seen_at timestamptz, retired_at timestamptz, updated_at timestamptz)`);
    await db.query(require("node:fs").readFileSync(require("node:path").join(__dirname, "../../apps/api/migrations/096-agent-credential-rotations.sql"), "utf8"));
    await db.query(require("node:fs").readFileSync(require("node:path").join(__dirname, "../../apps/api/migrations/097-agent-rotation-ack.sql"), "utf8"));
    await db.query("CREATE TABLE certops_agent_registration_replays (workspace_id uuid, agent_id text)");
    await db.query("CREATE TABLE certificate_jobs (id uuid, claimed_by_agent_id uuid, status text, workspace_id uuid, needs_operator_reconciliation boolean DEFAULT false)");
  });
  after(async () => {
    if (db) await db.end();
    const admin = new Client({ ...connection, database: process.env.DB_NAME || "tokentimer" });
    await admin.connect(); try { await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`); } finally { await admin.end(); }
  });
  async function fixture() {
    const old = generateAgentCredential(), id = randomUUID(), workspaceId = randomUUID();
    await db.query(`INSERT INTO certops_agents (id, workspace_id, agent_id, credential_prefix, credential_hash, status, protocol_version, agent_version)
      VALUES ($1, $2, $3, $4, $5, 'active', '1.0.0', '1.0.0')`, [id, workspaceId, `agent-${id}`, old.credentialPrefix, old.credentialHash]);
    const auth = await validateAgentCredential({ client: db, rawCredential: old.plaintextCredential });
    return { agent: auth.agent, old, next: generateAgentCredential(), operationId: randomUUID().replaceAll("-", ""), workspaceId };
  }
  function prep(f, extra = {}) { return prepareCredentialRotation({ dbPool: db, agent: f.agent, operationId: f.operationId, candidatePrefix: f.next.credentialPrefix, candidateHash: f.next.credentialHash, env, ...extra }); }
  function confirm(f, extra = {}) { return confirmCredentialRotation({ dbPool: db, operationId: f.operationId, rawCandidate: f.next.plaintextCredential, env, audit, ...extra }); }
  it("requires explicit gate and candidate proof before promotion, then retries after response loss", async () => {
    const f = await fixture();
    await assert.rejects(prep(f, { env: {} }), { code: "CERTOPS_AGENT_ROTATION_DISABLED" });
    await assert.rejects(confirm(f, { env: {} }), { code: "CERTOPS_AGENT_ROTATION_DISABLED" });
    assert.deepEqual(await prep(f), { state: "pending" });
    assert.deepEqual(await prep(f), { state: "pending" });
    assert.equal((await validateAgentCredential({ client: db, rawCredential: f.old.plaintextCredential })).valid, true);
    await assert.rejects(confirm(f, { rawCandidate: generateAgentCredential().plaintextCredential }), { code: "CERTOPS_AGENT_ROTATION_UNAUTHORIZED" });
    const agentId = f.agent.agentId;
    await db.query("INSERT INTO certops_agent_registration_replays VALUES ($1, $2), ($3, $2)", [f.workspaceId, agentId, randomUUID()]);
    assert.deepEqual(await confirm(f), { state: "committed" });
    assert.deepEqual(await confirm(f), { state: "committed" });
    const old = await validateAgentCredential({ client: db, rawCredential: f.old.plaintextCredential });
    const current = await validateAgentCredential({ client: db, rawCredential: f.next.plaintextCredential });
    assert.equal(old.valid, false); assert.equal(current.valid, true); assert.equal(current.agent.agentId, agentId);
    const future = generateAgentCredential();
    await assert.rejects(prep(f, { agent: current.agent, operationId: randomUUID().replaceAll("-", ""), candidatePrefix: future.credentialPrefix, candidateHash: future.credentialHash }), { code: "CERTOPS_AGENT_ROTATION_CONFLICT" });
    assert.deepEqual(await confirm(f), { state: "committed" });
    const replays = await db.query("SELECT workspace_id FROM certops_agent_registration_replays WHERE agent_id = $1", [agentId]);
    assert.equal(replays.rows.length, 1); assert.notEqual(replays.rows[0].workspace_id, f.workspaceId);
    await assert.rejects(prep(f), { code: "CERTOPS_AGENT_CREDENTIAL_STALE" });
  });
  it("serializes simultaneous candidates and rejects reused operation identities", async () => {
    const f = await fixture(), other = generateAgentCredential();
    const outcomes = await Promise.allSettled([prep(f), prep(f, { operationId: randomUUID().replaceAll("-", ""), candidatePrefix: other.credentialPrefix, candidateHash: other.credentialHash })]);
    assert.equal(outcomes.filter(x => x.status === "fulfilled").length, 1);
    assert.equal(outcomes.filter(x => x.status === "rejected" && x.reason.code === "CERTOPS_AGENT_ROTATION_CONFLICT").length, 1);
    const rotation = (await db.query("SELECT * FROM certops_agent_credential_rotations WHERE agent_id = $1", [f.agent.id])).rows[0];
    await assert.rejects(prep(f, { operationId: rotation.operation_id, candidatePrefix: generateAgentCredential().credentialPrefix }), { code: "CERTOPS_AGENT_ROTATION_CONFLICT" });
    const another = await fixture();
    await assert.rejects(prep(another, { operationId: rotation.operation_id }), { code: "CERTOPS_AGENT_ROTATION_CONFLICT" });
  });
  it("promotes once under simultaneous confirmations and rolls back when audit fails", async () => {
    const f = await fixture(); await prep(f);
    let auditCalls = 0;
    const audited = async () => { auditCalls += 1; };
    const results = await Promise.all([confirm(f, { audit: audited }), confirm(f, { audit: audited })]);
    assert.deepEqual(results, [{ state: "committed" }, { state: "committed" }]);
    assert.equal(auditCalls, 1);
    const failed = await fixture(); await prep(failed);
    await assert.rejects(confirm(failed, { audit: async () => { throw new Error("audit unavailable"); } }));
    assert.equal((await validateAgentCredential({ client: db, rawCredential: failed.old.plaintextCredential })).valid, true);
    assert.equal((await validateAgentCredential({ client: db, rawCredential: failed.next.plaintextCredential })).valid, false);
    assert.equal((await db.query("SELECT state FROM certops_agent_credential_rotations WHERE agent_id = $1", [failed.agent.id])).rows[0].state, "pending");
  });
  it("blocks preparation and confirmation while a job is claimed or running", async () => {
    const f = await fixture(), jobId = randomUUID();
    await db.query("INSERT INTO certificate_jobs (id, claimed_by_agent_id, status, workspace_id) VALUES ($1, $2, 'claimed', $3)", [jobId, f.agent.id, f.workspaceId]);
    await assert.rejects(prep(f), { code: "CERTOPS_AGENT_ROTATION_CONFLICT" });
    await db.query("UPDATE certificate_jobs SET status = 'orphaned_unknown_effect', claimed_by_agent_id = NULL, needs_operator_reconciliation = TRUE WHERE id = $1", [jobId]);
    await assert.rejects(prep(f), { code: "CERTOPS_AGENT_ROTATION_CONFLICT" });
    await db.query("UPDATE certificate_jobs SET status = 'succeeded', needs_operator_reconciliation = FALSE WHERE id = $1", [jobId]);
    await prep(f);
    await db.query("UPDATE certificate_jobs SET status = 'running', claimed_by_agent_id = $2 WHERE id = $1", [jobId, f.agent.id]);
    await assert.rejects(confirm(f), { code: "CERTOPS_AGENT_ROTATION_CONFLICT" });
    assert.equal((await validateAgentCredential({ client: db, rawCredential: f.old.plaintextCredential })).valid, true);
  });
  it("requires a separate ACK gate and the current credential; retries ACK without losing the receipt", async () => {
    const f = await fixture(); await prep(f); await confirm(f);
    const current = (await validateAgentCredential({ client: db, rawCredential: f.next.plaintextCredential })).agent;
    const ackEnv = { ...env, CERTOPS_AGENT_ROTATION_ACK_ENABLED: "true" };
    const ack = (extra = {}) => acknowledgeCredentialRotation({ dbPool: db, agent: current, operationId: f.operationId, env: ackEnv, audit, ...extra });
    await assert.rejects(ack({ env }), { code: "CERTOPS_AGENT_ROTATION_DISABLED" });
    await assert.rejects(ack({ agent: f.agent }), { code: "CERTOPS_AGENT_CREDENTIAL_STALE" });
    await assert.rejects(ack({ operationId: randomUUID().replaceAll("-", "") }), { code: "CERTOPS_AGENT_ROTATION_UNAUTHORIZED" });
    await assert.rejects(ack({ audit: async () => { throw new Error("audit unavailable"); } }));
    assert.equal((await db.query("SELECT state FROM certops_agent_credential_rotations WHERE agent_id = $1", [f.agent.id])).rows[0].state, "committed");
    let ackAudits = 0;
    const auditOnce = async () => { ackAudits++; };
    assert.deepEqual(await ack({ audit: auditOnce }), { state: "acknowledged" });
    assert.deepEqual(await ack({ audit: auditOnce }), { state: "acknowledged" });
    assert.equal(ackAudits, 1);
    assert.deepEqual(await confirm(f), { state: "committed" });
    const next = generateAgentCredential();
    assert.deepEqual(await prep(f, { agent: current, operationId: randomUUID().replaceAll("-", ""), candidatePrefix: next.credentialPrefix, candidateHash: next.credentialHash }), { state: "pending" });
    await assert.rejects(ack(), { code: "CERTOPS_AGENT_ROTATION_UNAUTHORIZED" });
  });
  it("rejects expired preparations and an agent retired before confirmation", async () => {
    const expired = await fixture(); await prep(expired);
    await db.query("UPDATE certops_agent_credential_rotations SET expires_at = NOW() - interval '1 second' WHERE agent_id = $1", [expired.agent.id]);
    await assert.rejects(confirm(expired), { code: "CERTOPS_AGENT_ROTATION_UNAUTHORIZED" });
    assert.equal((await validateAgentCredential({ client: db, rawCredential: expired.old.plaintextCredential })).valid, true);
    const retired = await fixture(); await prep(retired);
    await db.query("UPDATE certops_agents SET status = 'retired' WHERE id = $1", [retired.agent.id]);
    await assert.rejects(confirm(retired), { code: "CERTOPS_AGENT_ROTATION_UNAUTHORIZED" });
  });
});

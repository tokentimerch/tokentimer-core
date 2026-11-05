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
    await db.query(require("node:fs").readFileSync(require("node:path").join(__dirname, "../../apps/api/migrations/099-agent-credential-rotations.sql"), "utf8"));
    await db.query(require("node:fs").readFileSync(require("node:path").join(__dirname, "../../apps/api/migrations/100-agent-rotation-ack.sql"), "utf8"));
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
    const unknownJob = randomUUID(), unrelatedJob = randomUUID();
    await db.query("INSERT INTO certificate_jobs (id, workspace_id, status, needs_operator_reconciliation) VALUES ($1, $2, 'orphaned_unknown_effect', TRUE), ($3, $4, 'orphaned_unknown_effect', TRUE)", [unknownJob, f.workspaceId, unrelatedJob, randomUUID()]);
    await assert.rejects(ack(), { code: "CERTOPS_AGENT_ROTATION_CONFLICT" });
    assert.equal((await db.query("SELECT state FROM certops_agent_credential_rotations WHERE agent_id = $1", [f.agent.id])).rows[0].state, "committed");
    // Fixture-only state change; the product has no supported closure flow yet.
    await db.query("UPDATE certificate_jobs SET status = 'succeeded', needs_operator_reconciliation = FALSE WHERE id = $1", [unknownJob]);
    await assert.rejects(ack({ audit: async () => { throw new Error("audit unavailable"); } }));
    assert.equal((await db.query("SELECT state FROM certops_agent_credential_rotations WHERE agent_id = $1", [f.agent.id])).rows[0].state, "committed");
    let ackAudits = 0;
    const auditOnce = async () => { ackAudits++; };
    assert.deepEqual(await ack({ audit: auditOnce }), { state: "acknowledged" });
    // Once acknowledged, a lost ACK response remains retryable even if
    // normal claims have since resumed.
    await db.query("UPDATE certificate_jobs SET status = 'claimed', claimed_by_agent_id = $2 WHERE id = $1", [unknownJob, f.agent.id]);
    assert.deepEqual(await ack({ audit: auditOnce }), { state: "acknowledged" });
    assert.equal(ackAudits, 1);
    await db.query("UPDATE certificate_jobs SET status = 'succeeded' WHERE id = $1", [unknownJob]);
    assert.deepEqual(await confirm(f), { state: "committed" });
    const next = generateAgentCredential();
    assert.deepEqual(await prep(f, { agent: current, operationId: randomUUID().replaceAll("-", ""), candidatePrefix: next.credentialPrefix, candidateHash: next.credentialHash }), { state: "pending" });
    await assert.rejects(ack(), { code: "CERTOPS_AGENT_ROTATION_UNAUTHORIZED" });
  });
  it("documents that an unrelated workspace effect can appear after the ACK check", async () => {
    const f = await fixture(); await prep(f); await confirm(f);
    const current = (await validateAgentCredential({ client: db, rawCredential: f.next.plaintextCredential })).agent;
    const ackEnv = { ...env, CERTOPS_AGENT_ROTATION_ACK_ENABLED: "true" };
    let enteredAudit, resumeAudit;
    const entered = new Promise(resolve => { enteredAudit = resolve; });
    const resume = new Promise(resolve => { resumeAudit = resolve; });
    const ack = acknowledgeCredentialRotation({ dbPool: db, agent: current, operationId: f.operationId, env: ackEnv,
      audit: async () => { enteredAudit(); await resume; } });
    try {
      // ACK has checked jobs and written its uncommitted receipt. A distinct
      // workspace actor can still record an unknown effect before ACK commits.
      await entered;
      await db.query("INSERT INTO certificate_jobs (id, workspace_id, status, needs_operator_reconciliation) VALUES ($1, $2, 'orphaned_unknown_effect', TRUE)", [randomUUID(), f.workspaceId]);
    } finally { resumeAudit(); }
    assert.deepEqual(await ack, { state: "acknowledged" });
    const unknown = await db.query("SELECT count(*) FROM certificate_jobs WHERE workspace_id = $1 AND needs_operator_reconciliation", [f.workspaceId]);
    assert.equal(Number(unknown.rows[0].count), 1);
  });
  it("renews an expired preparation only for the same candidate and after checking intervening jobs", async () => {
    const f = await fixture(); await prep(f);
    await db.query("UPDATE certops_agent_credential_rotations SET expires_at = NOW() - interval '1 second' WHERE agent_id = $1", [f.agent.id]);
    const unrelatedCandidate = generateAgentCredential();
    await assert.rejects(prep(f, { candidatePrefix: unrelatedCandidate.credentialPrefix, candidateHash: unrelatedCandidate.credentialHash }), { code: "CERTOPS_AGENT_ROTATION_CONFLICT" });
    const jobId = randomUUID();
    await db.query("INSERT INTO certificate_jobs (id, workspace_id, claimed_by_agent_id, status) VALUES ($1, $2, $3, 'running')", [jobId, f.workspaceId, f.agent.id]);
    await assert.rejects(prep(f), { code: "CERTOPS_AGENT_ROTATION_CONFLICT" });
    const before = (await db.query("SELECT expires_at < NOW() AS expired FROM certops_agent_credential_rotations WHERE agent_id = $1", [f.agent.id])).rows[0];
    assert.equal(before.expired, true);
    await db.query("UPDATE certificate_jobs SET status = 'orphaned_unknown_effect', claimed_by_agent_id = NULL, needs_operator_reconciliation = TRUE WHERE id = $1", [jobId]);
    await assert.rejects(prep(f), { code: "CERTOPS_AGENT_ROTATION_CONFLICT" });
    // Test-only simulated state transition; the product has no general closure path.
    await db.query("UPDATE certificate_jobs SET status = 'succeeded', needs_operator_reconciliation = FALSE WHERE id = $1", [jobId]);
    assert.deepEqual(await prep(f), { state: "pending" });
    const after = (await db.query("SELECT operation_id, candidate_hash, expires_at > NOW() AS valid FROM certops_agent_credential_rotations WHERE agent_id = $1", [f.agent.id])).rows[0];
    assert.equal(after.operation_id, f.operationId); assert.equal(after.candidate_hash, f.next.credentialHash); assert.equal(after.valid, true);
    assert.deepEqual(await confirm(f), { state: "committed" });
  });
  it("serializes renewal of an expired preparation with an intervening claim", async () => {
    const f = await fixture(); await prep(f);
    await db.query("UPDATE certops_agent_credential_rotations SET expires_at = NOW() - interval '1 second' WHERE agent_id = $1", [f.agent.id]);
    const claimant = await db.connect();
    try {
      await claimant.query("BEGIN");
      await claimant.query("SELECT id FROM certops_agents WHERE id = $1 FOR UPDATE", [f.agent.id]);
      await claimant.query("INSERT INTO certificate_jobs (id, workspace_id, claimed_by_agent_id, status) VALUES ($1,$2,$3,'claimed')", [randomUUID(), f.workspaceId, f.agent.id]);
      const renewal = prep(f).then(() => null, error => error);
      let blocked = false;
      for (let i = 0; i < 50 && !blocked; i++) {
        const waiting = await db.query(`SELECT count(*) AS count FROM pg_stat_activity WHERE datname = current_database()
          AND wait_event_type = 'Lock' AND query LIKE '%SELECT credential_hash, status%'`);
        blocked = Number(waiting.rows[0].count) > 0;
        if (!blocked) await new Promise(resolve => setTimeout(resolve, 20));
      }
      assert.equal(blocked, true, "renewal must wait for the claim transaction");
      await claimant.query("COMMIT");
      assert.equal((await renewal)?.code, "CERTOPS_AGENT_ROTATION_CONFLICT");
      assert.equal((await db.query("SELECT expires_at < NOW() AS expired FROM certops_agent_credential_rotations WHERE agent_id = $1", [f.agent.id])).rows[0].expired, true);
    } finally { try { await claimant.query("ROLLBACK"); } catch (_) {} claimant.release(); }
  });
  it("rejects a pending replay if the current credential changed", async () => {
    const f = await fixture(); await prep(f);
    const other = generateAgentCredential();
    await db.query("UPDATE certops_agents SET credential_prefix = $2, credential_hash = $3 WHERE id = $1", [f.agent.id, other.credentialPrefix, other.credentialHash]);
    const auth = await validateAgentCredential({ client: db, rawCredential: other.plaintextCredential });
    await assert.rejects(prep(f, { agent: auth.agent }), { code: "CERTOPS_AGENT_ROTATION_CONFLICT" });
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

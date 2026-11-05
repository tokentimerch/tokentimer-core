"use strict";

const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const { Client, Pool } = require("pg");
const { generateAgentCredential, validateAgentCredential } = require("../../apps/api/services/certops/agentCredentials");
const { lockCurrentAgentCredential } = require("../../apps/api/services/certops/agentCredentialFence");
const { registerAgent, recordHeartbeat, claimJobs, renewJobLease, ingestResult } = require("../../apps/api/services/certops/agentDispatch");
const { persistAgentDiscoveryEvidenceBatch, persistAgentJobEvidenceBatch } = require("../../apps/api/services/certops/agentObservations");
const { encryptRegistrationCredential } = require("../../apps/api/services/certops/registrationCredentialCrypto");
const { ingestAgentJobLogs } = require("../../apps/api/services/certops/agentJobLogs");

const connection = {
  host: process.env.DB_HOST || "localhost", port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || "tokentimer", password: process.env.DB_PASSWORD || "password",
};
const database = `agent_credential_fence_${process.pid}_${Date.now()}`;

describe("Agent credential fencing on PostgreSQL", function () {
  this.timeout(30000);
  let db;
  before(async () => {
    const admin = new Client({ ...connection, database: process.env.DB_NAME || "tokentimer" });
    await admin.connect();
    try { await admin.query(`CREATE DATABASE ${database}`); } finally { await admin.end(); }
    db = new Pool({ ...connection, database });
    await db.query(`CREATE TABLE certops_agents (
      id uuid PRIMARY KEY, workspace_id uuid, agent_id text, name text,
      credential_prefix text, credential_hash text, status text, protocol_version text,
      agent_version text, pinned_signing_key_id text, last_seen_at timestamptz, retired_at timestamptz
    )`);
    await db.query(`CREATE TABLE certops_agent_bootstrap_tokens (id uuid PRIMARY KEY, status text, workspace_id uuid)`);
    await db.query(`CREATE TABLE certops_agent_registration_replays (
      bootstrap_token_id uuid, registration_id text, agent_id text, credential_ciphertext text,
      encryption_version integer, protocol_version text, signing_key_id text, signing_public_key_pem text, expires_at timestamptz
    )`);
  });
  after(async () => {
    if (db) await db.end();
    const admin = new Client({ ...connection, database: process.env.DB_NAME || "tokentimer" });
    await admin.connect();
    try { await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`); } finally { await admin.end(); }
  });

  async function fixture() {
    const credential = generateAgentCredential();
    const id = randomUUID();
    await db.query(`INSERT INTO certops_agents (id, workspace_id, agent_id, credential_prefix, credential_hash, status, protocol_version, agent_version)
      VALUES ($1, $2, $3, $4, $5, 'active', '1.0.0', '1.0.0')`,
    [id, randomUUID(), `agent-${id}`, credential.credentialPrefix, credential.credentialHash]);
    const auth = await validateAgentCredential({ client: db, rawCredential: credential.plaintextCredential });
    assert.equal(auth.valid, true);
    return { agent: auth.agent, credential };
  }

  it("serializes credential replacement against in-flight transactions", async () => {
    const { agent } = await fixture();
    const first = await db.connect(), rotation = await db.connect();
    try {
      await first.query("BEGIN");
      await lockCurrentAgentCredential(first, agent);
      await rotation.query("BEGIN");
      const pending = rotation.query("UPDATE certops_agents SET credential_hash = $2 WHERE id = $1", [agent.id, "f".repeat(64)]);
      const pid = rotation.processID;
      let blocked = false;
      for (let i = 0; i < 50 && !blocked; i++) {
        const result = await db.query("SELECT cardinality(pg_blocking_pids($1)) AS count", [pid]);
        blocked = Number(result.rows[0].count) > 0;
        if (!blocked) await new Promise(resolve => setTimeout(resolve, 20));
      }
      assert.equal(blocked, true, "replacement must wait for the current transaction");
      await first.query("COMMIT");
      await pending;
      await rotation.query("COMMIT");
      await first.query("BEGIN");
      await assert.rejects(lockCurrentAgentCredential(first, agent), { code: "CERTOPS_AGENT_CREDENTIAL_STALE" });
      await first.query("ROLLBACK");
    } finally {
      try { await first.query("ROLLBACK"); } catch (_) {}
      try { await rotation.query("ROLLBACK"); } catch (_) {}
      first.release(); rotation.release();
    }
  });

  it("serializes retirement against already running agent transactions", async () => {
    const { agent } = await fixture();
    const first = await db.connect(), retirement = await db.connect();
    try {
      await first.query("BEGIN");
      await lockCurrentAgentCredential(first, agent);
      await retirement.query("BEGIN");
      const pending = retirement.query("UPDATE certops_agents SET status = 'retired' WHERE id = $1", [agent.id]);
      let blocked = false;
      for (let i = 0; i < 50 && !blocked; i++) {
        const result = await db.query("SELECT cardinality(pg_blocking_pids($1)) AS count", [retirement.processID]);
        blocked = Number(result.rows[0].count) > 0;
        if (!blocked) await new Promise(resolve => setTimeout(resolve, 20));
      }
      assert.equal(blocked, true, "retirement must wait for the current transaction");
      await first.query("COMMIT");
      await pending;
      await retirement.query("COMMIT");
      await first.query("BEGIN");
      await assert.rejects(lockCurrentAgentCredential(first, agent), { code: "CERTOPS_AGENT_RETIRED" });
      await first.query("ROLLBACK");
    } finally {
      try { await first.query("ROLLBACK"); } catch (_) {}
      try { await retirement.query("ROLLBACK"); } catch (_) {}
      first.release(); retirement.release();
    }
  });

  it("rejects a stale authenticated agent on every mutation path", async () => {
    const { agent, credential } = await fixture();
    const jobId = randomUUID(), claimId = randomUUID();
    await db.query("UPDATE certops_agents SET credential_hash = $2 WHERE id = $1", [agent.id, "f".repeat(64)]);
    const laterAuth = await validateAgentCredential({ client: db, rawCredential: credential.plaintextCredential });
    assert.equal(laterAuth.valid, false);
    const evidence = { evidenceId: randomUUID(), eventType: "certificate.observed", observedAt: new Date().toISOString(),
      fingerprintSha256: "a".repeat(64), metadata: [{ name: "filePath", value: "/test/certificate.pem" }, { name: "targetHost", value: "test.example" }] };
    const calls = {
      heartbeat: () => recordHeartbeat({ dbPool: db, agent, envelope: {}, body: {} }),
      claim: () => claimJobs({ dbPool: db, agent, envelope: {}, body: {} }),
      lease: () => renewJobLease({ dbPool: db, agent, envelope: {}, jobId, claimId }),
      result: () => ingestResult({ dbPool: db, agent, envelope: {}, body: { jobId, claimId, status: "succeeded" } }),
      discoveryEvidence: () => persistAgentDiscoveryEvidenceBatch({ dbPool: db, agent, envelope: {}, evidenceItems: [evidence] }),
      jobEvidence: () => persistAgentJobEvidenceBatch({ dbPool: db, agent, envelope: {}, jobId, claimId, evidenceItems: [evidence] }),
      logs: () => ingestAgentJobLogs({ dbPool: db, agent, jobId, body: { claimId, lines: [] } }),
    };
    for (const [name, call] of Object.entries(calls)) {
      await assert.rejects(call(), { code: "CERTOPS_AGENT_CREDENTIAL_STALE" }, name);
    }
    assert.equal(JSON.stringify(agent).includes(credential.credentialHash), false);
    await assert.rejects(lockCurrentAgentCredential(db, { id: agent.id }), { code: "CERTOPS_AGENT_CREDENTIAL_STALE" });
  });
  it("rejects an authenticated request retired before its transaction on every mutation path", async () => {
    const { agent, credential } = await fixture();
    const jobId = randomUUID(), claimId = randomUUID();
    await db.query("UPDATE certops_agents SET status = 'retired' WHERE id = $1", [agent.id]);
    // Normal retired agents still authenticate so route middleware can return 410.
    const retiredAuth = await validateAgentCredential({ client: db, rawCredential: credential.plaintextCredential });
    assert.equal(retiredAuth.valid, true);
    assert.equal(retiredAuth.agent.status, "retired");
    const evidence = { evidenceId: randomUUID(), eventType: "certificate.observed", observedAt: new Date().toISOString(),
      fingerprintSha256: "a".repeat(64), metadata: [{ name: "filePath", value: "/test/certificate.pem" }, { name: "targetHost", value: "test.example" }] };
    const calls = {
      heartbeat: () => recordHeartbeat({ dbPool: db, agent, envelope: {}, body: {} }),
      claim: () => claimJobs({ dbPool: db, agent, envelope: {}, body: {} }),
      lease: () => renewJobLease({ dbPool: db, agent, envelope: {}, jobId, claimId }),
      result: () => ingestResult({ dbPool: db, agent, envelope: {}, body: { jobId, claimId, status: "succeeded" } }),
      discoveryEvidence: () => persistAgentDiscoveryEvidenceBatch({ dbPool: db, agent, envelope: {}, evidenceItems: [evidence] }),
      jobEvidence: () => persistAgentJobEvidenceBatch({ dbPool: db, agent, envelope: {}, jobId, claimId, evidenceItems: [evidence] }),
      logs: () => ingestAgentJobLogs({ dbPool: db, agent, jobId, body: { claimId, lines: [] } }),
    };
    for (const [name, call] of Object.entries(calls)) {
      await assert.rejects(call(), { code: "CERTOPS_AGENT_RETIRED" }, name);
    }
  });

  it("replays only the current credential and rejects retirement or replacement", async () => {
    const previousKey = process.env.CERTOPS_REGISTRATION_ENCRYPTION_KEY;
    process.env.CERTOPS_REGISTRATION_ENCRYPTION_KEY = "a".repeat(64);
    try {
      const { agent, credential } = await fixture();
      const bootstrapId = randomUUID(), registrationId = randomUUID();
      await db.query("INSERT INTO certops_agent_bootstrap_tokens VALUES ($1, 'used', $2)", [bootstrapId, agent.workspaceId]);
      await db.query(`INSERT INTO certops_agent_registration_replays VALUES ($1, $2, $3, $4, 1, '1.0.0', NULL, NULL, now() + interval '1 hour')`,
        [bootstrapId, registrationId, agent.agentId, encryptRegistrationCredential(credential.plaintextCredential)]);
      const replay = () => registerAgent({ dbPool: db, bootstrapToken: { id: bootstrapId }, envelope: {}, body: { registrationId } });
      assert.equal((await replay()).credential, credential.plaintextCredential);
      const retiring = await db.connect();
      try {
        await retiring.query("BEGIN");
        await retiring.query("UPDATE certops_agents SET status = 'retired' WHERE id = $1", [agent.id]);
        const pending = replay().then(() => null, error => error);
        let blocked = false;
        for (let i = 0; i < 50 && !blocked; i++) {
          const waiting = await db.query(`SELECT count(*) AS count FROM pg_stat_activity
            WHERE datname = current_database() AND wait_event_type = 'Lock'
              AND query LIKE '%SELECT credential_hash, status%'`);
          blocked = Number(waiting.rows[0].count) > 0;
          if (!blocked) await new Promise(resolve => setTimeout(resolve, 20));
        }
        assert.equal(blocked, true, "replay must wait for retirement to commit");
        await retiring.query("COMMIT");
        assert.equal((await pending)?.code, "CERTOPS_AGENT_REGISTRATION_UNAUTHORIZED");
      } finally {
        try { await retiring.query("ROLLBACK"); } catch (_) {}
        retiring.release();
      }
      await db.query("UPDATE certops_agents SET status = 'retired' WHERE id = $1", [agent.id]);
      await assert.rejects(replay(), { code: "CERTOPS_AGENT_REGISTRATION_UNAUTHORIZED" });
      await db.query("UPDATE certops_agents SET status = 'active' WHERE id = $1", [agent.id]);
      const rotating = await db.connect();
      try {
        await rotating.query("BEGIN");
        await rotating.query("UPDATE certops_agents SET credential_hash = $2 WHERE id = $1", [agent.id, "f".repeat(64)]);
        const pending = replay().then(() => null, error => error);
        let blocked = false;
        for (let i = 0; i < 50 && !blocked; i++) {
          const waiting = await db.query(`SELECT count(*) AS count FROM pg_stat_activity
            WHERE datname = current_database() AND wait_event_type = 'Lock'
              AND query LIKE '%SELECT credential_hash, status%'`);
          blocked = Number(waiting.rows[0].count) > 0;
          if (!blocked) await new Promise(resolve => setTimeout(resolve, 20));
        }
        assert.equal(blocked, true, "replay must wait for replacement to commit");
        await rotating.query("COMMIT");
        assert.equal((await pending)?.code, "CERTOPS_AGENT_REGISTRATION_UNAUTHORIZED");
      } finally {
        try { await rotating.query("ROLLBACK"); } catch (_) {}
        rotating.release();
      }
      await assert.rejects(replay(), { code: "CERTOPS_AGENT_REGISTRATION_UNAUTHORIZED" });
    } finally {
      if (previousKey === undefined) delete process.env.CERTOPS_REGISTRATION_ENCRYPTION_KEY;
      else process.env.CERTOPS_REGISTRATION_ENCRYPTION_KEY = previousKey;
    }
  });

});

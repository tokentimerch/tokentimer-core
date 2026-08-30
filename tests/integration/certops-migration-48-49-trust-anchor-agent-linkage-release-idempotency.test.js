/**
 * CertOps migrations 48 (certops_trust_anchor_installation_agent_linkage)
 * and 49 (certops_trust_reference_release_idempotency) - real-apply and
 * idempotency check against a real Postgres instance.
 *
 * Unlike tests/unit/certops-migration.test.js (which only pattern-matches the
 * migration SQL text), this test creates a fresh database, applies every
 * migration THROUGH version 47 only (a real pre-migration-48 snapshot), then
 * applies 48 and 49 and confirms: (a) migration 48's emptiness guard is a
 * real, enforced precondition rather than an assumption, (b) the new
 * agent_id linkage and generation/error/reconcile columns behave exactly as
 * their own comments claim on real inserts, (c) migration 49's idempotency
 * ledger table and its constraints hold on real rows, and (d) re-running
 * migration 49's raw SQL a second time (simulating an operator re-applying
 * it, not migrate.js's own already-executed-versions skip) is a genuine
 * no-op, not just "doesn't update the ledger twice."
 *
 * Migration 48 is intentionally NOT re-run a second time once real rows
 * exist: its own guard (see the "must be empty" DO block in the migration
 * SQL) is designed to reject a second real-apply once the table it locks
 * down is no longer empty. That guard is tested directly below instead of
 * asserting a false idempotency claim for 48.
 */

const { expect } = require("chai");
const { Client, Pool } = require("pg");
const path = require("path");

const DB_HOST = process.env.DB_HOST || "localhost";
const DB_PORT = Number(process.env.DB_PORT || process.env.TT_TEST_DB_PORT || 5432);
const DB_USER = process.env.DB_USER || "tokentimer";
const DB_PASSWORD = process.env.DB_PASSWORD || "password";
const ADMIN_DB_NAME = process.env.DB_NAME || "tokentimer";
const FRESH_DB_NAME = "tokentimer_certops_48_49_trust_anchor_agent_linkage_test";

const { migrations } = require(
  path.join(__dirname, "..", "..", "apps", "api", "migrations", "migrate.js"),
);

const MIGRATION_48 = migrations.find((m) => m.version === 48);
const MIGRATION_49 = migrations.find((m) => m.version === 49);

const FINGERPRINT_A = "a".repeat(64);
const FINGERPRINT_B = "b".repeat(64);
const FAKE_PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";

async function adminClient() {
  const client = new Client({
    user: DB_USER,
    host: DB_HOST,
    database: ADMIN_DB_NAME,
    password: DB_PASSWORD,
    port: DB_PORT,
  });
  await client.connect();
  return client;
}

async function dropDatabase(name) {
  const admin = await adminClient();
  try {
    await admin.query(
      `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
      [name],
    );
    await admin.query(`DROP DATABASE IF EXISTS ${name}`);
  } finally {
    await admin.end();
  }
}

describe("CertOps migrations 48/49 - real pre-migration snapshot, real-apply linkage/idempotency-ledger, and raw-SQL idempotency", function () {
  this.timeout(180000);

  let pool;
  let workspaceId;
  let userId;
  let agentId;
  let secondAgentId;
  let trustAnchorId;
  let certificateJobId;
  let preExistingInstallationId;

  before(async function () {
    expect(MIGRATION_48, "migration 48 must exist in migrate.js's migrations array").to.not.equal(undefined);
    expect(MIGRATION_49, "migration 49 must exist in migrate.js's migrations array").to.not.equal(undefined);

    await dropDatabase(FRESH_DB_NAME);
    const admin = await adminClient();
    try {
      await admin.query(`CREATE DATABASE ${FRESH_DB_NAME}`);
    } finally {
      await admin.end();
    }

    pool = new Pool({
      user: DB_USER,
      host: DB_HOST,
      database: FRESH_DB_NAME,
      password: DB_PASSWORD,
      port: DB_PORT,
      max: 4,
    });

    // Real pre-migration-48 snapshot: apply every migration up through
    // version 47 only, so the tables 48/49 touch exist in exactly the shape
    // they had immediately before those two migrations were written.
    const preMigrations = migrations.filter((m) => m.version <= 47);
    const client = await pool.connect();
    try {
      for (const migration of preMigrations) {
        await client.query("BEGIN");
        try {
          await client.query(migration.sql);
          await client.query("COMMIT");
        } catch (err) {
          await client.query("ROLLBACK");
          throw new Error(
            `Pre-migration-48 snapshot: migration ${migration.version} (${migration.name}) failed: ${err.message}`,
          );
        }
      }
    } finally {
      client.release();
    }

    // Real pre-existing data, planted BEFORE 48/49 run. Deliberately does
    // NOT include a certops_trust_anchor_installations row: migration 48's
    // own precondition requires that table be empty, matching every real
    // deployment (no write path exists for it yet).
    const userResult = await pool.query(
      `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
       VALUES ('migration-48-49-test@example.com', 'migration-48-49-test@example.com', 'Migration 48-49 Test User', 'x', 'local', TRUE)
       RETURNING id`,
    );
    userId = userResult.rows[0].id;

    const wsResult = await pool.query(
      `INSERT INTO workspaces (id, name, created_by, plan)
       VALUES (gen_random_uuid(), 'Migration 48-49 Test WS', $1, 'pro')
       RETURNING id`,
      [userId],
    );
    workspaceId = wsResult.rows[0].id;

    const bootstrapResult = await pool.query(
      `INSERT INTO certops_agent_bootstrap_tokens
         (workspace_id, name, token_prefix, token_hash, expires_at)
       VALUES ($1, 'pre-migration bootstrap token', 'ttboot_0000000000000001', repeat('a', 64), NOW() + INTERVAL '7 days')
       RETURNING id`,
      [workspaceId],
    );
    const bootstrapTokenId = bootstrapResult.rows[0].id;

    const agentResult = await pool.query(
      `INSERT INTO certops_agents
         (workspace_id, agent_id, agent_version, protocol_version, credential_prefix, credential_hash, bootstrap_token_id)
       VALUES ($1, 'pre-migration-agent-48-49-a', '1.0.0', '1.0.0', 'ttagent_0000000000000001', repeat('c', 64), $2)
       RETURNING id`,
      [workspaceId, bootstrapTokenId],
    );
    agentId = agentResult.rows[0].id;

    const secondAgentResult = await pool.query(
      `INSERT INTO certops_agents
         (workspace_id, agent_id, agent_version, protocol_version, credential_prefix, credential_hash, bootstrap_token_id)
       VALUES ($1, 'pre-migration-agent-48-49-b', '1.0.0', '1.0.0', 'ttagent_0000000000000002', repeat('d', 64), $2)
       RETURNING id`,
      [workspaceId, bootstrapTokenId],
    );
    secondAgentId = secondAgentResult.rows[0].id;

    const jobResult = await pool.query(
      `INSERT INTO certificate_jobs (workspace_id, operation, status, source)
       VALUES ($1, 'deploy', 'succeeded', 'system')
       RETURNING id`,
      [workspaceId],
    );
    certificateJobId = jobResult.rows[0].id;

    const anchorResult = await pool.query(
      `INSERT INTO certops_trust_anchors (workspace_id, name, pem, anchor_type, fingerprint_sha256)
       VALUES ($1, 'Migration 48-49 Test Anchor', $2, 'root', $3)
       RETURNING id`,
      [workspaceId, FAKE_PEM, FINGERPRINT_A],
    );
    trustAnchorId = anchorResult.rows[0].id;
  });

  after(async function () {
    if (pool) await pool.end();
    await dropDatabase(FRESH_DB_NAME);
  });

  it("applies migration 48 cleanly against the real empty installations table with no error", async function () {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(MIGRATION_48.sql);
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  });

  it("re-running migration 48's raw SQL a second time while the table is still empty is a genuine no-op", async function () {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(MIGRATION_48.sql);
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw new Error(`Re-running migration 48's raw SQL while the table is empty must be a no-op, but it threw: ${err.message}`);
    } finally {
      client.release();
    }
  });

  it("accepts a real installation insert anchored on agent_id, defaulting transition_generation to 1", async () => {
    const { rows } = await pool.query(
      `INSERT INTO certops_trust_anchor_installations
         (workspace_id, trust_anchor_id, agent_id, host, store, fingerprint_sha256, owner, provenance)
       VALUES ($1, $2, $3, 'migtest-host-01', 'ROOT', $4, 'migtest-owner', 'tokentimer_installed')
       RETURNING id, transition_generation, last_job_id, last_error, next_reconcile_at`,
      [workspaceId, trustAnchorId, agentId, FINGERPRINT_A],
    );
    expect(rows).to.have.length(1);
    expect(rows[0].transition_generation).to.equal(1);
    expect(rows[0].last_job_id).to.equal(null);
    expect(rows[0].last_error).to.equal(null);
    expect(rows[0].next_reconcile_at).to.equal(null);
    preExistingInstallationId = rows[0].id;
  });

  it("rejects a real installation insert with no agent_id (NOT NULL enforced)", async () => {
    let error = null;
    try {
      await pool.query(
        `INSERT INTO certops_trust_anchor_installations
           (workspace_id, trust_anchor_id, host, store, fingerprint_sha256, owner, provenance)
         VALUES ($1, $2, 'migtest-host-02', 'ROOT', $3, 'migtest-owner-2', 'tokentimer_installed')`,
        [workspaceId, trustAnchorId, FINGERPRINT_B],
      );
    } catch (err) {
      error = err;
    }
    expect(error).to.not.equal(null);
    expect(String(error.message)).to.match(/null value in column "agent_id"/i);
  });

  it("rejects a real installation insert referencing an agent_id from a different workspace (fk_certops_trust_anchor_installations_agent enforced)", async () => {
    const otherWsResult = await pool.query(
      `INSERT INTO workspaces (id, name, created_by, plan)
       VALUES (gen_random_uuid(), 'Migration 48-49 Other WS', $1, 'pro')
       RETURNING id`,
      [userId],
    );
    const otherWorkspaceId = otherWsResult.rows[0].id;

    // A trust anchor that DOES belong to the other workspace, so the only
    // mismatched reference below is agent_id -- isolating the agent FK
    // check from the pre-existing trust_anchor_id FK check.
    const otherAnchorResult = await pool.query(
      `INSERT INTO certops_trust_anchors (workspace_id, name, pem, anchor_type, fingerprint_sha256)
       VALUES ($1, 'Migration 48-49 Other WS Anchor', $2, 'root', $3)
       RETURNING id`,
      [otherWorkspaceId, FAKE_PEM, FINGERPRINT_B],
    );
    const otherAnchorId = otherAnchorResult.rows[0].id;

    let error = null;
    try {
      await pool.query(
        `INSERT INTO certops_trust_anchor_installations
           (workspace_id, trust_anchor_id, agent_id, host, store, fingerprint_sha256, owner, provenance)
         VALUES ($1, $2, $3, 'migtest-host-03', 'ROOT', $4, 'migtest-owner-3', 'tokentimer_installed')`,
        [otherWorkspaceId, otherAnchorId, agentId, FINGERPRINT_A],
      );
    } catch (err) {
      error = err;
    }
    expect(error).to.not.equal(null);
    expect(String(error.message)).to.match(/fk_certops_trust_anchor_installations_agent/i);
  });

  it("enforces the new (workspace_id, agent_id, store, fingerprint, owner) uniqueness tuple, replacing migration 43's host-based tuple", async () => {
    // Same agent/store/fingerprint/owner as the row already planted above,
    // but a different host: migration 43's (host, store, fingerprint,
    // owner) tuple would have allowed this; migration 48's
    // (agent_id, store, fingerprint, owner) tuple must reject it.
    let error = null;
    try {
      await pool.query(
        `INSERT INTO certops_trust_anchor_installations
           (workspace_id, trust_anchor_id, agent_id, host, store, fingerprint_sha256, owner, provenance)
         VALUES ($1, $2, $3, 'migtest-host-01-different', 'ROOT', $4, 'migtest-owner', 'tokentimer_installed')`,
        [workspaceId, trustAnchorId, agentId, FINGERPRINT_A],
      );
    } catch (err) {
      error = err;
    }
    expect(error).to.not.equal(null);
    expect(String(error.message)).to.match(/uq_certops_trust_anchor_installations_identity/i);
  });

  it("accepts the same store/fingerprint/owner tuple under a different agent_id (agent is now part of the identity)", async () => {
    const { rows } = await pool.query(
      `INSERT INTO certops_trust_anchor_installations
         (workspace_id, trust_anchor_id, agent_id, host, store, fingerprint_sha256, owner, provenance)
       VALUES ($1, $2, $3, 'migtest-host-04', 'ROOT', $4, 'migtest-owner', 'tokentimer_installed')
       RETURNING id`,
      [workspaceId, trustAnchorId, secondAgentId, FINGERPRINT_A],
    );
    expect(rows).to.have.length(1);
  });

  it("accepts a real last_job_id linkage to certificate_jobs and rejects a last_error over the documented 128-char cap", async () => {
    const { rows } = await pool.query(
      `UPDATE certops_trust_anchor_installations
          SET last_job_id = $2, last_attempt_at = NOW()
        WHERE id = $1
        RETURNING last_job_id`,
      [preExistingInstallationId, certificateJobId],
    );
    expect(rows[0].last_job_id).to.equal(certificateJobId);

    let error = null;
    try {
      await pool.query(
        `UPDATE certops_trust_anchor_installations SET last_error = $2 WHERE id = $1`,
        [preExistingInstallationId, "x".repeat(129)],
      );
    } catch (err) {
      error = err;
    }
    expect(error).to.not.equal(null);
    expect(String(error.message)).to.match(/certops_trust_anchor_installations_last_error_check/i);
  });

  it("re-running migration 48's raw SQL now that real rows exist correctly raises the documented emptiness guard instead of silently touching NOT NULL data", async () => {
    let error = null;
    try {
      await pool.query(MIGRATION_48.sql);
    } catch (err) {
      error = err;
    }
    expect(error).to.not.equal(null);
    expect(String(error.message)).to.match(
      /certops_trust_anchor_installations must be empty before agent_id can be added NOT NULL/i,
    );
  });

  it("applies migration 49 cleanly with no error", async function () {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(MIGRATION_49.sql);
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  });

  it("creates certops_trust_reference_release_idempotency and accepts a real revoke-trust idempotency record", async () => {
    const { rows } = await pool.query(
      `INSERT INTO certops_trust_reference_release_idempotency
         (workspace_id, trust_anchor_id, agent_id, store, owner, operation, idempotency_key, installation_snapshot)
       VALUES ($1, $2, $3, 'ROOT', 'migtest-owner', 'revoke-trust', 'migtest-idem-key-1', $4::jsonb)
       RETURNING id, operation, installation_snapshot`,
      [workspaceId, trustAnchorId, agentId, JSON.stringify({ id: preExistingInstallationId, transitionState: "removed" })],
    );
    expect(rows).to.have.length(1);
    expect(rows[0].operation).to.equal("revoke-trust");
    expect(rows[0].installation_snapshot).to.deep.equal({ id: preExistingInstallationId, transitionState: "removed" });
  });

  it("rejects an operation value outside the documented enum", async () => {
    let error = null;
    try {
      await pool.query(
        `INSERT INTO certops_trust_reference_release_idempotency
           (workspace_id, trust_anchor_id, agent_id, store, owner, operation, idempotency_key, installation_snapshot)
         VALUES ($1, $2, $3, 'ROOT', 'migtest-owner', 'not-a-real-operation', 'migtest-idem-key-bad-op', '{}'::jsonb)`,
        [workspaceId, trustAnchorId, agentId],
      );
    } catch (err) {
      error = err;
    }
    expect(error).to.not.equal(null);
    expect(String(error.message)).to.match(/certops_trust_reference_release_idempotency_operation_check/i);
  });

  it("enforces one outcome per (workspace_id, idempotency_key)", async () => {
    let error = null;
    try {
      await pool.query(
        `INSERT INTO certops_trust_reference_release_idempotency
           (workspace_id, trust_anchor_id, agent_id, store, owner, operation, idempotency_key, installation_snapshot)
         VALUES ($1, $2, $3, 'ROOT', 'migtest-owner', 'distribute-trust', 'migtest-idem-key-1', '{}'::jsonb)`,
        [workspaceId, trustAnchorId, agentId],
      );
    } catch (err) {
      error = err;
    }
    expect(error).to.not.equal(null);
    expect(String(error.message)).to.match(/uq_certops_trust_reference_release_idempotency_key/i);
  });

  it("re-running migration 49's raw SQL a second time is a genuine no-op (real CREATE TABLE/INDEX IF NOT EXISTS idempotency)", async () => {
    const before = await pool.query(
      `SELECT id, operation, idempotency_key, installation_snapshot
         FROM certops_trust_reference_release_idempotency
        WHERE idempotency_key = 'migtest-idem-key-1'`,
    );
    expect(before.rows).to.have.length(1);

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(MIGRATION_49.sql);
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw new Error(`Re-running migration 49's raw SQL a second time must be a no-op, but it threw: ${err.message}`);
    } finally {
      client.release();
    }

    const after = await pool.query(
      `SELECT id, operation, idempotency_key, installation_snapshot
         FROM certops_trust_reference_release_idempotency
        WHERE idempotency_key = 'migtest-idem-key-1'`,
    );
    expect(after.rows).to.deep.equal(before.rows);

    // The unique index itself must also survive a second
    // CREATE UNIQUE INDEX IF NOT EXISTS cycle unchanged, not silently
    // vanish -- re-check the negative case from above still fails.
    let error = null;
    try {
      await pool.query(
        `INSERT INTO certops_trust_reference_release_idempotency
           (workspace_id, trust_anchor_id, agent_id, store, owner, operation, idempotency_key, installation_snapshot)
         VALUES ($1, $2, $3, 'ROOT', 'migtest-owner', 'distribute-trust', 'migtest-idem-key-1', '{}'::jsonb)`,
        [workspaceId, trustAnchorId, agentId],
      );
    } catch (err_) {
      error = err_;
    }
    expect(error).to.not.equal(null);
    expect(String(error.message)).to.match(/uq_certops_trust_reference_release_idempotency_key/i);
  });
});
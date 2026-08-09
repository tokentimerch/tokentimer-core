/**
 * CertOps migrations 45 (certops_agent_observation_locality_and_downtime_alerts)
 * and 46 (alert_queue_agent_health_anchor) - real-apply and idempotency check
 * against a real Postgres instance.
 *
 * Unlike tests/unit/certops-migration.test.js (which only pattern-matches the
 * migration SQL text), this test creates a fresh database, applies every
 * migration THROUGH version 44 only (a real pre-migration-45 snapshot), plants
 * real rows on the tables migrations 45/46 alter, then applies 45 and 46 and
 * confirms: (a) every pre-existing row gets the documented backfill default
 * rather than an error or a NULL where a NOT NULL default was promised, (b)
 * every new CHECK constraint accepts the values the migration's own comments
 * claim it should, and (c) re-running the raw migration SQL a second time
 * (simulating an operator re-applying it, not migrate.js's own
 * already-executed-versions skip) is a genuine no-op, not just "doesn't
 * update the ledger twice."
 */

const { expect } = require("chai");
const { Client, Pool } = require("pg");
const path = require("path");

const DB_HOST = process.env.DB_HOST || "localhost";
const DB_PORT = Number(process.env.DB_PORT || process.env.TT_TEST_DB_PORT || 5432);
const DB_USER = process.env.DB_USER || "tokentimer";
const DB_PASSWORD = process.env.DB_PASSWORD || "password";
const ADMIN_DB_NAME = process.env.DB_NAME || "tokentimer";
const FRESH_DB_NAME = "tokentimer_certops_45_46_agent_obs_downtime_alerts_test";

const { migrations } = require(
  path.join(__dirname, "..", "..", "apps", "api", "migrations", "migrate.js"),
);

const MIGRATION_45 = migrations.find((m) => m.version === 45);
const MIGRATION_46 = migrations.find((m) => m.version === 46);

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

describe("CertOps migrations 45/46 - real pre-migration snapshot, real-apply backfill, and raw-SQL idempotency", function () {
  this.timeout(180000);

  let pool;
  let workspaceId;
  let userId;
  let preExistingAgentId;
  let preExistingBootstrapTokenId;
  let preExistingTokenRowId;
  let preExistingAlertQueueId;

  before(async function () {
    expect(MIGRATION_45, "migration 45 must exist in migrate.js's migrations array").to.not.equal(undefined);
    expect(MIGRATION_46, "migration 46 must exist in migrate.js's migrations array").to.not.equal(undefined);

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

    // Real pre-migration-45 snapshot: apply every migration up through
    // version 44 only, so the tables 45/46 alter exist in exactly the shape
    // they had immediately before those two migrations were written.
    const preMigrations = migrations.filter((m) => m.version <= 44);
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
            `Pre-migration-45 snapshot: migration ${migration.version} (${migration.name}) failed: ${err.message}`,
          );
        }
      }
    } finally {
      client.release();
    }

    // Real pre-existing data, planted BEFORE 45/46 run, so the backfill
    // behavior is exercised against genuine rows rather than inferred.
    const userResult = await pool.query(
      `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
       VALUES ('migration-45-46-test@example.com', 'migration-45-46-test@example.com', 'Migration 45-46 Test User', 'x', 'local', TRUE)
       RETURNING id`,
    );
    userId = userResult.rows[0].id;

    const wsResult = await pool.query(
      `INSERT INTO workspaces (id, name, created_by, plan)
       VALUES (gen_random_uuid(), 'Migration 45-46 Test WS', $1, 'pro')
       RETURNING id`,
      [userId],
    );
    workspaceId = wsResult.rows[0].id;

    const bootstrapResult = await pool.query(
      `INSERT INTO certops_agent_bootstrap_tokens
         (workspace_id, name, token_prefix, token_hash, expires_at)
       VALUES ($1, 'pre-migration bootstrap token', 'ttboot_0000000000000000', repeat('a', 64), NOW() + INTERVAL '7 days')
       RETURNING id`,
      [workspaceId],
    );
    preExistingBootstrapTokenId = bootstrapResult.rows[0].id;

    const agentResult = await pool.query(
      `INSERT INTO certops_agents
         (workspace_id, agent_id, agent_version, protocol_version, credential_prefix, credential_hash, bootstrap_token_id)
       VALUES ($1, 'pre-migration-agent-01', '1.0.0', '1.0.0', 'ttagent_0000000000000000', repeat('b', 64), $2)
       RETURNING id`,
      [workspaceId, preExistingBootstrapTokenId],
    );
    preExistingAgentId = agentResult.rows[0].id;

    const tokenResult = await pool.query(
      `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type)
       VALUES ($1, $2, $1, 'pre-migration cert token', CURRENT_DATE + 90, 'ssl_cert')
       RETURNING id`,
      [userId, workspaceId],
    );
    preExistingTokenRowId = tokenResult.rows[0].id;

    const alertResult = await pool.query(
      `INSERT INTO alert_queue (user_id, token_id, alert_key, threshold_days, due_date)
       VALUES ($1, $2, 'migtest-pre-migration-alert-key', 30, CURRENT_DATE + 30)
       RETURNING id`,
      [userId, preExistingTokenRowId],
    );
    preExistingAlertQueueId = alertResult.rows[0].id;
  });

  after(async function () {
    if (pool) await pool.end();
    await dropDatabase(FRESH_DB_NAME);
  });

  it("applies migration 45 cleanly against the real pre-existing rows with no error", async function () {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(MIGRATION_45.sql);
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  });

  it("backfills certops_agents.downtime_alerts_enabled to TRUE and contact_group_id to NULL on the real pre-existing agent row", async () => {
    const { rows } = await pool.query(
      `SELECT downtime_alerts_enabled, contact_group_id FROM certops_agents WHERE id = $1`,
      [preExistingAgentId],
    );
    expect(rows).to.have.length(1);
    expect(rows[0].downtime_alerts_enabled).to.equal(true);
    expect(rows[0].contact_group_id).to.equal(null);
  });

  it("leaves certops_agent_bootstrap_tokens.downtime_alerts_enabled/contact_group_id NULL (not TRUE) on the real pre-existing token row", async () => {
    const { rows } = await pool.query(
      `SELECT downtime_alerts_enabled, contact_group_id FROM certops_agent_bootstrap_tokens WHERE id = $1`,
      [preExistingBootstrapTokenId],
    );
    expect(rows).to.have.length(1);
    expect(rows[0].downtime_alerts_enabled).to.equal(null);
    expect(rows[0].contact_group_id).to.equal(null);
  });

  it("accepts 'agent_windows' as a managed_certificates/certificate_targets/certificate_instances source, and location_kind on real target/instance inserts", async () => {
    const mcResult = await pool.query(
      `INSERT INTO managed_certificates (workspace_id, common_name, source)
       VALUES ($1, 'migtest-agent-windows.example', 'agent_windows')
       RETURNING id`,
      [workspaceId],
    );
    const managedCertificateId = mcResult.rows[0].id;

    const targetResult = await pool.query(
      `INSERT INTO certificate_targets (workspace_id, name, target_type, source, location_kind)
       VALUES ($1, 'migtest-windows-store-target', 'windows-iis', 'agent_windows', 'windows_store')
       RETURNING id, location_kind`,
      [workspaceId],
    );
    expect(targetResult.rows[0].location_kind).to.equal("windows_store");
    const targetId = targetResult.rows[0].id;

    const instanceResult = await pool.query(
      `INSERT INTO certificate_instances (workspace_id, managed_certificate_id, target_id, source, location_kind)
       VALUES ($1, $2, $3, 'agent_windows', 'iis_binding')
       RETURNING location_kind`,
      [workspaceId, managedCertificateId, targetId],
    );
    expect(instanceResult.rows[0].location_kind).to.equal("iis_binding");
  });

  it("rejects a location_kind value outside the documented enum", async () => {
    let error = null;
    try {
      await pool.query(
        `INSERT INTO certificate_targets (workspace_id, name, target_type, location_kind)
         VALUES ($1, 'migtest-bad-location-kind', 'endpoint', 'not_a_real_kind')`,
        [workspaceId],
      );
    } catch (err) {
      error = err;
    }
    expect(error).to.not.equal(null);
    expect(String(error.message)).to.match(/certificate_targets_location_kind_check/i);
  });

  it("leaves location_kind NULL by default on a pre-existing-shaped (non-agent_windows) target insert", async () => {
    const { rows } = await pool.query(
      `INSERT INTO certificate_targets (workspace_id, name, target_type)
       VALUES ($1, 'migtest-endpoint-target', 'endpoint')
       RETURNING location_kind`,
      [workspaceId],
    );
    expect(rows[0].location_kind).to.equal(null);
  });

  it("applies migration 46 cleanly on top of 45 against the real pre-existing alert_queue row with no error", async function () {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(MIGRATION_46.sql);
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  });

  it("leaves the real pre-existing alert_queue row's token_id populated and certops_agent_id/metadata correctly defaulted", async () => {
    const { rows } = await pool.query(
      `SELECT token_id, certops_agent_id, metadata FROM alert_queue WHERE id = $1`,
      [preExistingAlertQueueId],
    );
    expect(rows).to.have.length(1);
    expect(rows[0].token_id).to.equal(preExistingTokenRowId);
    expect(rows[0].certops_agent_id).to.equal(null);
    expect(rows[0].metadata).to.deep.equal({});
  });

  it("accepts a real alert_queue insert anchored on certops_agent_id alone (token_id NULL), which was impossible before migration 46", async () => {
    const { rows } = await pool.query(
      `INSERT INTO alert_queue (user_id, certops_agent_id, alert_key, threshold_days, due_date)
       VALUES ($1, $2, 'migtest-agent-health-down-alert-key', 0, CURRENT_DATE)
       RETURNING token_id, certops_agent_id`,
      [userId, preExistingAgentId],
    );
    expect(rows[0].token_id).to.equal(null);
    expect(rows[0].certops_agent_id).to.equal(preExistingAgentId);
  });

  it("rejects a real alert_queue insert with neither token_id nor certops_agent_id set (anchor_check enforced)", async () => {
    let error = null;
    try {
      await pool.query(
        `INSERT INTO alert_queue (user_id, alert_key, threshold_days, due_date)
         VALUES ($1, 'migtest-no-anchor-alert-key', 0, CURRENT_DATE)`,
        [userId],
      );
    } catch (err) {
      error = err;
    }
    expect(error).to.not.equal(null);
    expect(String(error.message)).to.match(/alert_queue_anchor_check/i);
  });

  it("re-running migration 45's raw SQL a second time is a genuine no-op (real ADD COLUMN IF NOT EXISTS/CREATE INDEX IF NOT EXISTS idempotency, not just migrate.js's version-ledger skip)", async () => {
    const before = await pool.query(
      `SELECT downtime_alerts_enabled, contact_group_id FROM certops_agents WHERE id = $1`,
      [preExistingAgentId],
    );
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(MIGRATION_45.sql);
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw new Error(`Re-running migration 45's raw SQL a second time must be a no-op, but it threw: ${err.message}`);
    } finally {
      client.release();
    }
    const after = await pool.query(
      `SELECT downtime_alerts_enabled, contact_group_id FROM certops_agents WHERE id = $1`,
      [preExistingAgentId],
    );
    expect(after.rows[0]).to.deep.equal(before.rows[0]);
  });

  it("re-running migration 46's raw SQL a second time is a genuine no-op", async () => {
    const before = await pool.query(
      `SELECT token_id, certops_agent_id, metadata FROM alert_queue WHERE id = $1`,
      [preExistingAlertQueueId],
    );
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(MIGRATION_46.sql);
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw new Error(`Re-running migration 46's raw SQL a second time must be a no-op, but it threw: ${err.message}`);
    } finally {
      client.release();
    }
    const after = await pool.query(
      `SELECT token_id, certops_agent_id, metadata FROM alert_queue WHERE id = $1`,
      [preExistingAlertQueueId],
    );
    expect(after.rows[0]).to.deep.equal(before.rows[0]);
    // The anchor_check constraint itself must also survive a second
    // DROP CONSTRAINT IF EXISTS/ADD CONSTRAINT cycle unchanged, not silently
    // widen or vanish -- re-check the negative case from above still fails.
    let error = null;
    try {
      await pool.query(
        `INSERT INTO alert_queue (user_id, alert_key, threshold_days, due_date)
         VALUES ($1, 'migtest-no-anchor-alert-key-2', 0, CURRENT_DATE)`,
        [userId],
      );
    } catch (err_) {
      error = err_;
    }
    expect(error).to.not.equal(null);
    expect(String(error.message)).to.match(/alert_queue_anchor_check/i);
  });
});

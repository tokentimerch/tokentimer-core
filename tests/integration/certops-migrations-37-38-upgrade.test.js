/**
 * CertOps migrations 37-38 (domain_monitors URL dedup, cross-source monitor
 * dedup) - upgrade path test on a populated, MESSY database.
 *
 * Unlike a fresh-install test (which only proves migrations apply to an
 * empty schema) or an upgrade test seeded with clean, non-conflicting rows
 * (which only proves ordinary data survives), this seeds the exact
 * *colliding* legacy shapes migrations 37 and 38 exist to clean up:
 *   - two domain_monitors rows for the same (workspace_id, url)
 *   - two managed_certificates rows (one per monitor source) for the same
 *     domain_monitor_id, where the keeper already has its own
 *     certificate_instances row that shares (target_id,
 *     observed_fingerprint_sha256) with a loser's row - both sources
 *     observed the same real certificate on the same target, so those rows
 *     already collide on today's unique index *before* the migration
 *     touches them.
 *
 * v0.11.2 shipped migration 38 without handling that last case: its dedup
 * pass only scanned losers' own instances, missed the keeper's pre-existing
 * one, and the later UPDATE that re-points loser rows onto the keeper hit
 * uq_certificate_instances_target_cert_fingerprint - a data-dependent
 * failure invisible on an empty DB or on non-colliding seed data, which is
 * exactly why it shipped undetected and then broke a real deployment on
 * upgrade. Any future migration that merges or dedupes pre-existing rows
 * should get a test like this one (see release-tokentimer-core skill).
 */

const { expect } = require("chai");
const { Client, Pool } = require("pg");
const crypto = require("crypto");
const path = require("path");

const DB_HOST = process.env.DB_HOST || "localhost";
const DB_PORT = Number(process.env.DB_PORT || process.env.TT_TEST_DB_PORT || 5432);
const DB_USER = process.env.DB_USER || "tokentimer";
const DB_PASSWORD = process.env.DB_PASSWORD || "password";
const ADMIN_DB_NAME = process.env.DB_NAME || "tokentimer";
const UPGRADE_DB_NAME = "tokentimer_certops_37_38_upgrade_test";

const { migrations } = require(
  path.join(__dirname, "..", "..", "apps", "api", "migrations", "migrate.js"),
);

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

async function applyMigrations(client, list) {
  for (const migration of list) {
    await client.query("BEGIN");
    try {
      await client.query(migration.sql);
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw new Error(
        `Migration ${migration.version} (${migration.name}) failed: ${err.message}`,
      );
    }
  }
}

describe("CertOps migrations 37-38 - upgrade path on a populated, colliding database", function () {
  this.timeout(120000);

  let pool;
  let workspaceId;
  let duplicateMonitorUrl;
  let keeperMonitorId;
  let loserMonitorId;
  let keeperCertId;
  let loserCertId;
  let keeperInstanceId;
  let loserCollidingInstanceId;
  let loserRepointInstanceId;

  before(async function () {
    await dropDatabase(UPGRADE_DB_NAME);
    const admin = await adminClient();
    try {
      await admin.query(`CREATE DATABASE ${UPGRADE_DB_NAME}`);
    } finally {
      await admin.end();
    }

    pool = new Pool({
      user: DB_USER,
      host: DB_HOST,
      database: UPGRADE_DB_NAME,
      password: DB_PASSWORD,
      port: DB_PORT,
      max: 4,
    });

    const client = await pool.connect();
    try {
      const pre37 = migrations.filter((m) => m.version <= 36);
      const dedupBatch = migrations.filter((m) => m.version >= 37 && m.version <= 38);
      expect(pre37.length).to.be.greaterThan(0);
      expect(dedupBatch.length).to.equal(2);

      await applyMigrations(client, pre37);

      const userResult = await client.query(
        `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
         VALUES ('upgrade-37-38-test@example.com', 'upgrade-37-38-test@example.com', 'Upgrade 37-38 Test User', 'x', 'local', TRUE)
         RETURNING id`,
      );
      const userId = userResult.rows[0].id;

      const ws = await client.query(
        `INSERT INTO workspaces (id, name, created_by, plan)
         VALUES (gen_random_uuid(), 'Upgrade 37-38 Test WS', $1, 'oss')
         RETURNING id`,
        [userId],
      );
      workspaceId = ws.rows[0].id;

      // --- Legacy shape for migration 37: two domain_monitors rows for the
      // same (workspace_id, url), predating the single-add endpoint's
      // reuse-existing-monitor fix.
      duplicateMonitorUrl = "https://cross-source-dedup.example.com";
      const olderMonitor = await client.query(
        `INSERT INTO domain_monitors (workspace_id, url, created_by, created_at, updated_at)
         VALUES ($1, $2, $3, NOW() - INTERVAL '2 days', NOW() - INTERVAL '2 days')
         RETURNING id`,
        [workspaceId, duplicateMonitorUrl, userId],
      );
      loserMonitorId = olderMonitor.rows[0].id;
      const newerMonitor = await client.query(
        `INSERT INTO domain_monitors (workspace_id, url, created_by, created_at, updated_at)
         VALUES ($1, $2, $3, NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day')
         RETURNING id`,
        [workspaceId, duplicateMonitorUrl, userId],
      );
      keeperMonitorId = newerMonitor.rows[0].id;

      // --- Legacy shape for migration 38: Domain Checker discovered the
      // host under the OLDER (loser) domain_monitors row; Endpoint Monitor
      // was toggled on later, minting its own managed_certificates row tied
      // to the NEWER (keeper) domain_monitors row - both point at the same
      // real host once 37 merges the monitors.
      loserCertId = crypto.randomUUID();
      keeperCertId = crypto.randomUUID();
      await client.query(
        `INSERT INTO managed_certificates (id, workspace_id, source, updated_at)
         VALUES
           ($1, $3, 'domain_checker',   NOW() - INTERVAL '1 day'),
           ($2, $3, 'endpoint_monitor', NOW())`,
        [loserCertId, keeperCertId, workspaceId],
      );

      const target = await client.query(
        `INSERT INTO certificate_targets
           (workspace_id, domain_monitor_id, name, target_type, source)
         VALUES ($1, $2, 'Cross-source dedup target', 'endpoint', 'endpoint_monitor')
         RETURNING id`,
        [workspaceId, keeperMonitorId],
      );
      const targetId = target.rows[0].id;

      // keeperInstance and loserCollidingInstance already agree on (target,
      // fingerprint) - the same live certificate observed by both sources -
      // so they collide under today's schema before migration 38 ever runs.
      // loserRepointInstance has a distinct fingerprint and must simply be
      // re-pointed onto the keeper, not dropped.
      keeperInstanceId = crypto.randomUUID();
      loserCollidingInstanceId = crypto.randomUUID();
      loserRepointInstanceId = crypto.randomUUID();
      await client.query(
        `INSERT INTO certificate_instances
           (id, workspace_id, managed_certificate_id, target_id,
            domain_monitor_id, observed_fingerprint_sha256, updated_at)
         VALUES
           ($1, $4, $7, $5, $6, 'deadbeef', NOW()),
           ($2, $4, $8, $5, $6, 'deadbeef', NOW() - INTERVAL '1 day'),
           ($3, $4, $8, $5, $6, 'cafefeed', NOW() - INTERVAL '1 day')`,
        [
          keeperInstanceId,
          loserCollidingInstanceId,
          loserRepointInstanceId,
          workspaceId,
          targetId,
          keeperMonitorId,
          keeperCertId,
          loserCertId,
        ],
      );

      // Now upgrade: apply 37-38 on top of this populated, colliding
      // database. Must not throw
      // uq_certificate_instances_target_cert_fingerprint.
      await applyMigrations(client, dedupBatch);
    } finally {
      client.release();
    }
  });

  after(async function () {
    if (pool) await pool.end();
    await dropDatabase(UPGRADE_DB_NAME);
  });

  it("merges the duplicate domain_monitors row for the same URL (migration 37)", async () => {
    const monitors = await pool.query(
      `SELECT id::text AS id FROM domain_monitors WHERE workspace_id = $1 AND url = $2`,
      [workspaceId, duplicateMonitorUrl],
    );
    expect(monitors.rows.map((row) => row.id)).to.deep.equal([keeperMonitorId]);
  });

  it("merges the cross-source managed_certificates row onto the keeper (migration 38)", async () => {
    const certs = await pool.query(
      `SELECT id::text AS id FROM managed_certificates WHERE id = ANY($1::uuid[])`,
      [[loserCertId, keeperCertId]],
    );
    expect(certs.rows.map((row) => row.id)).to.deep.equal([keeperCertId]);
  });

  it("drops the same-observation collision and re-points the non-colliding loser instance (migration 38)", async () => {
    const instances = await pool.query(
      `SELECT id::text AS id, managed_certificate_id::text AS managed_certificate_id
         FROM certificate_instances
        WHERE id = ANY($1::uuid[])`,
      [[keeperInstanceId, loserCollidingInstanceId, loserRepointInstanceId]],
    );
    const byId = new Map(
      instances.rows.map((row) => [row.id, row.managed_certificate_id]),
    );
    expect(byId.get(keeperInstanceId)).to.equal(keeperCertId);
    expect(byId.has(loserCollidingInstanceId)).to.equal(false);
    expect(byId.get(loserRepointInstanceId)).to.equal(keeperCertId);
  });

  it("leaves no duplicate (workspace_id, target_id, managed_certificate_id, observed_fingerprint_sha256) rows behind", async () => {
    const dupes = await pool.query(
      `SELECT workspace_id, target_id, managed_certificate_id, observed_fingerprint_sha256, COUNT(*)
         FROM certificate_instances
        WHERE workspace_id = $1
        GROUP BY 1, 2, 3, 4
       HAVING COUNT(*) > 1`,
      [workspaceId],
    );
    expect(dupes.rows).to.have.length(0);
  });
});

/**
 * Migration 67 - upgrade path on a populated 0.17.2-shaped database.
 *
 * Stops at version 66, plants names that the old length>=3 check allowed
 * (plain, padded, and three-space whitespace), then applies 67 and checks
 * the widened CHECK plus auto-sync connection_key bound.
 */

const { expect } = require("chai");
const { Client, Pool } = require("pg");
const path = require("path");

const DB_HOST = process.env.DB_HOST || "localhost";
const DB_PORT = Number(process.env.DB_PORT || process.env.TT_TEST_DB_PORT || 5432);
const DB_USER = process.env.DB_USER || "tokentimer";
const DB_PASSWORD = process.env.DB_PASSWORD || "password";
const ADMIN_DB_NAME = process.env.DB_NAME || "tokentimer";
const UPGRADE_DB_NAME = "tokentimer_inventory_name_67_upgrade_test";

const { migrations, applyMigrationSql } = require(
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
      await applyMigrationSql(client, migration);
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw new Error(
        `Migration ${migration.version} (${migration.name}) failed: ${err.message}`,
      );
    }
  }
}

describe("Inventory name length migration 67 - upgrade path", function () {
  this.timeout(180000);

  let pool;
  let workspaceId;
  let userId;
  let normalId;
  let paddedId;
  let whitespaceId;
  let configId;

  before(async function () {
    const widen = migrations.find((m) => m.version === 67);
    expect(widen, "migration 67 must exist").to.not.equal(undefined);
    expect(widen.name).to.equal("inventory_and_auto_sync_name_length");

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
      const pre67 = migrations.filter((m) => m.version <= 66);
      expect(pre67.some((m) => m.version === 66)).to.equal(true);
      expect(pre67.some((m) => m.version === 67)).to.equal(false);
      await applyMigrations(client, pre67);

      const userResult = await client.query(
        `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
         VALUES ('upgrade-67-test@example.com', 'upgrade-67-test@example.com', 'Upgrade 67 Test User', 'x', 'local', TRUE)
         RETURNING id`,
      );
      userId = userResult.rows[0].id;
      const ws = await client.query(
        `INSERT INTO workspaces (id, name, created_by, plan)
         VALUES (gen_random_uuid(), 'Upgrade 67 Test WS', $1, 'oss')
         RETURNING id`,
        [userId],
      );
      workspaceId = ws.rows[0].id;

      const tokenRows = await client.query(
        `INSERT INTO tokens
           (user_id, workspace_id, created_by, name, expiration, type, category)
         VALUES
           ($1, $2, $1, 'NormalName', CURRENT_DATE + 90, 'api_key', 'key_secret'),
           ($1, $2, $1, '  Padded Name  ', CURRENT_DATE + 90, 'api_key', 'key_secret'),
           ($1, $2, $1, '   ', CURRENT_DATE + 90, 'api_key', 'key_secret')
         RETURNING id, name`,
        [userId, workspaceId],
      );
      const byName = new Map(tokenRows.rows.map((row) => [row.name, row.id]));
      normalId = byName.get("NormalName");
      paddedId = byName.get("  Padded Name  ");
      whitespaceId = byName.get("   ");

      const config = await client.query(
        `INSERT INTO auto_sync_configs
           (workspace_id, provider, credentials_encrypted, connection_key, created_by, enabled)
         VALUES ($1, 'gitlab', 'test-only', 'Existing Config', $2, FALSE)
         RETURNING id`,
        [workspaceId, userId],
      );
      configId = config.rows[0].id;

      await applyMigrations(client, [widen]);
    } finally {
      client.release();
    }
  });

  after(async function () {
    if (pool) await pool.end();
    await dropDatabase(UPGRADE_DB_NAME);
  });

  it("trims existing names and replaces whitespace-only names", async () => {
    const { rows } = await pool.query(
      `SELECT id, name FROM tokens WHERE id = ANY($1::int[])`,
      [[normalId, paddedId, whitespaceId]],
    );
    const byId = new Map(rows.map((row) => [row.id, row.name]));
    expect(byId.get(normalId)).to.equal("NormalName");
    expect(byId.get(paddedId)).to.equal("Padded Name");
    expect(byId.get(whitespaceId)).to.equal("unnamed");
  });

  it("widens tokens.name to VARCHAR(255) with a 1-255 trimmed CHECK", async () => {
    const { rows } = await pool.query(
      `SELECT character_maximum_length
         FROM information_schema.columns
        WHERE table_name = 'tokens' AND column_name = 'name'`,
    );
    expect(rows[0].character_maximum_length).to.equal(255);

    await pool.query(
      `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
       VALUES ($1, $2, $1, $3, CURRENT_DATE + 90, 'api_key', 'key_secret')`,
      [userId, workspaceId, "A"],
    );
    await pool.query(
      `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
       VALUES ($1, $2, $1, $3, CURRENT_DATE + 90, 'api_key', 'key_secret')`,
      [userId, workspaceId, "B".repeat(255)],
    );
    await pool
      .query(
        `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
         VALUES ($1, $2, $1, $3, CURRENT_DATE + 90, 'api_key', 'key_secret')`,
        [userId, workspaceId, "C".repeat(256)],
      )
      .then(
        () => expect.fail("256-character name should fail"),
        (err) => expect(err.code).to.equal("22001"),
      );
    await pool
      .query(
        `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
         VALUES ($1, $2, $1, '   ', CURRENT_DATE + 90, 'api_key', 'key_secret')`,
        [userId, workspaceId],
      )
      .then(
        () => expect.fail("whitespace-only name should fail"),
        (err) => expect(err.code).to.equal("23514"),
      );
  });

  it("raises the auto-sync connection_key CHECK to 255 without altering TEXT", async () => {
    const { rows } = await pool.query(
      `SELECT character_maximum_length
         FROM information_schema.columns
        WHERE table_name = 'auto_sync_configs' AND column_name = 'connection_key'`,
    );
    expect(rows[0].character_maximum_length).to.equal(null);

    const { rows: kept } = await pool.query(
      `SELECT connection_key FROM auto_sync_configs WHERE id = $1`,
      [configId],
    );
    expect(kept[0].connection_key).to.equal("Existing Config");

    await pool.query(
      `INSERT INTO auto_sync_configs
         (workspace_id, provider, credentials_encrypted, connection_key, created_by, enabled)
       VALUES ($1, 'github', 'test-only', $2, $3, FALSE)`,
      [workspaceId, "D".repeat(255), userId],
    );
    await pool
      .query(
        `INSERT INTO auto_sync_configs
           (workspace_id, provider, credentials_encrypted, connection_key, created_by, enabled)
         VALUES ($1, 'aws', 'test-only', $2, $3, FALSE)`,
        [workspaceId, "E".repeat(256), userId],
      )
      .then(
        () => expect.fail("256-character connection_key should fail"),
        (err) => expect(err.code).to.equal("23514"),
      );
  });
});

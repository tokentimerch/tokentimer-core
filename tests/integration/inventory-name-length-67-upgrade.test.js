/**
 * Migration 67 - upgrade path on a populated 0.17.2-shaped database.
 *
 * Stops at version 66, plants names that the old length>=3 check allowed
 * (plain, padded, three-space, and tab-only), then applies 67 and checks
 * the widened CHECK plus auto-sync connection_key bound.
 *
 * Also covers mixed-version writes against the old VARCHAR(100) column,
 * rollback of an in-flight 67 transaction, and a representative row load
 * (TT_NAME_LENGTH_LOAD_ROWS, default 10000).
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
const LOAD_ROWS = Math.max(
  0,
  Number.parseInt(process.env.TT_NAME_LENGTH_LOAD_ROWS || "10000", 10) || 0,
);

const { migrations, applyMigrationSql, applyPostCommitSql } = require(
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
      await applyPostCommitSql(client, migration);
    } catch (err) {
      await client.query("ROLLBACK");
      throw new Error(
        `Migration ${migration.version} (${migration.name}) failed: ${err.message}`,
      );
    }
  }
}

async function nameColumnLength(pool) {
  const { rows } = await pool.query(
    `SELECT character_maximum_length
       FROM information_schema.columns
      WHERE table_name = 'tokens' AND column_name = 'name'`,
  );
  return rows[0].character_maximum_length;
}

describe("Inventory name length migration 67 - upgrade path", function () {
  this.timeout(600000);

  let pool;
  let workspaceId;
  let userId;
  let normalId;
  let paddedId;
  let whitespaceId;
  let tabOnlyId;
  let configId;
  let widen;
  let walBytes = 0;
  let ddlMs = 0;
  let validateMs = 0;
  let rewritten = 0;

  before(async function () {
    widen = migrations.find((m) => m.version === 67);
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
           ($1, $2, $1, '   ', CURRENT_DATE + 90, 'api_key', 'key_secret'),
           ($1, $2, $1, $3, CURRENT_DATE + 90, 'api_key', 'key_secret')
         RETURNING id, name`,
        [userId, workspaceId, "\t\t\t"],
      );
      const byName = new Map(tokenRows.rows.map((row) => [row.name, row.id]));
      normalId = byName.get("NormalName");
      paddedId = byName.get("  Padded Name  ");
      whitespaceId = byName.get("   ");
      tabOnlyId = byName.get("\t\t\t");

      const config = await client.query(
        `INSERT INTO auto_sync_configs
           (workspace_id, provider, credentials_encrypted, connection_key, created_by, enabled)
         VALUES ($1, 'gitlab', 'test-only', 'Existing Config', $2, FALSE)
         RETURNING id`,
        [workspaceId, userId],
      );
      configId = config.rows[0].id;
    } finally {
      client.release();
    }
  });

  after(async function () {
    if (pool) await pool.end();
    await dropDatabase(UPGRADE_DB_NAME);
  });

  it("rejects 255-character names on the old VARCHAR(100) column", async () => {
    expect(await nameColumnLength(pool)).to.equal(100);
    await pool
      .query(
        `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
         VALUES ($1, $2, $1, $3, CURRENT_DATE + 90, 'api_key', 'key_secret')`,
        [userId, workspaceId, "N".repeat(255)],
      )
      .then(
        () => expect.fail("255-character name should fail before migration 67"),
        (err) => expect(err.code).to.equal("22001"),
      );
    await pool
      .query(
        `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
         VALUES ($1, $2, $1, 'A', CURRENT_DATE + 90, 'api_key', 'key_secret')`,
        [userId, workspaceId],
      )
      .then(
        () => expect.fail("1-character name should fail the old length>=3 check"),
        (err) => expect(err.code).to.equal("23514"),
      );
  });

  it("rolls back an interrupted migration 67 without widening the column", async () => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await applyMigrationSql(client, widen);
      await client.query("ROLLBACK");
    } finally {
      client.release();
    }
    expect(await nameColumnLength(pool)).to.equal(100);
    const { rows } = await pool.query(
      `SELECT name FROM tokens WHERE id = $1`,
      [whitespaceId],
    );
    expect(rows[0].name).to.equal("   ");
  });

  it("limits UPDATE-of-name trigger blast radius to whitespace-only rewrites", async () => {
    const { rows } = await pool.query(`
      SELECT tgname, pg_get_triggerdef(oid) AS def
        FROM pg_trigger
       WHERE tgrelid = 'tokens'::regclass AND NOT tgisinternal
       ORDER BY tgname
    `);
    const names = rows.map((row) => row.tgname);
    expect(names).to.include("trg_resolve_token_operational_notifications");
    expect(names).to.include("trg_certops_capture_token_before");
    expect(names).to.include("trg_certops_capture_token_after");
    const operational = rows.find(
      (row) => row.tgname === "trg_resolve_token_operational_notifications",
    );
    expect(operational.def).to.match(/UPDATE OF workspace_id/i);
  });

  describe("after migration 67", function () {
    before(async function () {
      if (LOAD_ROWS > 0) {
        await pool.query(
          `INSERT INTO tokens
             (user_id, workspace_id, created_by, name, expiration, type, category)
           SELECT $1, $2, $1,
                  'LoadToken-' || g,
                  CURRENT_DATE + 90,
                  'api_key',
                  'key_secret'
             FROM generate_series(1, $3) AS g`,
          [userId, workspaceId, LOAD_ROWS],
        );
      }

      const beforeCount = await pool.query(`SELECT COUNT(*)::int AS n FROM tokens`);
      const lsnBefore = await pool.query(`SELECT pg_current_wal_lsn() AS lsn`);
      const ddlStart = Date.now();
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await applyMigrationSql(client, widen);
        await client.query("COMMIT");
        ddlMs = Date.now() - ddlStart;
        const validateStart = Date.now();
        await applyPostCommitSql(client, widen);
        validateMs = Date.now() - validateStart;
      } finally {
        client.release();
      }
      const lsnAfter = await pool.query(
        `SELECT pg_wal_lsn_diff(pg_current_wal_lsn(), $1::pg_lsn) AS bytes`,
        [lsnBefore.rows[0].lsn],
      );
      walBytes = Number(lsnAfter.rows[0].bytes);
      const unnamed = await pool.query(
        `SELECT COUNT(*)::int AS n FROM tokens WHERE name = 'unnamed'`,
      );
      rewritten = unnamed.rows[0].n;
      expect(beforeCount.rows[0].n).to.be.at.least(LOAD_ROWS + 4);
      // Catalog widen plus a two-row unnamed rewrite should not WAL the whole table.
      expect(walBytes).to.be.below(32 * 1024 * 1024);
      expect(ddlMs + validateMs).to.be.below(120000);
    });

    it("rewrites only whitespace-only names and leaves padded names stored", async () => {
      const { rows } = await pool.query(
        `SELECT id, name FROM tokens WHERE id = ANY($1::int[])`,
        [[normalId, paddedId, whitespaceId, tabOnlyId]],
      );
      const byId = new Map(rows.map((row) => [row.id, row.name]));
      expect(byId.get(normalId)).to.equal("NormalName");
      expect(byId.get(paddedId)).to.equal("  Padded Name  ");
      expect(byId.get(whitespaceId)).to.equal("unnamed");
      expect(byId.get(tabOnlyId)).to.equal("unnamed");
      expect(rewritten).to.equal(2);
    });

    it("widens tokens.name to VARCHAR(255) with a 1-255 trimmed CHECK", async () => {
      expect(await nameColumnLength(pool)).to.equal(255);

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
      await pool
        .query(
          `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
           VALUES ($1, $2, $1, $3, CURRENT_DATE + 90, 'api_key', 'key_secret')`,
          [userId, workspaceId, "\t\n"],
        )
        .then(
          () => expect.fail("tab and newline-only name should fail"),
          (err) => expect(err.code).to.equal("23514"),
        );
      await pool.query(
        `INSERT INTO tokens (user_id, workspace_id, created_by, name, expiration, type, category)
         VALUES ($1, $2, $1, $3, CURRENT_DATE + 90, 'api_key', 'key_secret')`,
        [userId, workspaceId, "  Padded New  "],
      );

      const { rows: checks } = await pool.query(
        `SELECT conname, convalidated
           FROM pg_constraint
          WHERE conname IN ('tokens_name_check', 'auto_sync_configs_name_canonical')
          ORDER BY conname`,
      );
      expect(checks.map((row) => [row.conname, row.convalidated])).to.deep.equal([
        ["auto_sync_configs_name_canonical", true],
        ["tokens_name_check", true],
      ]);
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

    it("records migration 67 timing under a representative load", async () => {
      // eslint-disable-next-line no-console
      console.log(
        `migration 67 load=${LOAD_ROWS} ddlMs=${ddlMs} validateMs=${validateMs} walBytes=${walBytes} rewritten=${rewritten}`,
      );
      expect(ddlMs).to.be.greaterThan(0);
      expect(validateMs).to.be.at.least(0);
      expect(walBytes).to.be.greaterThan(0);
    });
  });
});

describe("Inventory name length migration 67 - post-commit recovery", function () {
  this.timeout(600000);

  const RECOVERY_DB_NAME = "tokentimer_inventory_name_67_recovery_test";
  let pool;
  let widen;

  before(async function () {
    widen = migrations.find((m) => m.version === 67);
    expect(widen.postCommitSql, "migration 67 must define postCommitSql").to.be
      .a("string");

    await dropDatabase(RECOVERY_DB_NAME);
    const admin = await adminClient();
    try {
      await admin.query(`CREATE DATABASE ${RECOVERY_DB_NAME}`);
    } finally {
      await admin.end();
    }

    pool = new Pool({
      user: DB_USER,
      host: DB_HOST,
      database: RECOVERY_DB_NAME,
      password: DB_PASSWORD,
      port: DB_PORT,
      max: 4,
    });

    const client = await pool.connect();
    try {
      await applyMigrations(
        client,
        migrations.filter((m) => m.version <= 66),
      );
      await client.query(`
        CREATE TABLE IF NOT EXISTS migrations (
          version INTEGER PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          executed_at TIMESTAMP DEFAULT NOW()
        )
      `);
      // Commit the schema change and ledger row, then crash before VALIDATE.
      await client.query("BEGIN");
      await applyMigrationSql(client, widen);
      await client.query(
        "INSERT INTO migrations (version, name) VALUES ($1, $2)",
        [widen.version, widen.name],
      );
      await client.query("COMMIT");
    } finally {
      client.release();
    }
  });

  after(async function () {
    if (pool) await pool.end();
    await dropDatabase(RECOVERY_DB_NAME);
  });

  async function constraintState() {
    const { rows } = await pool.query(
      `SELECT conname, convalidated
         FROM pg_constraint
        WHERE conname IN ('tokens_name_check', 'auto_sync_configs_name_canonical')
        ORDER BY conname`,
    );
    return rows.map((row) => [row.conname, row.convalidated]);
  }

  it("retries VALIDATE after a crash between ledger commit and postCommitSql", async () => {
    expect(await constraintState()).to.deep.equal([
      ["auto_sync_configs_name_canonical", false],
      ["tokens_name_check", false],
    ]);

    const client = await pool.connect();
    try {
      await applyPostCommitSql(client, widen);
    } finally {
      client.release();
    }

    expect(await constraintState()).to.deep.equal([
      ["auto_sync_configs_name_canonical", true],
      ["tokens_name_check", true],
    ]);

    const again = await pool.connect();
    try {
      await applyPostCommitSql(again, widen);
    } finally {
      again.release();
    }
    expect(await constraintState()).to.deep.equal([
      ["auto_sync_configs_name_canonical", true],
      ["tokens_name_check", true],
    ]);
  });

  it("allows concurrent post-commit VALIDATE from two migrators", async () => {
    // Drop validation so both runners start from NOT VALID again.
    await pool.query(
      `ALTER TABLE tokens DROP CONSTRAINT IF EXISTS tokens_name_check`,
    );
    await pool.query(
      `ALTER TABLE auto_sync_configs DROP CONSTRAINT IF EXISTS auto_sync_configs_name_canonical`,
    );
    await pool.query(`
      ALTER TABLE tokens ADD CONSTRAINT tokens_name_check
        CHECK (char_length(regexp_replace(name, '^[[:space:]]+|[[:space:]]+$', '', 'g')) BETWEEN 1 AND 255)
        NOT VALID
    `);
    await pool.query(`
      ALTER TABLE auto_sync_configs ADD CONSTRAINT auto_sync_configs_name_canonical
        CHECK (connection_key = REGEXP_REPLACE(
                 regexp_replace(connection_key, '^[[:space:]]+|[[:space:]]+$', '', 'g'),
                 '[[:space:]]+', ' ', 'g')
               AND CHAR_LENGTH(connection_key) BETWEEN 1 AND 255)
        NOT VALID
    `);

    const left = await pool.connect();
    const right = await pool.connect();
    try {
      await Promise.all([
        applyPostCommitSql(left, widen),
        applyPostCommitSql(right, widen),
      ]);
    } finally {
      left.release();
      right.release();
    }

    expect(await constraintState()).to.deep.equal([
      ["auto_sync_configs_name_canonical", true],
      ["tokens_name_check", true],
    ]);
  });
});

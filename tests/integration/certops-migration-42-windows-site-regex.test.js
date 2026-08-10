/**
 * CertOps migration 42 (certops_windows_iis_target_descriptors) -
 * windows_site CHECK regression test, against a real Postgres instance.
 *
 * Migration 42 originally declared certificate_targets.windows_site's CHECK
 * as `windows_site ~ '^[A-Za-z0-9 _.:-]{1,256}$'`. PostgreSQL's regex engine
 * rejects a bounded repetition count above 255 outright ("invalid regular
 * expression: invalid repetition count(s)"), so that CHECK failed to
 * *compile* - not merely to evaluate false - on every single non-null
 * insert or update touching windows_site. tests/unit/certops-migration.test
 * .js never caught this because it only pattern-matches the migration's SQL
 * text; it never runs the migration against a real database or inserts a
 * row with a non-null windows_site. This test closes that gap by inserting
 * a real windows-iis target row with a realistic IIS site name against a
 * live Postgres instance.
 */

const { expect } = require("chai");
const { Client, Pool } = require("pg");
const path = require("path");

const DB_HOST = process.env.DB_HOST || "localhost";
const DB_PORT = Number(process.env.DB_PORT || process.env.TT_TEST_DB_PORT || 5432);
const DB_USER = process.env.DB_USER || "tokentimer";
const DB_PASSWORD = process.env.DB_PASSWORD || "password";
const ADMIN_DB_NAME = process.env.DB_NAME || "tokentimer";
const FRESH_DB_NAME = "tokentimer_certops_42_windows_site_regex_test";

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

describe("CertOps migration 42 - windows_site CHECK compiles and enforces its length bound on a real database", function () {
  this.timeout(120000);

  let pool;
  let workspaceId;

  before(async function () {
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

    const client = await pool.connect();
    try {
      for (const migration of migrations) {
        await client.query("BEGIN");
        try {
          await client.query(migration.sql);
          await client.query("COMMIT");
        } catch (err) {
          await client.query("ROLLBACK");
          throw new Error(
            `Migration ${migration.version} (${migration.name}) failed on fresh db: ${err.message}`,
          );
        }
      }
    } finally {
      client.release();
    }

    const userResult = await pool.query(
      `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
       VALUES ('windows-site-regex-test@example.com', 'windows-site-regex-test@example.com', 'Windows Site Regex Test User', 'x', 'local', TRUE)
       RETURNING id`,
    );
    const userId = userResult.rows[0].id;

    const wsResult = await pool.query(
      `INSERT INTO workspaces (id, name, created_by, plan)
       VALUES (gen_random_uuid(), 'Windows Site Regex Test WS', $1, 'pro')
       RETURNING id`,
      [userId],
    );
    workspaceId = wsResult.rows[0].id;
  });

  after(async function () {
    if (pool) await pool.end();
    await dropDatabase(FRESH_DB_NAME);
  });

  it("accepts a realistic IIS site name (e.g. 'Default Web Site') without a regex-compile error", async () => {
    const { rows } = await pool.query(
      `INSERT INTO certificate_targets (workspace_id, name, target_type, windows_site)
       VALUES ($1, 'iis-01', 'windows-iis', 'Default Web Site')
       RETURNING windows_site`,
      [workspaceId],
    );
    expect(rows).to.have.length(1);
    expect(rows[0].windows_site).to.equal("Default Web Site");
  });

  it("accepts a windows_site value at exactly the 256-character upper bound", async () => {
    const maxLengthSite = "a".repeat(256);
    const { rows } = await pool.query(
      `INSERT INTO certificate_targets (workspace_id, name, target_type, windows_site)
       VALUES ($1, 'iis-02', 'windows-iis', $2)
       RETURNING windows_site`,
      [workspaceId, maxLengthSite],
    );
    expect(rows[0].windows_site).to.have.length(256);
  });

  it("rejects a windows_site value one character past the 256-character upper bound", async () => {
    const tooLongSite = "a".repeat(257);
    let error = null;
    try {
      await pool.query(
        `INSERT INTO certificate_targets (workspace_id, name, target_type, windows_site)
         VALUES ($1, 'iis-03', 'windows-iis', $2)`,
        [workspaceId, tooLongSite],
      );
    } catch (err) {
      error = err;
    }
    expect(error).to.not.equal(null);
    expect(String(error.message)).to.match(
      /certificate_targets_windows_site_check/i,
    );
  });

  it("rejects a windows_site value containing a character outside the allowed class", async () => {
    let error = null;
    try {
      await pool.query(
        `INSERT INTO certificate_targets (workspace_id, name, target_type, windows_site)
         VALUES ($1, 'iis-04', 'windows-iis', 'Site<script>')`,
        [workspaceId],
      );
    } catch (err) {
      error = err;
    }
    expect(error).to.not.equal(null);
    expect(String(error.message)).to.match(
      /certificate_targets_windows_site_check/i,
    );
  });

  it("still allows windows_site to be NULL (only windows-iis targets populate it)", async () => {
    const { rows } = await pool.query(
      `INSERT INTO certificate_targets (workspace_id, name, target_type)
       VALUES ($1, 'endpoint-01', 'endpoint')
       RETURNING windows_site`,
      [workspaceId],
    );
    expect(rows[0].windows_site).to.equal(null);
  });
});

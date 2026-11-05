"use strict";

const { before, after, test } = require("node:test");
const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const { spawnSync } = require("node:child_process");

const name = "tt-store-upgrade-" + randomUUID();
let container, pool, migrations;
function docker(args) {
  const result = spawnSync("docker", args, { encoding: "utf8", timeout: 120000 });
  assert.equal(result.status, 0, result.stderr || String(result.error));
  return result.stdout.trim();
}
function migrate() {
  const result = spawnSync(process.execPath, ["apps/api/migrations/migrate.js"], { encoding: "utf8", timeout: 120000, env: process.env });
  assert.equal(result.status, 0, result.stderr || String(result.error));
}

before(async () => {
  container = docker(["run", "-d", "--name", name, "--label", "tokentimer.test=store-migration-upgrade", "--memory=512m", "--cpus=2", "-p", "127.0.0.1::5432", "-e", "POSTGRES_USER=store_test", "-e", "POSTGRES_PASSWORD=isolated-store-only", "-e", "POSTGRES_DB=store_upgrade_ci_test", "postgres:16-alpine"]);
  const port = JSON.parse(docker(["inspect", container]))[0].NetworkSettings.Ports["5432/tcp"][0].HostPort;
  let ready = false;
  for (let i = 0; i < 240; i++) {
    if (spawnSync("docker", ["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "store_test"], { timeout: 10000 }).status === 0) { ready = true; break; }
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  assert.ok(ready, "The disposable PostgreSQL container did not become ready");
  Object.assign(process.env, { NODE_ENV: "test", DB_HOST: "127.0.0.1", DB_PORT: port, DB_NAME: "store_upgrade_ci_test", DB_USER: "store_test", DB_PASSWORD: "isolated-store-only" });
  ({ pool } = require("../../apps/api/db/database"));
  migrations = require("../../apps/api/migrations/migrate");
}, { timeout: 180000 });

after(async () => {
  if (pool) await pool.end();
  if (container) {
    const info = JSON.parse(docker(["inspect", container]))[0];
    assert.equal(info.Name, "/" + name);
    assert.equal(info.Config.Labels["tokentimer.test"], "store-migration-upgrade");
    docker(["rm", "--force", "--volumes", container]);
  }
});

test("upgrades a real main database with migrations through 108 and repeats safely", async () => {
  const client = await pool.connect();
  try {
    await client.query("CREATE TABLE migrations (version INTEGER PRIMARY KEY, name VARCHAR(255) NOT NULL, executed_at TIMESTAMP DEFAULT NOW())");
    for (const entry of migrations.migrations.filter(item => item.version <= 108)) {
      await client.query("BEGIN");
      try {
        await migrations.applyMigrationSql(client, entry);
        await client.query("INSERT INTO migrations(version,name) VALUES ($1,$2)", [entry.version, entry.name]);
        await client.query("COMMIT");
      } catch (error) { await client.query("ROLLBACK"); throw error; }
      await migrations.applyPostCommitSql(client, entry);
    }
    const before = await client.query("SELECT version,name,executed_at FROM migrations WHERE version=98");
    assert.equal(before.rows[0].name, "certops_manual_rollout_authority");
    migrate();
    const afterFirst = await client.query("SELECT version,name,executed_at FROM migrations WHERE version >= 109 ORDER BY version");
    assert.deepEqual(afterFirst.rows.map(({ version, name }) => [version, name]), [
      [109, "store_issuance_explicit_renewal_consent"],
      [110, "certops_acme_store_enrollment_identity"],
      [111, "certops_adcs_expected_identity_receipts"],
    ]);
    const preserved = await client.query("SELECT version,name,executed_at FROM migrations WHERE version=98");
    assert.deepEqual(preserved.rows[0], before.rows[0]);
    const objects = await client.query("SELECT to_regclass('certops_acme_store_enrollments') AS acme, to_regclass('certops_adcs_expected_identity_receipts') AS adcs, to_regprocedure('certops_sync_open_management_automation()') AS sync");
    assert.ok(objects.rows[0].acme && objects.rows[0].adcs && objects.rows[0].sync);
    migrate();
    const afterSecond = await client.query("SELECT version,name,executed_at FROM migrations WHERE version >= 109 ORDER BY version");
    assert.deepEqual(afterSecond.rows, afterFirst.rows);
  } finally { client.release(); }
}, { timeout: 180000 });

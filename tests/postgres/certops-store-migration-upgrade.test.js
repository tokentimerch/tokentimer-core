"use strict";

const { before, after, test } = require("node:test");
const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { Client } = require("pg");

const name = "tt-store-upgrade-" + randomUUID();
let container, pool, migrations;
function docker(args) {
  const result = spawnSync("docker", args, { encoding: "utf8", timeout: 120000 });
  assert.equal(result.status, 0, result.stderr || String(result.error));
  return result.stdout.trim();
}
function migrate(database = process.env.DB_NAME) {
  const result = spawnSync(process.execPath, ["apps/api/migrations/migrate.js"], { encoding: "utf8", timeout: 120000, env: { ...process.env, DB_NAME: database } });
  assert.equal(result.status, 0, result.stderr || String(result.error));
}

async function applyRegistry(client, registry) {
  await client.query("CREATE TABLE migrations (version INTEGER PRIMARY KEY, name VARCHAR(255) NOT NULL, executed_at TIMESTAMP DEFAULT NOW())");
  for (const entry of registry) {
    await client.query("BEGIN");
    try {
      await migrations.applyMigrationSql(client, entry);
      await client.query("INSERT INTO migrations(version,name) VALUES ($1,$2)", [entry.version, entry.name]);
      await client.query("COMMIT");
    } catch (error) { await client.query("ROLLBACK"); throw error; }
    await migrations.applyPostCommitSql(client, entry);
  }
}

async function isolatedDatabase() {
  const database = "store_upgrade_" + randomUUID().replaceAll("-", "") + "_test";
  assert.match(database, /^store_upgrade_[a-f0-9]{32}_test$/);
  await pool.query(`CREATE DATABASE "${database}"`);
  const client = new Client({ host: process.env.DB_HOST, port: Number(process.env.DB_PORT),
    database, user: process.env.DB_USER, password: process.env.DB_PASSWORD });
  await client.connect();
  return { client, database };
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

test("upgrades a real main database with migrations through 114 and repeats safely", async () => {
  const client = await pool.connect();
  try {
    await applyRegistry(client, migrations.migrations.filter(item => item.version <= 114));
    const before = await client.query("SELECT version,name,executed_at FROM migrations WHERE version=98");
    assert.equal(before.rows[0].name, "certops_manual_rollout_authority");
    migrate();
    const afterFirst = await client.query("SELECT version,name,executed_at FROM migrations WHERE version > 114 ORDER BY version");
    assert.deepEqual(afterFirst.rows.map(({ version, name }) => [version, name]), [
      [115, "store_issuance_explicit_renewal_consent"],
      [116, "certops_acme_store_enrollment_identity"],
      [117, "certops_adcs_expected_identity_receipts"],
      [122, "certops_observed_revocation"],
      [126, "certops_adcs_receipt_deadline"],
    ]);
    const preserved = await client.query("SELECT version,name,executed_at FROM migrations WHERE version=98");
    assert.deepEqual(preserved.rows[0], before.rows[0]);
    const objects = await client.query("SELECT to_regclass('certops_acme_store_enrollments') AS acme, to_regclass('certops_adcs_expected_identity_receipts') AS adcs, to_regprocedure('certops_sync_open_management_automation()') AS sync");
    assert.ok(objects.rows[0].acme && objects.rows[0].adcs && objects.rows[0].sync);
    migrate();
    const afterSecond = await client.query("SELECT version,name,executed_at FROM migrations WHERE version > 114 ORDER BY version");
    assert.deepEqual(afterSecond.rows, afterFirst.rows);
  } finally { client.release(); }
}, { timeout: 180000 });

test("fills recovery 114 and revocation 122 without rewriting an applied canonical Store ledger", async () => {
  const { client, database } = await isolatedDatabase();
  try {
    const missing = [114, 122];
    await applyRegistry(client, migrations.migrations.filter(entry => !missing.includes(entry.version)));
    const before = (await client.query("SELECT version,name,executed_at FROM migrations ORDER BY version")).rows;
    migrate(database);
    const after = (await client.query("SELECT version,name,executed_at FROM migrations ORDER BY version")).rows;
    assert.deepEqual(after.filter(row => !missing.includes(row.version)), before);
    assert.equal(after.find(row => row.version === 114).name, "distribution_pagerduty_recovery");
    assert.equal(after.find(row => row.version === 122).name, "certops_observed_revocation");
    migrate(database);
    assert.deepEqual((await client.query("SELECT version,name,executed_at FROM migrations ORDER BY version")).rows, after);
  } finally { await client.end(); }
}, { timeout: 180000 });

const baseAppend = ["certops_period_creator_delete", "recipient_member_verification", "auto_sync_owner_username", "certops_material_reconciliation"];
const storeAppend = ["store_issuance_explicit_renewal_consent", "certops_acme_store_enrollment_identity", "certops_adcs_expected_identity_receipts", "certops_adcs_receipt_deadline"];
const recovery = "distribution_pagerduty_recovery";
const revocation = "certops_observed_revocation";
for (const [history, applied, remaining] of [
  ["recovery-first", [recovery], [...storeAppend.slice(0, 3), revocation, storeAppend[3]]],
  ["revocation-first", [recovery, revocation], storeAppend],
  ["Store-first", storeAppend, [recovery, revocation]],
]) {
  test(`retirement preview with ${history} history upgrades and survives restart`, async () => {
    const { client, database } = await isolatedDatabase();
    try {
      const oldAppend = [...baseAppend, ...applied];
      const fixture = [
        ...migrations.migrations.filter(entry => entry.version <= 108),
        { ...migrations.migrations.find(entry => entry.name === "certops_retirement_dossiers"), version: 109 },
        ...oldAppend.map((name, index) => ({ ...migrations.migrations.find(entry => entry.name === name), version: 110 + index })),
      ];
      await applyRegistry(client, fixture);
      const before = (await client.query("SELECT version,name,executed_at FROM migrations ORDER BY version")).rows;
      migrate(database);
      const after = (await client.query("SELECT version,name,executed_at FROM migrations ORDER BY version")).rows;
      assert.deepEqual(after.slice(0, before.length), before);
      const expected = [...oldAppend, ...remaining];
      assert.deepEqual(after.filter(row => row.version >= 110).map(({ version, name }) => [version, name]),
        expected.map((name, index) => [110 + index, name]));
      const columns = (await client.query("SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='certops_adcs_expected_identity_receipts'")).rows;
      for (const name of ["origin_xid", "committed_seen_at", "receipt_claim_expires_at"]) {
        assert.ok(columns.some(row => row.column_name === name));
      }
      migrate(database);
      assert.deepEqual((await client.query("SELECT version,name,executed_at FROM migrations ORDER BY version")).rows, after);
    } finally { await client.end(); }
  }, { timeout: 180000 });
}

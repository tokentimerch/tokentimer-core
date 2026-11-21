"use strict";

const { before, after, test } = require("node:test");
const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const { spawnSync } = require("node:child_process");

const name = `tt-observed-preview-${randomUUID()}`;
let container, pool, migrations;
function docker(args) {
  const result = spawnSync("docker", args, { encoding: "utf8", timeout: 120000 });
  assert.equal(result.status, 0, result.stderr || result.stdout || String(result.error));
  return result.stdout.trim();
}
function migrate() {
  const result = spawnSync(process.execPath, ["apps/api/migrations/migrate.js"], { encoding: "utf8", timeout: 120000, env: process.env });
  assert.equal(result.status, 0, result.stderr || result.stdout || String(result.error));
}
before(async () => {
  container = docker(["run", "-d", "--name", name, "--label", "tokentimer.test=observed-preview-upgrade", "--memory=512m", "--cpus=2", "-p", "127.0.0.1::5432", "-e", "POSTGRES_USER=preview_test", "-e", "POSTGRES_PASSWORD=isolated-preview-only", "-e", "POSTGRES_DB=observed_preview_test", "postgres:16-alpine"]);
  const port = JSON.parse(docker(["inspect", container]))[0].NetworkSettings.Ports["5432/tcp"][0].HostPort;
  let ready = false;
  for (let i = 0; i < 240; i++) {
    if (spawnSync("docker", ["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "preview_test"], { timeout: 10000 }).status === 0) { ready = true; break; }
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  assert.ok(ready, "The disposable PostgreSQL container did not become ready");
  Object.assign(process.env, { NODE_ENV: "test", DB_HOST: "127.0.0.1", DB_PORT: port, DB_NAME: "observed_preview_test", DB_USER: "preview_test", DB_PASSWORD: "isolated-preview-only" });
  ({ pool } = require("../../apps/api/db/database"));
  migrations = require("../../apps/api/migrations/migrate");
}, { timeout: 180000 });
after(async () => {
  if (pool) await pool.end();
  if (container) {
    const info = JSON.parse(docker(["inspect", container]))[0];
    assert.equal(info.Name, "/" + name);
    assert.equal(info.Config.Labels["tokentimer.test"], "observed-preview-upgrade");
    docker(["rm", "--force", "--volumes", container]);
  }
});

test("upgrades the applied observed-revocation preview without rewriting its ledger", async () => {
  const client = await pool.connect();
  try {
    await client.query("CREATE TABLE migrations (version INTEGER PRIMARY KEY, name VARCHAR(255) NOT NULL, executed_at TIMESTAMP DEFAULT NOW())");
    const absent = new Set([86, 87, 88, 89, 90, 91, 96, 97]);
    const baseline = migrations.migrations.filter(entry => entry.version <= 111 && !absent.has(entry.version));
    const names = ["certops_observed_revocation", "store_issuance_explicit_renewal_consent", "certops_acme_store_enrollment_identity", "certops_adcs_expected_identity_receipts", "certops_windows_iis_consent"];
    const preview = [...baseline, ...names.map((name, index) => ({ ...migrations.migrations.find(entry => entry.name === name), version: 112 + index }))];
    for (const entry of preview) {
      await client.query("BEGIN");
      try {
        await migrations.applyMigrationSql(client, entry);
        await client.query("INSERT INTO migrations(version,name) VALUES ($1,$2)", [entry.version, entry.name]);
        await client.query("COMMIT");
      } catch (error) { await client.query("ROLLBACK"); throw error; }
      await migrations.applyPostCommitSql(client, entry);
    }
    const before = (await client.query("SELECT version,name,executed_at FROM migrations ORDER BY version")).rows;
    require("../../apps/api/migrations/compose-migrations").composeMigrations(migrations.migrations, before);
    migrate();
    const after = (await client.query("SELECT version,name,executed_at FROM migrations ORDER BY version")).rows;
    assert.deepEqual(after.slice(0, before.length), before);
    for (const name of ["certops_retirement_dossiers", "certops_material_reconciliation", "certops_material_adcs_operation_union"]) assert.ok(after.some(row => row.name === name));
    const constraint = await client.query("SELECT pg_get_constraintdef(oid) AS definition FROM pg_constraint WHERE conrelid='certificate_jobs'::regclass AND conname='certificate_jobs_operation_check'");
    for (const operation of ["cleanup-from-store", "reconcile-from-store", "adcs-installation-proof"]) assert.match(constraint.rows[0].definition, new RegExp(operation));
    migrate();
    assert.deepEqual((await client.query("SELECT version,name,executed_at FROM migrations ORDER BY version")).rows, after);
  } finally { client.release(); }
}, { timeout: 180000 });

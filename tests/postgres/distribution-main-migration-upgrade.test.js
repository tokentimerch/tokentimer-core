"use strict";

// Run only against a fresh disposable database. The first pass models the
// released Core ledger; the second applies the previously reserved lifecycle slots.
const test = require("node:test");
const assert = require("node:assert/strict");
assert.equal(process.env.DB_HOST, "127.0.0.1");
assert.equal(process.env.NODE_ENV, "test");
assert.match(process.env.DB_NAME || "", /^pr329_distribution_main_upgrade.*_test$/);

const { pool } = require("../../apps/api/db/database");
const { migrations, runMigrations } = require("../../apps/api/migrations/migrate");

test("released Core through 108 upgrades to the distribution lifecycle without rewriting its ledger", async () => {
  const original = migrations.slice();
  const lifecycle = new Set([86, 87, 88, 89, 90, 91, 96, 97]);
  const pending = new Set([...lifecycle, ...original.filter(({ version }) => version >= 109).map(({ version }) => version)]);
  try {
    assert.equal(
      (await pool.query("SELECT to_regclass('public.migrations') AS name")).rows[0].name,
      null,
      "Use a fresh database",
    );
    migrations.splice(0, migrations.length, ...original.filter((entry) => !pending.has(entry.version)));
    await runMigrations();
    const released = (await pool.query("SELECT * FROM migrations ORDER BY version")).rows;
    assert.equal(released.at(-1).version, 108);
    assert.equal(released.some((row) => lifecycle.has(row.version)), false);
    assert.equal((await pool.query("SELECT to_regclass('public.certops_material_retirement_dossiers') AS name")).rows[0].name, null);

    // A released database may already contain both material operations.
    migrations.splice(0, migrations.length, ...original.filter(({ version }) => version <= 114));
    await runMigrations();
    const materialLedger = (await pool.query("SELECT * FROM migrations ORDER BY version")).rows;
    const { id: ownerId } = (await pool.query(
      "INSERT INTO users(email, display_name, password_hash, auth_method) VALUES ('ledger-owner@example.test', 'Ledger fixture', 'synthetic-test-only', 'local') RETURNING id",
    )).rows[0];
    const { id: workspaceId } = (await pool.query(
      "INSERT INTO workspaces(id, name, created_by, plan) VALUES (gen_random_uuid(), 'Ledger fixture', $1, 'oss') RETURNING id",
      [ownerId],
    )).rows[0];
    const materialJobs = (await pool.query(
      "INSERT INTO certificate_jobs(workspace_id, operation, status) VALUES ($1, 'cleanup-from-store', 'succeeded'), ($1, 'reconcile-from-store', 'succeeded') RETURNING id, operation",
      [workspaceId],
    )).rows;

    // Restore the actual planner, not a synthetic hand-ordered migration list.
    migrations.splice(0, migrations.length, ...original);
    await runMigrations();
    const upgraded = (await pool.query("SELECT * FROM migrations ORDER BY version")).rows;
    assert.deepEqual(upgraded.filter((row) => !pending.has(row.version)), released);
    assert.deepEqual(upgraded.filter((row) => row.version <= 114), materialLedger);
    assert.deepEqual((await pool.query("SELECT id, operation FROM certificate_jobs WHERE workspace_id = $1 ORDER BY operation", [workspaceId])).rows, materialJobs);
    assert.deepEqual(upgraded.filter((row) => lifecycle.has(row.version)).map((row) => row.version), [...lifecycle]);
    assert.equal(upgraded.find((row) => row.version === 112).name, "certops_retirement_dossiers");
    assert.equal((await pool.query("SELECT to_regclass('public.certops_material_retirement_dossiers') AS name")).rows[0].name, "certops_material_retirement_dossiers");

    await runMigrations();
    assert.deepEqual((await pool.query("SELECT * FROM migrations ORDER BY version")).rows, upgraded);
  } finally {
    migrations.splice(0, migrations.length, ...original);
  }
});

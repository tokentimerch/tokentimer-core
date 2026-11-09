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
  const pending = new Set([...lifecycle, 109]);
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

    // Restore the actual planner, not a synthetic hand-ordered migration list.
    migrations.splice(0, migrations.length, ...original);
    await runMigrations();
    const upgraded = (await pool.query("SELECT * FROM migrations ORDER BY version")).rows;
    assert.deepEqual(upgraded.filter((row) => !pending.has(row.version)), released);
    assert.deepEqual(upgraded.filter((row) => lifecycle.has(row.version)).map((row) => row.version), [...lifecycle]);
    assert.equal(upgraded.find((row) => row.version === 109).name, "certops_retirement_dossiers");
    assert.equal((await pool.query("SELECT to_regclass('public.certops_material_retirement_dossiers') AS name")).rows[0].name, "certops_material_retirement_dossiers");

    await runMigrations();
    assert.deepEqual((await pool.query("SELECT * FROM migrations ORDER BY version")).rows, upgraded);
  } finally {
    migrations.splice(0, migrations.length, ...original);
  }
});

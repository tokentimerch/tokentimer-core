"use strict";

const { test, after } = require("node:test");
const assert = require("node:assert/strict");

assert.equal(process.env.NODE_ENV, "test");
assert.equal(process.env.DB_HOST, "127.0.0.1");
assert.match(process.env.DB_NAME || "", /^recovery_preview_[a-f0-9]+_test$/);
const { pool } = require("../../apps/api/db/database");
const { migrations, runMigrations } = require("../../apps/api/migrations/migrate");
after(() => pool.end());

test("recovery preview upgrade preserves applied migration identities and timestamps", async () => {
  const registry = migrations.slice();
  try {
    assert.equal((await pool.query("SELECT to_regclass('public.migrations') AS name")).rows[0].name, null);
    const recovery = registry.find((entry) => entry.name === "distribution_pagerduty_recovery");
    assert.equal(recovery?.version, 122);
    // Execute the real historical SQL, including the original recovery slot.
    migrations.splice(0, migrations.length,
      ...registry.filter((entry) => entry.version <= 113), { ...recovery, version: 114 });
    await runMigrations();
    const historical = (await pool.query("SELECT version, name, executed_at FROM migrations ORDER BY version")).rows;
    assert.equal(historical.length, 114);
    assert.equal(historical.at(-1).name, "distribution_pagerduty_recovery");
    assert.equal((await pool.query("SELECT to_regclass('public.certops_distribution_pagerduty') AS name")).rows[0].name, "certops_distribution_pagerduty");

    migrations.splice(0, migrations.length, ...registry);
    await runMigrations();
    const upgraded = (await pool.query("SELECT version, name, executed_at FROM migrations ORDER BY version")).rows;
    assert.deepEqual(upgraded.slice(0, historical.length), historical);
    assert.deepEqual(upgraded.slice(historical.length).map(({ version, name }) => ({ version, name })),
      registry.filter((entry) => entry.version > 113 && entry.name !== recovery.name)
        .map((entry, index) => ({ version: 115 + index, name: entry.name })));
    await runMigrations();
    assert.deepEqual((await pool.query("SELECT version, name, executed_at FROM migrations ORDER BY version")).rows, upgraded);
  } finally {
    migrations.splice(0, migrations.length, ...registry);
  }
});

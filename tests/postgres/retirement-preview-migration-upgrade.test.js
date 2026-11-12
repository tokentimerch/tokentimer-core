"use strict";

// Dedicated disposable database: reproduce the previously shipped preview ledger.
const test = require("node:test");
const assert = require("node:assert/strict");
assert.equal(process.env.NODE_ENV, "test");
assert.equal(process.env.DB_HOST, "127.0.0.1");
assert.match(process.env.DB_NAME || "", /^pr498_retirement_preview.*_test$/);
const { pool } = require("../../apps/api/db/database");
const { migrations, runMigrations } = require("../../apps/api/migrations/migrate");

test("an applied retirement preview upgrades and replays without rewriting its ledger", async () => {
  const full = migrations.slice();
  try {
    assert.equal((await pool.query("SELECT to_regclass('public.migrations') AS name")).rows[0].name, null);
    const retirement = full.find((entry) => entry.name === "certops_retirement_dossiers");
    migrations.splice(0, migrations.length, ...full.filter((entry) => entry.version <= 108), { ...retirement, version: 109 });
    await runMigrations();
    const before = (await pool.query("SELECT * FROM migrations ORDER BY version")).rows;
    assert.equal(before.at(-1).name, "certops_retirement_dossiers");
    assert.equal(before.at(-1).version, 109);
    assert.equal((await pool.query("SELECT to_regclass('public.certops_material_retirement_dossiers') AS name")).rows[0].name, "certops_material_retirement_dossiers");
    migrations.splice(0, migrations.length, ...full);
    await runMigrations();
    const upgraded = (await pool.query("SELECT * FROM migrations ORDER BY version")).rows;
    assert.deepEqual(upgraded.slice(0, before.length), before);
    assert.deepEqual(upgraded.slice(before.length).map(({ version, name }) => ({ version, name })), [
      { version: 110, name: "certops_period_creator_delete" },
      { version: 111, name: "recipient_member_verification" },
      { version: 112, name: "auto_sync_owner_username" },
      {version:113,name:"certops_material_reconciliation"},
    ]);
    await runMigrations();
    assert.deepEqual((await pool.query("SELECT * FROM migrations ORDER BY version")).rows, upgraded);
  } finally {
    migrations.splice(0, migrations.length, ...full);
    await pool.end();
  }
});

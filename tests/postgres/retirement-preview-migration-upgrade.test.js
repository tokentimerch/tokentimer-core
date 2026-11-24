"use strict";

// Dedicated disposable database: reproduce the previously shipped preview ledger.
const test = require("node:test");
const assert = require("node:assert/strict");
assert.equal(process.env.NODE_ENV, "test");
assert.equal(process.env.DB_HOST, "127.0.0.1");
assert.match(process.env.DB_NAME || "", /^pr498_retirement_preview.*_test$/);
const { pool } = require("../../apps/api/db/database");
const { migrations, runMigrations } = require("../../apps/api/migrations/migrate");
const { composeMigrations } = require("../../apps/api/migrations/compose-migrations");

test("an applied retirement preview upgrades and replays without rewriting its ledger", async () => {
  const full = migrations.slice();
  try {
    assert.equal((await pool.query("SELECT to_regclass('public.migrations') AS name")).rows[0].name, null);
    const retirement = full.find((entry) => entry.name === "certops_retirement_dossiers");
    migrations.splice(0, migrations.length, ...full.filter((entry) => entry.version <= 108), { ...retirement, version: 109 });
    await runMigrations();
    const retirementLedger = (await pool.query("SELECT * FROM migrations ORDER BY version")).rows;
    assert.equal(retirementLedger.at(-1).name, "certops_retirement_dossiers");
    assert.equal(retirementLedger.at(-1).version, 109);
    assert.equal((await pool.query("SELECT to_regclass('public.certops_material_retirement_dossiers') AS name")).rows[0].name, "certops_material_retirement_dossiers");
    // Apply the exact historical #728 tail with real SQL before rotation arrives.
    const observedPreview = composeMigrations(full.filter(({ version }) => version <= 114 || version === 122), retirementLedger);
    migrations.splice(0, migrations.length, ...observedPreview);
    await runMigrations();
    const before = (await pool.query("SELECT * FROM migrations ORDER BY version")).rows;
    assert.deepEqual(before.slice(0, retirementLedger.length), retirementLedger);
    assert.deepEqual(before.slice(-1).map(({ version, name }) => ({ version, name })), [
      { version: 115, name: "certops_observed_revocation" },
    ]);
    migrations.splice(0, migrations.length, ...full);
    await runMigrations();
    const upgraded = (await pool.query("SELECT * FROM migrations ORDER BY version")).rows;
    assert.deepEqual(upgraded.slice(0, before.length), before);
    assert.deepEqual(upgraded.slice(before.length).map(({ version, name }) => ({ version, name })), [
      ...full.filter(({ version }) => version >= 115 && version <= 121)
        .map(({ name }, index) => ({ version: 116 + index, name })),
      { version: 123, name: "agent_credential_rotations" },
      { version: 124, name: "agent_credential_rotation_ack" },
      { version: 125, name: "certops_adcs_preflight_lookup_index" },
      { version: 126, name: "certops_adcs_receipt_deadline" },
      { version: 127, name: "auto_sync_creation_expiration" },
      { version: 128, name: "shared_sso_schema" },
      { version: 129, name: "certops_acme_store_cancelled" },
    ]);
    await runMigrations();
    assert.deepEqual((await pool.query("SELECT * FROM migrations ORDER BY version")).rows, upgraded);
  } finally {
    migrations.splice(0, migrations.length, ...full);
    await pool.end();
  }
});

"use strict";

const { test, after } = require("node:test");
const assert = require("node:assert/strict");

assert.equal(process.env.NODE_ENV, "test");
assert.equal(process.env.DB_HOST, "127.0.0.1");
assert.match(process.env.DB_NAME || "", /^rotation_mcp_preview_[a-f0-9]+_test$/);
const { pool } = require("../../apps/api/db/database");
const { migrations, runMigrations } = require("../../apps/api/migrations/migrate");
const { composeMigrations } = require("../../apps/api/migrations/compose-migrations");
after(() => pool.end());

test("MCP rotation preview upgrades real SQL without rewriting its ledger", async () => {
  const registry = migrations.slice();
  try {
    assert.equal((await pool.query("SELECT to_regclass('public.migrations') AS name")).rows[0].name, null);
    const oldRegistry = registry.filter((entry) =>
      (entry.version <= 113 || entry.name.startsWith("agent_credential_rotation")) &&
      !["certops_retirement_dossiers", "certops_material_reconciliation"].includes(entry.name))
      .map((entry) => entry.name === "agent_credential_rotations" ? { ...entry, version: 114 }
        : entry.name === "agent_credential_rotation_ack" ? { ...entry, version: 115 } : entry);
    const prefix = oldRegistry.filter((entry) => entry.version <= 85 || [92, 93].includes(entry.version));
    const mcp = ["operator_connections", "operator_enrollment_grants", "operator_action_requests"]
      .map((name, index) => ({ ...oldRegistry.find((entry) => entry.name === name), version: 94 + index }));
    const historicalPlan = composeMigrations(oldRegistry, [...prefix, ...mcp]);
    assert.equal(historicalPlan.find((entry) => entry.name === "agent_credential_rotations")?.version, 110);
    assert.equal(historicalPlan.find((entry) => entry.name === "agent_credential_rotation_ack")?.version, 111);
    migrations.splice(0, migrations.length, ...historicalPlan);
    await runMigrations();
    const historical = (await pool.query("SELECT version, name, executed_at FROM migrations ORDER BY version")).rows;
    assert.deepEqual(historical.map(({ version, name }) => ({ version, name })),
      historicalPlan.map(({ version, name }) => ({ version, name })));

    migrations.splice(0, migrations.length, ...registry);
    await runMigrations();
    const upgraded = (await pool.query("SELECT version, name, executed_at FROM migrations ORDER BY version")).rows;
    assert.deepEqual(upgraded.filter((row) => historical.some((entry) => entry.version === row.version)), historical);
    assert.equal(upgraded.filter((row) => row.name === "agent_credential_rotations").length, 1);
    assert.equal(upgraded.filter((row) => row.name === "agent_credential_rotation_ack").length, 1);
    assert.equal(upgraded.filter((row) => row.name === "certops_observed_revocation").length, 1);
    assert.equal(upgraded.filter((row) => row.name === "distribution_pagerduty_recovery").length, 1);
    await runMigrations();
    assert.deepEqual((await pool.query("SELECT version, name, executed_at FROM migrations ORDER BY version")).rows, upgraded);
  } finally {
    migrations.splice(0, migrations.length, ...registry);
  }
});

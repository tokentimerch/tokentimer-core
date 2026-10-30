"use strict";

// Run with --test-force-exit against an empty dedicated database. Core's
// migration runner owns a separate pool; it must not reuse audit databases.
const test = require("node:test");
const assert = require("node:assert/strict");
assert.equal(process.env.DB_HOST, "127.0.0.1");
assert.equal(process.env.NODE_ENV, "test");
assert.match(process.env.DB_NAME || "", /^pr329_distribution_upgrade.*_test$/);
const { pool } = require("../../apps/api/db/database");
const {
  migrations,
  runMigrations,
} = require("../../apps/api/migrations/migrate");

test("an installation at main's AD CS migration 72 upgrades to distribution without changing its history", async () => {
  const pending = migrations.splice(
    migrations.findIndex((entry) => entry.version === 73),
  );
  try {
    assert.equal(
      (
        await pool.query(
          "SELECT to_regclass('public.migrations') AS table_name",
        )
      ).rows[0].table_name,
      null,
      "Use a fresh database for the two-step upgrade reproduction",
    );
    await runMigrations();
    const originalLedger = (await pool.query("SELECT * FROM migrations ORDER BY version")).rows;
    const before = await pool.query(
      "SELECT version, name FROM migrations WHERE version=72",
    );
    assert.equal(
      before.rows[0].name,
      "certops_profile_issuer",
    );
    migrations.push(...pending);
    await runMigrations();
    assert.deepEqual((await pool.query("SELECT * FROM migrations WHERE version<=72 ORDER BY version")).rows, originalLedger);
    const upgradedLedger = (await pool.query("SELECT * FROM migrations ORDER BY version")).rows;
    await runMigrations();
    assert.deepEqual((await pool.query("SELECT * FROM migrations ORDER BY version")).rows, upgradedLedger);
    const after = await pool.query(
      "SELECT version, name FROM migrations WHERE version>=68 ORDER BY version",
    );
    assert.deepEqual(after.rows, [
      {
        version: 68,
        name: "certops_adcs_awaiting_issuer_and_continue_enrollment",
      },
      { version: 69, name: "certops_agent_job_logs" },
      { version: 70, name: "certops_certificate_enrollments" },
      { version: 71, name: "certops_adcs_evidence_types" },
      { version: 72, name: "certops_profile_issuer" },
      { version: 73, name: "certops_job_alert_context" },
      { version: 74, name: "certops_material_distribution" },
      { version: 75, name: "certops_distribution_review" },
      { version: 76, name: "certops_distribution_transfer" },
      { version: 77, name: "onboarding_sessions" },
      { version: 78, name: "certops_installed_file_distribution" },
      { version: 79, name: "auto_sync_provider_stats" },
      { version: 80, name: "auto_sync_run_metrics" },
      { version: 81, name: "auto_sync_metric_labels" },
      { version: 82, name: "auto_sync_system_metrics" },
      { version: 83, name: "operator_connections" },
      { version: 84, name: "operator_enrollment_grants" },
      { version: 85, name: "operator_action_requests" },
    ]);
    const constraints =
      await pool.query(`SELECT conname, pg_get_constraintdef(oid) AS definition
      FROM pg_constraint WHERE conrelid='certificate_jobs'::regclass
      AND conname IN ('certificate_jobs_operation_check','certificate_jobs_status_check')`);
    assert.match(
      constraints.rows.find((row) => row.conname.endsWith("operation_check"))
        .definition,
      /continue-enrollment/,
    );
    assert.match(
      constraints.rows.find((row) => row.conname.endsWith("operation_check"))
        .definition,
      /adcs-preflight/,
    );
    assert.match(
      constraints.rows.find((row) => row.conname.endsWith("operation_check"))
        .definition,
      /deploy-from-store/,
    );
    assert.match(
      constraints.rows.find((row) => row.conname.endsWith("status_check"))
        .definition,
      /awaiting_issuer/,
    );
    assert.equal(
      (
        await pool.query(
          "SELECT to_regclass('public.certops_distribution_groups') AS table_name",
        )
      ).rows[0].table_name,
      "certops_distribution_groups",
    );
    const filePolicies = await pool.query(`SELECT conname,pg_get_constraintdef(oid) AS definition FROM pg_constraint
      WHERE conname=ANY($1::text[])`, [["certops_consumer_bindings_verification_policy_check",
      "certops_consumer_deployments_verification_policy_check", "certops_consumer_current_state_verification_method_check",
      "certops_distribution_rollouts_state_check"]]);
    assert.equal(filePolicies.rows.length, 4);
    for (const constraint of filePolicies.rows) {
      assert.match(constraint.definition, /installed/);
      assert.match(constraint.definition, /served|verified/);
    }
    // Exercise the exact additive DDL against retained legacy assurance rows.
    // Temporary tables shadow the public tables only on this dedicated client.
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const tables = [
        ["certops_consumer_bindings", "verification_policy", ["served", "trust"]],
        ["certops_consumer_deployments", "verification_policy", ["served", "trust"]],
        ["certops_consumer_current_state", "verification_method", ["served", "trust"]],
        ["certops_distribution_rollouts", "state", ["pending", "deploying", "verified", "degraded", "paused", "retired"]],
      ];
      for (const [table, column, values] of tables) {
        await client.query(`CREATE TEMP TABLE ${table} (${column} TEXT CHECK (${column} IN (${values.map(value => `'${value}'`).join(",")}))) ON COMMIT DROP`);
        await client.query(`INSERT INTO ${table} (${column}) VALUES ($1)`, [values[0]]);
      }
      await client.query(migrations.find(entry => entry.version === 78).sql);
      for (const [table, column, values] of tables) {
        assert.deepEqual((await client.query(`SELECT ${column} FROM ${table}`)).rows, [{ [column]: values[0] }]);
        await client.query(`INSERT INTO ${table} (${column}) VALUES ('installed')`);
        await client.query("SAVEPOINT invalid_policy");
        await assert.rejects(client.query(`INSERT INTO ${table} (${column}) VALUES ('pretend_verified')`), { code: "23514" });
        await client.query("ROLLBACK TO SAVEPOINT invalid_policy");
      }
      await client.query("ROLLBACK");
    } finally { client.release(); }
  } finally {
    if (migrations.at(-1).version === 72) migrations.push(...pending);
    await pool.end();
  }
});

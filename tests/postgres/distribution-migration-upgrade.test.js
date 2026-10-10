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

test("an installation at main's AD CS migration 68 upgrades to distribution without changing its history", async () => {
  const pending = migrations.splice(
    migrations.findIndex((entry) => entry.version === 69),
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
    const before = await pool.query(
      "SELECT version, name FROM migrations WHERE version=68",
    );
    assert.equal(
      before.rows[0].name,
      "certops_adcs_awaiting_issuer_and_continue_enrollment",
    );
    migrations.push(...pending);
    await runMigrations();
    const after = await pool.query(
      "SELECT version, name FROM migrations WHERE version>=68 ORDER BY version",
    );
    assert.deepEqual(after.rows, [
      {
        version: 68,
        name: "certops_adcs_awaiting_issuer_and_continue_enrollment",
      },
      { version: 69, name: "certops_material_distribution" },
      { version: 70, name: "certops_distribution_review" },
      { version: 71, name: "certops_distribution_transfer" },
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
  } finally {
    if (migrations.at(-1).version === 68) migrations.push(...pending);
    await pool.end();
  }
});

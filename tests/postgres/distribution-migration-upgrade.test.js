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

test("installations at migrations 72, 80 and 84 upgrade with preserved history and backfilled consumer streaks", async () => {
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
    migrations.push(...pending.filter(entry=>entry.version<=80));
    await runMigrations();
    const currentMainLedger=(await pool.query("SELECT * FROM migrations ORDER BY version")).rows;
    assert.equal(currentMainLedger.at(-1).version,80);
    assert.equal(currentMainLedger.at(-1).name,"auto_sync_run_metrics");
    migrations.push(...pending.filter(entry=>entry.version>80 && entry.version<=84));
    await runMigrations();
    const beforeVerificationLedger=(await pool.query("SELECT * FROM migrations ORDER BY version")).rows;
    const {fixture,proveConsumer}=require("../helpers/distribution-lifecycle-fixture.cjs");
    const operations=require("../../apps/api/services/certops/distributionOperations");
    const f=await fixture();
    await operations.requestRollout({...f,actorUserId:f.actor});await proveConsumer(f);
    async function oldFailure(verificationOnly){
      const parent=await operations.requestRollout({...f,verificationOnly,actorUserId:f.actor});
      const rollout=(await pool.query("SELECT id FROM certops_distribution_rollouts WHERE approval_job_id=$1",[parent.id])).rows[0];
      await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,rollout.id));
      const child=(await pool.query("SELECT job_id FROM certops_consumer_deployments WHERE rollout_id=$1 AND binding_id=$2",[rollout.id,f.bindingId])).rows[0];
      await pool.query("UPDATE certificate_jobs SET status='failed',attempt_count=99,completed_at=clock_timestamp() WHERE id=$1",[child.job_id]);
      await pool.query("UPDATE certops_consumer_deployments SET stage='failed',failure_code='historical_fixture_failure' WHERE job_id=$1",[child.job_id]);
      await pool.query("INSERT INTO certificate_job_log(workspace_id,job_id,event_type,status,message) VALUES($1,$2,'job.failed','failed','Historical verification fixture')",[f.workspaceId,child.job_id]);
      return child.job_id;
    }
    await oldFailure(true);await oldFailure(true);
    await operations.requestRollout({...f,verificationOnly:true,actorUserId:f.actor});await proveConsumer(f);
    await oldFailure(false);const retrying=await oldFailure(true);
    await pool.query("UPDATE certificate_jobs SET status='pending',completed_at=NULL WHERE id=$1",[retrying]);
    await pool.query("UPDATE certops_consumer_deployments SET stage='pending' WHERE job_id=$1",[retrying]);
    const oldJobs=(await pool.query("SELECT * FROM certificate_jobs WHERE workspace_id=$1 ORDER BY id",[f.workspaceId])).rows;
    const oldDeployments=(await pool.query("SELECT * FROM certops_consumer_deployments WHERE workspace_id=$1 ORDER BY id",[f.workspaceId])).rows;
    migrations.push(...pending.filter(entry=>entry.version>84));
    await runMigrations();
    assert.deepEqual((await pool.query("SELECT * FROM migrations WHERE version<=84 ORDER BY version")).rows,beforeVerificationLedger);
    const backfilled=(await pool.query("SELECT verification_failure_count,verification_failure_revision FROM certops_consumer_current_state WHERE workspace_id=$1 AND binding_id=$2",[f.workspaceId,f.bindingId])).rows[0];
    assert.equal(Number(backfilled.verification_failure_count),1,"Fresh success resets the two earlier failures; the retrying failed cycle is retained from its log, not attempt_count=99");
    assert.equal(backfilled.verification_failure_revision,1);
    assert.equal((await pool.query("SELECT count(*)::int AS count FROM certops_consumer_verification_outcomes WHERE workspace_id=$1",[f.workspaceId])).rows[0].count,5);
    assert.deepEqual((await pool.query("SELECT * FROM certificate_jobs WHERE workspace_id=$1 ORDER BY id",[f.workspaceId])).rows,oldJobs);
    assert.deepEqual((await pool.query("SELECT * FROM certops_consumer_deployments WHERE workspace_id=$1 ORDER BY id",[f.workspaceId])).rows,oldDeployments);
    assert.deepEqual((await pool.query("SELECT * FROM migrations WHERE version<=72 ORDER BY version")).rows, originalLedger);
    assert.deepEqual((await pool.query("SELECT * FROM migrations WHERE version<=80 ORDER BY version")).rows, currentMainLedger);
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
      { version: 81, name: "certops_distribution_lifecycle" },
      { version: 82, name: "certops_distribution_incident_delivery" },
      { version: 83, name: "certops_stable_consumer_discovery" },
      { version: 84, name: "certops_material_cleanup" },
      { version: 85, name: "certops_consumer_verification_failures" },
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

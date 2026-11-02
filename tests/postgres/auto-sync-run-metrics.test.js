"use strict";

const { before, beforeEach, after, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { pool } = require("../../apps/api/db/database");
const { Registry } = require("../../apps/api/node_modules/prom-client");
const { registerAutoSyncMetrics } = require("../../apps/api/services/autoSyncMetrics");

let userId, workspaceId;
async function start(client = pool, provider = "github", started = "2026-10-26T10:00:00Z") {
  return (await client.query(`INSERT INTO auto_sync_runs
    (workspace_id, config_id_snapshot, provider, name_snapshot, trigger, generation, scan_version, started_at)
    VALUES ($1,$2,$3,'Metrics test','schedule',1,1,$4) RETURNING run_id`,
  [workspaceId, crypto.randomUUID(), provider, started])).rows[0].run_id;
}
async function finish(id, status, client = pool, finished = "2026-10-26T10:01:00Z") {
  await client.query("UPDATE auto_sync_runs SET status=$2, finished_at=$3 WHERE run_id=$1", [id, status, finished]);
}
async function snapshot() {
  const registry = new Registry();
  registerAutoSyncMetrics(registry);
  return Object.fromEntries((await registry.getMetricsAsJSON()).map(metric => [metric.name, metric.values]));
}
async function count(status) {
  return Number((await pool.query("SELECT runs_total FROM auto_sync_run_outcome_stats WHERE provider='github' AND status=$1", [status])).rows[0]?.runs_total || 0);
}

describe("PostgreSQL durable auto-sync run metrics", { concurrency: false }, () => {
  before(async () => {
    assert.match(process.env.DB_NAME || "", /_issue71_test$/);
    userId = (await pool.query("INSERT INTO users(email, display_name, password_hash) VALUES ($1,'Metrics test','test-only') RETURNING id",
      [`metrics-${crypto.randomUUID()}@example.test`])).rows[0].id;
  });
  beforeEach(async () => {
    if (workspaceId) await pool.query("DELETE FROM workspaces WHERE id=$1", [workspaceId]);
    await pool.query("TRUNCATE auto_sync_run_outcome_stats, auto_sync_run_freshness");
    workspaceId = crypto.randomUUID();
    await pool.query("INSERT INTO workspaces(id, name, created_by) VALUES ($1,'Metrics test',$2)", [workspaceId, userId]);
  });
  after(async () => {
    if (workspaceId) await pool.query("DELETE FROM workspaces WHERE id=$1", [workspaceId]);
    await pool.end();
  });

  it("exposes zero outcomes and unknown freshness before the first run", async () => {
    const metrics = await snapshot();
    assert.equal(metrics.auto_sync_run_outcomes_total.length, 8);
    assert.ok(metrics.auto_sync_run_outcomes_total.every(sample => sample.value === 0));
    assert.ok(metrics.auto_sync_last_attempt_timestamp_seconds.every(sample => sample.value === 0));
    assert.ok(metrics.auto_sync_last_success_timestamp_seconds.every(sample => sample.value === 0));
  });

  it("records attempts at start and counts each terminal outcome once", async () => {
    for (const status of ["success", "partial", "failed", "superseded"]) {
      const id = await start();
      await finish(id, status);
      await finish(id, status);
      await pool.query("UPDATE auto_sync_runs SET error_text='metadata edit' WHERE run_id=$1", [id]);
      assert.equal(await count(status), 1);
    }
    const metrics = await snapshot();
    assert.equal(metrics.auto_sync_last_attempt_timestamp_seconds.find(s => s.labels.provider === "github").value, Date.parse("2026-10-26T10:00:00Z") / 1000);
    assert.equal(metrics.auto_sync_last_success_timestamp_seconds.find(s => s.labels.provider === "github").value, Date.parse("2026-10-26T10:01:00Z") / 1000);
  });

  it("rolls back attempted starts and terminal outcomes with their run transaction", async () => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await start(client);
      await client.query("ROLLBACK");
      assert.equal((await pool.query("SELECT 1 FROM auto_sync_run_freshness")).rowCount, 0);
      const id = await start();
      await client.query("BEGIN");
      await finish(id, "success", client);
      await client.query("ROLLBACK");
      assert.equal(await count("success"), 0);
      assert.equal((await pool.query("SELECT last_success_at FROM auto_sync_run_freshness")).rows[0].last_success_at, null);
      await finish(id, "success");
      assert.equal(await count("success"), 1);
    } finally { client.release(); }
  });

  it("does not move freshness backwards when old runs complete late or fail", async () => {
    const old = await start();
    const current = await start(pool, "github", "2026-10-26T12:00:00Z");
    await finish(current, "success", pool, "2026-10-26T12:01:00Z");
    await finish(old, "success");
    const failure = await start(pool, "github", "2026-10-26T13:00:00Z");
    await finish(failure, "failed", pool, "2026-10-26T13:01:00Z");
    const row = (await pool.query("SELECT * FROM auto_sync_run_freshness WHERE provider='github'")).rows[0];
    assert.equal(row.last_attempt_at.toISOString(), "2026-10-26T13:00:00.000Z");
    assert.equal(row.last_success_at.toISOString(), "2026-10-26T12:01:00.000Z");
  });

  it("rolls back telemetry when a deferred run constraint rejects COMMIT", async () => {
    const id = await start();
    const name = `metrics_reject_${crypto.randomUUID().replaceAll("-", "")}`;
    const client = await pool.connect();
    try {
      await pool.query(`CREATE FUNCTION ${name}() RETURNS TRIGGER LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'forced run commit failure'; END; $$`);
      await pool.query(`CREATE CONSTRAINT TRIGGER ${name} AFTER UPDATE ON auto_sync_runs
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
        WHEN (NEW.run_id = '${id}'::uuid) EXECUTE FUNCTION ${name}()`);
      await client.query("BEGIN");
      await finish(id, "success", client);
      await assert.rejects(client.query("COMMIT"), /forced run commit failure/);
      await client.query("ROLLBACK");
      assert.equal(await count("success"), 0);
      assert.equal((await pool.query("SELECT last_success_at FROM auto_sync_run_freshness")).rows[0].last_success_at, null);
      assert.equal((await pool.query("SELECT status FROM auto_sync_runs WHERE run_id=$1", [id])).rows[0].status, "running");
    } finally {
      await pool.query(`DROP TRIGGER IF EXISTS ${name} ON auto_sync_runs`);
      await pool.query(`DROP FUNCTION IF EXISTS ${name}()`);
      client.release();
    }
  });

  it("starts at rollout without backfilling old terminal runs and observes an in-flight completion", async () => {
    const { migrations } = require("../../apps/api/migrations/migrate");
    const migration = migrations.find(entry => entry.version === 80);
    const schema = `metrics_upgrade_${crypto.randomUUID().replaceAll("-", "")}`;
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(`CREATE SCHEMA ${schema}`);
      await client.query(`SET LOCAL search_path TO ${schema}, public`);
      await client.query("CREATE TABLE auto_sync_runs (LIKE public.auto_sync_runs INCLUDING ALL)");
      const historical = await start(client);
      await finish(historical, "success", client);
      const inFlight = await start(client);
      await client.query(migration.sql);
      assert.equal((await client.query("SELECT 1 FROM auto_sync_run_outcome_stats")).rowCount, 0);
      assert.equal((await client.query("SELECT 1 FROM auto_sync_run_freshness")).rowCount, 0);
      await finish(inFlight, "partial", client);
      assert.equal((await client.query("SELECT runs_total::text AS total FROM auto_sync_run_outcome_stats")).rows[0].total, "1");
    } finally {
      await client.query("ROLLBACK");
      client.release();
    }
  });

  it("counts concurrent completions once and retains metrics after workspace deletion and collector restart", async () => {
    const ids = await Promise.all(Array.from({ length: 12 }, () => start()));
    await Promise.all(ids.flatMap(id => [finish(id, "success"), finish(id, "success")]));
    assert.equal(await count("success"), 12);
    const beforeDeletion = await snapshot();
    await pool.query("DELETE FROM workspaces WHERE id=$1", [workspaceId]);
    workspaceId = null;
    assert.deepEqual(await snapshot(), beforeDeletion);
    const registry = new Registry(Registry.OPENMETRICS_CONTENT_TYPE);
    registerAutoSyncMetrics(registry);
    assert.match(await registry.metrics(), /auto_sync_run_outcomes_total\{provider="github",status="success"\} 12/);
    assert.doesNotMatch(await registry.metrics(), /outcomes_total_total/);
  });
});

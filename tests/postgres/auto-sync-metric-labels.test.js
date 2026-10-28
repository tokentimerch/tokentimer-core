"use strict";

// Run against a migrated, disposable database whose name ends in _metric_labels_test.
// This suite uses real PostgreSQL transactions, locks, routes, and token models.
const { before, beforeEach, after, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const request = require("supertest");
const express = require("../../apps/api/node_modules/express");
const { pool } = require("../../apps/api/db/database");
const provenance = require("../../apps/api/services/autoSyncProvenance");
const { persistScan } = require("../../apps/api/services/integrationScans");

let runs, workerPool, userId, workspaceId, app;
let sequence = 0;
const source = { source_provider: "gitlab", source_instance: "gitlab.example",
  source_owner_key: "17", source_kind: "gitlab-project-token", source_object_id: "42" };

async function configuration(name = `Config ${++sequence}`) {
  const result = await pool.query(`INSERT INTO auto_sync_configs
    (workspace_id, provider, credentials_encrypted, connection_key, created_by, next_sync_at)
    VALUES ($1, 'gitlab', 'test-only', $2, $3, NOW() + INTERVAL '1 day') RETURNING *`,
  [workspaceId, name, userId]);
  return result.rows[0];
}
async function start(config) {
  await pool.query("UPDATE auto_sync_configs SET next_sync_at = NOW() WHERE id = $1", [config.id]);
  const [claimed] = await runs.claimDueAutoSyncRuns();
  assert.equal(claimed.id, config.id);
  return { config: claimed, context: { configId: claimed.id, workspaceId, provider: "gitlab",
    runId: claimed.runId, generation: claimed.generation, scanVersion: Number(claimed.scanVersion), leaseOwner: claimed.leaseOwner } };
}
async function scan(run, items = [], complete = true) {
  const result = await persistScan({ workspaceId, provider: "gitlab",
    identityContext: { host: source.source_instance, ownerKey: source.source_owner_key },
    createdBy: userId, items: items.map(id => ({ sourceKind: source.source_kind, sourceObjectId: id, dimensions: { project: "platform/backend", group: "platform" } })),
    subScopes: [{ sourceKind: source.source_kind, complete }], request: {
      isWorkerCall: true, integrationScanStartedAt: new Date(), body: { auto_sync_run: runs.runContext(run.config) } } });
  run.context.scanId = result.scanId;
  return result.scanId;
}
async function imported(run, extra = {}, manual = false) {
  return provenance.upsertImportedToken({ context: manual ? null : run.context,
    payload: { name: "Shared credential", location: "gitlab.example", type: "api_key", category: "key_secret",
      expiration: "2028-01-01", ...source, source_dimensions: { project: "platform/backend", group: "platform" }, source_observed_at: new Date(), ...extra },
    workspaceId, userId, manual, assignMembership() {} });
}
async function finish(run) {
  return runs.withCurrentRun(run.config, client => runs.finishAutoSyncRun(client, run.config, { status: "success" }));
}
async function createdTotal(provider = "gitlab") {
  const result = await pool.query(
    "SELECT items_created_total FROM auto_sync_provider_stats WHERE provider = $1",
    [provider],
  );
  assert.equal(result.rowCount, 1, `Persistent statistics exist for ${provider}`);
  return BigInt(result.rows[0].items_created_total);
}

// Fail an actual PostgreSQL write or COMMIT. Unlike a mocked rollback, this
// detects a counter accidentally written through a separate/autocommit client.
async function withRejectedCreation({ atCommit }, work) {
  const name = `auto_sync_metrics_${crypto.randomUUID().replaceAll("-", "")}`;
  const table = atCommit ? "tokens" : "auto_sync_provider_stats";
  await pool.query(`CREATE FUNCTION ${name}() RETURNS TRIGGER LANGUAGE plpgsql AS $$
    BEGIN
      RAISE EXCEPTION 'forced creation counter test failure';
    END;
  $$`);
  try {
    if (atCommit) {
      await pool.query(`CREATE CONSTRAINT TRIGGER ${name}
        AFTER INSERT ON tokens DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW WHEN (NEW.workspace_id = '${workspaceId}'::uuid)
        EXECUTE FUNCTION ${name}()`);
    } else {
      await pool.query(`CREATE TRIGGER ${name}
        BEFORE INSERT OR UPDATE ON auto_sync_provider_stats
        FOR EACH ROW WHEN (NEW.provider = 'gitlab')
        EXECUTE FUNCTION ${name}()`);
    }
    await work();
  } finally {
    await pool.query(`DROP TRIGGER IF EXISTS ${name} ON ${table}`);
    await pool.query(`DROP FUNCTION IF EXISTS ${name}()`);
  }
}

describe("PostgreSQL selectable auto-sync metrics", { concurrency: false }, () => {
  before(async () => {
    assert.match(process.env.DB_NAME || "", /_metric_labels_test$/, "Use a disposable metric-label test database");
    ({ pool: workerPool } = await import("../../apps/worker/src/db.js"));
    runs = await import("../../apps/worker/src/shared/autoSyncRuns.js");
    assert.equal((await pool.query("SELECT 1 FROM migrations WHERE version = 61")).rowCount, 1);
    userId = (await pool.query(`INSERT INTO users(email, display_name, email_verified, password_hash)
      VALUES ($1, 'Fencing test', TRUE, 'test-only-hash') RETURNING id`, [`issue71-${crypto.randomUUID()}@example.test`])).rows[0].id;
    app = express();
    app.use(express.json());
    app.use((req, _res, next) => {
      req.user = req.get("Authorization") === "Bearer issue71-test-worker" ? null : { id: userId, email_verified: true };
      req.isAuthenticated = () => true;
      next();
    });
    app.use(require("../../apps/api/routes/admin"));
    process.env.WORKER_API_KEY = "issue71-test-worker";
    app.use(require("../../apps/api/routes/integrations"));
  });
  beforeEach(async () => {
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "asset_name,project,group";
    if (workspaceId) await pool.query("DELETE FROM workspaces WHERE id = $1", [workspaceId]);
    workspaceId = crypto.randomUUID();
    await pool.query("INSERT INTO workspaces(id, name, created_by) VALUES ($1, 'Fencing test', $2)", [workspaceId, userId]);
    await pool.query("INSERT INTO workspace_memberships(workspace_id, user_id, role) VALUES ($1,$2,'admin')", [workspaceId,userId]);
    await pool.query("UPDATE auto_sync_feature_state SET multi_config_enabled = TRUE WHERE id = TRUE");
  });
  after(async () => {
    if (workspaceId) await pool.query("DELETE FROM workspaces WHERE id = $1", [workspaceId]);
    // Audit history is immutable; the disposable database owns the user fixture.
    await workerPool?.end();
    await pool.end();
  });


  async function settings(config, labels = ["configuration_name", "monitoring_group", "kind", "asset_name", "project", "group"]) {
    await pool.query("UPDATE auto_sync_configs SET metrics_settings=$2 WHERE id=$1", [config.id,
      { enabled: true, labels, monitoring_group: "critical" }]);
  }
  async function metric(name) {
    const { Registry } = require("../../apps/api/node_modules/prom-client");
    const { registerAutoSyncMetrics } = require("../../apps/api/services/autoSyncMetrics");
    const registry = new Registry(); registerAutoSyncMetrics(registry);
    return (await registry.getSingleMetric(name).get()).values;
  }
  async function kindTotal() {
    return BigInt((await pool.query("SELECT items_created_total FROM auto_sync_kind_stats WHERE provider='gitlab' AND kind='gitlab-project-token'"))?.rows[0]?.items_created_total || 0);
  }
  it("counts each committed creation once and retains selected names and timestamps across collector restarts", async () => {
    const config = await configuration(); await settings(config);
    const run = await start(config); await scan(run, ["42"]);
    const initial = await createdTotal(), kinds = await kindTotal();
    await imported(run); await imported(run);
    assert.equal(await createdTotal(), initial + 1n); assert.equal(await kindTotal(), kinds + 1n);
    for (let attempt = 0; attempt < 2; attempt++) {
      const values = await metric("auto_sync_items_created_detailed_total");
      assert.equal(values.length, 1); assert.equal(values[0].value, 1);
      assert.equal(values[0].labels.configuration_id, config.id);
      assert.equal(values[0].labels.asset_name, "Shared credential");
      assert.equal(values[0].labels.project, "platform/backend");
      assert.equal(values[0].labels.group, "platform");
      assert.equal(values[0].labels.monitoring_group, "critical");
    }
    const timestamp = (await metric("auto_sync_last_creation_timestamp_seconds"))[0].value;
    assert.ok(timestamp > Date.now() / 1000 - 60); assert.ok(timestamp <= Date.now() / 1000 + 1);
  });
  it("does not capture or expose detailed names by default, and hiding labels takes effect immediately", async () => {
    const config = await configuration(); const run = await start(config); await scan(run, ["42"]);
    await imported(run);
    assert.equal((await pool.query("SELECT asset_name, project, group_name FROM auto_sync_creation_stats WHERE config_id=$1", [config.id])).rows[0].asset_name, "");
    assert.deepEqual(await metric("auto_sync_items_created_detailed_total"), []);
    await settings(config, ["kind", "configuration_name"]);
    assert.equal((await metric("auto_sync_items_created_detailed_total"))[0].labels.asset_name, "");
    await pool.query("UPDATE auto_sync_configs SET metrics_settings='{\"enabled\":false,\"labels\":[]}' WHERE id=$1", [config.id]);
    assert.deepEqual(await metric("auto_sync_items_created_detailed_total"), []);
  });
  it("attributes an overlapping discovery to the configuration that actually created the asset", async () => {
    const first = await configuration("Critical"), second = await configuration("Other");
    await settings(first); await settings(second);
    const runA = await start(first); await scan(runA, ["42"]); await imported(runA); await finish(runA);
    const runB = await start(second); await scan(runB, ["42"]); await imported(runB);
    const values = await metric("auto_sync_items_created_detailed_total");
    assert.equal(values.length, 1); assert.equal(values[0].labels.configuration_id, first.id);
  });
  it("rolls back inventory and every counter when the detailed statistics write fails", async () => {
    const config = await configuration(); await settings(config); const run = await start(config); await scan(run, ["42"]);
    const initial = await createdTotal(), kinds = await kindTotal();
    await pool.query("CREATE FUNCTION reject_metric_detail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic detail failure'; END $$");
    await pool.query("CREATE TRIGGER reject_metric_detail BEFORE INSERT ON auto_sync_creation_stats FOR EACH ROW EXECUTE FUNCTION reject_metric_detail()");
    try { await assert.rejects(imported(run), /synthetic detail failure/); }
    finally { await pool.query("DROP TRIGGER reject_metric_detail ON auto_sync_creation_stats"); await pool.query("DROP FUNCTION reject_metric_detail()"); }
    assert.equal(await createdTotal(), initial); assert.equal(await kindTotal(), kinds);
    assert.equal((await pool.query("SELECT 1 FROM tokens WHERE workspace_id=$1", [workspaceId])).rowCount, 0);
  });
  it("rolls back both new breakdowns when COMMIT is rejected", async () => {
    const config = await configuration(); const run = await start(config); await scan(run, ["42"]);
    const initial = await createdTotal(), kinds = await kindTotal();
    await withRejectedCreation({ atCommit: true }, async () => { await assert.rejects(imported(run), /forced creation counter test failure/); });
    assert.equal(await createdTotal(), initial); assert.equal(await kindTotal(), kinds);
    assert.equal((await pool.query("SELECT 1 FROM auto_sync_creation_stats WHERE config_id=$1", [config.id])).rowCount, 0);
  });
  it("saves label preferences through the workspace API without restarting an active scan", async () => {
    const config = await configuration(); const run = await start(config);
    const response = await request(app).put(`/api/v1/workspaces/${workspaceId}/auto-sync/${config.id}`)
      .send({ metrics_settings: { enabled: true, labels: ["kind", "monitoring_group"], monitoring_group: " critical " } });
    assert.equal(response.status, 200, JSON.stringify(response.body));
    assert.equal(response.body.metrics_settings.monitoring_group, "critical");
    const updated = (await pool.query("SELECT active_run_id, scan_version FROM auto_sync_configs WHERE id=$1", [config.id])).rows[0];
    assert.equal(updated.active_run_id, run.context.runId); assert.equal(Number(updated.scan_version), run.context.scanVersion);
    const invalid = await request(app).put(`/api/v1/workspaces/${workspaceId}/auto-sync/${config.id}`).send({ metrics_settings: { enabled: true, labels: ["secret"] } });
    assert.equal(invalid.status, 400);
    const listed = await request(app).get(`/api/v1/workspaces/${workspaceId}/auto-sync`);
    assert.equal(listed.body.items[0].metrics_settings.monitoring_group, "critical");
  });
  it("removes per-config details on deletion while retaining global creation/type history", async () => {
    const config = await configuration(); await settings(config); const run = await start(config); await scan(run, ["42"]); await imported(run); await finish(run);
    const initial = await createdTotal(), kinds = await kindTotal();
    await pool.query("DELETE FROM auto_sync_configs WHERE id=$1", [config.id]);
    assert.deepEqual(await metric("auto_sync_items_created_detailed_total"), []);
    assert.equal(await createdTotal(), initial); assert.equal(await kindTotal(), kinds);
  });
  it("aggregates hidden asset dimensions and uses new series when names or selections change", async () => {
    const config = await configuration(); await settings(config);
    const run = await start(config); await scan(run, ["42", "43"]);
    await imported(run); await imported(run, { name: "Second credential", source_object_id: "43", location: "second-location" });
    assert.equal((await metric("auto_sync_items_created_detailed_total")).length, 2);
    await settings(config, ["kind", "configuration_name"]);
    const combined = (await metric("auto_sync_items_created_detailed_total"))[0];
    assert.equal(combined.value, 2); assert.equal(combined.labels.asset_name, "");
    await pool.query("UPDATE auto_sync_configs SET connection_key='Renamed' WHERE id=$1", [config.id]);
    const renamed = (await metric("auto_sync_items_created_detailed_total"))[0];
    assert.equal(renamed.value, 2); assert.equal(renamed.labels.configuration_id, config.id);
    assert.equal(renamed.labels.configuration_name, "Renamed");
  });
  it("supports long UTF-8 scope names without exceeding PostgreSQL index limits", async () => {
    const config = await configuration(); await settings(config); const run = await start(config); await scan(run, ["42"]);
    const project = "界".repeat(512), group = "組".repeat(512);
    await imported(run, { source_dimensions: { project, group } });
    const value = (await metric("auto_sync_items_created_detailed_total"))[0];
    assert.equal(value.labels.project, project); assert.equal(value.labels.group, group);
  });

  it("enforces the deployment allowlist for storage, export and API policy despite saved preferences", async () => {
    const config = await configuration(); await settings(config); const run = await start(config); await scan(run, ["42", "43"]);
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "";
    await imported(run);
    const stored = (await pool.query("SELECT asset_name, project, group_name FROM auto_sync_creation_stats WHERE config_id=$1", [config.id])).rows[0];
    assert.deepEqual(stored, { asset_name: "", project: "", group_name: "" });
    const response = await request(app).get(`/api/v1/workspaces/${workspaceId}/auto-sync`);
    assert.equal(response.body.metric_label_policy.extra_labels.length, 0);
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "asset_name,project,group";
    await imported(run, { name: "Second credential", source_object_id: "43", location: "second-location" });
    assert.ok((await metric("auto_sync_items_created_detailed_total")).some(sample => sample.labels.asset_name === "Second credential"));
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "project";
    const partial = await metric("auto_sync_items_created_detailed_total");
    assert.ok(partial.every(sample => sample.labels.asset_name === "" && sample.labels.group === ""));
    assert.ok(partial.some(sample => sample.labels.project === "platform/backend"));
    const policy = await request(app).get(`/api/v1/workspaces/${workspaceId}/auto-sync`);
    assert.deepEqual(policy.body.metric_label_policy.extra_labels, ["project"]);
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "";
    const hidden = await metric("auto_sync_items_created_detailed_total");
    assert.ok(hidden.every(sample => sample.labels.asset_name === "" && sample.labels.project === "" && sample.labels.group === ""));
    assert.equal(hidden.reduce((total, sample) => total + sample.value, 0), 2);
  });

});

"use strict";

// Run against a migrated, disposable database whose name ends in _metric_labels_test.
// This suite uses real PostgreSQL transactions, locks, routes, and token models.
const { before, beforeEach, after, describe, it, mock } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const request = require("supertest");
const express = require("../../apps/api/node_modules/express");
const { pool } = require("../../apps/api/db/database");
const provenance = require("../../apps/api/services/autoSyncProvenance");
const { persistScan } = require("../../apps/api/services/integrationScans");
const { gitlabPatFixture } = require("../helpers/gitlab-pat-fixture");

let runs, workerPool, userId, workspaceId, app;
let sequence = 0;
const source = { source_provider: "gitlab", source_instance: "gitlab.example",
  source_owner_key: "17", source_kind: "gitlab-project-token", source_object_id: "42" };
const providerScanFixtures = new Map();

async function configuration(name = `Config ${++sequence}`, provider = "gitlab") {
  const result = await pool.query(`INSERT INTO auto_sync_configs
    (workspace_id, provider, credentials_encrypted, connection_key, created_by, next_sync_at)
    VALUES ($1, $2, 'test-only', $3, $4, NOW() + INTERVAL '1 day') RETURNING *`,
  [workspaceId, provider, name, userId]);
  return result.rows[0];
}
async function start(config) {
  await pool.query("UPDATE auto_sync_configs SET next_sync_at = NOW() WHERE id = $1", [config.id]);
  const [claimed] = await runs.claimDueAutoSyncRuns();
  assert.equal(claimed.id, config.id);
  return { config: claimed, context: { configId: claimed.id, workspaceId, provider: claimed.provider,
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
    assert.equal((await pool.query("SELECT 1 FROM migrations WHERE version = 111")).rowCount, 1);
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
    // Stub only the provider boundary. The HTTP scan routes still apply
    // their own provenance mapping, fencing and response serialization.
    for (const [provider, moduleName, method] of [
      ["github", "githubIntegration", "scanGitHub"],
      ["gitlab", "gitlabIntegration", "scanGitLab"],
      ["aws", "awsIntegration", "scanAWS"],
      ["azure", "azureIntegration", "scanAzure"],
      ["azure-ad", "azureADIntegration", "scanAzureAD"],
      ["gcp", "gcpIntegration", "scanGCP"],
      ["vault", "vaultIntegration", "scanVault"],
    ]) {
      const scanner = require(`../../apps/api/services/${moduleName}`);
      const original = scanner[method];
      mock.method(scanner, method, (...args) => providerScanFixtures.has(provider)
        ? structuredClone(providerScanFixtures.get(provider)) : original(...args));
    }
    app.use(require("../../apps/api/routes/integrations"));
    require("../../apps/api/services/autoSyncMetrics").registerAutoSyncMetrics(
      require("../../apps/api/node_modules/prom-client").register,
    );
    app.use(require("../../apps/api/routes/health"));
  });
  beforeEach(async () => {
    providerScanFixtures.clear();
    await pool.query('UPDATE users SET is_admin=FALSE WHERE id=$1',[userId]);
    delete process.env.AUTO_SYNC_METRICS_ENABLED;
    delete process.env.AUTO_SYNC_METRICS_LABELS;
    delete process.env.AUTO_SYNC_METRICS_MONITORING_GROUP;
    await pool.query("UPDATE system_settings SET auto_sync_metrics = '{}'::jsonb WHERE id=1");
    require("../../apps/api/services/systemSettings").invalidateCache();
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "asset_name,project,group";
    if (workspaceId) await pool.query("DELETE FROM workspaces WHERE id = $1", [workspaceId]);
    workspaceId = crypto.randomUUID();
    await pool.query("INSERT INTO workspaces(id, name, created_by) VALUES ($1, 'Fencing test', $2)", [workspaceId, userId]);
    await pool.query("INSERT INTO workspace_memberships(workspace_id, user_id, role) VALUES ($1,$2,'admin')", [workspaceId,userId]);
    await pool.query("UPDATE auto_sync_feature_state SET multi_config_enabled = TRUE WHERE id = TRUE");
  });
  after(async () => {
    mock.restoreAll();
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
  async function ownerScan(run, entries, { manual = false } = {}) {
    const result = await persistScan({
      workspaceId, provider: "gitlab", createdBy: userId,
      identityContext: { host: source.source_instance, ownerKey: source.source_owner_key },
      items: entries.map(([id, owner, kind = "gitlab-pat", expiration]) => ({
        sourceKind: kind, sourceObjectId: id,
        dimensions: { project: "platform/backend", ...(owner === undefined ? {} : { owner_username: owner }),
          ...(expiration === undefined ? {} : { expiration }) },
      })),
      subScopes: [{ sourceKind: "gitlab-pat", complete: true }],
      request: manual ? null : {
        isWorkerCall: true, integrationScanStartedAt: new Date(),
        body: { auto_sync_run: runs.runContext(run.config) },
      },
    });
    if (!manual) run.context.scanId = result.scanId;
    return result.scanId;
  }
  async function ownerImport(run, id, extra = {}, kind = "gitlab-pat") {
    const { bindImportItemsToScan } = require("../../apps/api/services/scanBinding");
    const binding = await bindImportItemsToScan({
      scanId: run.context.scanId, workspaceId, provider: "gitlab",
      pairs: [{ sourceKind: kind, sourceObjectId: id, owner_username: "client-spoof" }],
    });
    const authoritative = binding.resolveForItem(0);
    assert.ok(authoritative, "Owner imports must bind to a persisted scan item");
    return provenance.upsertImportedToken({
      context: run.context, workspaceId, userId, manual: false, assignMembership() {},
      payload: {
        name: `Owner credential ${id}`, location: `owner-location-${id}`,
        type: "api_key", category: "key_secret", expiration: "2028-01-01",
        source_dimensions: { owner_username: "client-spoof" },
        ...extra, ...authoritative,
      },
    });
  }
  async function ownerRows(config) {
    return (await pool.query(
      `SELECT dimension_key, owner_username, items_created_total, last_created_at
       FROM auto_sync_creation_stats WHERE config_id=$1 ORDER BY dimension_key`,
      [config.id],
    )).rows;
  }
  async function ownerSettings(config, enabled = true, labels = ["kind", "owner_username"]) {
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "owner_username";
    await pool.query("UPDATE auto_sync_configs SET metrics_settings=$2 WHERE id=$1",
      [config.id, { enabled, inherit_system: false, labels }]);
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
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "none";
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
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "none";
    const hidden = await metric("auto_sync_items_created_detailed_total");
    assert.ok(hidden.every(sample => sample.labels.asset_name === "" && sample.labels.project === "" && sample.labels.group === ""));
    assert.equal(hidden.reduce((total, sample) => total + sample.value, 0), 2);
  });

  it("serves valid Prometheus text with escaped metadata and suppresses details when disabled", async () => {
    const config = await configuration(); await settings(config);
    const run = await start(config); await scan(run, ["42"]);
    const name = 'Credential "blue"\\lane\nrotated';
    await imported(run, { name });
    const { Registry } = require("../../apps/api/node_modules/prom-client");
    const { registerAutoSyncMetrics } = require("../../apps/api/services/autoSyncMetrics");
    const registry = new Registry(); registerAutoSyncMetrics(registry);
    app.get("/test-metrics", async (_req, res, next) => {
      try { res.type(registry.contentType).send(await registry.metrics()); } catch (error) { next(error); }
    });
    const response = await request(app).get("/test-metrics");
    assert.equal(response.status, 200);
    assert.match(response.headers["content-type"], /text\/plain/);
    const samples = response.text.split("\n").filter(line => line.includes('configuration_id="' + config.id + '"'));
    assert.equal(samples.length, 2, "one creation counter and one last-creation timestamp");
    const escaped = name.replaceAll("\\", "\\\\").replaceAll('"', '\\"').replaceAll("\n", "\\n");
    assert.ok(samples.every(line => line.includes('asset_name="' + escaped + '"')));
    assert.ok(samples.some(line => line.startsWith("auto_sync_items_created_detailed_total{") && line.endsWith(" 1")));
    assert.ok(samples.some(line => line.startsWith("auto_sync_last_creation_timestamp_seconds{")));
    await pool.query("UPDATE auto_sync_configs SET metrics_settings=$2 WHERE id=$1", [config.id, { enabled: false, labels: [] }]);
    const disabled = await request(app).get("/test-metrics");
    assert.equal(disabled.status, 200);
    assert.ok(!disabled.text.includes('configuration_id="' + config.id + '"'));
    assert.ok(disabled.text.includes("auto_sync_items_created_total{"), "existing provider counters remain exposed");
  });

  it("applies system defaults to existing and new connections, including the critical group", async () => {
    delete process.env.AUTO_SYNC_METRICS_EXTRA_LABELS;
    const existing=await configuration();
    await pool.query("UPDATE users SET is_admin=TRUE WHERE id=$1",[userId]);
    const update=await request(app).put('/api/v1/admin/auto-sync/metrics').send({enabled:true,labels:['configuration_name','monitoring_group','kind']});
    assert.equal(update.status,200,JSON.stringify(update.body));
    for (const [config,objectId] of [[existing,'existing'],[await configuration(),'new']]) {
      const saved=await request(app).put(`/api/v1/workspaces/${workspaceId}/auto-sync/${config.id}`).send({metrics_settings:{inherit_system:true,monitoring_group:'critical'}});
      assert.equal(saved.status,200,JSON.stringify(saved.body));
      const run=await start(config);await scan(run,[objectId]);await imported(run,{name:objectId,location:objectId,source_object_id:objectId});
      const row=(await metric('auto_sync_items_created_detailed_total')).find(s=>s.labels.configuration_id===config.id);
      assert.equal(row.value,1);assert.equal(row.labels.monitoring_group,'critical');assert.equal(row.labels.asset_name,'');await finish(run);
    }
    await pool.query('UPDATE users SET is_admin=FALSE WHERE id=$1',[userId]);
  });
  it("exports inherited metrics for older client payloads without an inheritance field", async () => {
    delete process.env.AUTO_SYNC_METRICS_EXTRA_LABELS;
    await pool.query("UPDATE system_settings SET auto_sync_metrics=$1 WHERE id=1", [{enabled:true,labels:['kind']}]);
    const config=await configuration();
    await pool.query("UPDATE auto_sync_configs SET metrics_settings=$2 WHERE id=$1", [config.id,{enabled:false,labels:[]}]);
    const run=await start(config); await scan(run,['legacy']);
    await imported(run,{name:'legacy',location:'legacy',source_object_id:'legacy'});
    const sample=(await metric('auto_sync_items_created_detailed_total')).find(s=>s.labels.configuration_id===config.id);
    assert.equal(sample.value,1); assert.equal(sample.labels.kind,'gitlab-project-token');
    await finish(run);
  });
  it("enforces system-admin writes, typed values and env-locked global disable", async () => {
    const url='/api/v1/admin/auto-sync/metrics';
    assert.equal((await request(app).get(url)).status,403);
    assert.equal((await request(app).put(url).send({enabled:true,labels:['kind']})).status,403);
    await pool.query('UPDATE users SET is_admin=TRUE WHERE id=$1',[userId]);
    assert.equal((await request(app).put(url).send({enabled:'true',labels:['kind']})).status,400);
    assert.equal((await request(app).put(url).send({enabled:true,labels:['secret']})).status,400);
    process.env.AUTO_SYNC_METRICS_ENABLED='false';
    const saved=await request(app).put(url).send({override_metrics:true,enabled:true,labels:['kind']});
    assert.equal(saved.status,200);assert.equal(saved.body.enabled,false);assert.equal(saved.body.locked,true);assert.equal(saved.body.source,'env');
    assert.notEqual((await pool.query('SELECT auto_sync_metrics FROM system_settings WHERE id=1')).rows[0].auto_sync_metrics.enabled,true);
    delete process.env.AUTO_SYNC_METRICS_ENABLED;
    assert.equal((await request(app).get(url)).body.override_metrics,false);
    await pool.query('UPDATE users SET is_admin=FALSE WHERE id=$1',[userId]);
  });
  it("globally hides existing details and stops capturing new high-cardinality values",async()=>{
    const config=await configuration();await settings(config);const run=await start(config);await scan(run,['42','43']);await imported(run);
    assert.ok((await metric('auto_sync_items_created_detailed_total')).length);
    await pool.query("UPDATE system_settings SET auto_sync_metrics=$1 WHERE id=1",[{enabled:false,labels:['kind','asset_name','project','group']}]);
    assert.deepEqual(await metric('auto_sync_items_created_detailed_total'),[]);
    await imported(run,{name:'Globally disabled',location:'globally-disabled',source_object_id:'43'});
    const rows=(await pool.query('SELECT asset_name,project,group_name,items_created_total FROM auto_sync_creation_stats WHERE config_id=$1',[config.id])).rows;
    assert.ok(rows.some(row=>row.asset_name===''&&row.project===''&&row.group_name===''));
    assert.equal(rows.reduce((n,row)=>n+Number(row.items_created_total),0),2);
  });

  it("migration preserves explicit opt-ins and moves other connections onto inheritance",async()=>{
    const a=await configuration(),b=await configuration(),c=await configuration();
    await pool.query('UPDATE auto_sync_configs SET metrics_settings=$2 WHERE id=$1',[a.id,{enabled:true,labels:['kind']}]);
    await pool.query('UPDATE auto_sync_configs SET metrics_settings=$2 WHERE id=$1',[b.id,{enabled:false,labels:[]}]);
    await pool.query('UPDATE auto_sync_configs SET metrics_settings=$2 WHERE id=$1',[c.id,{enabled:false,inherit_system:false,labels:[]}]);
    await pool.query(require('node:fs').readFileSync(require('node:path').join(__dirname,'../../apps/api/migrations/082-auto-sync-system-metrics.sql'),'utf8'));
    const rows=(await pool.query('SELECT id,metrics_settings FROM auto_sync_configs WHERE workspace_id=$1',[workspaceId])).rows;
    assert.equal(rows.find(r=>r.id===a.id).metrics_settings.inherit_system,false);
    assert.equal(rows.find(r=>r.id===b.id).metrics_settings.inherit_system,true);
    assert.equal(rows.find(r=>r.id===c.id).metrics_settings.inherit_system,false);
  });
  it("UI-saved labels apply when env is unset and a deployment list takes precedence",async()=>{
    delete process.env.AUTO_SYNC_METRICS_EXTRA_LABELS;
    await pool.query('UPDATE users SET is_admin=TRUE WHERE id=$1',[userId]);
    const url='/api/v1/admin/auto-sync/metrics';
    const saved=await request(app).put(url).send({enabled:true,labels:['kind','asset_name']});assert.equal(saved.status,200);assert.ok(saved.body.labels.includes('asset_name'));assert.equal(saved.body.extra_labels_locked,false);
    const connections=await request(app).get(`/api/v1/workspaces/${workspaceId}/auto-sync`);
    assert.deepEqual(connections.body.metric_label_policy.extra_labels,['asset_name']);
    assert.equal(connections.body.metric_label_policy.system.enabled,true);
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS='project';
    const locked=await request(app).get(url);assert.equal(locked.body.extra_labels_locked,true);assert.ok(locked.body.labels.includes('project'));assert.ok(!locked.body.labels.includes('asset_name'));
    await request(app).put(url).send({enabled:true,labels:['kind','project']});
    delete process.env.AUTO_SYNC_METRICS_EXTRA_LABELS;
    const restored=await request(app).get(url);assert.ok(restored.body.labels.includes('asset_name'));assert.ok(!restored.body.labels.includes('project'));
  });

  it("forces both global overrides, rejects managed edits and restores independent local values", async () => {
    const config=await configuration();
    const path='/api/v1/workspaces/'+workspaceId+'/auto-sync/'+config.id;
    const local={enabled:false,labels:['kind','monitoring_group'],monitoring_group:'local'};
    assert.equal((await request(app).put(path).send({metrics_settings:local})).status,200);
    const run=await start(config);await scan(run,['42']);await imported(run);
    await pool.query('UPDATE users SET is_admin=TRUE WHERE id=$1',[userId]);
    const global='/api/v1/admin/auto-sync/metrics';
    const policy={override_metrics:true,enabled:true,labels:['kind','monitoring_group'],override_monitoring_group:true,monitoring_group:'critical'};
    assert.equal((await request(app).put(global).send(policy)).status,200);
    let sample=(await metric('auto_sync_items_created_detailed_total')).find(s=>s.labels.configuration_id===config.id);
    assert.equal(sample.value,1);assert.equal(sample.labels.monitoring_group,'critical');
    assert.equal((await request(app).put(path).send({metrics_settings:{...local,enabled:true}})).status,409);
    assert.equal((await request(app).put(path).send({metrics_settings:{...local,monitoring_group:'bypass'}})).status,409);
    assert.equal((await request(app).put(path).send({metrics_settings:local,name:'Still editable'})).status,200);
    assert.equal((await request(app).put(global).send({...policy,override_metrics:false})).status,200);
    assert.deepEqual(await metric('auto_sync_items_created_detailed_total'),[]);
    assert.equal((await request(app).put(path).send({metrics_settings:{...local,enabled:true}})).status,200);
    sample=(await metric('auto_sync_items_created_detailed_total'))[0];assert.equal(sample.labels.monitoring_group,'critical');
    assert.equal((await request(app).put(global).send({...policy,override_metrics:false,override_monitoring_group:false})).status,200);
    sample=(await metric('auto_sync_items_created_detailed_total'))[0];assert.equal(sample.labels.monitoring_group,'local');
    await finish(run);
  });
  it("keeps the monitoring-group environment override ahead of saved values and connection edits",async()=>{
    const config=await configuration();await settings(config);const run=await start(config);await scan(run,['42']);await imported(run);
    process.env.AUTO_SYNC_METRICS_MONITORING_GROUP='environment';
    await pool.query('UPDATE users SET is_admin=TRUE WHERE id=$1',[userId]);
    const global='/api/v1/admin/auto-sync/metrics';
    const saved=await request(app).put(global).send({override_metrics:false,enabled:true,labels:['kind'],override_monitoring_group:true,monitoring_group:'database'});
    assert.equal(saved.status,200);assert.equal(saved.body.monitoring_group,'environment');assert.equal(saved.body.monitoring_group_locked,true);
    const local=(await pool.query('SELECT metrics_settings FROM auto_sync_configs WHERE id=$1',[config.id])).rows[0].metrics_settings;
    assert.equal((await request(app).put('/api/v1/workspaces/'+workspaceId+'/auto-sync/'+config.id).send({metrics_settings:{...local,monitoring_group:'bypass'}})).status,409);
    assert.equal((await metric('auto_sync_items_created_detailed_total'))[0].labels.monitoring_group,'environment');
    delete process.env.AUTO_SYNC_METRICS_MONITORING_GROUP;
    assert.equal((await metric('auto_sync_items_created_detailed_total'))[0].labels.monitoring_group,'critical');
    await finish(run);
  });

  it("persists authoritative opted-in PAT owners but never copies them into inventory", async () => {
    const config = await configuration(); await ownerSettings(config);
    const run = await start(config);
    const scanId = await ownerScan(run, [["pat", "actual-owner"], ["project", "spoof", "gitlab-project-token"]]);
    const recorded = (await pool.query(
      "SELECT source_kind, source_dimensions FROM integration_scan_items WHERE scan_id=$1 ORDER BY source_kind",
      [scanId],
    )).rows;
    assert.equal(recorded.find(row => row.source_kind === "gitlab-pat").source_dimensions.owner_username, "actual-owner");
    assert.equal(Object.hasOwn(recorded.find(row => row.source_kind === "gitlab-project-token").source_dimensions, "owner_username"), false);
    const { token } = await ownerImport(run, "pat", {
      source_dimensions: { owner_username: "import-spoof" },
    });
    assert.equal((await ownerRows(config))[0].owner_username, "actual-owner");
    const stored = (await pool.query("SELECT source_dimensions FROM tokens WHERE id=$1", [token.id])).rows[0];
    assert.equal(Object.hasOwn(stored.source_dimensions, "owner_username"), false);
    assert.equal(stored.source_dimensions.project, "platform/backend");
    await ownerImport(run, "project", {}, "gitlab-project-token");
    assert.ok((await ownerRows(config)).some(row => row.owner_username === ""));
    const { bindImportItemsToScan } = require("../../apps/api/services/scanBinding");
    const absent = await bindImportItemsToScan({
      scanId, workspaceId, provider: "gitlab",
      pairs: [{ sourceKind: "gitlab-pat", sourceObjectId: "not-scanned", owner_username: "spoof" }],
    });
    assert.equal(absent.resolveForItem(0), null);
  });

  it("HTTP imports ignore owner spoofing and scrape only server-recorded PAT owners", async () => {
    const config = await configuration(); await ownerSettings(config);
    const run = await start(config);
    await ownerScan(run, [
      ["pat", "actual-owner"], ["unknown", undefined],
      ["project", "forged-project-owner", "gitlab-project-token"],
    ]);
    const response = await request(app)
      .post(`/api/v1/integrations/import?workspace_id=${workspaceId}`)
      .set("Authorization", "Bearer issue71-test-worker")
      .send({
        scan_id: run.context.scanId, auto_sync_run: runs.runContext(run.config),
        items: ["pat", "unknown", "project"].map(id => ({
          name: `HTTP credential ${id}`, location: `gitlab.example/${id}`,
          source: "gitlab", sourceKind: id === "project" ? "gitlab-project-token" : "gitlab-pat",
          sourceObjectId: id, type: "api_key", expiresAt: "2028-01-01",
          owner_username: "import-spoof", dimensions: { owner_username: "import-spoof" },
          source_dimensions: { owner_username: "import-spoof" },
        })),
      });
    assert.equal(response.status, 201, JSON.stringify(response.body));
    assert.equal(response.body.error_count, 0, JSON.stringify(response.body));
    assert.equal(response.body.created_count, 3);
    for (const name of ["auto_sync_items_created_detailed_total", "auto_sync_last_creation_timestamp_seconds"]) {
      const samples = await metric(name);
      assert.deepEqual(samples.map(sample => sample.labels.owner_username).sort(), ["", "", "actual-owner"]);
      assert.ok(samples.every(sample => sample.value > 0));
    }
    const inventory = (await pool.query(
      "SELECT source_dimensions FROM tokens WHERE workspace_id=$1", [workspaceId],
    )).rows;
    assert.ok(inventory.every(row => !Object.hasOwn(row.source_dimensions, "owner_username")));
  });

  it("keeps provider expiry on creation samples and ignores dates supplied by the importer", async () => {
    const config = await configuration();
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "expiration,asset_name";
    await settings(config, ["expiration", "asset_name", "kind"]);
    const run = await start(config);
    await ownerScan(run, [
      ["known-expiry", undefined, "gitlab-pat", "2032-02-29"],
      ["missing-expiry", undefined, "gitlab-pat"],
      ["deploy-expiry", undefined, "gitlab-deploy-token", "2032-03-01T01:00:00+01:00"],
    ]);
    const response = await request(app)
      .post(`/api/v1/integrations/import?workspace_id=${workspaceId}`)
      .set("Authorization", "Bearer issue71-test-worker")
      .send({
        scan_id: run.context.scanId, auto_sync_run: runs.runContext(run.config),
        items: ["known-expiry", "missing-expiry", "deploy-expiry"].map(id => ({
          name: id, location: `gitlab.example/${id}`,
          source: "gitlab", sourceKind: id === "deploy-expiry" ? "gitlab-deploy-token" : "gitlab-pat",
          sourceObjectId: id, type: "api_key", expiration: "2099-12-31",
          source_dimensions: { expiration: "2099-12-31" },
        })),
      });
    assert.equal(response.status, 201, JSON.stringify(response.body));
    assert.equal(response.body.created_count, 3);
    for (const metricName of ["auto_sync_items_created_detailed_total", "auto_sync_last_creation_timestamp_seconds"]) {
      const samples = await metric(metricName);
      assert.deepEqual(Object.fromEntries(samples.map(sample => [sample.labels.asset_name, sample.labels.expiration])), {
        "known-expiry": "2032-02-29", "missing-expiry": "", "deploy-expiry": "2032-03-01T00:00:00.000Z",
      });
      assert.ok(samples.every(sample => metricName.endsWith("_total") ? sample.value === 1 : sample.value > 0));
    }
    const { rows } = await pool.query("SELECT source_dimensions FROM tokens WHERE workspace_id=$1", [workspaceId]);
    assert.ok(rows.every(row => !Object.hasOwn(row.source_dimensions, "expiration")));
    await finish(run);
  });

  it("carries authoritative expiration through every provider scan and import route to HTTP metrics", async () => {
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "asset_name,expiration,owner_username";
    const token = "synthetic-provider-token";
    const authoritativeTime = "2032-03-01T01:02:03+01:00";
    const utcTime = "2032-03-01T00:02:03.000Z";
    const gcpExpiry = "2032-03-01T00:02:03.123456789Z";
    const fixture = (name, sourceKind, metricExpiration, attributes) => ({
      name, source: sourceKind, sourceKind, sourceObjectId: name,
      location: `fixture:${name}`, category: "key_secret", type: "api_key",
      expiration: "2032-03-01", metric_expiration: metricExpiration, ...attributes,
    });
    const cert = { category: "cert", type: "tls_cert" };
    const cases = [
      ["gitlab", { baseUrl: "https://gitlab.example", token }, { host: "gitlab.example", ownerKey: "17" }, [
        [fixture("gitlab-pat", "gitlab-pat", "2032-02-29", { owner_username: "fixture-owner" }), "2032-02-29"],
        [fixture("gitlab-deploy", "gitlab-deploy-token", authoritativeTime), utcTime],
        [fixture("gitlab-no-expiry", "gitlab-pat", null, { expiration: null }), ""],
      ]],
      ["github", { baseUrl: "https://github.example", token }, { host: "github.example", ownerKey: "18" }, [
        [fixture("github-ssh", "github-ssh-key", undefined, { expiration: null, type: "ssh_key" }), ""],
      ]],
      ["aws", { accessKeyId: "synthetic-access-id", secretAccessKey: token, region: "us-east-1" }, { accountId: "123456789012" }, [
        [fixture("aws-certificate", "aws-acm", authoritativeTime, { ...cert, region: "us-east-1" }), utcTime],
        [fixture("aws-rotation-only", "aws-secrets-manager", undefined, { region: "us-east-1" }), ""],
      ]],
      ["azure", { vaultUrl: "https://fixture.vault.azure.net", token }, {}, [
        [fixture("azure-key", "azure-key-vault-key", authoritativeTime), utcTime],
        [fixture("azure-secret", "azure-key-vault-secret", authoritativeTime), utcTime],
        [fixture("azure-certificate", "azure-key-vault-certificate", authoritativeTime, cert), utcTime],
      ]],
      ["azure-ad", { token }, { tenantId: "00000000-0000-4000-8000-000000000017" }, [
        [fixture("entra-app-secret", "azure-ad-client-secret", authoritativeTime), utcTime],
        [fixture("entra-sp-certificate", "azure-ad-sp-certificate", authoritativeTime, { ...cert, servicePrincipalType: "Application" }), utcTime],
      ]],
      ["gcp", { projectId: "fixture-project", accessToken: token }, {}, [
        [fixture("gcp-secret", "gcp-secret-manager", gcpExpiry, { dimensions: { project: "fixture-project" } }), gcpExpiry],
        [fixture("gcp-certificate", "gcp-compute-ssl-cert", authoritativeTime, cert), utcTime],
        [fixture("gcp-rotation-only", "gcp-secret-manager"), ""],
      ]],
      ["vault", { address: "https://vault.example", token }, {}, [
        [fixture("vault-pki-certificate", "vault-pki", authoritativeTime, { ...cert, mount: "pki", path: "cert/01" }), utcTime],
        [fixture("vault-kv-certificate", "vault-kv", authoritativeTime, { ...cert, mount: "secret", path: "example-cert" }), utcTime],
        [fixture("vault-rotation-only", "vault-kv", undefined, { mount: "secret", path: "rotation" }), ""],
      ]],
    ];
    const workerPost = path => request(app).post(`${path}?workspace_id=${workspaceId}`)
      .set("Authorization", "Bearer issue71-test-worker");
    const labels = ["asset_name", "kind", "monitoring_group", "owner_username"];
    const expected = [];
    const beforeCreation = Date.now() / 1000;
    async function scanAndImport(provider, credentials, sourceIdentity, fixtures, expirationSelected = true) {
      const config = await configuration(`${provider} ${expected.length}`, provider);
      await settings(config, expirationSelected ? [...labels, "expiration"] : labels);
      const run = await start(config);
      const runContext = runs.runContext(run.config);
      const items = fixtures.map(([item]) => item);
      providerScanFixtures.set(provider, { ...sourceIdentity, items,
        summary: items.map(item => ({ sourceKind: item.sourceKind, complete: true })) });
      const scanResponse = await workerPost(`/api/v1/integrations/${provider}/scan`)
        .send({ ...credentials, auto_sync_run: runContext });
      assert.equal(scanResponse.status, 200, `${provider} scan: ${scanResponse.text}`);
      const scanId = scanResponse.body.scan_id;
      assert.ok(scanId, `${provider} scan must be persisted`);
      assert.ok(scanResponse.body.items.every(item => !Object.hasOwn(item, "metric_expiration")));
      const { rows } = await pool.query(
        "SELECT source_object_id, source_dimensions FROM integration_scan_items WHERE scan_id=$1", [scanId],
      );
      assert.equal(rows.length, items.length);
      for (const [item, expiration] of fixtures) {
        const persisted = rows.find(row => row.source_object_id === item.sourceObjectId);
        assert.equal(persisted.source_dimensions.expiration, expirationSelected && expiration ? expiration : undefined, item.name);
        expected.push({ provider, name: item.name, expiration: expirationSelected ? expiration : "", configId: config.id });
      }
      const importPath = provider === "vault" ? "/api/v1/integrations/vault/import" : "/api/v1/integrations/import";
      const imported = await workerPost(importPath).send({
        scan_id: scanId, auto_sync_run: runContext,
        items: scanResponse.body.items.map(item => ({ ...item,
          expiration: "2099-12-31", metric_expiration: "2099-12-31", source_dimensions: { expiration: "2099-12-31" },
        })),
      });
      assert.equal(imported.status, 201, `${provider} import: ${imported.text}`);
      assert.equal(imported.body.created_count, items.length, imported.text);
      await finish(run);
    }

    for (const args of cases) await scanAndImport(...args);
    const [provider, credentials, identity] = cases.find(([provider]) => provider === "aws");
    await scanAndImport(provider, credentials, identity, [
      [fixture("aws-unselected-expiry", "aws-acm", authoritativeTime, cert), utcTime],
    ], false);

    const scrape = await request(app).get("/metrics");
    assert.equal(scrape.status, 200, scrape.text);
    assert.match(scrape.headers["content-type"], /^text\/plain;.*version=0\.0\.4/);
    const families = ["auto_sync_items_created_detailed_total", "auto_sync_last_creation_timestamp_seconds"];
    for (const family of families) {
      const lines = scrape.text.split("\n").filter(line => line.startsWith(`${family}{`));
      assert.equal(lines.length, expected.length);
      for (const { provider, name, expiration, configId } of expected) {
        const line = lines.find(line => line.includes(`asset_name="${name}"`));
        assert.ok(line, `Missing ${family} sample for ${name}`);
        assert.ok(line.includes(`provider="${provider}"`) && line.includes(`configuration_id="${configId}"`));
        assert.ok(line.includes(`expiration="${expiration}"`), line);
        assert.ok(line.includes(`owner_username="${name === "gitlab-pat" ? "fixture-owner" : ""}"`), line);
        const value = Number(line.slice(line.lastIndexOf(" ") + 1));
        if (family.endsWith("_total")) assert.equal(value, 1);
        else assert.ok(value >= beforeCreation && value <= Date.now() / 1000, `${name}: ${value}`);
      }
    }

    const { rows } = await pool.query("SELECT source_dimensions FROM tokens WHERE workspace_id=$1", [workspaceId]);
    assert.ok(rows.every(row => !Object.hasOwn(row.source_dimensions, "expiration")));
    const aggregateSamples = scrape.text.split("\n").filter(line => line.startsWith("auto_sync_") &&
      !families.some(family => line.startsWith(`${family}{`)));
    assert.ok(aggregateSamples.every(line => !line.includes("expiration=")));
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "asset_name,owner_username";
    const restricted = await request(app).get("/metrics");
    assert.equal(restricted.status, 200, restricted.text);
    const restrictedSamples = restricted.text.split("\n").filter(line => families.some(family => line.startsWith(`${family}{`)));
    assert.equal(restrictedSamples.length, expected.length * families.length);
    assert.ok(restrictedSamples.every(line => line.includes('expiration=""')));
  });

  it("imports page-two GitLab expiry and retains its inventory link across failed later pages", async (t) => {
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "asset_name,expiration";
    const gitlab = await gitlabPatFixture(t);
    const tokenPath = "/api/v4/projects/7/access_tokens";
    const expiry = "2032-02-29";
    const projectToken = { id: 42, name: "page-two-token", active: true, expires_at: expiry };
    const firstToken = { id: 41, name: "page-one-token", active: true };
    gitlab.routes.set("/api/v4/projects", () => ({
      data: [{ id: 7, name: "Project", path_with_namespace: "platform/project" }],
      headers: { "x-next-page": "" },
    }));
    // Keep an independently complete sibling scope in each run.
    gitlab.routes.set("/api/v4/user/keys", () => ({ data: [], headers: { "x-next-page": "" } }));
    const config = await configuration();
    await settings(config, ["kind", "asset_name", "expiration"]);

    const workerPost = path => request(app).post(`${path}?workspace_id=${workspaceId}`)
      .set("Authorization", "Bearer issue71-test-worker");
    const fractionalLimit = await workerPost("/api/v1/integrations/gitlab/scan").send({
      baseUrl: gitlab.baseUrl, token: gitlab.options.token, maxItems: 1.5,
    });
    assert.equal(fractionalLimit.status, 400, fractionalLimit.text);
    assert.equal(gitlab.calls.length, 0, "An invalid limit must not query the provider");
    async function scanAndImport() {
      gitlab.calls.length = 0;
      const run = await start(config);
      const runContext = runs.runContext(run.config);
      const scanned = await workerPost("/api/v1/integrations/gitlab/scan").send({
        baseUrl: gitlab.baseUrl, token: gitlab.options.token, auto_sync_run: runContext,
        include: { tokens: true, keys: true },
        filters: {
          includePATs: false, includeProjectTokens: true, includeGroupTokens: false,
          includeDeployTokens: false, includeTriggerTokens: false, includeSSHKeys: true,
        },
      });
      assert.equal(scanned.status, 200, scanned.text);
      const scanId = scanned.body.scan_id;
      assert.ok(scanId, "The worker scan must be persisted and fenced");
      const result = await workerPost("/api/v1/integrations/import").send({
        scan_id: scanId, auto_sync_run: runContext, items: scanned.body.items,
        cleanup: { enabled: true, provider: "gitlab", scanId },
      });
      assert.equal(result.status, 201, result.text);
      assert.equal(result.body.error_count, 0, result.text);
      await finish(run);
      return { scanned: scanned.body, imported: result.body };
    }
    const pageNumber = url => Number(url.searchParams.get("page") || 1);
    const pages = () => gitlab.calls.filter(url => url.pathname === tokenPath).map(pageNumber);
    const projectScope = scanned => scanned.summary.find(scope => scope.sourceKind === "gitlab-project-token");
    const firstPage = { data: [firstToken], headers: { "x-next-page": "2" } };
    const terminalPage = { data: [firstToken], headers: {
      "x-next-page": "", "x-total-pages": "1", "x-total": "1",
    } };
    const linkTarget = new URL("/unused-link-path?page=2&state=all", gitlab.baseUrl);
    linkTarget.hostname = "localhost";
    const observedRequests = [];
    gitlab.routes.set(tokenPath, (url, headers) => {
      observedRequests.push({
        host: headers.host, authenticated: headers["private-token"] === gitlab.options.token,
        state: url.searchParams.get("state"),
      });
      return pageNumber(url) === 1
        ? { data: firstPage.data, headers: { ...firstPage.headers, link: `<${linkTarget}>; rel="next"` } }
        : { data: [projectToken], headers: {
          "x-next-page": "", "x-total-pages": "2", "x-total": "2",
        } };
    });
    const beforeCreation = Date.now() / 1000;
    const initial = await scanAndImport();
    assert.deepEqual(pages(), [1, 2]);
    const originalRequest = { host: new URL(gitlab.baseUrl).host, authenticated: true, state: "active" };
    assert.deepEqual(observedRequests, [originalRequest, originalRequest]);
    assert.equal(initial.imported.created_count, 2);
    assert.equal(projectScope(initial.scanned).complete, true);
    assert.equal(initial.imported.cleanup_complete, true);
    const discovered = initial.scanned.items.find(item => item.sourceObjectId === "7:42");
    assert.equal(discovered.expiration, expiry);
    assert.equal(Object.hasOwn(discovered, "metric_expiration"), false);
    const { rows: [stored] } = await pool.query(
      "SELECT source_dimensions FROM integration_scan_items WHERE scan_id=$1 AND source_object_id='7:42'",
      [initial.scanned.scan_id],
    );
    assert.equal(stored.source_dimensions.expiration, expiry);
    const { rows: [tracked] } = await pool.query(
      "SELECT id FROM tokens WHERE workspace_id=$1 AND source_object_id='7:42' AND auto_sync_managed=TRUE",
      [workspaceId],
    );
    assert.ok(tracked, "Page two token is auto-sync-managed inventory");

    const initialScrape = await request(app).get("/metrics");
    assert.equal(initialScrape.status, 200);
    const trackedSeries = text => text.split("\n").filter(line => line.startsWith("auto_sync_") &&
      line.includes(`configuration_id="${config.id}"`) && line.includes('asset_name="page-two-token"'));
    const samples = trackedSeries(initialScrape.text);
    assert.equal(samples.length, 2);
    for (const metricName of ["auto_sync_items_created_detailed_total", "auto_sync_last_creation_timestamp_seconds"]) {
      const sample = samples.find(line => line.startsWith(`${metricName}{`));
      assert.ok(sample?.includes(`expiration="${expiry}"`), sample);
      const value = Number(sample.split(" ").at(-1));
      if (metricName.endsWith("_total")) assert.equal(value, 1);
      else assert.ok(value >= beforeCreation - 1 && value <= Date.now() / 1000 + 1, sample);
      t.diagnostic(sample);
    }

    const partialCases = [
      ...[403, 404, 503].map(status => ({
        label: `page two HTTP ${status}`, expectedPages: [1, 2],
        respond: url => pageNumber(url) === 1 ? firstPage : { status },
      })),
      {
        label: "page one HTTP 404", expectedPages: [1], expectedIds: [],
        respond: () => ({ status: 404 }),
      },
      {
        label: "conflicting continuation", expectedPages: [1],
        respond: () => ({ ...firstPage, headers: { ...firstPage.headers, "x-total-pages": "1" } }),
      },
      {
        label: "repeated item with headerless short pages", expectedPages: [1, 2],
        respond: () => ({ data: [firstToken] }),
      },
      {
        label: "headerless short page followed by failure", expectedPages: [1, 2],
        respond: url => pageNumber(url) === 1 ? { data: [firstToken] } : { status: 503 },
      },
    ];
    for (const { label, expectedPages, respond, expectedIds = ["7:41"] } of partialCases) {
      gitlab.routes.set(tokenPath, respond);
      const partial = await scanAndImport();
      assert.deepEqual(pages(), expectedPages, label);
      assert.deepEqual(partial.scanned.items.map(item => item.sourceObjectId), expectedIds, label);
      assert.equal(projectScope(partial.scanned).complete, false, label);
      assert.equal(partial.scanned.summary.find(scope => scope.sourceKind === "gitlab-ssh-key").complete, true);
      assert.equal(partial.imported.scan_complete, false);
      assert.equal(partial.imported.cleanup_complete, false);
      assert.equal(partial.imported.created_count, 0);
      assert.equal(partial.imported.updated_count, expectedIds.length);
      assert.equal(partial.imported.deleted_count, 0);
      assert.equal((await pool.query(
        "SELECT 1 FROM tokens t JOIN auto_sync_token_links l ON l.token_id=t.id WHERE t.id=$1 AND l.config_id=$2",
        [tracked.id, config.id],
      )).rowCount, 1, `${label} must preserve linked inventory`);
      t.diagnostic(`GitLab ${label}: scan_complete=false, deleted_count=0, linked_inventory=1`);
    }
    const partialScrape = await request(app).get("/metrics");
    assert.equal(partialScrape.status, 200);
    assert.deepEqual(trackedSeries(partialScrape.text), samples);

    gitlab.routes.set(tokenPath, () => terminalPage);
    const complete = await scanAndImport();
    assert.deepEqual(pages(), [1]);
    assert.equal(projectScope(complete.scanned).complete, true);
    assert.equal(complete.imported.cleanup_complete, true);
    assert.equal(complete.imported.deleted_count, 1);
    assert.equal((await pool.query("SELECT 1 FROM tokens WHERE id=$1", [tracked.id])).rowCount, 0);
    t.diagnostic("GitLab authoritative absence: cleanup_complete=true, deleted_count=1, linked_inventory=0");
  });

  it("keeps GitHub page-two inventory on denied scans and reconciles complete absence", async (t) => {
    const github = await gitlabPatFixture(t);
    github.routes.set("/api/v3/user", () => ({ data: { id: 31, login: "fixture" } }));
    github.routes.set("/api/v3/user/repos", url => ({
      data: Number(url.searchParams.get("page") || 1) === 1
        ? [{ id: 5, owner: { login: "fixture" }, name: "repo", full_name: "fixture/repo" }]
        : [],
    }));
    const secretPath = "/api/v3/repos/fixture/repo/actions/secrets";
    let mode = "healthy";
    github.routes.set(secretPath, url => {
      const page = Number(url.searchParams.get("page") || 1);
      if (mode === "gone") return { data: { secrets: [{ name: "ONE" }], total_count: 1 } };
      if (page === 1) return {
        data: { secrets: [{ name: "ONE" }], total_count: 2 },
        headers: { link: `<${github.baseUrl}${secretPath}?page=2>; rel="next"` },
      };
      if (mode === "denied") return { status: 403 };
      return { data: { secrets: [{ name: "TWO" }], total_count: 2 } };
    });
    const config = await configuration("GitHub paginated", "github");
    const workerPost = path => request(app).post(`${path}?workspace_id=${workspaceId}`)
      .set("Authorization", "Bearer issue71-test-worker");
    async function scanAndImport() {
      github.calls.length = 0;
      const run = await start(config);
      const runContext = runs.runContext(run.config);
      const scanned = await workerPost("/api/v1/integrations/github/scan").send({
        baseUrl: `${github.baseUrl}/api/v3`, token: github.options.token, auto_sync_run: runContext,
        include: { tokens: true, sshKeys: false, deployKeys: false, secrets: true },
      });
      assert.equal(scanned.status, 200, scanned.text);
      const scanId = scanned.body.scan_id;
      assert.ok(scanId);
      assert.ok(scanned.body.summary.some(scope => scope.type === "personal_access_tokens" && scope.note));
      const result = await workerPost("/api/v1/integrations/import").send({
        scan_id: scanId, auto_sync_run: runContext, items: scanned.body.items,
        cleanup: { enabled: true, provider: "github", scanId },
      });
      assert.equal(result.status, 201, result.text);
      assert.equal(result.body.error_count, 0, result.text);
      await finish(run);
      return result.body;
    }
    const listedPages = () => github.calls.filter(url => url.pathname === secretPath)
      .map(url => Number(url.searchParams.get("page") || 1));
    const initial = await scanAndImport();
    assert.deepEqual(listedPages(), [1, 2]);
    assert.equal(initial.created_count, 2);
    assert.equal(initial.scan_complete, true, "An informational PAT note is not a failed scope");
    assert.equal(initial.cleanup_complete, true);
    const { rows: [tracked] } = await pool.query(
      "SELECT id FROM tokens WHERE workspace_id=$1 AND source_object_id='5:TWO'", [workspaceId],
    );
    assert.ok(tracked);
    mode = "denied";
    const partial = await scanAndImport();
    assert.deepEqual(listedPages(), [1, 2]);
    assert.equal(partial.scan_complete, false);
    assert.equal(partial.cleanup_complete, false);
    assert.equal(partial.updated_count, 1);
    assert.equal(partial.deleted_count, 0);
    assert.equal((await pool.query(
      "SELECT 1 FROM tokens t JOIN auto_sync_token_links l ON l.token_id=t.id WHERE t.id=$1 AND l.config_id=$2",
      [tracked.id, config.id],
    )).rowCount, 1);
    mode = "gone";
    const complete = await scanAndImport();
    assert.deepEqual(listedPages(), [1]);
    assert.equal(complete.cleanup_complete, true);
    assert.equal(complete.deleted_count, 1);
    assert.equal((await pool.query("SELECT 1 FROM tokens WHERE id=$1", [tracked.id])).rowCount, 0);
  });

  it("defers manual cleanup when an import fails, including an otherwise complete scan", async () => {
    const { token } = await imported(null, { name: "Manual candidate" }, true);
    const scan = await persistScan({
      workspaceId, provider: "gitlab", createdBy: userId,
      identityContext: { host: source.source_instance, ownerKey: source.source_owner_key },
      items: [], subScopes: [{ sourceKind: source.source_kind, complete: true }],
    });
    const url = `/api/v1/integrations/import?workspace_id=${workspaceId}`;
    const body = { scan_id: scan.scanId, cleanup: { enabled: true, provider: "gitlab", scanId: scan.scanId } };
    const failed = await request(app).post(url).send({
      ...body, items: [{ source: "gitlab", name: "Bad credential", location: "fixture",
        category: "key_secret", type: "api_key", expiresAt: "2032-02-29", key_size: 1 }],
    });
    assert.equal(failed.status, 201, failed.text);
    assert.equal(failed.body.error_count, 1, failed.text);
    assert.equal(failed.body.deleted_count, 0);
    assert.equal((await pool.query("SELECT 1 FROM tokens WHERE id=$1", [token.id])).rowCount, 1);
    assert.equal((await pool.query(
      "SELECT cleanup_consumed_at FROM integration_scans WHERE id=$1", [scan.scanId],
    )).rows[0].cleanup_consumed_at, null);
    const complete = await request(app).post(url).send({ ...body, items: [] });
    assert.equal(complete.status, 201, complete.text);
    assert.equal(complete.body.deleted_count, 1);
  });

  it("offers expiry to connections allowed by deployment without selecting it globally", async () => {
    const config = await configuration();
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "expiration";
    const url = `/api/v1/workspaces/${workspaceId}/auto-sync`;
    const list = await request(app).get(url);
    assert.equal(list.status, 200);
    assert.deepEqual(list.body.metric_label_policy.extra_labels, ["expiration"]);
    assert.ok(!list.body.metric_label_policy.system.labels.includes("expiration"));
    const updated = await request(app).put(`${url}/${config.id}`).send({
      metrics_settings: { enabled: true, labels: ["kind", "expiration"] },
    });
    assert.equal(updated.status, 200, updated.text);
    assert.deepEqual(updated.body.metrics_settings.labels, ["expiration", "kind"]);
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "none";
    const denied = await request(app).get(url);
    assert.equal(denied.status, 200);
    assert.deepEqual(denied.body.metric_label_policy.extra_labels, []);
  });

  it("saves a system-wide owner override, applies it to opted-out connections and respects deployment restrictions", async () => {
    const config = await configuration();
    const local = { enabled: false, labels: ["kind"], inherit_system: false };
    await pool.query("UPDATE auto_sync_configs SET metrics_settings=$2 WHERE id=$1", [config.id, local]);
    delete process.env.AUTO_SYNC_METRICS_EXTRA_LABELS;
    await pool.query("UPDATE users SET is_admin=TRUE WHERE id=$1", [userId]);
    const url = "/api/v1/admin/auto-sync/metrics";
    const policy = { override_metrics: true, enabled: true, labels: ["kind", "owner_username"] };
    const saved = await request(app).put(url).send(policy);
    assert.equal(saved.status, 200, JSON.stringify(saved.body));
    assert.equal(saved.body.override_metrics, true);
    assert.equal(saved.body.extra_labels_locked, false);
    assert.ok(saved.body.labels.includes("owner_username"));
    const loaded = await request(app).get(url);
    assert.equal(loaded.status, 200);
    assert.ok(loaded.body.labels.includes("owner_username"));
    const connectionUrl = `/api/v1/workspaces/${workspaceId}/auto-sync`;
    const connections = await request(app).get(connectionUrl);
    assert.equal(connections.status, 200);
    assert.equal(connections.body.metric_label_policy.system.override_metrics, true);
    assert.ok(connections.body.metric_label_policy.system.labels.includes("owner_username"));
    const change = await request(app).put(`${connectionUrl}/${config.id}`)
      .send({ metrics_settings: { ...local, enabled: true } });
    assert.equal(change.status, 409, JSON.stringify(change.body));
    const run = await start(config);
    await ownerScan(run, [["global", "global-owner"]]);
    await ownerImport(run, "global");
    for (const name of ["auto_sync_items_created_detailed_total", "auto_sync_last_creation_timestamp_seconds"]) {
      const samples = await metric(name);
      assert.equal(samples.length, 1);
      assert.equal(samples[0].labels.owner_username, "global-owner");
      assert.ok(samples[0].value > 0);
    }
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "none";
    assert.ok(!(await request(app).get(url)).body.labels.includes("owner_username"));
    await ownerScan(run, [["restricted", "must-not-persist"]]);
    await ownerImport(run, "restricted");
    const rows = await ownerRows(config);
    assert.deepEqual(rows.map(row => row.owner_username).sort(), ["", "global-owner"]);
    const restricted = await request(app).get("/metrics");
    assert.equal(restricted.status, 200);
    assert.ok(!restricted.text.includes("global-owner"));
    assert.ok(!restricted.text.includes("must-not-persist"));
    delete process.env.AUTO_SYNC_METRICS_EXTRA_LABELS;
    assert.ok((await metric("auto_sync_items_created_detailed_total"))
      .some(sample => sample.labels.owner_username === "global-owner"));
    const released = await request(app).put(url).send({ ...policy, override_metrics: false });
    assert.equal(released.status, 200);
    assert.deepEqual(await metric("auto_sync_items_created_detailed_total"), []);
    assert.deepEqual(await metric("auto_sync_last_creation_timestamp_seconds"), []);
    assert.deepEqual((await pool.query(
      "SELECT metrics_settings FROM auto_sync_configs WHERE id=$1", [config.id],
    )).rows[0].metrics_settings, local);
  });

  for (const mode of ["permission-only", "connection-without-permission", "default"]) {
    it(`does not persist or scrape owners for ${mode}`, async () => {
      const config = await configuration();
      const connection = { enabled: true, inherit_system: false, labels: ["kind", "owner_username"] };
      await pool.query("UPDATE auto_sync_configs SET metrics_settings=$2 WHERE id=$1", [config.id, connection]);
      delete process.env.AUTO_SYNC_METRICS_EXTRA_LABELS;
      await pool.query("UPDATE users SET is_admin=TRUE WHERE id=$1", [userId]);
      const globalUrl = "/api/v1/admin/auto-sync/metrics";
      if (mode === "permission-only") {
        const saved = await request(app).put(globalUrl)
          .send({ override_metrics: true, enabled: true, labels: ["kind"] });
        assert.equal(saved.status, 200, JSON.stringify(saved.body));
        process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "owner_username";
        const policy = await request(app).get(globalUrl);
        assert.deepEqual(policy.body.labels, ["kind"]);
        assert.deepEqual((await pool.query("SELECT auto_sync_metrics FROM system_settings WHERE id=1"))
          .rows[0].auto_sync_metrics.labels, ["kind"]);
      } else if (mode === "default") {
        await pool.query("UPDATE auto_sync_configs SET metrics_settings='{}' WHERE id=$1", [config.id]);
      }
      const run = await start(config);
      const scanId = await ownerScan(run, [[mode, "must-not-persist"]]);
      const dimensions = (await pool.query(
        "SELECT source_dimensions FROM integration_scan_items WHERE scan_id=$1", [scanId],
      )).rows[0].source_dimensions;
      assert.equal(Object.hasOwn(dimensions, "owner_username"), false);
      await ownerImport(run, mode);
      assert.ok((await ownerRows(config)).every(row => row.owner_username === ""));
      const scrape = await request(app).get("/metrics");
      assert.equal(scrape.status, 200);
      assert.ok(!scrape.text.includes("must-not-persist"));
      if (mode !== "default") {
        for (const name of ["auto_sync_items_created_detailed_total", "auto_sync_last_creation_timestamp_seconds"]) {
          const samples = await metric(name);
          assert.equal(samples.length, 1);
          assert.equal(samples[0].labels.owner_username, "");
        }
      }
    });
  }

  it("emits valid HTTP scrape text with escaped owners, stable counts and immediate policy changes", async () => {
    const config = await configuration(); await ownerSettings(config);
    const run = await start(config);
    const owner = 'owner"\\\n界';
    await ownerScan(run, [
      ["pat", owner], ["unknown", undefined],
      ["project", "not-a-PAT-owner", "gitlab-project-token"],
    ]);
    await ownerImport(run, "pat"); await ownerImport(run, "unknown");
    await ownerImport(run, "project", {}, "gitlab-project-token");
    const countName = "auto_sync_items_created_detailed_total";
    const timeName = "auto_sync_last_creation_timestamp_seconds";
    const samples = (text, name) => text.split("\n").filter(line => line.startsWith(`${name}{`));
    const autoSyncText = text => text.split("\n").filter(line => line.startsWith("auto_sync_")).join("\n");
    const escape = value => value.replaceAll("\\", "\\\\").replaceAll("\n", "\\n").replaceAll('"', '\\"');
    const scrape = async () => {
      const response = await request(app).get("/metrics");
      assert.equal(response.status, 200, response.text);
      assert.match(response.headers["content-type"], /^text\/plain;.*version=0\.0\.4/);
      assert.match(response.text, new RegExp(`^# TYPE ${countName} counter$`, "m"));
      assert.match(response.text, new RegExp(`^# TYPE ${timeName} gauge$`, "m"));
      const aggregates = response.text.split("\n").filter(line =>
        line.startsWith("auto_sync_") && !line.startsWith(`${countName}{`) &&
        !line.startsWith(`${timeName}{`));
      assert.ok(aggregates.length > 0);
      assert.ok(aggregates.every(line => !line.includes("owner_username")));
      assert.ok(!response.text.includes("not-a-PAT-owner"));
      return response.text;
    };
    const first = await scrape();
    for (const name of [countName, timeName]) {
      const lines = samples(first, name);
      assert.equal(lines.length, 3);
      assert.equal(lines.filter(line => line.includes(`owner_username="${escape(owner)}"`)).length, 1);
      assert.equal(lines.filter(line => line.includes('owner_username=""')).length, 2);
      assert.ok(lines.every(line => line.includes(`configuration_id="${config.id}"`)));
    }
    assert.ok(samples(first, countName).every(line => line.endsWith(" 1")));
    const timestamps = samples(first, timeName).map(line => Number(line.slice(line.lastIndexOf(" ") + 1)));
    assert.ok(timestamps.every(value => value > Date.now() / 1000 - 60 && value <= Date.now() / 1000));
    assert.equal(autoSyncText(await scrape()), autoSyncText(first), "Repeated scrapes do not increment persisted counters");
    if (process.env.AUTO_SYNC_PROMTOOL_IMAGE) {
      const result = require("node:child_process").spawnSync("docker", [
        "run", "--rm", "-i", "--network", "none", "--entrypoint", "/bin/promtool",
        process.env.AUTO_SYNC_PROMTOOL_IMAGE, "check", "metrics",
      ], { input: first, encoding: "utf8", timeout: 60000 });
      assert.equal(result.status, 0, `${result.error || ""}\n${result.stdout}\n${result.stderr}`);
    }
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "none";
    const hidden = await scrape();
    for (const name of [countName, timeName]) {
      const lines = samples(hidden, name);
      assert.equal(lines.length, 2);
      assert.ok(lines.every(line => line.includes('owner_username=""')));
      assert.ok(!lines.some(line => line.includes(escape(owner))));
    }
    assert.ok(samples(hidden, countName).find(line => line.includes('kind="gitlab-pat"')).endsWith(" 2"));
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "owner_username";
    assert.equal(autoSyncText(await scrape()), autoSyncText(first), "Re-enabling owner restores historical creation-time samples");
    await ownerSettings(config, false);
    const disabled = await scrape();
    assert.deepEqual(samples(disabled, countName), []);
    assert.deepEqual(samples(disabled, timeName), []);
    await ownerSettings(config);
    assert.equal(autoSyncText(await scrape()), autoSyncText(first));
    await finish(run);
    await pool.query("DELETE FROM auto_sync_configs WHERE id=$1", [config.id]);
    const deleted = await scrape();
    assert.deepEqual(samples(deleted, countName), []);
    assert.deepEqual(samples(deleted, timeName), []);
    assert.equal((await pool.query(
      "SELECT 1 FROM auto_sync_creation_stats WHERE config_id=$1", [config.id],
    )).rowCount, 0);
  });

  it("strips owner from manual, disabled, unselected and deployment-disallowed scan persistence", async () => {
    const config = await configuration(); await ownerSettings(config);
    const run = await start(config);
    for (const mode of ["manual", "disabled", "unselected", "deployment", "system"]) {
      await ownerSettings(config, mode !== "disabled", mode === "unselected" ? ["kind"] : ["owner_username"]);
      if (mode === "deployment") process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "none";
      await pool.query("UPDATE system_settings SET auto_sync_metrics=$1 WHERE id=1", [
        mode === "system" ? { override_metrics: true, enabled: false, labels: ["owner_username"] } : {},
      ]);
      const scanId = await ownerScan(run, [[mode, "must-not-persist"]], { manual: mode === "manual" });
      const dimensions = (await pool.query(
        "SELECT source_dimensions FROM integration_scan_items WHERE scan_id=$1", [scanId],
      )).rows[0].source_dimensions;
      assert.equal(Object.hasOwn(dimensions, "owner_username"), false, mode);
      if (mode !== "manual") await ownerImport(run, mode);
    }
    assert.ok((await ownerRows(config)).every(row => row.owner_username === ""));
  });

  it("retains owner counter and first-scrape timestamps across toggles, renames and overlapping configurations", async () => {
    const first = await configuration("Same name"); await ownerSettings(first);
    const run = await start(first);
    await ownerScan(run, [["a", "alice"], ["b", "bob"], ["unknown", undefined]]);
    for (const id of ["a", "b", "unknown"]) await ownerImport(run, id);
    const initial = await createdTotal();
    const originalRows = await ownerRows(first);
    const countName = "auto_sync_items_created_detailed_total";
    const timeName = "auto_sync_last_creation_timestamp_seconds";
    const firstCounts = await metric(countName), firstTimes = await metric(timeName);
    assert.deepEqual(firstCounts.map(sample => sample.labels.owner_username).sort(), ["", "alice", "bob"]);
    assert.ok(firstCounts.every(sample => sample.value === 1));
    assert.ok(firstTimes.every(sample => sample.value > Date.now() / 1000 - 60));
    await ownerSettings(first, true, ["kind"]);
    const hidden = await metric(countName);
    assert.equal(hidden.length, 1); assert.equal(hidden[0].value, 3);
    assert.equal(hidden[0].labels.owner_username, "");
    assert.equal((await metric(timeName))[0].value, Math.max(...firstTimes.map(sample => sample.value)));
    await ownerSettings(first, false);
    assert.deepEqual(await metric(countName), []); assert.deepEqual(await metric(timeName), []);
    await ownerSettings(first);
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "none";
    assert.ok((await metric(countName)).every(sample => sample.labels.owner_username === ""));
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "owner_username";
    assert.deepEqual(await metric(countName), firstCounts);
    assert.deepEqual(await metric(timeName), firstTimes);
    await pool.query("UPDATE auto_sync_configs SET connection_key='Renamed connection' WHERE id=$1", [first.id]);
    await ownerScan(run, [["a", "renamed-owner"]]);
    await ownerImport(run, "a", { name: "Renamed asset" });
    assert.deepEqual(await ownerRows(first), originalRows, "Rediscovery and renaming do not mint creation events");
    const inventory = (await pool.query(
      "SELECT source_dimensions FROM tokens WHERE workspace_id=$1", [workspaceId],
    )).rows;
    assert.ok(inventory.every(row => !Object.hasOwn(row.source_dimensions, "owner_username")));
    assert.equal(await createdTotal(), initial);
    await finish(run);
    const second = await configuration("Same name"); await ownerSettings(second);
    const secondRun = await start(second);
    await ownerScan(secondRun, [["a", "renamed-owner"], ["new", "alice"]]);
    await ownerImport(secondRun, "a"); await ownerImport(secondRun, "new");
    const values = await metric(countName);
    assert.equal(values.filter(sample => sample.labels.configuration_id === first.id).reduce((n, sample) => n + sample.value, 0), 3);
    assert.equal(values.filter(sample => sample.labels.configuration_id === second.id).reduce((n, sample) => n + sample.value, 0), 1);
    assert.equal(await createdTotal(), initial + 1n);
  });

  it("rolls back owner statistics and inventory when the owner detail write fails", async () => {
    const config = await configuration(); await ownerSettings(config);
    const run = await start(config); await ownerScan(run, [["rollback", "alice"]]);
    const initial = await createdTotal();
    const name = `reject_owner_${crypto.randomUUID().replaceAll("-", "")}`;
    await pool.query(`CREATE FUNCTION ${name}() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'synthetic owner detail failure'; END $$`);
    await pool.query(`CREATE TRIGGER ${name} BEFORE INSERT ON auto_sync_creation_stats
      FOR EACH ROW WHEN (NEW.owner_username <> '') EXECUTE FUNCTION ${name}()`);
    try {
      await assert.rejects(ownerImport(run, "rollback"), /synthetic owner detail failure/);
    } finally {
      await pool.query(`DROP TRIGGER ${name} ON auto_sync_creation_stats`);
      await pool.query(`DROP FUNCTION ${name}()`);
    }
    assert.deepEqual(await ownerRows(config), []);
    assert.equal(await createdTotal(), initial);
    assert.equal((await pool.query("SELECT 1 FROM tokens WHERE workspace_id=$1", [workspaceId])).rowCount, 0);
  });

  it("upgrades real legacy rows without changing hashes, totals or timestamps and continues the same aggregate", async () => {
    const config = await configuration();
    const dimensions = { kind: "gitlab-pat", asset_name: "", project: "", group: "" };
    const key = crypto.createHash("sha256").update(JSON.stringify(dimensions)).digest("hex");
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      // A transaction-local pre-upgrade table exercises DDL without altering shared fixtures.
      await client.query(`CREATE TEMP TABLE auto_sync_creation_stats
        (LIKE public.auto_sync_creation_stats INCLUDING ALL) ON COMMIT DROP`);
      await client.query("ALTER TABLE pg_temp.auto_sync_creation_stats DROP COLUMN owner_username");
      await client.query("ALTER TABLE pg_temp.auto_sync_creation_stats DROP COLUMN expiration");
      await client.query(`INSERT INTO pg_temp.auto_sync_creation_stats
        (config_id,kind,asset_name,project,group_name,dimension_key,items_created_total,last_created_at)
        VALUES ($1,'gitlab-pat','','','',$2,7,'2026-01-02T03:04:05Z')`, [config.id, key]);
      const before = (await client.query("SELECT * FROM pg_temp.auto_sync_creation_stats")).rows[0];
      const sql = require("node:fs").readFileSync(require("node:path").join(
        __dirname, "../../apps/api/migrations/111-auto-sync-owner-username.sql"), "utf8");
      await client.query(sql);
      await client.query(require("node:fs").readFileSync(require("node:path").join(
        __dirname, "../../apps/api/migrations/115-auto-sync-creation-expiration.sql"), "utf8"));
      const upgraded = (await client.query("SELECT * FROM pg_temp.auto_sync_creation_stats")).rows[0];
      assert.equal(upgraded.owner_username, "");
      assert.equal(upgraded.expiration, "");
      const { owner_username: _owner, expiration: _expiration, ...unchanged } = upgraded;
      assert.deepEqual(unchanged, before);
      await require("../../apps/api/services/autoSyncMetricLabels").recordCreationMetrics(
        client, { provider: "gitlab", configId: config.id },
        { source_provider: "gitlab", source_kind: "gitlab-pat", source_dimensions: {} },
        { enabled: true, labels: ["kind"] },
      );
      const continued = (await client.query("SELECT * FROM pg_temp.auto_sync_creation_stats")).rows;
      assert.equal(continued.length, 1); assert.equal(continued[0].dimension_key, key);
      assert.equal(continued[0].items_created_total, "8"); assert.equal(continued[0].owner_username, "");
      assert.ok(continued[0].last_created_at > before.last_created_at);
    } finally {
      await client.query("ROLLBACK"); client.release();
    }
  });

  it("reports environment label ownership through the integration policy without locking unrelated fields",async()=>{
    const config=await configuration();process.env.AUTO_SYNC_METRICS_EXTRA_LABELS='none';
    try{
      const url='/api/v1/workspaces/'+workspaceId+'/auto-sync';const result=await request(app).get(url);assert.equal(result.status,200);
      const policy=result.body.metric_label_policy.system;assert.equal(policy.extra_labels_locked,true);assert.equal(policy.locked,false);assert.equal(policy.override_metrics,false);assert.equal(policy.override_monitoring_group,false);
      const update=await request(app).put(url+'/'+config.id).send({metrics_settings:{enabled:true,labels:['kind'],monitoring_group:'local'}});assert.equal(update.status,200);
      delete process.env.AUTO_SYNC_METRICS_EXTRA_LABELS;
      const restored=await request(app).get(url);assert.equal(restored.body.metric_label_policy.system.extra_labels_locked,false);
    }finally{delete process.env.AUTO_SYNC_METRICS_EXTRA_LABELS;}
  });

  it("preserves database labels during env-controlled UI saves and restores them when released",async()=>{
    delete process.env.AUTO_SYNC_METRICS_EXTRA_LABELS;
    await pool.query('UPDATE users SET is_admin=TRUE WHERE id=$1',[userId]);
    const stored={override_metrics:false,enabled:false,labels:['kind','asset_name']};
    await pool.query('UPDATE system_settings SET auto_sync_metrics=$1 WHERE id=1',[stored]);
    const config=await configuration();await settings(config,['kind']);
    process.env.AUTO_SYNC_METRICS_ENABLED='true';process.env.AUTO_SYNC_METRICS_LABELS='kind,project';
    try{
      const url='/api/v1/admin/auto-sync/metrics';const get=await request(app).get(url);assert.equal(get.status,200);assert.deepEqual(get.body.labels,['kind','project']);assert.equal(get.body.labels_locked,true);
      const save=await request(app).put(url).send({override_metrics:true,enabled:true,labels:['kind','project']});assert.equal(save.status,200);
      assert.deepEqual((await pool.query('SELECT auto_sync_metrics FROM system_settings WHERE id=1')).rows[0].auto_sync_metrics,stored);
      const connections=await request(app).get('/api/v1/workspaces/'+workspaceId+'/auto-sync');assert.equal(connections.body.metric_label_policy.system.labels_locked,true);
      const run=await start(config);await scan(run,['42']);await imported(run);
      let sample=(await metric('auto_sync_items_created_detailed_total'))[0];assert.equal(sample.labels.project,'platform/backend');assert.equal(sample.labels.asset_name,'');assert.equal(sample.labels.kind,'gitlab-project-token');
      delete process.env.AUTO_SYNC_METRICS_ENABLED;delete process.env.AUTO_SYNC_METRICS_LABELS;
      const restored=await request(app).get(url);assert.deepEqual(restored.body.labels,stored.labels);assert.equal(restored.body.labels_locked,false);assert.equal(restored.body.override_metrics,false);
      sample=(await metric('auto_sync_items_created_detailed_total'))[0];assert.equal(sample.labels.project,'');await finish(run);
    }finally{delete process.env.AUTO_SYNC_METRICS_ENABLED;delete process.env.AUTO_SYNC_METRICS_LABELS;}
  });

});

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
    await pool.query('UPDATE users SET is_admin=FALSE WHERE id=$1',[userId]);
    delete process.env.AUTO_SYNC_METRICS_ENABLED;
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

});

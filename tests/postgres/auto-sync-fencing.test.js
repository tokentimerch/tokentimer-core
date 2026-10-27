"use strict";

// Run against a migrated, disposable database whose name ends in _issue71_test.
// This suite uses real PostgreSQL transactions, locks, routes, and token models.
const { before, beforeEach, after, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const request = require("supertest");
const express = require("../../apps/api/node_modules/express");
const { pool } = require("../../apps/api/db/database");
const Token = require("../../apps/api/db/models/Token");
const provenance = require("../../apps/api/services/autoSyncProvenance");
const { persistScan } = require("../../apps/api/services/integrationScans");
const { cleanupObsoleteTokens } = require("../../apps/api/services/importCleanup");

let runs, workerPool, userId, workspaceId, app;
let sequence = 0;
const source = { source_provider: "gitlab", source_instance: "gitlab.example",
  source_owner_key: "17", source_kind: "gitlab-pat", source_object_id: "42" };

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
    createdBy: userId, items: items.map(id => ({ sourceKind: source.source_kind, sourceObjectId: id, dimensions: {} })),
    subScopes: [{ sourceKind: source.source_kind, complete }], request: {
      isWorkerCall: true, integrationScanStartedAt: new Date(), body: { auto_sync_run: runs.runContext(run.config) } } });
  run.context.scanId = result.scanId;
  return result.scanId;
}
async function imported(run, extra = {}, manual = false) {
  return provenance.upsertImportedToken({ context: manual ? null : run.context,
    payload: { name: "Shared credential", location: "gitlab.example", type: "api_key", category: "key_secret",
      expiration: "2028-01-01", ...source, source_observed_at: new Date(), ...extra },
    workspaceId, userId, manual, assignMembership() {} });
}
async function finish(run) {
  return runs.withCurrentRun(run.config, client => runs.finishAutoSyncRun(client, run.config, { status: "success" }));
}
async function inventory(id) {
  return (await pool.query("SELECT * FROM tokens WHERE id = $1", [id])).rows[0];
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

describe("PostgreSQL auto-sync ownership and fencing", { concurrency: false }, () => {
  before(async () => {
    assert.match(process.env.DB_NAME || "", /_issue71_test$/, "Use a disposable issue71 test database");
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
    app.use(require("../../apps/api/routes/tokens"));
    process.env.WORKER_API_KEY = "issue71-test-worker";
    app.use(require("../../apps/api/routes/integrations"));
  });
  beforeEach(async () => {
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

  it("accepts fenced zero-item imports with cleanup disabled and rejects legacy imports on activation", async () => {
    const run=await start(await configuration());await scan(run);
    const url=`/api/v1/integrations/import?workspace_id=${workspaceId}`;
    const response=await request(app).post(url).set("Authorization","Bearer issue71-test-worker").send({items:[],scan_id:run.context.scanId,auto_sync_run:runs.runContext(run.config)});
    assert.equal(response.status,201,JSON.stringify(response.body));
    assert.equal(response.body.scan_complete,true);
    const legacy=await request(app).post(url).set("Authorization","Bearer issue71-test-worker").send({items:[{name:"Legacy",source:"gitlab",type:"api_key"}]});
    assert.equal(legacy.status,409,JSON.stringify(legacy.body));
    assert.equal(legacy.body.code,"AUTO_SYNC_RUN_REQUIRED");
  });

  it("worker HTTP discovery creates managed inventory; legacy cleanup never deletes before activation", async () => {
    const run=await start(await configuration());await scan(run,["42"]);
    const url=`/api/v1/integrations/import?workspace_id=${workspaceId}`;
    const response=await request(app).post(url).set("Authorization","Bearer issue71-test-worker").send({
      items:[{name:"Worker token",location:"gitlab.example",source:"gitlab",sourceKind:"gitlab-pat",sourceObjectId:"42",type:"api_key",expiresAt:"2028-01-01"}],
      scan_id:run.context.scanId,auto_sync_run:runs.runContext(run.config)});
    assert.equal(response.status,201,JSON.stringify(response.body));assert.equal(response.body.error_count,0,JSON.stringify(response.body));
    assert.equal(response.body.created_count,1);
    const tokenId=response.body.created[0].id;assert.equal((await inventory(tokenId)).auto_sync_managed,true);
    await pool.query("UPDATE auto_sync_feature_state SET multi_config_enabled=FALSE WHERE id=TRUE");
    await pool.query("DELETE FROM auto_sync_token_links WHERE token_id=$1",[tokenId]);
    const legacyScan=await persistScan({workspaceId,provider:"gitlab",identityContext:{host:source.source_instance,ownerKey:source.source_owner_key},items:[],subScopes:[{sourceKind:source.source_kind,complete:true}]});
    const legacy=await request(app).post(url).set("Authorization","Bearer issue71-test-worker").send({items:[],cleanup:{enabled:true,provider:"gitlab",scanId:legacyScan.scanId}});
    assert.equal(legacy.status,201,JSON.stringify(legacy.body));assert.equal(legacy.body.deleted_count,0);assert.ok(await inventory(tokenId));
  });

  it("Vault prefix scopes treat wildcard characters as literal path characters", async () => {
    const {buildDimensionFilterSql} = require("../../apps/api/services/importCleanup");
    for(const prefix of ["prod_", "prod%", "prod\\"]) {
      const {sql,params} = buildDimensionFilterSql({pathPrefix:prefix},4);
      const result = await pool.query(`SELECT source_dimensions->>'path' AS path
        FROM (VALUES($1::jsonb),($2::jsonb),($3::jsonb)) t(source_dimensions) WHERE TRUE ${sql}`,
        [JSON.stringify({path:prefix+"db/a"}),JSON.stringify({path:"prodXdb/b"}),JSON.stringify({path:"prod/db/c"}),...params]);
      assert.deepEqual(result.rows.map(row=>row.path),[prefix+"db/a"]);
    }
  });

  it("migrates a legacy schema without changing IDs or inventing ownership", async () => {
    const {migrations} = require("../../apps/api/migrations/migrate");
    const client = await pool.connect();
    const schema = `issue71_migration_${crypto.randomUUID().replaceAll("-","")}`;
    try {
      await client.query("BEGIN");
      await client.query(`CREATE SCHEMA ${schema}`);
      await client.query(`SET LOCAL search_path TO ${schema}`);
      for (const migration of migrations.filter(entry=>[1,2,8,50].includes(entry.version))) await client.query(migration.sql);
      const uid=(await client.query("INSERT INTO users(email,display_name,password_hash) VALUES('legacy@example.test','Legacy','test-hash') RETURNING id")).rows[0].id;
      const wid=crypto.randomUUID();
      await client.query("INSERT INTO workspaces(id,name,created_by) VALUES($1,'Legacy',$2)",[wid,uid]);
      const cid=(await client.query("INSERT INTO auto_sync_configs(workspace_id,provider,credentials_encrypted,created_by) VALUES($1,'gitlab','legacy',$2) RETURNING id",[wid,uid])).rows[0].id;
      const tid=(await client.query(`INSERT INTO tokens(user_id,workspace_id,name,type,expiration,location)
        VALUES($1,$2,'Legacy token','api_key','2028-01-01','gitlab.example') RETURNING id`,[uid,wid])).rows[0].id;
      await client.query(migrations.find(entry=>entry.version===61).sql);
      assert.equal((await client.query("SELECT id FROM auto_sync_configs")).rows[0].id,cid);
      assert.equal((await client.query("SELECT auto_sync_managed FROM tokens WHERE id=$1",[tid])).rows[0].auto_sync_managed,false);
      assert.equal((await client.query("SELECT 1 FROM auto_sync_token_links")).rowCount,0);
      assert.equal((await client.query("SELECT multi_config_enabled FROM auto_sync_feature_state")).rows[0].multi_config_enabled,false);
    } finally { await client.query("ROLLBACK");client.release(); }
  });

  it("does not acquire deletion ownership when rediscovering a manual or legacy token", async () => {
    const token = await Token.create({ userId, workspaceId, name: "Shared credential", location: "gitlab.example", type: "api_key", expiration: "2028-01-01" });
    const first = await start(await configuration());
    await scan(first, ["42"]);
    const found = await imported(first);
    assert.equal(found.token.id, token.id);
    assert.equal((await inventory(token.id)).auto_sync_managed, false);
    await finish(first);
    const next = await start(first.config);
    await scan(next);
    assert.deepEqual(await provenance.reconcileAutoSyncRun(next.context), { complete: true, detached: 1, deleted: 0 });
    assert.ok(await inventory(token.id));
  });

  it("deletes only auto-sync-created inventory after a verified zero-item scan", async () => {
    const before = await createdTotal();
    const first = await start(await configuration());
    await scan(first, ["42"]);
    const { token } = await imported(first);
    assert.equal((await inventory(token.id)).auto_sync_managed, true);
    await finish(first);
    const next = await start(first.config);
    await scan(next);
    assert.deepEqual(await provenance.reconcileAutoSyncRun(next.context), { complete: true, detached: 1, deleted: 1 });
    assert.equal(await inventory(token.id), undefined);
    const events = await pool.query("SELECT event FROM auto_sync_token_link_events WHERE token_id_snapshot=$1 ORDER BY id", [token.id]);
    assert.deepEqual(events.rows.map(row => row.event), ["attached", "detached"]);
    assert.equal(await createdTotal(), before + 1n, "cleanup cannot reduce the historical counter");
  });

  it("manual integration adoption and confirmed file import relinquish ownership", async () => {
    const run = await start(await configuration());
    await scan(run, ["42"]);
    const { token } = await imported(run);
    await imported(run, {}, true);
    assert.equal((await inventory(token.id)).auto_sync_managed, false);
    await pool.query("UPDATE tokens SET auto_sync_managed=TRUE WHERE id=$1", [token.id]);
    const response = await request(app).post("/api/tokens").send({ name: token.name, location: token.location,
      type: "api_key", category: "key_secret", expiresAt: "2028-01-01", workspace_id: workspaceId, confirm_duplicate: true });
    assert.equal(response.status, 200, JSON.stringify(response.body));
    assert.equal((await inventory(token.id)).auto_sync_managed, false);
  });

  it("concurrent first discoveries create one token and attach both configurations", async () => {
    const before = await createdTotal();
    const a = await start(await configuration("A"));
    const b = await start(await configuration("B"));
    await scan(a, ["42"]); await scan(b, ["42"]);
    const results = await Promise.all([imported(a), imported(b)]);
    assert.equal(results[0].token.id, results[1].token.id);
    assert.equal(results.filter(result => result.created).length, 1);
    assert.equal((await pool.query("SELECT 1 FROM auto_sync_token_links WHERE token_id=$1", [results[0].token.id])).rowCount, 2);
    assert.equal(await createdTotal(), before + 1n);
  });

  it("a concurrent attach protects managed inventory while another config detaches", async () => {
    const first = await start(await configuration("A")); await scan(first,["42"]);
    const {token} = await imported(first); await finish(first);
    const b = await start(await configuration("B")); await scan(b,["42"]);
    const a = await start(first.config); await scan(a);
    const attaching = await pool.connect(); await attaching.query("BEGIN");
    await provenance.assertRunFence(attaching,b.context);
    await attaching.query("SELECT id FROM tokens WHERE id=$1 FOR UPDATE",[token.id]);
    const reconciling = provenance.reconcileAutoSyncRun(a.context);
    try {
      for(let i=0;i<100;i++) {
        const waiting = await pool.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%JOIN tokens t%' AND pid<>pg_backend_pid()");
        if(waiting.rowCount) break;
        if(i===99) throw new Error("reconciliation never waited on token lock");
        await new Promise(resolve=>setTimeout(resolve,10));
      }
      await provenance.attachObservedToken(b.context,token.id,false,{client:attaching});
      await attaching.query("COMMIT");
    } finally { attaching.release(); }
    const result = await reconciling;
    assert.equal(result.detached,1); assert.equal(result.deleted,0);
    assert.ok(await inventory(token.id));
    assert.equal((await pool.query("SELECT config_id FROM auto_sync_token_links WHERE token_id=$1",[token.id])).rows[0].config_id,b.config.id);
  });

  it("partial scans, prior batch errors and missing imports retain associations", async () => {
    const first = await start(await configuration()); await scan(first,["42"]);
    const { token } = await imported(first); await finish(first);
    const next = await start(first.config); await scan(next,[],false);
    assert.equal((await provenance.reconcileAutoSyncRun(next.context)).complete, false);
    await finish(next);
    const failedBatch = await start(next.config); await scan(failedBatch);
    await provenance.recordAutoSyncImportErrors(failedBatch.context, 1);
    assert.equal((await provenance.reconcileAutoSyncRun(failedBatch.context)).complete, false);
    assert.ok(await inventory(token.id)); await finish(failedBatch);
    const missing = await start(failedBatch.config); await scan(missing,["100"]);
    assert.equal((await provenance.reconcileAutoSyncRun(missing.context)).complete, false);
    assert.ok(await inventory(token.id));
  });

  it("rejects unrelated scans and incomplete scan sets", async () => {
    const a = await start(await configuration("A")); const old = await scan(a);
    const b = await start(await configuration("B")); await scan(b);
    await assert.rejects(provenance.resolveAutoSyncImportContext({ isWorkerCall:true, body:{auto_sync_run:runs.runContext(b.config)} }, workspaceId,"gitlab",old), {code:"AUTO_SYNC_SCAN_INVALID"});
    const prior = b.context.scanId; await scan(b);
    await assert.rejects(provenance.reconcileAutoSyncRun(b.context,[prior]), /Invalid auto-sync scan set|every scan/);
  });

  it("same-config claims serialize; expired owners cannot import or finish after a newer run", async () => {
    const config = await configuration(); await pool.query("UPDATE auto_sync_configs SET next_sync_at=NOW() WHERE id=$1",[config.id]);
    const claims = await Promise.all([runs.claimDueAutoSyncRuns(),runs.claimDueAutoSyncRuns()]);
    assert.equal(claims.flat().length,1);
    const old = claims.flat()[0];
    await pool.query("UPDATE auto_sync_configs SET lease_until=NOW()-INTERVAL '1 second' WHERE id=$1",[config.id]);
    const newer = (await runs.claimDueAutoSyncRuns())[0];
    assert.equal(newer.generation,old.generation+1);
    assert.equal(await runs.withCurrentRun(old,async () => { throw new Error("stale callback executed"); }),false);
    await assert.rejects(provenance.withFencedImport({configId:old.id,workspaceId,provider:"gitlab",runId:old.runId,
      generation:old.generation,scanVersion:Number(old.scanVersion),leaseOwner:old.leaseOwner},async()=>{}),{code:"AUTO_SYNC_RUN_STALE"});
  });

  it("run-now requests coalesce durably; metadata edits preserve runs and current schedules", async () => {
    const run=await start(await configuration());
    const url=`/api/v1/workspaces/${workspaceId}/auto-sync/${run.config.id}`;
    for(let i=0;i<3;i++) assert.equal((await request(app).post(`${url}/run`)).status,200);
    const queued=(await pool.query("SELECT * FROM auto_sync_configs WHERE id=$1",[run.config.id])).rows[0];
    assert.equal(queued.pending_manual_run,true);
    assert.equal(queued.active_run_id,run.config.runId);
    assert.equal((await request(app).put(url).send({name:"  GitLab   Prod  ",frequency:"weekly",schedule_time:"14:30"})).status,200);
    assert.equal(await runs.withCurrentRun(run.config,async()=>{}),true);
    await finish(run);
    const next=(await runs.claimDueAutoSyncRuns())[0];
    assert.equal(next.trigger,"manual");
    assert.equal(next.connection_key,"GitLab Prod");
    assert.equal(next.frequency,"weekly");
    assert.equal((await pool.query("SELECT pending_manual_run FROM auto_sync_configs WHERE id=$1",[next.id])).rows[0].pending_manual_run,false);
  });

  it("concurrent scan edits each invalidate the locked current state", async () => {
    const run=await start(await configuration());
    const url=`/api/v1/workspaces/${workspaceId}/auto-sync/${run.config.id}`;
    const replies=await Promise.all([request(app).put(url).send({scan_params:{maxItems:20}}),request(app).put(url).send({scan_params:{}})]);
    assert.ok(replies.every(reply=>reply.status===200),JSON.stringify(replies.map(reply=>reply.body)));
    const config=(await pool.query("SELECT * FROM auto_sync_configs WHERE id=$1",[run.config.id])).rows[0];
    assert.equal(await runs.withCurrentRun(run.config,async()=>{}),false);
    assert.ok(Number(config.scan_version)>=2);
    assert.equal(config.pending_replacement_run,true);
    assert.equal((await pool.query("SELECT status FROM auto_sync_runs WHERE run_id=$1",[run.config.runId])).rows[0].status,"superseded");
  });

  it("configuration deletion retains inventory and exposes former provenance", async () => {
    const run=await start(await configuration("Former production"));await scan(run,["42"]);
    const {token}=await imported(run);
    const reply=await request(app).delete(`/api/v1/workspaces/${workspaceId}/auto-sync/${run.config.id}`);
    assert.equal(reply.status,200,JSON.stringify(reply.body));
    assert.equal((await inventory(token.id)).auto_sync_managed,false);
    const history=await request(app).get(`/api/tokens/${token.id}/auto-sync-provenance`);
    assert.equal(history.status,200);
    assert.equal(history.body.items[0].config_name,"Former production");
    assert.equal(history.body.items[0].reason,"configuration_deleted");
    await assert.rejects(pool.query("UPDATE auto_sync_token_link_events SET config_name='tampered' WHERE token_id_snapshot=$1",[token.id]),{code:"P0001"});
  });

  it("activation is enforced for old SQL clients even after renaming; names are case-insensitive", async () => {
    await pool.query("UPDATE auto_sync_feature_state SET multi_config_enabled=FALSE WHERE id=TRUE");
    await configuration("Renamed first");
    await assert.rejects(pool.query(`INSERT INTO auto_sync_configs(workspace_id,provider,credentials_encrypted)
      VALUES ($1,'gitlab','legacy')`,[workspaceId]),{code:"23514"});
    await pool.query("UPDATE auto_sync_feature_state SET multi_config_enabled=TRUE WHERE id=TRUE");
    await assert.rejects(configuration("renamed FIRST"),{code:"23505"});
    await assert.rejects(provenance.resolveAutoSyncImportContext({isWorkerCall:true,body:{}},workspaceId,"gitlab",null),{code:"AUTO_SYNC_RUN_REQUIRED"});
  });

  it("history pagination handles same-millisecond runs and rejects invalid limits/cursors", async () => {
    const config=await configuration();
    for(const [generation,timestamp] of [[1,"2026-01-01T00:00:00.000500Z"],[2,"2026-01-01T00:00:00.000900Z"]]) {
      await pool.query(`INSERT INTO auto_sync_runs(config_id,config_id_snapshot,workspace_id,provider,name_snapshot,trigger,generation,scan_version,status,started_at,error_text)
        VALUES($1,$1,$2,'gitlab','History','schedule',$3,1,'failed',$4,$5)`,[config.id,workspaceId,generation,timestamp,'{"token":"fake-credential"}']);
    }
    const url=`/api/v1/workspaces/${workspaceId}/auto-sync/${config.id}/runs`;
    const first=await request(app).get(`${url}?limit=1`);assert.equal(first.status,200);
    assert.equal(Number(first.body.items[0].generation),2);assert.ok(!JSON.stringify(first.body).includes("fake-credential"));
    const second=await request(app).get(`${url}?limit=1&cursor=${first.body.next_cursor}`);
    assert.equal(Number(second.body.items[0].generation),1);assert.equal(second.body.next_cursor,null);
    assert.equal((await request(app).get(`${url}?limit=1.5`)).status,400);
    assert.equal((await request(app).get(`${url}?cursor=${Buffer.from('{"generation":"bad"}').toString("base64url")}`)).status,400);
  });

  it("manual cleanup rechecks links after waiting for a concurrent attach", async () => {
    const run=await start(await configuration());await scan(run,["42"]);
    const {token}=await imported(run);
    await pool.query("DELETE FROM auto_sync_token_links WHERE token_id=$1",[token.id]);
    const manualScan=await persistScan({workspaceId,provider:"gitlab",identityContext:{host:source.source_instance,ownerKey:source.source_owner_key},items:[],subScopes:[{sourceKind:source.source_kind,complete:true}]});
    const attaching=await pool.connect();await attaching.query("BEGIN");
    await attaching.query("SELECT id FROM tokens WHERE id=$1 FOR UPDATE",[token.id]);
    const cleaning=cleanupObsoleteTokens({workspaceId,actorUserId:userId,cleanup:{enabled:true,provider:"gitlab",scanId:manualScan.scanId}});
    // Wait for a real lock waiter, not a timing guess.
    for(let i=0;i<100;i++) {
      const waiting=await pool.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%FROM tokens t%' AND pid<>pg_backend_pid()");
      if(waiting.rowCount) break;
      if(i===99) throw new Error("cleanup never waited on the token lock");
      await new Promise(resolve=>setTimeout(resolve,10));
    }
    await provenance.attachObservedToken(run.context,token.id,false,{client:attaching});
    await attaching.query("COMMIT");attaching.release();
    assert.deepEqual((await cleaning).deleted,[]);
    assert.ok(await inventory(token.id));
  });

  describe("durable creation counter", () => {
    it("initializes both provider totals at zero without reconstructing historical runs", async () => {
      const { migrations } = require("../../apps/api/migrations/migrate");
      const migration = migrations.find((entry) => entry.name === "auto_sync_provider_stats");
      assert.ok(migration, "durable counter migration is registered");
      const client = await pool.connect();
      const schema = `auto_sync_metrics_${crypto.randomUUID().replaceAll("-", "")}`;
      try {
        await client.query("BEGIN");
        await client.query(`CREATE SCHEMA ${schema}`);
        await client.query(`SET LOCAL search_path TO ${schema}`);
        await client.query(migration.sql);
        const rows = (await client.query(
          "SELECT provider, items_created_total::text FROM auto_sync_provider_stats ORDER BY provider",
        )).rows;
        assert.deepEqual(rows, [
          { provider: "github", items_created_total: "0" },
          { provider: "gitlab", items_created_total: "0" },
        ]);
      } finally {
        await client.query("ROLLBACK");
        client.release();
      }
    });

    it("counts new committed auto-sync rows, excluding updates, manual imports and adoption", async () => {
      const before = await createdTotal();
      const githubBefore = await createdTotal("github");
      const run = await start(await configuration());
      await scan(run, ["42", "manual", "legacy"]);
      assert.equal((await imported(run)).created, true);
      assert.equal(await createdTotal(), before + 1n);
      assert.equal((await imported(run, { name: "Renamed credential" })).created, false);

      const manual = await imported(run, {
        source_object_id: "manual", name: "Manually imported credential",
      }, true);
      assert.equal(manual.created, true);
      const rediscovered = await imported(run, {
        source_object_id: "manual", name: "Manually imported credential",
      });
      assert.equal(rediscovered.created, false);
      assert.equal(rediscovered.token.id, manual.token.id);

      const legacy = await Token.create({
        userId, workspaceId, name: "Legacy credential", location: "gitlab.example",
        type: "api_key", expiration: "2028-01-01",
      });
      const adopted = await imported(run, {
        source_object_id: "legacy", name: "Legacy credential",
      });
      assert.equal(adopted.created, false);
      assert.equal(adopted.token.id, legacy.id);
      assert.equal(await createdTotal(), before + 1n);
      assert.equal(await createdTotal("github"), githubBefore);
    });

    for (const atCommit of [false, true]) {
      it(`rolls back inventory and totals when ${atCommit ? "COMMIT" : "the counter write"} fails`, async () => {
        const before = await createdTotal();
        const run = await start(await configuration());
        await scan(run, ["42"]);
        await withRejectedCreation({ atCommit }, async () => {
          await assert.rejects(imported(run), /forced creation counter test failure/);
        });

        assert.equal(await createdTotal(), before);
        assert.equal((await pool.query(
          "SELECT id FROM tokens WHERE workspace_id = $1", [workspaceId],
        )).rowCount, 0);
        assert.equal((await pool.query(
          "SELECT token_id FROM auto_sync_token_links WHERE config_id = $1", [run.config.id],
        )).rowCount, 0);
        assert.equal((await pool.query(
          "SELECT id FROM auto_sync_token_link_events WHERE workspace_id = $1", [workspaceId],
        )).rowCount, 0);
      });
    }

    for (const status of ["partial", "failed"]) {
      it(`retains committed creations when the run later finishes ${status}`, async () => {
        const before = await createdTotal();
        const run = await start(await configuration());
        await scan(run, ["42"]);
        await imported(run);
        assert.equal(await createdTotal(), before + 1n);

        const result = status === "partial"
          ? { status, discovered: 2, created: 1, errors: 1 }
          : { status, errors: 1 };
        await runs.withCurrentRun(run.config, (client) =>
          runs.finishAutoSyncRun(client, run.config, result));
        assert.equal(await createdTotal(), before + 1n);
      });
    }

    it("survives a worker crash after import and does not recount the replacement run", async () => {
      const before = await createdTotal();
      const original = await start(await configuration());
      await scan(original, ["42"]);
      const { token } = await imported(original);
      // The token transaction committed, but the worker never received the
      // response or called finishAutoSyncRun. Expire its lease as after a crash.
      const unfinished = (await pool.query(
        "SELECT status, created_count FROM auto_sync_runs WHERE run_id = $1", [original.config.runId],
      )).rows[0];
      assert.deepEqual(unfinished, { status: "running", created_count: 0 });
      assert.equal(await createdTotal(), before + 1n);
      await pool.query(
        "UPDATE auto_sync_configs SET lease_until = NOW() - INTERVAL '1 second' WHERE id = $1",
        [original.config.id],
      );

      const replacement = await start(original.config);
      await scan(replacement, ["42"]);
      const retry = await imported(replacement);
      assert.equal(retry.token.id, token.id);
      assert.equal(retry.created, false);
      await finish(replacement);
      assert.equal((await pool.query(
        "SELECT status FROM auto_sync_runs WHERE run_id = $1", [original.config.runId],
      )).rows[0].status, "superseded");
      assert.equal(await createdTotal(), before + 1n);
    });

    it("does not decrease when inventory, its configuration, or its workspace is deleted", async () => {
      const before = await createdTotal();
      const run = await start(await configuration());
      await scan(run, ["42"]);
      const { token } = await imported(run);
      await finish(run);
      await Token.delete(token.id);
      assert.equal(await createdTotal(), before + 1n);

      const response = await request(app).delete(
        `/api/v1/workspaces/${workspaceId}/auto-sync/${run.config.id}`,
      );
      assert.equal(response.status, 200, JSON.stringify(response.body));
      assert.equal(await createdTotal(), before + 1n);
      await pool.query("DELETE FROM workspaces WHERE id = $1", [workspaceId]);
      assert.equal((await pool.query(
        "SELECT run_id FROM auto_sync_runs WHERE workspace_id = $1", [workspaceId],
      )).rowCount, 0);
      assert.equal(await createdTotal(), before + 1n);
    });

    it("a fresh collector reports persisted creations when no sync configs are due", async () => {
      const { Registry } = require("../../apps/api/node_modules/prom-client");
      const { registerAutoSyncMetrics } = require("../../apps/api/services/autoSyncMetrics");
      const before = await createdTotal();
      const run = await start(await configuration());
      await scan(run, ["42"]);
      await imported(run);
      await finish(run);
      assert.deepEqual(await runs.claimDueAutoSyncRuns(), []);

      for (let i = 0; i < 2; i++) {
        const registry = new Registry();
        registerAutoSyncMetrics(registry);
        const metric = (await registry.getMetricsAsJSON()).find(
          (entry) => entry.name === "auto_sync_items_created_total",
        );
        assert.equal(metric.type, "counter");
        const gitlab = metric.values.find((sample) => sample.labels.provider === "gitlab");
        assert.equal(gitlab.value, Number(before + 1n));
      }
    });
  });
});

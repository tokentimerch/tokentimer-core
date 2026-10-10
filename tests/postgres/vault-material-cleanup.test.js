"use strict";

// Dedicated migrated PostgreSQL only. Fixtures create users/workspaces/configs;
// inventory tokens and scan provenance go through the production HTTP routes.
// Only the external Vault HTTP boundary and authenticated test identity are
// substituted. No private material is generated, returned, or read by fixtures.
const {
  before,
  after,
  beforeEach,
  afterEach,
  describe,
  it,
  mock,
} = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
assert.equal(process.env.DB_HOST, "127.0.0.1");
assert.match(process.env.DB_NAME || "", /^pr329_cleanup.*_test$/);
assert.equal(process.env.NODE_ENV, "test");
const request = require("supertest");
const express = require("../../apps/api/node_modules/express");
const { pool } = require("../../apps/api/db/database");
const { getScan } = require("../../apps/api/services/integrationScans");
const {
  cleanupObsoleteTokens,
} = require("../../apps/api/services/importCleanup");

const version = "22222222-2222-4222-8222-222222222222";
const protectedPath = `bundles/${version}`;
const publicPath = `${protectedPath}-public`;
const address = "https://vault.cleanup.fixture.invalid";
const hits = [];
let keys, materialPresent, userId, workspaceId, app, runs, workerPool;

async function inventory() {
  return (
    await pool.query(
      "SELECT id,source_object_id,source_dimensions FROM tokens WHERE workspace_id=$1",
      [workspaceId],
    )
  ).rows;
}
async function scan(pathPrefix = "", run = null, workspace = workspaceId) {
  const response = await request(app)
    .post("/api/v1/integrations/vault/scan")
    .set(run ? { Authorization: "Bearer vault-cleanup-test-worker" } : {})
    .send({
      workspace_id: workspace,
      address,
      token: "synthetic-vault-token",
      include: { kv: true, pki: false },
      pathPrefix,
      ...(run ? { auto_sync_run: runs.runContext(run) } : {}),
    });
  assert.equal(response.status, 200, JSON.stringify(response.body));
  assert.ok(
    response.body.scan_id,
    "The production route must persist its scanner result",
  );
  return response.body;
}
async function importScan(
  result,
  { cleanup = false, run = null, workspace = workspaceId } = {},
) {
  const response = await request(app)
    .post("/api/v1/integrations/vault/import")
    .set(run ? { Authorization: "Bearer vault-cleanup-test-worker" } : {})
    .send({
      workspace_id: workspace,
      items: result.items,
      scan_id: result.scan_id,
      ...(cleanup
        ? {
            cleanup: {
              enabled: true,
              provider: "vault",
              scanId: result.scan_id,
            },
          }
        : {}),
      ...(run
        ? {
            auto_sync_run: runs.runContext(run),
            auto_sync_scan_ids: [result.scan_id],
          }
        : {}),
    });
  assert.equal(response.status, 201, JSON.stringify(response.body));
  assert.equal(response.body.error_count, 0, JSON.stringify(response.body));
  return response.body;
}
async function claim(configId) {
  // Claim only this fixture when retained evidence contains older due configs.
  await pool.query(
    "UPDATE auto_sync_configs SET next_sync_at='1970-01-01' WHERE id=$1",
    [configId],
  );
  const claimed = await runs.claimDueAutoSyncRuns(1);
  assert.equal(claimed.length, 1);
  assert.equal(claimed[0].id, configId);
  return claimed[0];
}
async function finish(run) {
  return runs.withCurrentRun(run, (client) =>
    runs.finishAutoSyncRun(client, run, { status: "success" }),
  );
}

describe(
  "Vault excluded material scan cleanup (real PostgreSQL and HTTP routes)",
  { concurrency: false },
  () => {
    before(async () => {
      ({ pool: workerPool } = await import("../../apps/worker/src/db.js"));
      runs = await import("../../apps/worker/src/shared/autoSyncRuns.js");
      assert.equal(
        (await pool.query("SELECT 1 FROM migrations WHERE version=70"))
          .rowCount,
        1,
      );
      process.env.WORKER_API_KEY = "vault-cleanup-test-worker";
      userId = (
        await pool.query(
          `INSERT INTO users(email,display_name,email_verified,password_hash)
      VALUES($1,'Vault cleanup test',TRUE,'synthetic-fixture') RETURNING id`,
          [`vault-cleanup-${crypto.randomUUID()}@example.test`],
        )
      ).rows[0].id;
      app = express();
      app.use(express.json());
      app.use((req, _res, next) => {
        req.user = req.get("Authorization")
          ? null
          : { id: userId, email_verified: true };
        req.isAuthenticated = () => Boolean(req.user);
        next();
      });
      app.use(require("../../apps/api/routes/integrations"));
      mock.method(globalThis, "fetch", async (url, options) => {
        assert.equal(new URL(url).origin, address);
        const pathname = new URL(url).pathname;
        hits.push({ pathname, method: options.method });
        assert.ok(
          !pathname.includes(protectedPath + "/") &&
            !pathname.endsWith(protectedPath),
          "No GET or LIST may target a protected material object",
        );
        let body;
        if (pathname === "/v1/sys/mounts")
          body = {
            data: { "secret/": { type: "kv", options: { version: "2" } } },
          };
        else if (pathname === "/v1/secret/metadata/")
          body = { data: { keys: ["bundles/"] } };
        else if (pathname === "/v1/secret/metadata/bundles/")
          body = {
            data: {
              keys: [
                ...keys.map((key) => key.slice("bundles/".length)),
                ...(materialPresent ? [version, version + "/"] : []),
              ],
            },
          };
        else if (
          pathname.startsWith("/v1/secret/data/") &&
          keys.includes(pathname.slice("/v1/secret/data/".length))
        ) {
          body = {
            data: {
              data: { expires_at: "2099-01-01" },
              metadata: { version: 1 },
            },
          };
        }
        return new Response(JSON.stringify(body || {}), {
          status: body ? 200 : 404,
          headers: { "Content-Type": "application/json" },
        });
      });
    });
    beforeEach(async () => {
      keys = [publicPath, "bundles/legacy-public"];
      materialPresent = false;
      hits.length = 0;
      workspaceId = crypto.randomUUID();
      await pool.query(
        "INSERT INTO workspaces(id,name,created_by) VALUES($1,'Isolated Vault cleanup',$2)",
        [workspaceId, userId],
      );
      await pool.query(
        "INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES($1,$2,'admin')",
        [workspaceId, userId],
      );
    });
    afterEach(async () => {
      await pool.query(
        "UPDATE auto_sync_configs SET enabled=FALSE WHERE workspace_id=$1",
        [workspaceId],
      );
    });
    after(async () => {
      mock.restoreAll();
      await workerPool?.end();
      await pool.end();
      // Keep the dedicated database as reproducible evidence; never shared data.
    });

    it("manual cleanup cannot delete a legitimate public sibling after an explicitly excluded scan", async () => {
      const original = await scan();
      assert.equal(original.summary[0].complete, true);
      await importScan(original);
      const token = (await inventory()).find(
        (item) => item.source_object_id === "secret/" + publicPath,
      );
      assert.ok(
        token,
        "Import must create a provenance-bound public inventory token",
      );
      const start = hits.length;
      const excluded = await scan(protectedPath);
      const persisted = await getScan({
        scanId: excluded.scan_id,
        workspaceId,
        provider: "vault",
      });
      const cleaned = await importScan(excluded, { cleanup: true });
      const retained = (await inventory()).some((item) => item.id === token.id);
      console.log(
        JSON.stringify({
          scenario: "manual protected-prefix cleanup",
          reportedComplete: excluded.summary[0].complete,
          persistedComplete: persisted.cleanup_scope.subScopes[0].complete,
          deleted: cleaned.deleted_count,
          tokenRetained: retained,
        }),
      );
      assert.ok(
        hits.slice(start).every((hit) => hit.pathname === "/v1/sys/mounts"),
      );
      assert.equal(
        retained,
        true,
        "An uninspected protected prefix must not delete a public UUID-suffix sibling",
      );
      assert.equal(cleaned.deleted_count, 0);
      assert.equal(excluded.summary[0].complete, false);
      assert.equal(persisted.cleanup_scope.subScopes[0].complete, false);
      assert.equal(
        persisted.cleanup_scope.subScopes[0].reason,
        "protected_material_paths",
      );
    });

    it("mixed scans retain obsolete public inventory, while a complete public scan can still clean it up once", async () => {
      await importScan(await scan());
      keys = ["bundles/legacy-public"];
      materialPresent = true;
      const mixed = await scan();
      assert.equal(mixed.items.length, 1);
      assert.equal(mixed.summary[0].complete, false);
      assert.equal(
        (await importScan(mixed, { cleanup: true })).deleted_count,
        0,
      );
      assert.equal((await inventory()).length, 2);
      materialPresent = false;
      const complete = await scan();
      assert.equal(complete.summary[0].complete, true);
      assert.equal(
        (await importScan(complete, { cleanup: true })).deleted_count,
        1,
      );
      assert.equal((await inventory()).length, 1);
      assert.equal(
        (await importScan(complete, { cleanup: true })).deleted_count,
        0,
        "Scan IDs remain single-use",
      );
    });

    it("a scan ID from another workspace cannot authorize destructive cleanup", async () => {
      await importScan(await scan());
      keys = [];
      const empty = await scan();
      const other = crypto.randomUUID();
      await pool.query(
        "INSERT INTO workspaces(id,name,created_by) VALUES($1,'Other isolated workspace',$2)",
        [other, userId],
      );
      assert.deepEqual(
        (
          await cleanupObsoleteTokens({
            workspaceId: other,
            actorUserId: userId,
            cleanup: {
              enabled: true,
              provider: "vault",
              scanId: empty.scan_id,
            },
          })
        ).deleted,
        [],
      );
      assert.equal((await inventory()).length, 2);
      assert.equal(
        (await importScan(empty, { cleanup: true })).deleted_count,
        2,
      );
    });

    it("fenced auto-sync retains associations for excluded scopes and cleans up only a complete public scope", async () => {
      await pool.query(
        "UPDATE auto_sync_feature_state SET multi_config_enabled=TRUE WHERE id=TRUE",
      );
      const config = (
        await pool.query(
          `INSERT INTO auto_sync_configs(workspace_id,provider,credentials_encrypted,connection_key,created_by,next_sync_at)
      VALUES($1,'vault','synthetic-fixture','Vault cleanup run',$2,NOW()) RETURNING id`,
          [workspaceId, userId],
        )
      ).rows[0];
      let run = await claim(config.id);
      const original = await scan("", run);
      await importScan(original, { run });
      assert.equal((await inventory()).length, 2);
      await finish(run);
      run = await claim(config.id);
      const excluded = await scan(protectedPath, run);
      const result = await importScan(excluded, { cleanup: true, run });
      console.log(
        JSON.stringify({
          scenario: "fenced auto-sync protected-prefix cleanup",
          scanComplete: result.scan_complete,
          cleanupComplete: result.cleanup_complete,
          deleted: result.deleted_count,
          remaining: (await inventory()).length,
        }),
      );
      assert.equal(result.scan_complete, false);
      assert.equal(result.cleanup_complete, false);
      assert.equal(result.deleted_count, 0);
      assert.equal(result.detached_count, 0);
      assert.equal((await inventory()).length, 2);
      await finish(run);
      run = await claim(config.id);
      keys = [];
      const empty = await scan("", run);
      const removed = await importScan(empty, { cleanup: true, run });
      assert.equal(removed.scan_complete, true);
      assert.equal(removed.cleanup_complete, true);
      assert.equal(removed.deleted_count, 2);
      assert.equal((await inventory()).length, 0);
      await finish(run);
      // A finished run cannot replay a previously valid scan/import context.
      const replay = await request(app)
        .post("/api/v1/integrations/vault/import")
        .set("Authorization", "Bearer vault-cleanup-test-worker")
        .send({
          workspace_id: workspaceId,
          items: [],
          scan_id: empty.scan_id,
          auto_sync_run: runs.runContext(run),
        });
      assert.equal(replay.status, 409);
      assert.equal(replay.body.code, "AUTO_SYNC_RUN_STALE");
    });
  },
);

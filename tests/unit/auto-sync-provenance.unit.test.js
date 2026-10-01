"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { pool } = require("../../apps/api/db/database");
const provenance = require("../../apps/api/services/autoSyncProvenance");
const { migrations } = require("../../apps/api/migrations/migrate");

const configId = "11111111-1111-4111-8111-111111111111";
const runId = "22222222-2222-4222-8222-222222222222";
const leaseOwner = "33333333-3333-4333-8333-333333333333";
const workspaceId = "44444444-4444-4444-8444-444444444444";
const scanId = "55555555-5555-4555-8555-555555555555";
const context = {
  configId, runId, leaseOwner, workspaceId, scanId,
  provider: "gitlab", generation: 2, scanVersion: 1,
};

function fakeClient(handler, calls) {
  return {
    async query(sql, params) {
      calls.push({ sql, params });
      if (sql.includes("SELECT scan_id FROM auto_sync_run_scans")) return { rows: [{ scan_id: scanId }], rowCount: 1 };
      return handler(sql, params);
    },
    release() {},
  };
}

async function withPoolClient(client, work) {
  const original = pool.connect;
  pool.connect = async () => client;
  try {
    return await work();
  } finally {
    pool.connect = original;
  }
}

describe("auto-sync provenance transaction boundaries", () => {
  it("rejects a stale fence before any token write", async () => {
    const calls = [];
    const client = fakeClient((sql) => {
      if (sql.includes("FROM auto_sync_configs c")) return { rows: [] };
      return { rows: [], rowCount: 0 };
    }, calls);
    let wrote = false;
    await withPoolClient(client, async () => {
      await assert.rejects(
        provenance.withFencedImport(context, async () => { wrote = true; }),
        { code: "AUTO_SYNC_RUN_STALE" },
      );
    });
    assert.equal(wrote, false);
    assert.equal(calls.at(-1).sql, "ROLLBACK");
  });

  for (const managed of [false, true]) {
    it(`detaches an unseen ${managed ? "managed" : "observed"} token atomically`, async () => {
      const calls = [];
      const scan = {
        id: scanId, source_instance: "https://gitlab.example",
        source_owner_key: "group", started_at: new Date("2026-01-01"),
        completed_at: new Date("2026-01-01"),
        cleanup_scope: { subScopes: [{ sourceKind: "gitlab-pat", complete: true }] },
      };
      const client = fakeClient((sql) => {
        if (sql.includes("FROM auto_sync_configs c")) {
          return { rows: [{ connection_key: "Production" }], rowCount: 1 };
        }
        if (sql.includes("FROM integration_scans")) return { rows: [scan], rowCount: 1 };
        if (sql.includes("UPDATE integration_scans")) return { rows: [scan], rowCount: 1 };
        if (sql.includes("FROM auto_sync_token_links l") && sql.includes("JOIN tokens t")) {
          return { rows: [{ id: 12, auto_sync_managed: managed }], rowCount: 1 };
        }
        if (sql.includes("DELETE FROM auto_sync_token_links")) return { rows: [{ token_id: 12 }], rowCount: 1 };
        if (sql.includes("DELETE FROM tokens")) return { rows: [{ id: 12 }], rowCount: 1 };
        if (sql.includes("SELECT 1 FROM auto_sync_token_links")) return { rows: [], rowCount: 0 };
        return { rows: [], rowCount: 0 };
      }, calls);
      const result = await withPoolClient(client, () => provenance.reconcileAutoSyncRun(context));
      assert.equal(result.complete, true);
      assert.equal(result.detached, 1);
      assert.equal(result.deleted, managed ? 1 : 0);
      assert.equal(calls.some((call) => call.sql.includes("DELETE FROM tokens")), managed);
      assert.equal(calls.at(-1).sql, "COMMIT");
      const detach = calls.findIndex((call) => call.sql.includes("DELETE FROM auto_sync_token_links"));
      const event = calls.findIndex((call) => call.sql.includes("'detached'"));
      assert.ok(event > detach);
    });
  }

  it("keeps associations when any requested scope is incomplete", async () => {
    const calls = [];
    const client = fakeClient((sql) => {
      if (sql.includes("FROM auto_sync_configs c")) {
        return { rows: [{ connection_key: "Production" }], rowCount: 1 };
      }
      if (sql.includes("FROM integration_scans")) {
        return { rows: [{
          id: scanId, completed_at: new Date(),
          cleanup_scope: { subScopes: [{ sourceKind: "gitlab-pat", complete: false }] },
        }], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    }, calls);
    const result = await withPoolClient(client, () => provenance.reconcileAutoSyncRun(context));
    assert.equal(result.complete, false);
    assert.equal(calls.some((call) => call.sql.includes("DELETE FROM auto_sync_token_links")), false);
  });

  it("snapshots effective scope metadata without credential objects", async () => {
    const { settingsSnapshot } = await import("../../apps/worker/src/shared/autoSyncRuns.js");
    const snapshot = settingsSnapshot({cleanup_obsolete:true,credentials_encrypted:"do-not-copy",scan_params:{
      token:"do-not-copy",region:"eu-west-1",include:{tokens:true,secret:"do-not-copy"},
      filters:{includeProjectTokens:true,includeRevoked:false},
      filterRules:[{field:"name",matchType:"regex",value:"^prod",action:"include",token:"do-not-copy"},
        {value:{token:"do-not-copy"}}]}});
    assert.equal(snapshot.filters.includeProjectTokens,true);
    assert.equal(snapshot.filterRules[0].value,"^prod");
    assert.equal(snapshot.region,"eu-west-1");
    assert.ok(!JSON.stringify(snapshot).includes("do-not-copy"));
  });

  it("normalizes names before PostgreSQL uniqueness enforcement", () => {
    assert.equal(provenance.normalizeConnectionName("  Prod \t GitLab  "), "Prod GitLab");
    assert.equal(provenance.normalizeConnectionName("   "), null);
  });

  it("does not supersede a run for JSON key ordering alone", () => {
    assert.equal(provenance.scanSettingsEqual(
      { include: { tokens: true, keys: false }, maxItems: 50 },
      { maxItems: 50, include: { keys: false, tokens: true } },
    ), true);
  });

  it("migrates legacy inventory without claiming deletion ownership", () => {
    const sql = migrations.find((migration) => migration.version === 61)?.sql || "";
    assert.match(sql, /auto_sync_managed BOOLEAN NOT NULL DEFAULT FALSE/);
    assert.match(sql, /LOWER\(connection_key\)/);
    assert.doesNotMatch(sql, /INSERT INTO auto_sync_token_links/i);
  });
});

"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  raiseOperationalNotification,
  resolveOperationalNotification,
} = require(
  path.resolve(__dirname, "../../apps/api/services/operationalNotifications.js"),
);

function mockClient(handler) {
  const calls = [];
  return {
    calls,
    async query(sql, params) {
      calls.push({ sql: String(sql), params });
      return handler(String(sql), params);
    },
  };
}

describe("operationalNotifications service (API, CJS)", () => {
  describe("raiseOperationalNotification", () => {
    it("returns null and issues no query when required fields are missing", async () => {
      const client = mockClient(() => {
        throw new Error("should not query");
      });
      const id = await raiseOperationalNotification(client, {
        workspaceId: "ws-1",
        category: "delivery",
        // missing type/severity/dedupeKey/title
      });
      assert.equal(id, null);
      assert.equal(client.calls.length, 0);
    });

    it("returns null and issues no query for an invalid category", async () => {
      const client = mockClient(() => {
        throw new Error("should not query");
      });
      const id = await raiseOperationalNotification(client, {
        workspaceId: "ws-1",
        category: "not_a_category",
        type: "x",
        severity: "critical",
        dedupeKey: "k",
        title: "t",
      });
      assert.equal(id, null);
      assert.equal(client.calls.length, 0);
    });

    it("returns null and issues no query for an invalid severity", async () => {
      const client = mockClient(() => {
        throw new Error("should not query");
      });
      const id = await raiseOperationalNotification(client, {
        workspaceId: "ws-1",
        category: "delivery",
        type: "x",
        severity: "urgent",
        dedupeKey: "k",
        title: "t",
      });
      assert.equal(id, null);
      assert.equal(client.calls.length, 0);
    });

    it("upserts on the open-incident dedupe key and returns the row id", async () => {
      const client = mockClient((sql, params) => {
        assert.match(sql, /ON CONFLICT \(workspace_id, dedupe_key\) WHERE resolved_at IS NULL/);
        assert.equal(params[0], "ws-1");
        assert.equal(params[5], "delivery_blocked:42");
        assert.equal(params[8], JSON.stringify({ alert_queue_id: 42 }));
        return { rows: [{ id: "notif-1" }] };
      });
      const id = await raiseOperationalNotification(client, {
        workspaceId: "ws-1",
        tokenId: 7,
        category: "delivery",
        type: "delivery_blocked",
        severity: "critical",
        dedupeKey: "delivery_blocked:42",
        title: "Delivery blocked",
        message: "Maximum delivery attempts reached",
        metadata: { alert_queue_id: 42 },
      });
      assert.equal(id, "notif-1");
      assert.equal(client.calls.length, 1);
    });

    it("defaults to the module pool when no client is passed", async () => {
      // Passing null/undefined client falls back to `pool` internally; we
      // only assert this does not throw synchronously before hitting the DB
      // (missing required fields short-circuits before any query).
      const id = await raiseOperationalNotification(null, {});
      assert.equal(id, null);
    });

    it("swallows DB errors and returns null", async () => {
      const client = mockClient(() => {
        throw new Error("connection reset");
      });
      const id = await raiseOperationalNotification(client, {
        workspaceId: "ws-1",
        category: "auto_sync",
        type: "auto_sync_failed",
        severity: "warning",
        dedupeKey: "auto_sync_failed:9",
        title: "Auto-sync failed",
      });
      assert.equal(id, null);
    });
  });

  describe("resolveOperationalNotification", () => {
    it("is a no-op without workspaceId or dedupeKey", async () => {
      const client = mockClient(() => {
        throw new Error("should not query");
      });
      await resolveOperationalNotification(client, null, "some-key");
      await resolveOperationalNotification(client, "ws-1", null);
      assert.equal(client.calls.length, 0);
    });

    it("resolves the open notification matching workspace and dedupe key", async () => {
      const client = mockClient((sql, params) => {
        assert.match(sql, /SET resolved_at = NOW\(\), updated_at = NOW\(\)/);
        assert.match(sql, /WHERE workspace_id = \$1 AND dedupe_key = \$2 AND resolved_at IS NULL/);
        assert.deepEqual(params, ["ws-1", "delivery_blocked:42"]);
        return { rowCount: 1 };
      });
      await resolveOperationalNotification(client, "ws-1", "delivery_blocked:42");
      assert.equal(client.calls.length, 1);
    });

    it("swallows DB errors instead of throwing", async () => {
      const client = mockClient(() => {
        throw new Error("boom");
      });
      await assert.doesNotReject(() =>
        resolveOperationalNotification(client, "ws-1", "delivery_blocked:42"),
      );
    });
  });
});

"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const Module = require("module");
const path = require("path");

const alertQueueModulePath = path.resolve(
  __dirname,
  "../../apps/api/services/alertQueue.js",
);

function loadAlertQueue(pool) {
  const originalLoad = Module._load;
  delete require.cache[alertQueueModulePath];
  Module._load = function patchedLoad(request, parent, isMain) {
    if (request === "../db/database") return { pool };
    return originalLoad.call(this, request, parent, isMain);
  };
  try {
    return require(alertQueueModulePath);
  } finally {
    Module._load = originalLoad;
  }
}

describe("alertQueue.requeueAlertsCore (operational notification cleanup)", () => {
  it("returns 0 immediately without querying when userId is missing", async () => {
    const pool = {
      query: async () => {
        throw new Error("should not query");
      },
    };
    const count = await loadAlertQueue(pool).requeueAlertsCore({ userId: null });
    assert.equal(count, 0);
  });

  it("batches blocked and degraded cleanup for a workspace-scoped requeue", async () => {
    const calls = [];
    const pool = {
      query: async (sql, params) => {
        calls.push({ sql, params });
        if (calls.length === 1) {
          assert.match(sql, /RETURNING aq.id/);
          return { rowCount: 2, rows: [{ id: 10 }, { id: 11 }] };
        }
        return { rowCount: 4 };
      },
    };
    const count = await loadAlertQueue(pool).requeueAlertsCore({
      userId: "user-1",
      workspaceId: "ws-1",
    });

    assert.equal(count, 2);
    assert.equal(calls.length, 2);
    assert.match(calls[1].sql, /FROM unnest\(\$1::uuid\[\], \$2::text\[\]\)/);
    assert.match(calls[1].sql, /n.workspace_id = keys.workspace_id/);
    assert.match(calls[1].sql, /n.dedupe_key = keys.dedupe_key/);
    assert.deepEqual(calls[1].params, [
      ["ws-1", "ws-1", "ws-1", "ws-1"],
      [
        "delivery_blocked:10",
        "delivery_degraded:10",
        "delivery_blocked:11",
        "delivery_degraded:11",
      ],
    ]);
  });

  it("pairs each alert with its own workspace in an account-wide requeue", async () => {
    const calls = [];
    const pool = {
      query: async (sql, params) => {
        calls.push({ sql, params });
        if (calls.length === 1) {
          assert.match(sql, /RETURNING id, \(SELECT workspace_id/);
          return {
            rowCount: 2,
            rows: [
              { id: 20, workspace_id: "ws-a" },
              { id: 21, workspace_id: "ws-b" },
            ],
          };
        }
        return { rowCount: 4 };
      },
    };
    const count = await loadAlertQueue(pool).requeueAlertsCore({
      userId: "user-1",
    });

    assert.equal(count, 2);
    assert.equal(calls.length, 2);
    assert.deepEqual(calls[1].params, [
      ["ws-a", "ws-a", "ws-b", "ws-b"],
      [
        "delivery_blocked:20",
        "delivery_degraded:20",
        "delivery_blocked:21",
        "delivery_degraded:21",
      ],
    ]);
  });

  it("skips rows without a workspace and does not query cleanup for them", async () => {
    let calls = 0;
    const pool = {
      query: async () => {
        calls += 1;
        return { rowCount: 1, rows: [{ id: 30, workspace_id: null }] };
      },
    };
    const count = await loadAlertQueue(pool).requeueAlertsCore({
      userId: "user-1",
    });
    assert.equal(count, 1);
    assert.equal(calls, 1);
  });

  it("does nothing when the requeue affects no rows", async () => {
    let calls = 0;
    const pool = {
      query: async () => {
        calls += 1;
        return { rowCount: 0, rows: [] };
      },
    };
    const count = await loadAlertQueue(pool).requeueAlertsCore({
      userId: "user-1",
      workspaceId: "ws-1",
    });
    assert.equal(count, 0);
    assert.equal(calls, 1);
  });

  it("keeps the requeue successful if notification cleanup fails", async () => {
    let calls = 0;
    const pool = {
      query: async () => {
        calls += 1;
        if (calls === 1) return { rowCount: 1, rows: [{ id: 40 }] };
        throw new Error("notification table unavailable");
      },
    };
    const originalWarn = console.warn;
    console.warn = () => {};
    try {
      const count = await loadAlertQueue(pool).requeueAlertsCore({
        userId: "user-1",
        workspaceId: "ws-1",
      });
      assert.equal(count, 1);
      assert.equal(calls, 2);
    } finally {
      console.warn = originalWarn;
    }
  });
});

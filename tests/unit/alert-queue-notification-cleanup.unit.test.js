"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const Module = require("module");
const path = require("path");

const alertQueueModulePath = path.resolve(
  __dirname,
  "../../apps/api/services/alertQueue.js",
);
const operationalNotificationsModulePath = path.resolve(
  __dirname,
  "../../apps/api/services/operationalNotifications.js",
);

function withPatchedLoad(stubs, fn) {
  const originalLoad = Module._load;
  Module._load = function patchedLoad(request, parent, isMain) {
    if (Object.prototype.hasOwnProperty.call(stubs, request)) {
      return stubs[request];
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  try {
    return fn();
  } finally {
    Module._load = originalLoad;
  }
}

function loadAlertQueue({ pool, resolveOperationalNotification }) {
  delete require.cache[alertQueueModulePath];
  delete require.cache[operationalNotificationsModulePath];
  return withPatchedLoad(
    {
      "../db/database": { pool },
      "./operationalNotifications": { resolveOperationalNotification },
    },
    () => require(alertQueueModulePath),
  );
}

describe("alertQueue.requeueAlertsCore (operational notification cleanup)", () => {
  it("returns 0 immediately without querying when userId is missing", async () => {
    const pool = {
      query: async () => {
        throw new Error("should not query");
      },
    };
    const { requeueAlertsCore } = loadAlertQueue({
      pool,
      resolveOperationalNotification: async () => {
        throw new Error("should not resolve");
      },
    });
    const count = await requeueAlertsCore({ userId: null });
    assert.equal(count, 0);
  });

  it("workspace-scoped requeue resolves delivery_blocked/delivery_degraded notifications for each requeued alert", async () => {
    const resolvedKeys = [];
    const pool = {
      query: async (sql) => {
        assert.match(sql, /RETURNING aq.id/);
        return { rowCount: 2, rows: [{ id: 10 }, { id: 11 }] };
      },
    };
    const { requeueAlertsCore } = loadAlertQueue({
      pool,
      resolveOperationalNotification: async (client, workspaceId, dedupeKey) => {
        resolvedKeys.push({ workspaceId, dedupeKey });
      },
    });

    const count = await requeueAlertsCore({
      userId: "user-1",
      workspaceId: "ws-1",
    });

    assert.equal(count, 2);
    assert.deepEqual(
      resolvedKeys.sort((a, b) => a.dedupeKey.localeCompare(b.dedupeKey)),
      [
        { workspaceId: "ws-1", dedupeKey: "delivery_blocked:10" },
        { workspaceId: "ws-1", dedupeKey: "delivery_blocked:11" },
        { workspaceId: "ws-1", dedupeKey: "delivery_degraded:10" },
        { workspaceId: "ws-1", dedupeKey: "delivery_degraded:11" },
      ].sort((a, b) => a.dedupeKey.localeCompare(b.dedupeKey)),
    );
  });

  it("account-wide requeue resolves notifications using the workspace_id read off each row", async () => {
    const resolvedKeys = [];
    const pool = {
      query: async (sql) => {
        assert.match(sql, /RETURNING id, \(SELECT workspace_id/);
        return {
          rowCount: 2,
          rows: [
            { id: 20, workspace_id: "ws-a" },
            { id: 21, workspace_id: "ws-b" },
          ],
        };
      },
    };
    const { requeueAlertsCore } = loadAlertQueue({
      pool,
      resolveOperationalNotification: async (client, workspaceId, dedupeKey) => {
        resolvedKeys.push({ workspaceId, dedupeKey });
      },
    });

    const count = await requeueAlertsCore({ userId: "user-1" });

    assert.equal(count, 2);
    assert.ok(
      resolvedKeys.some(
        (r) => r.workspaceId === "ws-a" && r.dedupeKey === "delivery_blocked:20",
      ),
    );
    assert.ok(
      resolvedKeys.some(
        (r) => r.workspaceId === "ws-b" && r.dedupeKey === "delivery_degraded:21",
      ),
    );
  });

  it("account-wide requeue skips resolving a row whose workspace_id is null", async () => {
    let resolveCalls = 0;
    const pool = {
      query: async () => ({
        rowCount: 1,
        rows: [{ id: 30, workspace_id: null }],
      }),
    };
    const { requeueAlertsCore } = loadAlertQueue({
      pool,
      resolveOperationalNotification: async () => {
        resolveCalls += 1;
      },
    });

    const count = await requeueAlertsCore({ userId: "user-1" });

    assert.equal(count, 1);
    assert.equal(resolveCalls, 0);
  });

  it("does nothing when the requeue affects no rows", async () => {
    let resolveCalls = 0;
    const pool = {
      query: async () => ({ rowCount: 0, rows: [] }),
    };
    const { requeueAlertsCore } = loadAlertQueue({
      pool,
      resolveOperationalNotification: async () => {
        resolveCalls += 1;
      },
    });

    const count = await requeueAlertsCore({
      userId: "user-1",
      workspaceId: "ws-1",
    });

    assert.equal(count, 0);
    assert.equal(resolveCalls, 0);
  });
});

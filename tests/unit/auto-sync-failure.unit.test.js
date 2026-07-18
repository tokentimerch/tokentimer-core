"use strict";

const { describe, it, before } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const { pathToFileURL } = require("url");

async function importFresh(relativePath) {
  const abs = path.join(__dirname, "..", "..", relativePath);
  const href = `${pathToFileURL(abs).href}?t=${Date.now()}-${Math.random()}`;
  return import(href);
}

describe("autoSyncFailure helpers", () => {
  it("formatAutoSyncError prefers API error body over Axios message", async () => {
    const mod = await importFresh("apps/worker/src/shared/autoSyncFailure.js");
    const err = {
      message: "Request failed with status code 401",
      response: {
        status: 401,
        data: {
          error:
            "Authentication failed. Token may be expired (Azure CLI tokens expire quickly).",
        },
      },
    };
    assert.strictEqual(
      mod.formatAutoSyncError(err),
      "Authentication failed. Token may be expired (Azure CLI tokens expire quickly).",
    );
  });

  it("formatAutoSyncError falls back to err.message", async () => {
    const mod = await importFresh("apps/worker/src/shared/autoSyncFailure.js");
    assert.strictEqual(
      mod.formatAutoSyncError(new Error("Network timeout")),
      "Network timeout",
    );
  });
});

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

describe("recordAutoSyncFailure (bell + email escalation)", () => {
  before(() => {
    process.env.NODE_ENV = "test";
  });

  it("raises a warning-severity bell notification below the critical threshold, without emailing", async () => {
    const mod = await importFresh("apps/worker/src/shared/autoSyncFailure.js");
    let raisedSeverity = null;
    const client = mockClient((sql) => {
      if (sql.includes("UPDATE auto_sync_configs")) {
        return { rows: [{ consecutive_failures: 1 }] };
      }
      if (sql.includes("INSERT INTO operational_notifications")) {
        raisedSeverity = "checked-below";
        return { rows: [{ id: "notif-1" }] };
      }
      if (sql.includes("email_sent_at IS NULL")) {
        throw new Error("must not attempt to email below the critical threshold");
      }
      if (sql.includes("INSERT INTO audit_events")) {
        return { rows: [] };
      }
      if (sql.includes("workspace_memberships")) {
        return { rows: [{ user_id: 1 }] };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    await mod.recordAutoSyncFailure(client, {
      configId: "cfg-1",
      workspaceId: "ws-1",
      provider: "github",
      createdBy: 1,
      previousStatus: "success",
      errorMessage: "Rate limited",
      nextSync: new Date(),
    });

    assert.equal(raisedSeverity, "checked-below");
    const insertCall = client.calls.find((c) =>
      c.sql.includes("INSERT INTO operational_notifications"),
    );
    assert.equal(insertCall.params[4], "warning");
  });

  it("escalates to critical (and emails) once consecutive_failures reaches the threshold", async () => {
    const mod = await importFresh("apps/worker/src/shared/autoSyncFailure.js");
    let emailClaimed = false;
    const client = mockClient((sql) => {
      if (sql.includes("UPDATE auto_sync_configs")) {
        return { rows: [{ consecutive_failures: 3 }] };
      }
      if (sql.includes("INSERT INTO operational_notifications")) {
        return { rows: [{ id: "notif-1" }] };
      }
      if (sql.includes("email_sent_at IS NULL")) {
        emailClaimed = true;
        return { rows: [{ id: "notif-1" }] };
      }
      if (sql.includes("COUNT(*)::int AS c")) {
        return { rows: [{ c: 0 }] };
      }
      if (sql.includes("wm.role = 'admin'")) {
        return { rows: [{ email: "admin@example.com" }] };
      }
      if (sql.includes("INSERT INTO audit_events")) {
        return { rows: [] };
      }
      if (sql.includes("workspace_memberships")) {
        return { rows: [{ user_id: 1 }] };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    await mod.recordAutoSyncFailure(client, {
      configId: "cfg-1",
      workspaceId: "ws-1",
      provider: "github",
      createdBy: 1,
      previousStatus: "success",
      errorMessage: "Rate limited",
      nextSync: new Date(),
    });

    const insertCall = client.calls.find((c) =>
      c.sql.includes("INSERT INTO operational_notifications"),
    );
    assert.equal(insertCall.params[4], "critical");
    assert.equal(emailClaimed, true);
  });

  it("skips the AUTO_SYNC_FAILED audit write when already failed (no duplicate hourly audit rows)", async () => {
    const mod = await importFresh("apps/worker/src/shared/autoSyncFailure.js");
    let auditWritten = false;
    const client = mockClient((sql) => {
      if (sql.includes("UPDATE auto_sync_configs")) {
        return { rows: [{ consecutive_failures: 2 }] };
      }
      if (sql.includes("INSERT INTO operational_notifications")) {
        return { rows: [{ id: "notif-1" }] };
      }
      if (sql.includes("INSERT INTO audit_events")) {
        auditWritten = true;
        return { rows: [] };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    await mod.recordAutoSyncFailure(client, {
      configId: "cfg-1",
      workspaceId: "ws-1",
      provider: "github",
      createdBy: 1,
      previousStatus: "failed",
      errorMessage: "Rate limited",
      nextSync: new Date(),
    });

    assert.equal(auditWritten, false);
  });
});

describe("recordAutoSyncRecovery", () => {
  it("resets the consecutive-failure counter and resolves the open bell notification", async () => {
    const mod = await importFresh("apps/worker/src/shared/autoSyncFailure.js");
    const client = mockClient((sql, params) => {
      if (sql.includes("UPDATE auto_sync_configs")) {
        assert.match(sql, /SET consecutive_failures = 0/);
        return { rowCount: 1 };
      }
      if (sql.includes("resolved_at = NOW()")) {
        assert.deepEqual(params, ["ws-1", "auto_sync_failed:cfg-1"]);
        return { rowCount: 1 };
      }
      throw new Error(`unexpected query: ${sql}`);
    });

    await mod.recordAutoSyncRecovery(client, {
      configId: "cfg-1",
      workspaceId: "ws-1",
    });

    assert.equal(client.calls.length, 2);
  });

  it("swallows errors instead of throwing", async () => {
    const mod = await importFresh("apps/worker/src/shared/autoSyncFailure.js");
    const client = mockClient(() => {
      throw new Error("boom");
    });
    await assert.doesNotReject(() =>
      mod.recordAutoSyncRecovery(client, { configId: "cfg-1", workspaceId: "ws-1" }),
    );
  });
});

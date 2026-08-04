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

  it("recordAutoSyncCompleted writes an AUTO_SYNC_COMPLETED audit event for scheduled runs", async () => {
    const mod = await importFresh("apps/worker/src/shared/autoSyncFailure.js");
    const calls = [];
    const client = {
      async query(sql, params) {
        calls.push({ sql, params });
        return { rows: [] };
      },
    };

    await mod.recordAutoSyncCompleted(client, {
      configId: "cfg-1",
      workspaceId: "ws-1",
      provider: "gitlab",
      createdBy: 42,
      status: "success",
      itemsScanned: 7,
      itemsImported: 7,
    });

    const insert = calls.find((c) => c.sql.includes("INSERT INTO audit_events"));
    assert.ok(insert, "expected an audit_events INSERT");
    const [subjectUserId, action, metadata, workspaceId] = insert.params;
    assert.strictEqual(subjectUserId, 42);
    assert.strictEqual(action, "AUTO_SYNC_COMPLETED");
    assert.strictEqual(workspaceId, "ws-1");
    assert.strictEqual(metadata.provider, "gitlab");
    assert.strictEqual(metadata.status, "success");
    assert.strictEqual(metadata.items_scanned, 7);
    assert.strictEqual(metadata.items_imported, 7);
    assert.strictEqual(metadata.config_id, "cfg-1");
    assert.ok(!("error" in metadata));
  });

  it("recordAutoSyncCompleted includes the partial error and resolves the subject from workspace admins", async () => {
    const mod = await importFresh("apps/worker/src/shared/autoSyncFailure.js");
    const calls = [];
    const client = {
      async query(sql, params) {
        calls.push({ sql, params });
        if (sql.includes("workspace_memberships") && sql.includes("'admin'")) {
          return { rows: [{ user_id: 7 }] };
        }
        return { rows: [] };
      },
    };

    await mod.recordAutoSyncCompleted(client, {
      configId: "cfg-2",
      workspaceId: "ws-2",
      provider: "github",
      createdBy: null,
      status: "partial",
      itemsScanned: 5,
      itemsImported: 3,
      error: "2 of 5 scanned item(s) failed to import.",
    });

    const insert = calls.find((c) => c.sql.includes("INSERT INTO audit_events"));
    assert.ok(insert, "expected an audit_events INSERT");
    const [subjectUserId, action, metadata] = insert.params;
    assert.strictEqual(subjectUserId, 7);
    assert.strictEqual(action, "AUTO_SYNC_COMPLETED");
    assert.strictEqual(metadata.status, "partial");
    assert.strictEqual(metadata.error, "2 of 5 scanned item(s) failed to import.");
  });

  it("recordAutoSyncCompleted never throws when the audit insert fails", async () => {
    const mod = await importFresh("apps/worker/src/shared/autoSyncFailure.js");
    const client = {
      async query(sql) {
        if (sql.includes("INSERT INTO audit_events")) {
          throw new Error("insert failed");
        }
        return { rows: [] };
      },
    };

    await assert.doesNotReject(() =>
      mod.recordAutoSyncCompleted(client, {
        configId: "cfg-3",
        workspaceId: "ws-3",
        provider: "gitlab",
        createdBy: 1,
        status: "success",
        itemsScanned: 1,
        itemsImported: 1,
      }),
    );
  });

  it("summarizeImportErrors bounds the sample to 5 items and truncates long fields", async () => {
    const mod = await importFresh("apps/worker/src/shared/autoSyncFailure.js");
    const errors = Array.from({ length: 8 }, (_, i) => ({
      item: `token-${i}`,
      error: "x".repeat(500),
    }));
    const sample = mod.summarizeImportErrors(errors);
    assert.strictEqual(sample.length, 5);
    assert.strictEqual(sample[0].item, "token-0");
    assert.strictEqual(sample[0].error.length, 300);
  });

  it("summarizeImportErrors tolerates missing/invalid input", async () => {
    const mod = await importFresh("apps/worker/src/shared/autoSyncFailure.js");
    assert.deepStrictEqual(mod.summarizeImportErrors(undefined), []);
    assert.deepStrictEqual(mod.summarizeImportErrors("not-an-array"), []);
    assert.deepStrictEqual(mod.summarizeImportErrors([{}]), [
      { item: "unknown", error: "unknown error" },
    ]);
  });

  it("formatImportErrorDetail lists up to 3 item errors and counts the rest", async () => {
    const mod = await importFresh("apps/worker/src/shared/autoSyncFailure.js");
    const detail = mod.formatImportErrorDetail(
      [
        { item: "a", error: "missing name" },
        { item: "b", error: "invalid category" },
        { item: "c", error: "invalid type" },
        { item: "d", error: "notes too long" },
      ],
      6,
    );
    assert.strictEqual(
      detail,
      "Details: a: missing name; b: invalid category; c: invalid type (+3 more)",
    );
    assert.strictEqual(mod.formatImportErrorDetail([], 0), "");
    assert.strictEqual(mod.formatImportErrorDetail(null, 2), "");
  });

  it("recordAutoSyncCompleted includes the import_errors sample in the audit metadata", async () => {
    const mod = await importFresh("apps/worker/src/shared/autoSyncFailure.js");
    const calls = [];
    const client = {
      async query(sql, params) {
        calls.push({ sql, params });
        return { rows: [] };
      },
    };

    await mod.recordAutoSyncCompleted(client, {
      configId: "cfg-4",
      workspaceId: "ws-4",
      provider: "gitlab",
      createdBy: 42,
      status: "partial",
      itemsScanned: 3,
      itemsImported: 1,
      error:
        "2 of 3 scanned item(s) failed to import. Details: t1: missing name; t2: invalid type",
      importErrors: [
        { item: "t1", error: "missing name" },
        { item: "t2", error: "invalid type" },
      ],
    });

    const insert = calls.find((c) => c.sql.includes("INSERT INTO audit_events"));
    assert.ok(insert, "expected an audit_events INSERT");
    const metadata = insert.params[2];
    assert.deepStrictEqual(metadata.import_errors, [
      { item: "t1", error: "missing name" },
      { item: "t2", error: "invalid type" },
    ]);
    assert.match(metadata.error, /Details: t1: missing name/);
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

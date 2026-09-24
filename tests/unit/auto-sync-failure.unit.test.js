"use strict";

const { describe, it } = require("node:test");
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

    const insert = calls.find((c) =>
      c.sql.includes("INSERT INTO audit_events"),
    );
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

    const insert = calls.find((c) =>
      c.sql.includes("INSERT INTO audit_events"),
    );
    assert.ok(insert, "expected an audit_events INSERT");
    const [subjectUserId, action, metadata] = insert.params;
    assert.strictEqual(subjectUserId, 7);
    assert.strictEqual(action, "AUTO_SYNC_COMPLETED");
    assert.strictEqual(metadata.status, "partial");
    assert.strictEqual(
      metadata.error,
      "2 of 5 scanned item(s) failed to import.",
    );
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

    const insert = calls.find((c) =>
      c.sql.includes("INSERT INTO audit_events"),
    );
    assert.ok(insert, "expected an audit_events INSERT");
    const metadata = insert.params[2];
    assert.deepStrictEqual(metadata.import_errors, [
      { item: "t1", error: "missing name" },
      { item: "t2", error: "invalid type" },
    ]);
    assert.match(metadata.error, /Details: t1: missing name/);
  });
});

describe("auto-sync operational incidents", () => {
  it("sanitizes URL locations without changing ordinary or non-URL locations", async () => {
    const { sanitizeAutoSyncLocation } = await importFresh(
      "apps/worker/src/shared/autoSyncLocation.js",
    );
    assert.strictEqual(
      sanitizeAutoSyncLocation(
        "https://user:password@gitlab.example.com:443/root/path?token=secret#section",
      ),
      "https://gitlab.example.com:443/root/path",
    );
    assert.strictEqual(
      sanitizeAutoSyncLocation("https://gitlab.example.com/root/path"),
      "https://gitlab.example.com/root/path",
    );
    assert.strictEqual(
      sanitizeAutoSyncLocation("https://gitlab.example.com"),
      "https://gitlab.example.com",
    );
    assert.strictEqual(
      sanitizeAutoSyncLocation("vault:secret/prod/cert"),
      "vault:secret/prod/cert",
    );
    assert.strictEqual(
      sanitizeAutoSyncLocation(
        "https://user:password@bad host/path?token=secret",
      ),
      null,
    );
    assert.strictEqual(
      sanitizeAutoSyncLocation("gitlab.example.com/path?token=secret"),
      null,
    );
  });

  it("persists only available config identity and scan context in the incident and deferred email", async () => {
    const mod = await importFresh("apps/worker/src/shared/autoSyncFailure.js");
    const raised = [];
    const client = {
      async query(sql, params) {
        if (sql.includes("UPDATE auto_sync_configs")) {
          return { rows: [{ consecutive_failures: 3 }] };
        }
        if (sql.includes("INSERT INTO operational_notifications")) {
          raised.push(JSON.parse(params[8]));
          return { rows: [{ id: "incident-1" }] };
        }
        throw new Error(`unexpected query: ${sql}`);
      },
    };
    const deferred = [];
    await mod.recordAutoSyncFailure(
      client,
      {
        configId: "cfg-1",
        workspaceId: "ws-1",
        provider: "gitlab",
        previousStatus: "failed",
        errorMessage: "Bad credentials",
        nextSync: new Date(),
        config: {
          id: "cfg-1",
          provider: "gitlab",
          connection_key: "  Production GitLab  ",
          scan_params: {
            baseUrl:
              "https://user:password@gitlab.company.com/root?token=secret#section",
          },
        },
      },
      (email) => deferred.push(email),
    );
    assert.deepStrictEqual(raised[0], {
      provider: "gitlab",
      auto_sync_config_id: "cfg-1",
      workspace_id: "ws-1",
      connection_key: "Production GitLab",
      location: "https://gitlab.company.com/root",
      config_id: "cfg-1",
      consecutive_failures: 3,
    });
    assert.deepStrictEqual(deferred[0].metadata, raised[0]);
  });

  it("omits absent optional fields and does not mislabel an all-regions scan", async () => {
    const mod = await importFresh("apps/worker/src/shared/autoSyncFailure.js");
    const metadata = [];
    const client = {
      async query(sql, params) {
        if (sql.includes("UPDATE auto_sync_configs")) {
          return { rows: [{ consecutive_failures: 1 }] };
        }
        if (sql.includes("INSERT INTO operational_notifications")) {
          metadata.push(JSON.parse(params[8]));
          return { rows: [{ id: "incident-1" }] };
        }
        throw new Error(`unexpected query: ${sql}`);
      },
    };
    await mod.recordAutoSyncFailure(client, {
      configId: "cfg-2",
      workspaceId: "ws-1",
      provider: "github",
      previousStatus: "failed",
      errorMessage: "Bad credentials",
      nextSync: new Date(),
      config: { connection_key: " ", scan_params: { baseUrl: "N/A" } },
    });
    assert.deepStrictEqual(metadata[0], {
      provider: "github",
      auto_sync_config_id: "cfg-2",
      workspace_id: "ws-1",
      config_id: "cfg-2",
      consecutive_failures: 1,
    });

    await mod.recordAutoSyncFailure(client, {
      configId: "cfg-3",
      workspaceId: "ws-1",
      provider: "aws",
      previousStatus: "failed",
      errorMessage: "Unavailable",
      nextSync: new Date(),
      config: { scan_params: { scanMode: "all-regions", region: "us-east-1" } },
    });
    assert.equal(Object.hasOwn(metadata[1], "region"), false);

    await mod.recordAutoSyncFailure(client, {
      configId: "cfg-4",
      workspaceId: "ws-1",
      provider: "aws",
      previousStatus: "failed",
      errorMessage: "Unavailable",
      nextSync: new Date(),
      config: { scan_params: { scanMode: "single", region: "eu-central-1" } },
    });
    assert.equal(metadata[2].region, "eu-central-1");

    await mod.recordAutoSyncFailure(client, {
      configId: "cfg-5",
      workspaceId: "ws-1",
      provider: "gcp",
      previousStatus: "failed",
      errorMessage: "Unavailable",
      nextSync: new Date(),
      config: { scan_params: { projectId: "project-123" } },
    });
    assert.equal(metadata[3].project_id, "project-123");

    await mod.recordAutoSyncFailure(client, {
      configId: "cfg-6",
      workspaceId: "ws-1",
      provider: "vault",
      previousStatus: "failed",
      errorMessage: "Unavailable",
      nextSync: new Date(),
      config: {
        scan_params: {
          address:
            "https://user:pass@vault.example.com:8200/root?token=secret#frag",
        },
      },
    });
    assert.equal(metadata[4].location, "https://vault.example.com:8200/root");

    await mod.recordAutoSyncFailure(client, {
      configId: "cfg-7",
      workspaceId: "ws-1",
      provider: "azure",
      previousStatus: "failed",
      errorMessage: "Unavailable",
      nextSync: new Date(),
      config: {
        scan_params: {
          vaultUrl:
            "https://user:pass@vault.azure.example/root?sig=secret#frag",
        },
      },
    });
    assert.equal(metadata[5].location, "https://vault.azure.example/root");
  });

  it("keeps two same-provider configs independent through escalation and recovery", async () => {
    const mod = await importFresh("apps/worker/src/shared/autoSyncFailure.js");
    const failures = new Map();
    const raised = [];
    const resolved = [];
    const client = {
      async query(sql, params) {
        if (
          sql.includes("UPDATE auto_sync_configs") &&
          sql.includes("consecutive_failures = consecutive_failures + 1")
        ) {
          const count = (failures.get(params[2]) || 0) + 1;
          failures.set(params[2], count);
          return { rows: [{ consecutive_failures: count }] };
        }
        if (sql.includes("INSERT INTO operational_notifications")) {
          raised.push({ severity: params[4], key: params[5] });
          return { rows: [{ id: `incident-${params[5]}` }] };
        }
        if (sql.includes("SET consecutive_failures = 0"))
          return { rowCount: 1 };
        if (sql.includes("SET resolved_at = NOW()")) {
          resolved.push(params);
          return { rowCount: 1 };
        }
        throw new Error(`unexpected query: ${sql}`);
      },
    };
    const deferred = [];
    const failure = (configId) =>
      mod.recordAutoSyncFailure(
        client,
        {
          configId,
          workspaceId: "ws-1",
          provider: "gitlab",
          previousStatus: "failed",
          errorMessage: "Bad credentials",
          nextSync: new Date(),
        },
        (email) => deferred.push(email),
      );
    await failure("cfg-a");
    await failure("cfg-b");
    await failure("cfg-a");
    await failure("cfg-a");
    assert.deepStrictEqual(raised, [
      { severity: "warning", key: "auto_sync_failed:cfg-a" },
      { severity: "warning", key: "auto_sync_failed:cfg-b" },
      { severity: "warning", key: "auto_sync_failed:cfg-a" },
      { severity: "critical", key: "auto_sync_failed:cfg-a" },
    ]);
    assert.deepStrictEqual(
      deferred.map((email) => email.metadata.auto_sync_config_id),
      ["cfg-a"],
    );

    await mod.recordAutoSyncRecovery(client, {
      configId: "cfg-a",
      workspaceId: "ws-1",
    });
    assert.deepStrictEqual(resolved, [["ws-1", "auto_sync_failed:cfg-a"]]);
  });

  it("raises a warning first, then escalates the same dedupe key to critical", async () => {
    const mod = await importFresh("apps/worker/src/shared/autoSyncFailure.js");
    let failures = 0;
    const raised = [];
    const calls = [];
    const client = {
      async query(sql, params) {
        calls.push({ sql: String(sql), params });
        if (sql.includes("UPDATE auto_sync_configs")) {
          failures += 1;
          return { rows: [{ consecutive_failures: failures }] };
        }
        if (sql.includes("INSERT INTO operational_notifications")) {
          raised.push(params);
          return { rows: [{ id: "same-incident" }] };
        }
        if (sql.includes("SET email_claim_id = $2"))
          return { rows: [{ id: "same-incident" }] };
        if (sql.includes("pg_advisory_lock(")) return { rows: [{}] };
        if (sql.includes("pg_advisory_unlock(")) return { rows: [{}] };
        if (sql.includes("COUNT(*)::int AS c")) return { rows: [{ c: 0 }] };
        if (sql.includes("wm.role = 'admin'"))
          return { rows: [{ email: "admin@example.com" }] };
        if (sql.includes("SET email_sent_at = CASE")) return { rowCount: 1 };
        throw new Error(`unexpected query: ${sql}`);
      },
    };
    const incident = {
      configId: "cfg-1",
      workspaceId: "ws-1",
      provider: "github",
      previousStatus: "failed",
      errorMessage: "Rate limited",
      nextSync: new Date(),
    };
    const deferred = [];
    await mod.recordAutoSyncFailure(client, incident, (email) =>
      deferred.push(email),
    );
    await mod.recordAutoSyncFailure(client, incident, (email) =>
      deferred.push(email),
    );
    await mod.recordAutoSyncFailure(client, incident, (email) =>
      deferred.push(email),
    );
    assert.deepEqual(
      raised.map((params) => params[4]),
      ["warning", "warning", "critical"],
    );
    assert.deepEqual(
      raised.map((params) => params[5]),
      [
        "auto_sync_failed:cfg-1",
        "auto_sync_failed:cfg-1",
        "auto_sync_failed:cfg-1",
      ],
    );
    assert.equal(deferred.length, 1);
    assert.equal(
      calls.filter((call) => call.sql.includes("SET email_claim_id = $2"))
        .length,
      0,
    );
  });

  it("defers critical email until the worker commits the incident", async () => {
    const mod = await importFresh("apps/worker/src/shared/autoSyncFailure.js");
    const calls = [];
    const client = {
      async query(sql, params) {
        calls.push(String(sql));
        if (sql.includes("UPDATE auto_sync_configs")) {
          return { rows: [{ consecutive_failures: 3 }] };
        }
        if (sql.includes("INSERT INTO operational_notifications")) {
          return { rows: [{ id: "critical-incident" }] };
        }
        throw new Error(`unexpected query: ${sql}`);
      },
    };
    const deferred = [];
    await mod.recordAutoSyncFailure(
      client,
      {
        configId: "cfg-deferred",
        workspaceId: "ws-deferred",
        provider: "github",
        previousStatus: "failed",
        errorMessage: "Rate limited",
        nextSync: new Date(),
      },
      (incident) => deferred.push(incident),
    );
    assert.equal(deferred.length, 1);
    assert.equal(deferred[0].notificationId, "critical-incident");
    assert.equal(
      calls.some((sql) => sql.includes("SET email_claim_id")),
      false,
    );
  });

  it("clears the counter and resolves the open incident on recovery", async () => {
    const mod = await importFresh("apps/worker/src/shared/autoSyncFailure.js");
    const calls = [];
    const client = {
      async query(sql, params) {
        calls.push({ sql: String(sql), params });
        return { rowCount: 1 };
      },
    };
    await mod.recordAutoSyncRecovery(client, {
      configId: "cfg-1",
      workspaceId: "ws-1",
    });
    assert.match(calls[0].sql, /SET consecutive_failures = 0/);
    assert.deepEqual(calls[1].params, ["ws-1", "auto_sync_failed:cfg-1"]);
  });
});

describe("buildAutoSyncImportBody", () => {
  it("always forwards scan_id when present, even without cleanup", async () => {
    const mod = await importFresh(
      "apps/worker/src/shared/autoSyncImportBody.js",
    );
    assert.deepStrictEqual(
      mod.buildAutoSyncImportBody({
        items: [{ name: "TEST3" }],
        scanId: "scan-42",
        cleanup: null,
      }),
      { items: [{ name: "TEST3" }], scan_id: "scan-42" },
    );
  });

  it("omits scan_id when it is missing and still attaches cleanup when set", async () => {
    const mod = await importFresh(
      "apps/worker/src/shared/autoSyncImportBody.js",
    );
    assert.deepStrictEqual(
      mod.buildAutoSyncImportBody({
        items: [],
        scanId: null,
        cleanup: { categories: ["secret"] },
      }),
      { items: [], cleanup: { categories: ["secret"] } },
    );
  });

  it("normalizes a non-array items value to an empty list", async () => {
    const mod = await importFresh(
      "apps/worker/src/shared/autoSyncImportBody.js",
    );
    assert.deepStrictEqual(
      mod.buildAutoSyncImportBody({ items: null, scanId: "scan-1" }),
      { items: [], scan_id: "scan-1" },
    );
  });
});

describe("gitlabFiltersForAutoSync", () => {
  it("forces includeRevoked off when cleanup is enabled", async () => {
    const mod = await importFresh(
      "apps/worker/src/shared/autoSyncImportBody.js",
    );
    assert.deepStrictEqual(
      mod.gitlabFiltersForAutoSync(
        { includePATs: true, includeRevoked: true, includeExpired: true },
        true,
      ),
      { includePATs: true, includeRevoked: false, includeExpired: true },
    );
  });

  it("leaves includeRevoked alone when cleanup is off", async () => {
    const mod = await importFresh(
      "apps/worker/src/shared/autoSyncImportBody.js",
    );
    assert.deepStrictEqual(
      mod.gitlabFiltersForAutoSync({ includeRevoked: true }, false),
      { includeRevoked: true },
    );
  });
});

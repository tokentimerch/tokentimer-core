"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const Module = require("module");
const path = require("path");

const workspaceModulePath = path.resolve(
  __dirname,
  "../../apps/api/services/workspace.js",
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

function loadWorkspaceService(poolImpl, writeAuditImpl = async () => {}) {
  delete require.cache[workspaceModulePath];
  return withPatchedLoad(
    {
      "../db/database": { pool: poolImpl },
      "./audit": { writeAudit: writeAuditImpl },
      "../utils/logger": {
        logger: { warn() {}, error() {}, debug() {} },
      },
    },
    () => require(workspaceModulePath),
  );
}

function makeTxClient(queryImpl) {
  return {
    query: queryImpl,
    release() {},
  };
}

describe("ensureInitialWorkspaceForUser (shared default workspace)", () => {
  it("creates Default workspace when installation has none", async () => {
    const queryLog = [];
    const pool = {
      query: async (sql, params) => {
        const text = String(sql);
        queryLog.push({ text, params });
        if (text.includes("FROM workspace_invitations")) {
          return { rowCount: 0, rows: [] };
        }
        if (text.includes("FROM workspace_memberships WHERE user_id")) {
          return { rowCount: 0, rows: [] };
        }
        if (text.includes("INSERT INTO workspace_settings")) {
          return { rowCount: 1, rows: [] };
        }
        if (text.includes("FROM workspace_contacts")) {
          return { rowCount: 0, rows: [] };
        }
        if (text.includes("INSERT INTO workspace_contacts")) {
          return { rowCount: 1, rows: [{ id: "contact-1" }] };
        }
        return { rowCount: 1, rows: [] };
      },
      connect: async () =>
        makeTxClient(async (sql, params) => {
          const text = String(sql);
          queryLog.push({ text, params, tx: true });
          if (text.startsWith("BEGIN") || text.startsWith("COMMIT")) {
            return { rowCount: 0, rows: [] };
          }
          if (text.includes("pg_advisory_xact_lock")) {
            return { rowCount: 1, rows: [] };
          }
          if (text.includes("FROM workspaces")) {
            return { rowCount: 0, rows: [] };
          }
          if (text.includes("INSERT INTO workspaces")) {
            return { rowCount: 1, rows: [] };
          }
          if (text.includes("INSERT INTO workspace_memberships")) {
            return { rowCount: 1, rows: [] };
          }
          return { rowCount: 1, rows: [] };
        }),
    };

    const audits = [];
    const { ensureInitialWorkspaceForUser, DEFAULT_WORKSPACE_NAME } =
      loadWorkspaceService(pool, async (entry) => {
        audits.push(entry);
      });

    await ensureInitialWorkspaceForUser(
      "user-first",
      "first@example.com",
      "First User",
    );

    const workspaceInsert = queryLog.find(
      (q) => q.tx && q.text.includes("INSERT INTO workspaces"),
    );
    assert.ok(workspaceInsert);
    assert.strictEqual(workspaceInsert.params[1], DEFAULT_WORKSPACE_NAME);

    const membershipInsert = queryLog.find(
      (q) =>
        q.tx &&
        q.text.includes("INSERT INTO workspace_memberships") &&
        q.params?.[2] === "admin",
    );
    assert.ok(membershipInsert);
    assert.strictEqual(
      audits.some((a) => a.action === "WORKSPACE_CREATED"),
      true,
    );
  });

  it("joins existing default workspace instead of creating another", async () => {
    const queryLog = [];
    const pool = {
      query: async (sql) => {
        const text = String(sql);
        queryLog.push({ text });
        if (text.includes("FROM workspace_invitations")) {
          return { rowCount: 0, rows: [] };
        }
        if (text.includes("FROM workspace_memberships WHERE user_id")) {
          return { rowCount: 0, rows: [] };
        }
        return { rowCount: 1, rows: [] };
      },
      connect: async () =>
        makeTxClient(async (sql, params) => {
          const text = String(sql);
          queryLog.push({ text, params, tx: true });
          if (text.includes("FROM workspaces") && text.includes("LOWER")) {
            return { rowCount: 1, rows: [{ id: "ws-default" }] };
          }
          if (text.includes("is_admin FROM users")) {
            return { rowCount: 1, rows: [{ is_admin: false }] };
          }
          if (text.includes("INSERT INTO workspaces")) {
            throw new Error("should not create a workspace");
          }
          return { rowCount: 1, rows: [] };
        }),
    };

    const { ensureInitialWorkspaceForUser } = loadWorkspaceService(pool);
    await ensureInitialWorkspaceForUser(
      "user-second",
      "second@example.com",
      "Second User",
    );

    const join = queryLog.find(
      (q) =>
        q.tx &&
        q.text.includes("INSERT INTO workspace_memberships") &&
        q.params?.[1] === "ws-default" &&
        q.params?.[2] === "workspace_manager",
    );
    assert.ok(join);
    assert.strictEqual(
      queryLog.some((q) => q.tx && q.text.includes("INSERT INTO workspaces")),
      false,
    );
  });

  it("returns early when user already has a workspace membership", async () => {
    const queryLog = [];
    const pool = {
      query: async (sql) => {
        queryLog.push({ text: String(sql) });
        if (String(sql).includes("FROM workspace_invitations")) {
          return { rowCount: 0, rows: [] };
        }
        if (String(sql).includes("FROM workspace_memberships WHERE user_id")) {
          return { rowCount: 1, rows: [{}] };
        }
        return { rowCount: 0, rows: [] };
      },
      connect: async () => {
        throw new Error("should not open transaction");
      },
    };

    const { ensureInitialWorkspaceForUser } = loadWorkspaceService(pool);
    await ensureInitialWorkspaceForUser(
      "user-member",
      "member@example.com",
      "Member User",
    );

    assert.strictEqual(
      queryLog.some((q) => q.text.includes("INSERT INTO workspaces")),
      false,
    );
  });

  it("grants workspace admin when joining user is system admin", async () => {
    const queryLog = [];
    const pool = {
      query: async (sql) => {
        if (String(sql).includes("FROM workspace_invitations")) {
          return { rowCount: 0, rows: [] };
        }
        if (String(sql).includes("FROM workspace_memberships WHERE user_id")) {
          return { rowCount: 0, rows: [] };
        }
        return { rowCount: 1, rows: [] };
      },
      connect: async () =>
        makeTxClient(async (sql, params) => {
          const text = String(sql);
          queryLog.push({ text, params, tx: true });
          if (text.includes("FROM workspaces") && text.includes("LOWER")) {
            return { rowCount: 1, rows: [{ id: "ws-default" }] };
          }
          if (text.includes("is_admin FROM users")) {
            return { rowCount: 1, rows: [{ is_admin: true }] };
          }
          return { rowCount: 1, rows: [] };
        }),
    };

    const { ensureInitialWorkspaceForUser } = loadWorkspaceService(pool);
    await ensureInitialWorkspaceForUser(
      "user-admin",
      "admin@example.com",
      "Admin User",
    );

    const join = queryLog.find(
      (q) =>
        q.tx &&
        q.text.includes("INSERT INTO workspace_memberships") &&
        q.params?.[2] === "admin",
    );
    assert.ok(join);
  });

  it("joins the sole existing workspace on legacy single-workspace installs", async () => {
    const queryLog = [];
    const pool = {
      query: async (sql) => {
        if (String(sql).includes("FROM workspace_invitations")) {
          return { rowCount: 0, rows: [] };
        }
        if (String(sql).includes("FROM workspace_memberships WHERE user_id")) {
          return { rowCount: 0, rows: [] };
        }
        return { rowCount: 1, rows: [] };
      },
      connect: async () =>
        makeTxClient(async (sql, params) => {
          const text = String(sql);
          queryLog.push({ text, params, tx: true });
          if (text.includes("FROM workspaces") && text.includes("LOWER")) {
            return { rowCount: 0, rows: [] };
          }
          if (
            text.includes("SELECT id FROM workspaces ORDER BY created_at ASC FOR UPDATE")
          ) {
            return { rowCount: 1, rows: [{ id: "ws-legacy" }] };
          }
          if (text.includes("is_admin FROM users")) {
            return { rowCount: 1, rows: [{ is_admin: false }] };
          }
          if (text.includes("INSERT INTO workspaces")) {
            throw new Error("should not create a workspace");
          }
          return { rowCount: 1, rows: [] };
        }),
    };

    const { ensureInitialWorkspaceForUser } = loadWorkspaceService(pool);
    await ensureInitialWorkspaceForUser(
      "user-legacy",
      "legacy@example.com",
      "Legacy User",
    );

    const join = queryLog.find(
      (q) =>
        q.tx &&
        q.text.includes("INSERT INTO workspace_memberships") &&
        q.params?.[1] === "ws-legacy",
    );
    assert.ok(join);
  });

  it("creates Default workspace when multiple legacy workspaces exist without canonical name", async () => {
    const queryLog = [];
    const pool = {
      query: async (sql) => {
        if (String(sql).includes("FROM workspace_invitations")) {
          return { rowCount: 0, rows: [] };
        }
        if (String(sql).includes("FROM workspace_memberships WHERE user_id")) {
          return { rowCount: 0, rows: [] };
        }
        return { rowCount: 1, rows: [] };
      },
      connect: async () =>
        makeTxClient(async (sql, params) => {
          const text = String(sql);
          queryLog.push({ text, params, tx: true });
          if (text.includes("FROM workspaces") && text.includes("LOWER")) {
            return { rowCount: 0, rows: [] };
          }
          if (
            text.includes("SELECT id FROM workspaces ORDER BY created_at ASC FOR UPDATE")
          ) {
            return {
              rowCount: 3,
              rows: [{ id: "ws-1" }, { id: "ws-2" }, { id: "ws-3" }],
            };
          }
          if (text.includes("is_admin FROM users")) {
            return { rowCount: 1, rows: [{ is_admin: false }] };
          }
          return { rowCount: 1, rows: [] };
        }),
    };

    const { ensureInitialWorkspaceForUser, DEFAULT_WORKSPACE_NAME } =
      loadWorkspaceService(pool);
    await ensureInitialWorkspaceForUser(
      "user-new",
      "new@example.com",
      "New User",
    );

    const created = queryLog.find(
      (q) => q.tx && q.text.includes("INSERT INTO workspaces"),
    );
    assert.ok(created);
    assert.strictEqual(created.params[1], DEFAULT_WORKSPACE_NAME);
  });
});

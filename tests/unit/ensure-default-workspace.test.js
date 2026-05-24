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

  it("joins existing Default as workspace_manager even when user is system admin (0.6.0 hardening)", async () => {
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
          // resolveJoinRole no longer reads is_admin, but if anything queries
          // it we still return true to prove the value cannot be promoted.
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

    const membershipInserts = queryLog.filter(
      (q) =>
        q.tx && q.text.includes("INSERT INTO workspace_memberships"),
    );
    assert.strictEqual(
      membershipInserts.length,
      1,
      "exactly one membership insert is expected for the default workspace join",
    );
    const join = membershipInserts[0];
    assert.strictEqual(join.params?.[1], "ws-default");
    assert.strictEqual(
      join.params?.[2],
      "workspace_manager",
      "system admin joining existing Default workspace must NOT be promoted to workspace admin",
    );

    const adminPromotion = membershipInserts.find(
      (q) => q.params?.[2] === "admin",
    );
    assert.strictEqual(
      adminPromotion,
      undefined,
      "system admin must never receive workspace admin role automatically",
    );

    // Belt-and-braces: ensureInitialWorkspaceForUser must no longer consult
    // users.is_admin to derive a join role for the shared Default workspace.
    assert.strictEqual(
      queryLog.some((q) => q.text.includes("is_admin FROM users")),
      false,
      "resolveJoinRole must not read users.is_admin in 0.6.0",
    );
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

"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const Module = require("module");
const path = require("path");

const bootstrapModulePath = path.resolve(
  __dirname,
  "../../apps/api/auth/bootstrap.js",
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

function loadBootstrap(poolImpl) {
  delete require.cache[bootstrapModulePath];
  return withPatchedLoad(
    {
      bcryptjs: {
        hash: async () => "hashed-password",
      },
      uuid: { v4: () => "ws-uuid" },
      "../db/models/User": {
        canonicalizeEmail: (email) => String(email).trim().toLowerCase(),
      },
      "../utils/logger": {
        logger: { info() {}, warn() {}, error() {}, debug() {} },
      },
      "../services/workspace": {
        DEFAULT_WORKSPACE_NAME: "Default workspace",
      },
    },
    () => require(bootstrapModulePath),
  );
}

describe("bootstrapAdmin (shared default workspace)", () => {
  it("seeds Default workspace for the first admin", async () => {
    const queryLog = [];
    const pool = {
      query: async (sql, params) => {
        queryLog.push({ text: String(sql), params });
        if (String(sql).includes("COUNT(*)::int as count FROM users")) {
          return { rows: [{ count: 0 }] };
        }
        if (String(sql).includes("INSERT INTO users")) {
          return { rows: [{ id: "admin-1", email: "admin@example.com" }] };
        }
        return { rowCount: 1, rows: [] };
      },
    };

    process.env.ADMIN_EMAIL = "admin@example.com";
    process.env.ADMIN_PASSWORD = "SecurePass123!";
    process.env.ADMIN_NAME = "Administrator";

    const { bootstrapAdmin } = loadBootstrap(pool);
    const result = await bootstrapAdmin(pool);

    assert.strictEqual(result.created, true);
    const workspaceInsert = queryLog.find((q) =>
      q.text.includes("INSERT INTO workspaces"),
    );
    assert.ok(workspaceInsert);
    assert.strictEqual(workspaceInsert.params[1], "Default workspace");
  });

  it("skips when users already exist", async () => {
    const pool = {
      query: async (sql) => {
        if (String(sql).includes("COUNT(*)::int as count FROM users")) {
          return { rows: [{ count: 2 }] };
        }
        throw new Error("should not bootstrap");
      },
    };

    const { bootstrapAdmin } = loadBootstrap(pool);
    const result = await bootstrapAdmin(pool);
    assert.strictEqual(result.created, false);
    assert.strictEqual(result.admin, null);
  });
});

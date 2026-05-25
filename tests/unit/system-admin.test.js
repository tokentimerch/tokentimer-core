"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const {
  isActiveSystemAdminRow,
  lockSystemAdminMutation,
  countActiveSystemAdmins,
  countOtherActiveSystemAdmins,
  ensureSystemAdminWorkspaceAccess,
  SYSTEM_ADMIN_LOCK_KEY,
} = require("../../apps/api/services/systemAdmin");

describe("systemAdmin helpers", () => {
  it("treats tombstoned deleted accounts as inactive system admins", () => {
    assert.strictEqual(
      isActiveSystemAdminRow({
        is_admin: true,
        email: "deleted+42@example.invalid",
        display_name: "Deleted Account",
      }),
      false,
    );
    assert.strictEqual(
      isActiveSystemAdminRow({
        is_admin: true,
        email: "still-admin@example.com",
        display_name: "Deleted Account",
      }),
      false,
    );
    assert.strictEqual(
      isActiveSystemAdminRow({
        is_admin: true,
        email: "deleted+42@example.invalid",
        display_name: "Admin",
      }),
      false,
    );
  });

  it("acquires pg_advisory_xact_lock for system-admin mutations", async () => {
    const queries = [];
    const client = {
      query: async (sql, params) => {
        queries.push({ sql, params });
        return { rows: [] };
      },
    };

    await lockSystemAdminMutation(client);
    assert.strictEqual(queries.length, 1);
    assert.match(queries[0].sql, /pg_advisory_xact_lock/);
    assert.strictEqual(queries[0].params[0], SYSTEM_ADMIN_LOCK_KEY);
  });

  it("counts active system admins excluding tombstones", async () => {
    const queries = [];
    const queryable = {
      query: async (sql, params) => {
        queries.push({ sql, params });
        if (sql.includes("id <> $1")) {
          return { rows: [{ c: 1 }] };
        }
        return { rows: [{ c: 2 }] };
      },
    };

    assert.strictEqual(await countActiveSystemAdmins(queryable), 2);
    assert.strictEqual(await countOtherActiveSystemAdmins(queryable, 9), 1);
    assert.match(queries[0].sql, /@example\.invalid/);
    assert.match(queries[0].sql, /Deleted Account/);
  });

  it("ensureSystemAdminWorkspaceAccess upgrades viewer but preserves workspace admin", async () => {
    let upsertSql = "";
    const queryable = {
      query: async (sql) => {
        if (sql.includes("SELECT is_admin")) {
          return { rows: [{ is_admin: true }] };
        }
        upsertSql = sql;
        return { rowCount: 2, rows: [{ workspace_id: "ws-a" }] };
      },
    };

    const result = await ensureSystemAdminWorkspaceAccess(queryable, 9);
    assert.strictEqual(result.applied, 2);
    assert.match(upsertSql, /WHEN workspace_memberships\.role = 'viewer'/);
    assert.doesNotMatch(upsertSql, /'admin'/);
  });

  it("ensureSystemAdminWorkspaceAccess no-ops for non-admin users", async () => {
    const queryable = {
      query: async (sql) => {
        if (sql.includes("SELECT is_admin")) {
          return { rows: [{ is_admin: false }] };
        }
        throw new Error(`unexpected query: ${sql}`);
      },
    };

    const result = await ensureSystemAdminWorkspaceAccess(queryable, 9);
    assert.strictEqual(result.applied, 0);
  });
});

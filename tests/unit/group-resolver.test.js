"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");

const {
  resolveSsoBindings,
  applyResolution,
  hasAnyWorkspaceMembership,
  pickHighest,
  ROLE_RANK,
} = require("../../apps/api/sso/group-resolver");

/**
 * Minimal pool stub: queues query results in FIFO order. Each call to
 * pool.query() consumes the next queued result. Throws if more queries
 * are made than results queued so we never silently shadow a missing
 * fixture.
 */
function makePool(queuedResults) {
  const queue = [...queuedResults];
  return {
    query: async () => {
      if (queue.length === 0) {
        throw new Error("makePool: no more queued results");
      }
      return queue.shift();
    },
  };
}

describe("group-resolver", () => {
  describe("pickHighest()", () => {
    it("admin beats workspace_manager and viewer", () => {
      assert.strictEqual(
        pickHighest("workspace_manager", "admin"),
        "admin",
      );
      assert.strictEqual(pickHighest("viewer", "admin"), "admin");
    });

    it("workspace_manager beats viewer", () => {
      assert.strictEqual(
        pickHighest("workspace_manager", "viewer"),
        "workspace_manager",
      );
      assert.strictEqual(
        pickHighest("viewer", "workspace_manager"),
        "workspace_manager",
      );
    });

    it("handles missing inputs", () => {
      assert.strictEqual(pickHighest(undefined, "viewer"), "viewer");
      assert.strictEqual(pickHighest("admin", null), "admin");
    });
  });

  describe("ROLE_RANK", () => {
    it("has admin > workspace_manager > viewer", () => {
      assert.ok(ROLE_RANK.admin > ROLE_RANK.workspace_manager);
      assert.ok(ROLE_RANK.workspace_manager > ROLE_RANK.viewer);
    });
  });

  describe("hasAnyWorkspaceMembership()", () => {
    it("mirrors Core's ensureInitialWorkspaceForUser gating query exactly", async () => {
      let seenSql = null;
      let seenParams = null;
      const pool = {
        query: async (sql, params) => {
          seenSql = sql;
          seenParams = params;
          return { rows: [] };
        },
      };
      await hasAnyWorkspaceMembership(pool, 42);
      assert.match(
        seenSql.replace(/\s+/g, " ").trim(),
        /^SELECT 1 FROM workspace_memberships WHERE user_id = \$1 LIMIT 1$/,
      );
      assert.deepStrictEqual(seenParams, [42]);
    });

    it("returns true when at least one row exists", async () => {
      const pool = makePool([{ rows: [{}] }]);
      assert.strictEqual(await hasAnyWorkspaceMembership(pool, 1), true);
    });

    it("returns false when no rows exist", async () => {
      const pool = makePool([{ rows: [] }]);
      assert.strictEqual(await hasAnyWorkspaceMembership(pool, 1), false);
    });
  });

  describe("resolveSsoBindings()", () => {
    it("highest role wins when multiple mappings hit the same workspace", async () => {
      const pool = makePool([
        {
          rows: [
            {
              id: "m1",
              providerSlug: "oidc",
              idp_group: "devops",
              role: "viewer",
              workspace_id: "ws_a",
            },
            {
              id: "m2",
              providerSlug: "oidc",
              idp_group: "devops",
              role: "workspace_manager",
              workspace_id: "ws_a",
            },
          ],
        },
        { rows: [] },
      ]);

      const result = await resolveSsoBindings({
        pool,
        providerSlug: "oidc",
        userId: 42,
        idpGroups: ["DevOps"],
        strictSync: false,
      });

      assert.strictEqual(result.isAdmin, false);
      assert.deepStrictEqual(result.workspaceGrants, [
        { workspace_id: "ws_a", role: "workspace_manager" },
      ]);
      assert.deepStrictEqual(result.revoked, []);
    });

    it("system admin row sets isAdmin and expands workspace_manager to every workspace", async () => {
      const pool = makePool([
        {
          rows: [
            {
              id: "m1",
              providerSlug: "oidc",
              idp_group: "tt-admins",
              role: "admin",
              workspace_id: null,
            },
          ],
        },
        { rows: [{ id: "ws_a" }, { id: "ws_b" }] },
      ]);

      const result = await resolveSsoBindings({
        pool,
        providerSlug: "oidc",
        userId: 42,
        idpGroups: ["tt-admins"],
      });

      assert.strictEqual(result.isAdmin, true);
      const grantsByWs = Object.fromEntries(
        result.workspaceGrants.map((g) => [g.workspace_id, g.role]),
      );
      assert.deepStrictEqual(grantsByWs, {
        ws_a: "workspace_manager",
        ws_b: "workspace_manager",
      });
    });

    it("is_admin_manual expands workspace_manager to every workspace", async () => {
      const pool = makePool([
        { rows: [] },
        { rows: [{ "?column?": 1 }] },
        { rows: [{ id: "ws_a" }, { id: "ws_b" }] },
      ]);

      const result = await resolveSsoBindings({
        pool,
        providerSlug: "oidc",
        userId: 99,
        idpGroups: ["some-group"],
      });

      assert.strictEqual(result.isAdmin, false);
      assert.deepStrictEqual(
        Object.fromEntries(
          result.workspaceGrants.map((g) => [g.workspace_id, g.role]),
        ),
        { ws_a: "workspace_manager", ws_b: "workspace_manager" },
      );
    });

    it("durable SSO system admin keeps all-workspace workspace_manager under strict sync", async () => {
      const pool = makePool([
        {
          rows: [
            {
              id: "m1",
              providerSlug: "oidc",
              idp_group: "eng-only",
              role: "viewer",
              workspace_id: "ws_a",
            },
          ],
        },
        { rows: [{ "?column?": 1 }] },
        { rows: [{ id: "ws_a" }, { id: "ws_b" }] },
        {
          rows: [
            { workspace_id: "ws_a" },
            { workspace_id: "ws_b" },
          ],
        },
      ]);

      const result = await resolveSsoBindings({
        pool,
        providerSlug: "oidc",
        userId: 42,
        idpGroups: ["eng-only"],
        strictSync: true,
      });

      assert.strictEqual(result.isAdmin, false);
      const grantsByWs = Object.fromEntries(
        result.workspaceGrants.map((g) => [g.workspace_id, g.role]),
      );
      assert.deepStrictEqual(grantsByWs, {
        ws_a: "workspace_manager",
        ws_b: "workspace_manager",
      });
      assert.deepStrictEqual(result.revoked, []);
    });

    it("strict sync diffs current SSO memberships against new bindings", async () => {
      const pool = makePool([
        {
          rows: [
            {
              id: "m1",
              providerSlug: "saml",
              idp_group: "eng-london",
              role: "viewer",
              workspace_id: "ws_london",
            },
          ],
        },
        { rows: [] },
        {
          rows: [
            { workspace_id: "ws_london" },
            { workspace_id: "ws_paris" }, // no longer mapped -> revoke
          ],
        },
      ]);

      const result = await resolveSsoBindings({
        pool,
        providerSlug: "saml",
        userId: 7,
        idpGroups: ["eng-london"],
        strictSync: true,
      });

      assert.deepStrictEqual(result.workspaceGrants, [
        { workspace_id: "ws_london", role: "viewer" },
      ]);
      assert.deepStrictEqual(result.revoked, [{ workspace_id: "ws_paris" }]);
    });

    it("admin is never revoked under strict sync", async () => {
      // Even if the system-admin mapping was removed (no admin rows
      // returned), the function only emits workspace-scoped revocations.
      const pool = makePool([
        { rows: [] },
        { rows: [] },
        { rows: [{ workspace_id: "ws_old" }] },
      ]);

      const result = await resolveSsoBindings({
        pool,
        providerSlug: "oidc",
        userId: 7,
        idpGroups: ["something-else"],
        strictSync: true,
      });

      assert.strictEqual(result.isAdmin, false);
      assert.deepStrictEqual(result.revoked, [{ workspace_id: "ws_old" }]);
    });

    it("bootstrap_admin_groups injects a virtual system-admin mapping", async () => {
      const pool = makePool([
        { rows: [] },
        { rows: [{ id: "ws_default" }] },
      ]);

      const result = await resolveSsoBindings({
        pool,
        providerSlug: "oidc",
        userId: 7,
        idpGroups: ["TT-ADMINS", "devs"],
        bootstrapAdminGroups: ["tt-admins"],
      });

      assert.strictEqual(result.isAdmin, true);
      assert.ok(result.matchedGroups.includes("tt-admins"));
      assert.deepStrictEqual(result.workspaceGrants, [
        { workspace_id: "ws_default", role: "workspace_manager" },
      ]);
    });

    it("rejects missing provider_slug", async () => {
      const pool = makePool([]);
      await assert.rejects(
        () =>
          resolveSsoBindings({
            pool,
            userId: 7,
            idpGroups: [],
          }),
        /providerSlug is required/,
      );
    });

    it("returns empty resolution when no IdP groups asserted", async () => {
      const pool = makePool([{ rows: [] }]);
      const result = await resolveSsoBindings({
        pool,
        providerSlug: "oidc",
        userId: 7,
        idpGroups: [],
      });
      assert.strictEqual(result.isAdmin, false);
      assert.deepStrictEqual(result.workspaceGrants, []);
    });

    it("expands a global viewer mapping to every workspace", async () => {
      const pool = makePool([
        {
          rows: [
            {
              id: "m1",
              providerSlug: "oidc",
              idp_group: "everyone",
              role: "viewer",
              workspace_id: null,
            },
          ],
        },
        { rows: [] },
        { rows: [{ id: "ws_a" }, { id: "ws_b" }, { id: "ws_c" }] },
      ]);

      const result = await resolveSsoBindings({
        pool,
        providerSlug: "oidc",
        userId: 1,
        idpGroups: ["everyone"],
      });

      assert.strictEqual(result.isAdmin, false);
      const grantsByWs = Object.fromEntries(
        result.workspaceGrants.map((g) => [g.workspace_id, g.role]),
      );
      assert.deepStrictEqual(grantsByWs, {
        ws_a: "viewer",
        ws_b: "viewer",
        ws_c: "viewer",
      });
    });

    it("workspace-specific manager beats global viewer on the same workspace", async () => {
      const pool = makePool([
        {
          rows: [
            {
              id: "m1",
              providerSlug: "saml",
              idp_group: "everyone",
              role: "viewer",
              workspace_id: null,
            },
            {
              id: "m2",
              providerSlug: "saml",
              idp_group: "london-mgrs",
              role: "workspace_manager",
              workspace_id: "ws_london",
            },
          ],
        },
        { rows: [] },
        { rows: [{ id: "ws_london" }, { id: "ws_paris" }] },
      ]);

      const result = await resolveSsoBindings({
        pool,
        providerSlug: "saml",
        userId: 1,
        idpGroups: ["everyone", "london-mgrs"],
      });

      const grantsByWs = Object.fromEntries(
        result.workspaceGrants.map((g) => [g.workspace_id, g.role]),
      );
      assert.deepStrictEqual(grantsByWs, {
        ws_london: "workspace_manager",
        ws_paris: "viewer",
      });
    });

    it("does NOT trigger workspace expansion query when no global grants exist", async () => {
      // Regression: a previous version queried `SELECT id FROM workspaces`
      // even when nothing was global, paying a round-trip for every login.
      const pool = makePool([
        {
          rows: [
            {
              id: "m1",
              providerSlug: "saml",
              idp_group: "team-x",
              role: "workspace_manager",
              workspace_id: "ws_x",
            },
          ],
        },
        { rows: [] },
      ]);
      const result = await resolveSsoBindings({
        pool,
        providerSlug: "saml",
        userId: 1,
        idpGroups: ["team-x"],
      });
      assert.deepStrictEqual(result.workspaceGrants, [
        { workspace_id: "ws_x", role: "workspace_manager" },
      ]);
    });

    it("global workspace_manager beats global viewer (collapsed to bestGlobalRole)", async () => {
      const pool = makePool([
        {
          rows: [
            {
              id: "m1",
              providerSlug: "oidc",
              idp_group: "everyone",
              role: "viewer",
              workspace_id: null,
            },
            {
              id: "m2",
              providerSlug: "oidc",
              idp_group: "leads",
              role: "workspace_manager",
              workspace_id: null,
            },
          ],
        },
        { rows: [] },
        { rows: [{ id: "ws_a" }, { id: "ws_b" }] },
      ]);

      const result = await resolveSsoBindings({
        pool,
        providerSlug: "oidc",
        userId: 1,
        idpGroups: ["everyone", "leads"],
      });

      const grantsByWs = Object.fromEntries(
        result.workspaceGrants.map((g) => [g.workspace_id, g.role]),
      );
      assert.deepStrictEqual(grantsByWs, {
        ws_a: "workspace_manager",
        ws_b: "workspace_manager",
      });
    });
  });

  /**
   * applyResolution() runs writes inside a single transaction. We stub a
   * pool.connect()-style client that records every issued statement and lets
   * each test pre-program return values from RETURNING. The interesting
   * behaviour is the diff-aware audit:
   *   - rowCount=0 from the upsert MUST NOT produce an audit row
   *   - rowCount=1 with `inserted=true` -> change=created
   *   - rowCount=1 with `inserted=false` -> change=role_changed
   *   - revoked rows with rowCount=1 -> include previous_role in metadata
   *   - revoked rows with rowCount=0 -> no audit (DELETE no-op)
   */
  function makeApplyPool({
    adminAlreadyAdmin = false,
    adminNewlyGranted = false,
    hadGrant = false,
    upsertRows,
    deleteRows,
  }) {
    // applyResolution() now issues at most one batched UPSERT and one
    // batched DELETE per call, regardless of the number of workspaces.
    // The test mock returns the whole result set in a single response.
    let queries = [];
    let inTx = false;
    const client = {
      query: async (sql) => {
        queries.push(sql);
        const trim = String(sql).trim().toUpperCase();
        if (sql.includes("FROM sso_providers")) return { rows: [{}] };
        if (trim === "BEGIN") {
          inTx = true;
          return { rowCount: 0, rows: [] };
        }
        if (trim === "COMMIT" || trim === "ROLLBACK") {
          inTx = false;
          return { rowCount: 0, rows: [] };
        }
        if (sql.includes("INSERT INTO sso_system_admin_grants")) {
          return { rowCount: 1, rows: [] };
        }
        if (
          sql.includes("SELECT is_admin FROM users WHERE id = $1") &&
          !sql.includes("is_admin_manual")
        ) {
          return {
            rowCount: 1,
            rows: [{ is_admin: adminAlreadyAdmin === true }],
          };
        }
        if (
          sql.includes("UPDATE users") &&
          sql.includes("sso_system_admin_grants")
        ) {
          const isAdmin =
            adminAlreadyAdmin === true || adminNewlyGranted === true;
          return {
            rowCount: 1,
            rows: [{ id: 1, is_admin: isAdmin, is_admin_manual: false }],
          };
        }
        if (sql.includes("SELECT 1") && sql.includes("sso_system_admin_grants")) {
          return {
            rowCount: hadGrant ? 1 : 0,
            rows: hadGrant ? [{}] : [],
          };
        }
        if (sql.includes("DELETE FROM sso_system_admin_grants")) {
          return { rowCount: hadGrant ? 1 : 0, rows: [] };
        }
        if (sql.includes("INSERT INTO workspace_memberships")) {
          const rows = upsertRows || [];
          return { rowCount: rows.length, rows };
        }
        if (sql.includes("FROM workspaces w")) {
          return { rowCount: 0, rows: [] };
        }
        if (sql.includes("DELETE FROM workspace_memberships")) {
          const rows = deleteRows || [];
          return { rowCount: rows.length, rows };
        }
        return { rowCount: 0, rows: [] };
      },
      release: () => {},
    };
    return {
      connect: async () => client,
      query: async (sql, params) => client.query(sql, params),
      isInTx: () => inTx,
      queries: () => queries,
    };
  }

  describe("applyResolution() audit emission", () => {
    it("emits one audit row per applied UPSERT and none for no-ops", async () => {
      // ws_b was a manual row and is filtered out by the upsert WHERE clause
      // -> not present in the returned rows. Only ws_a (created) and ws_c
      // (role_changed) come back from RETURNING.
      const pool = makeApplyPool({
        upsertRows: [
          { workspace_id: "ws_a", new_role: "viewer", inserted: true },
          {
            workspace_id: "ws_c",
            new_role: "workspace_manager",
            inserted: false,
          },
        ],
        deleteRows: [],
      });

      const audits = [];
      const result = await applyResolution({
        pool,
        userId: 7,
        providerSlug: "saml",
        resolution: {
          isAdmin: false,
          workspaceGrants: [
            { workspace_id: "ws_a", role: "viewer" },
            { workspace_id: "ws_b", role: "viewer" },
            { workspace_id: "ws_c", role: "workspace_manager" },
          ],
          revoked: [],
          matchedGroups: ["g1"],
        },
        matchedGroups: ["g1"],
        writeAudit: async (params) => audits.push(params),
      });

      assert.strictEqual(result.workspaceGrantsApplied, 2);
      assert.strictEqual(result.workspaceRevocationsApplied, 0);
      assert.strictEqual(audits.length, 2);
      const auditedWorkspaces = audits.map((a) => a.workspaceId).sort();
      assert.deepStrictEqual(auditedWorkspaces, ["ws_a", "ws_c"]);
      const changes = audits.map((a) => a.metadata.change).sort();
      assert.deepStrictEqual(changes, ["created", "role_changed"]);
    });

    it("issues exactly one batched UPSERT regardless of grant count", async () => {
      const pool = makeApplyPool({
        upsertRows: [
          { workspace_id: "ws_a", new_role: "viewer", inserted: true },
          { workspace_id: "ws_b", new_role: "viewer", inserted: true },
          { workspace_id: "ws_c", new_role: "viewer", inserted: true },
          { workspace_id: "ws_d", new_role: "viewer", inserted: true },
          { workspace_id: "ws_e", new_role: "viewer", inserted: true },
        ],
        deleteRows: [],
      });

      await applyResolution({
        pool,
        userId: 1,
        providerSlug: "oidc",
        resolution: {
          isAdmin: false,
          workspaceGrants: Array.from({ length: 5 }, (_, i) => ({
            workspace_id: `ws_${String.fromCharCode(97 + i)}`,
            role: "viewer",
          })),
          revoked: [],
          matchedGroups: [],
        },
        matchedGroups: [],
        writeAudit: async () => {},
      });

      const upsertStatements = pool
        .queries()
        .filter((q) => q.includes("INSERT INTO workspace_memberships"));
      assert.strictEqual(
        upsertStatements.length,
        1,
        "expected a single batched UPSERT, got " + upsertStatements.length,
      );
    });

    it("emits revocation audit with previous_role and skips no-op deletes", async () => {
      // ws_a: SSO row deleted (returned by RETURNING).
      // ws_b: no matching row (was manual or already gone) - not returned.
      const pool = makeApplyPool({
        upsertRows: [],
        deleteRows: [{ workspace_id: "ws_a", previous_role: "viewer" }],
      });

      const audits = [];
      const result = await applyResolution({
        pool,
        userId: 7,
        providerSlug: "oidc",
        resolution: {
          isAdmin: false,
          workspaceGrants: [],
          revoked: [{ workspace_id: "ws_a" }, { workspace_id: "ws_b" }],
          matchedGroups: [],
        },
        matchedGroups: [],
        writeAudit: async (params) => audits.push(params),
      });

      assert.strictEqual(result.workspaceRevocationsApplied, 1);
      assert.strictEqual(audits.length, 1);
      assert.strictEqual(audits[0].workspaceId, "ws_a");
      assert.strictEqual(audits[0].metadata.change, "revoked");
      assert.strictEqual(audits[0].metadata.previous_role, "viewer");
    });

    it("does NOT emit an admin_granted audit row when user was already admin", async () => {
      const pool = makeApplyPool({
        adminAlreadyAdmin: true,
        upsertRows: [],
        deleteRows: [],
      });
      const audits = [];
      const result = await applyResolution({
        pool,
        userId: 7,
        providerSlug: "oidc",
        resolution: {
          isAdmin: true,
          effectiveSystemAdmin: true,
          workspaceGrants: [],
          revoked: [],
          matchedGroups: ["tt-admins"],
        },
        matchedGroups: ["tt-admins"],
        writeAudit: async (params) => audits.push(params),
      });
      assert.strictEqual(result.adminGranted, false);
      assert.strictEqual(audits.length, 0);
    });

    it("rolls back the transaction on a failure inside the loop", async () => {
      const pool = {
        connect: async () => ({
          query: async (sql) => {
            const trim = String(sql).trim().toUpperCase();
            if (sql.includes("FROM sso_providers")) return { rows: [{}] };
            if (trim === "BEGIN" || trim === "ROLLBACK") {
              return { rowCount: 0, rows: [] };
            }
            if (sql.includes("INSERT INTO workspace_memberships")) {
              throw new Error("simulated upsert failure");
            }
            return { rowCount: 0, rows: [] };
          },
          release: () => {},
        }),
      };
      await assert.rejects(
        () =>
          applyResolution({
            pool,
            userId: 1,
            providerSlug: "saml",
            resolution: {
              isAdmin: false,
              workspaceGrants: [{ workspace_id: "ws_x", role: "viewer" }],
              revoked: [],
              matchedGroups: [],
            },
            matchedGroups: [],
            writeAudit: async () => {},
          }),
        /simulated upsert failure/,
      );
    });

    it("still upserts memberships when DISABLE_MANUAL_INVITES is true", async () => {
      process.env.DISABLE_MANUAL_INVITES = "true";
      try {
        const pool = makeApplyPool({
          upsertRows: [
            { workspace_id: "ws_a", new_role: "viewer", inserted: true },
          ],
          deleteRows: [],
        });
        const result = await applyResolution({
          pool,
          userId: 7,
          providerSlug: "saml",
          resolution: {
            isAdmin: false,
            workspaceGrants: [{ workspace_id: "ws_a", role: "viewer" }],
            revoked: [],
            matchedGroups: ["g1"],
          },
          matchedGroups: ["g1"],
        });
        assert.strictEqual(result.workspaceGrantsApplied, 1);
      } finally {
        delete process.env.DISABLE_MANUAL_INVITES;
      }
    });
  });
});

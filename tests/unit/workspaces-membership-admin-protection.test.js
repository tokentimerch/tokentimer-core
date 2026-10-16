"use strict";
/** Execute the actual checked-in membership POST handler with controlled DB,
 * audit and email boundaries. No user, external API or email is contacted. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  vm = require("node:vm"),
  Module = require("node:module");
function fixture({ target = 2, owner = 9, existingRole = "admin" } = {}) {
  const filename = path.resolve(
      __dirname,
      "../../apps/api/routes/workspaces.js",
    ),
    source = fs.readFileSync(filename, "utf8"),
    routes = [],
    state = {
      role: existingRole,
      queries: [],
      audits: [],
      emails: [],
      metrics: 0,
    };
  const router = new Proxy(
    {},
    {
      get(object, key) {
        if (key === "_test") return object[key];
        if (key in object) return object[key];
        return (route, ...handlers) =>
          routes.push({ method: key, route, handlers });
      },
    },
  );
  const pool = {
    async query(sql, args) {
      state.queries.push({ sql, args });
      if (sql.includes("SELECT id, display_name FROM users"))
        return {
          rowCount: 1,
          rows: [{ id: target, display_name: "Owned test user" }],
        };
      if (sql.includes("INSERT INTO workspace_memberships")) {
        const protectedSql =
          /WHERE\s+workspace_memberships\.role\s*<>\s*'admin'/i.test(sql);
        if (protectedSql && state.role === "admin")
          return { rowCount: 0, rows: [] };
        state.role = args[2];
        return { rowCount: 1, rows: [{ user_id: target }] };
      }
      if (sql.includes("DELETE FROM workspace_invitations"))
        return { rowCount: 0, rows: [] };
      throw Error("Unexpected route query");
    },
  };
  const noop = () => {},
    middleware = () => noop,
    actual = Module.createRequire(filename),
    mocks = {
      express: { Router: () => router },
      "../db/database": { pool },
      "../utils/logger": { logger: { error: noop, warn: noop, debug: noop } },
      "../services/audit": {
        writeAudit: async (value) => state.audits.push(value),
        normalizeAuditAction: (value) => value,
        auditActionSql: (value) => value,
      },
      "../middleware/auth": { requireAuth: noop },
      "../middleware/rateLimit": { getApiLimiter: middleware },
      "../utils/emailAddress": { isValidEmail: () => true },
      "../services/rbac": {
        loadWorkspace: noop,
        requireWorkspaceMembership: noop,
        authorize: middleware,
        getUserWorkspaceRole: noop,
        hasAtLeastRole: () => true,
      },
      "../services/planLimits": { MEMBER_LIMITS: { oss: Infinity } },
      "../services/emailService": {
        generateEmailTemplate: async () => ({
          html: "public fixture",
          text: "public fixture",
        }),
        sendEmail: async (value) => {
          state.emails.push(value);
          return { success: true };
        },
      },
      "../utils/sanitize": { sanitizeForLogging: (value) => value },
      "../utils/metrics": {
        workspacesCreatedTotal: { inc: noop },
        inviteSentTotal: { inc: () => state.metrics++ },
        inviteCancelledTotal: { inc: noop },
      },
      "../services/workspaceTokenTransfer": {
        TransferAssociationConflictError: Error,
        transferTokenAssociations: noop,
      },
    };
  const module = { exports: {} };
  vm.runInThisContext(Module.wrap(source), { filename })(
    module.exports,
    (name) => (Object.hasOwn(mocks, name) ? mocks[name] : actual(name)),
    module,
    filename,
    path.dirname(filename),
  );
  const route = routes.find(
    (row) =>
      row.method === "post" && row.route === "/api/v1/workspaces/:id/members",
  );
  assert.ok(route);
  const response = {
    statusCode: 200,
    status(value) {
      this.statusCode = value;
      return this;
    },
    json(value) {
      this.body = value;
      return this;
    },
  };
  return {
    state,
    response,
    async run() {
      await route.handlers.at(-1)(
        {
          user: { id: 1, email: "controller@example.test" },
          workspace: {
            id: "11111111-1111-1111-1111-111111111111",
            created_by: owner,
            name: "Owned workspace",
            plan: "oss",
          },
          body: { email: "target@example.test", role: "viewer" },
        },
        response,
      );
      return response;
    },
  };
}
test("existing admin cannot be downgraded through membership POST", async () => {
  const value = fixture();
  await value.run();
  assert.equal(value.response.statusCode, 403);
  assert.equal(value.state.role, "admin");
  assert.equal(value.state.audits.length, 0);
  assert.equal(value.state.emails.length, 0);
  assert.equal(value.state.metrics, 0);
  assert.equal(
    value.state.queries.filter((row) =>
      row.sql.includes("DELETE FROM workspace_invitations"),
    ).length,
    0,
  );
});
test("implicit workspace owner remains admin when membership is missing", async () => {
  const value = fixture({ target: 9, owner: 9, existingRole: null });
  await value.run();
  assert.equal(value.response.statusCode, 403);
  assert.equal(value.state.role, null);
  assert.equal(
    value.state.queries.some((row) =>
      row.sql.includes("INSERT INTO workspace_memberships"),
    ),
    false,
  );
  assert.equal(value.state.audits.length, 0);
  assert.equal(value.state.emails.length, 0);
});
test("ordinary member updates preserve audit, invitation cleanup and notification behavior", async () => {
  const value = fixture({ existingRole: "workspace_manager" });
  await value.run();
  assert.equal(value.response.statusCode, 201);
  assert.equal(value.state.role, "viewer");
  assert.deepEqual(
    value.state.audits.map((row) => row.action),
    ["MEMBER_INVITED_OR_UPDATED", "INVITE_EMAIL_SENT"],
  );
  assert.equal(value.state.emails.length, 1);
  assert.equal(value.state.metrics, 1);
  const mutation = value.state.queries.find((row) =>
    row.sql.includes("INSERT INTO workspace_memberships"),
  );
  assert.match(
    mutation.sql,
    /WHERE\s+workspace_memberships\.role\s*<>\s*'admin'/,
  );
  assert.match(mutation.sql, /RETURNING\s+user_id/);
});

async function acceptInvitation({ existingRole, owner = false }) {
  const filename = path.resolve(
      __dirname,
      "../../apps/api/services/workspace.js",
    ),
    source = fs.readFileSync(filename, "utf8"),
    state = { role: existingRole, audits: [], queries: [], errors: [] };
  const pool = {
    async query(sql, args) {
      state.queries.push(sql);
      if (sql.includes("SELECT id, workspace_id, role"))
        return {
          rowCount: 1,
          rows: [{ id: "invite", workspace_id: "workspace", role: "viewer" }],
        };
      if (sql.includes("INSERT INTO workspace_memberships")) {
        assert.match(sql, /w.created_by IS DISTINCT FROM \$1/);
        assert.match(sql, /WHERE workspace_memberships.role <> 'admin'/);
        if (owner || state.role === "admin") return { rowCount: 0, rows: [] };
        state.role = args[2];
        return { rowCount: 1, rows: [{ role: state.role }] };
      }
      if (sql.includes("SELECT 1 FROM workspace_memberships"))
        return { rowCount: 1, rows: [{}] };
      if (sql.includes("workspace_invitations"))
        return { rowCount: 1, rows: [] };
      throw Error("Unexpected invitation query");
    },
  };
  const noop = () => {},
    mocks = {
      "../db/database": { pool },
      "../utils/logger": {
        logger: { error: (value) => state.errors.push(value), warn: noop },
      },
      "./audit": { writeAudit: async (value) => state.audits.push(value) },
      "./systemAdmin": { ensureSystemAdminWorkspaceAccess: async () => {} },
    },
    module = { exports: {} };
  vm.runInThisContext(Module.wrap(source), { filename })(
    module.exports,
    (name) => {
      assert.ok(Object.hasOwn(mocks, name));
      return mocks[name];
    },
    module,
    filename,
    path.dirname(filename),
  );
  await module.exports.ensureInitialWorkspaceForUser(
    "user",
    "owned+alias@example.test",
    "Owned",
  );
  assert.equal(state.errors.length, 0);
  return state;
}
test("login invitation cannot replace an existing admin", async () => {
  const state = await acceptInvitation({ existingRole: "admin" });
  assert.equal(state.role, "admin");
  assert.equal(state.audits.length, 0);
  assert.ok(
    state.queries.some((sql) =>
      sql.startsWith("DELETE FROM workspace_invitations"),
    ),
  );
});
test("login invitation cannot override an implicit owner with no membership", async () => {
  const state = await acceptInvitation({ existingRole: null, owner: true });
  assert.equal(state.role, null);
  assert.equal(state.audits.length, 0);
});
test("ordinary login invitation still updates role and audits acceptance", async () => {
  const state = await acceptInvitation({ existingRole: "workspace_manager" });
  assert.equal(state.role, "viewer");
  assert.equal(state.audits.length, 1);
  assert.equal(state.audits[0].metadata.role, "viewer");
});

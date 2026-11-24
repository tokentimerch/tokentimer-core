"use strict";
/** Execute the checked-in membership handlers with controlled DB,
 * audit and email boundaries. No external API or email is contacted. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  vm = require("node:vm"),
  Module = require("node:module");
function fixture({
  target = 2,
  owner = 9,
  existingRole = "admin",
  authMethod = "local",
  emailVerified = true,
  method = "post",
  auditFails = false,
} = {}) {
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
      auditQueryCounts: [],
      emails: [],
      templates: [],
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
  let beforeTransaction;
  const pool = {
    async connect() {
      return client;
    },
    async query(sql, args) {
      state.queries.push({ sql, args });
      if (sql === "BEGIN") beforeTransaction = state.role;
      if (sql === "ROLLBACK") state.role = beforeTransaction;
      if (/^(BEGIN|COMMIT|ROLLBACK)$/.test(sql) || sql.includes("pg_advisory_xact_lock"))
        return { rowCount: 0, rows: [] };
      if (sql.startsWith("SELECT role FROM workspace_memberships")) {
        assert.match(sql, /FOR UPDATE$/);
        const rows = state.role ? [{ role: state.role }] : [];
        return { rowCount: rows.length, rows };
      }
      if (/^UPDATE workspace_memberships\s+SET role\s*=/.test(sql)) {
        state.role = args[0];
        return { rowCount: 1, rows: [] };
      }
      if (sql.startsWith("DELETE FROM workspace_memberships")) {
        state.role = null;
        return { rowCount: 1, rows: [] };
      }
      if (sql.includes("SELECT id FROM users WHERE id IN"))
        return { rowCount: 3, rows: [{ id: owner }, { id: 1 }, { id: target }] };
      if (sql.includes("SELECT created_by,plan FROM workspaces"))
        return { rowCount: 1, rows: [{ created_by: owner, plan: "oss" }] };
      if (sql.includes("SELECT id, display_name, auth_method, email_verified FROM users"))
        return {
          rowCount: 1,
          rows: [{
            id: target, display_name: "Owned test user",
            auth_method: authMethod, email_verified: emailVerified,
          }],
        };
      if (sql.startsWith("SELECT 1 FROM workspace_memberships WHERE user_id")) {
        return { rowCount: state.role ? 1 : 0, rows: state.role ? [{}] : [] };
      }
      if (sql.includes("INSERT INTO workspace_memberships")) {
        const protectedSql =
          /WHERE\s+workspace_memberships\.role\s*<>\s*'admin'/i.test(sql);
        if (protectedSql && state.role === "admin")
          return { rowCount: 0, rows: [] };
        state.role = args[2];
        return { rowCount: 1, rows: [{ user_id: target }] };
      }
      if (sql.includes("INSERT INTO workspace_invitations"))
        return { rowCount: 1, rows: [] };
      if (sql.includes("DELETE FROM workspace_invitations"))
        return { rowCount: 0, rows: [] };
      throw Error("Unexpected route query");
    },
  };
  const client = { query: pool.query.bind(pool), release() {} };
  const noop = () => {},
    middleware = () => noop,
    actual = Module.createRequire(filename),
    mocks = {
      express: { Router: () => router },
      "../db/database": { pool },
      "../utils/logger": { logger: { error: noop, warn: noop, debug: noop } },
      "../services/audit": {
        writeAudit: async (value) => {
          if (method !== "post") assert.equal(value.client, client);
          if (auditFails) throw Error("audit insert failed");
          state.auditQueryCounts.push(state.queries.length);
          state.audits.push(value);
        },
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
        generateEmailTemplate: async (value) => {
          state.templates.push(value);
          return { html: "public fixture", text: "public fixture" };
        },
        sendEmail: async (value) => {
          state.emails.push(value);
          return { success: true };
        },
      },
      "../utils/sanitize": {
        escapeHtml: (value) => value,
        sanitizeForLogging: (value) => value,
      },
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
  const membersPath = "/api/v1/workspaces/:id/members";
  const route = routes.find((row) =>
    row.method === method && row.route === (method === "post" ? membersPath : membersPath + "/:userId"),
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
    send() { return this; },
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
          params: { userId: String(target) },
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

test("an existing SSO account receives a pending invite instead of a direct membership", async () => {
  // SSO's legacy email_verified flag does not attest to the invited mailbox.
  const value = fixture({ authMethod: "sso", existingRole: null });
  await value.run();
  assert.equal(value.response.statusCode, 201);
  assert.deepEqual({ ...value.response.body }, { user_id: null, role: "viewer" });
  assert.equal(value.state.role, null);
  assert.equal(value.state.queries.some(({ sql }) => sql.includes("INSERT INTO workspace_memberships")), false);
  const invitation = value.state.queries.find(({ sql }) => sql.includes("INSERT INTO workspace_invitations"));
  assert.equal(invitation.args[2], "target@example.test");
  assert.equal(value.state.templates[0].buttonText, "Sign in");
  assert.match(value.state.templates[0].buttonUrl, /\/login$/);
});

test("email POST sends existing SSO member role edits to the member-ID endpoint", async () => {
  const value = fixture({ authMethod: "sso", existingRole: "workspace_manager" });
  await value.run();
  assert.equal(value.response.statusCode, 409);
  assert.equal(value.response.body.code, "MEMBER_ALREADY_EXISTS");
  assert.match(value.response.body.error, /member ID/);
  assert.equal(value.state.role, "workspace_manager");
  assert.equal(value.state.queries.some(({ sql }) => sql.includes("INSERT INTO workspace_invitations")), false);
  assert.equal(value.state.emails.length, 0);
});

test("role changes audit the locked prior role before commit", async () => {
  const value = fixture({ method: "patch", existingRole: "workspace_manager" });
  await value.run();
  assert.equal(value.response.statusCode, 200);
  assert.equal(value.state.role, "viewer");
  const lockIndex = value.state.queries.findIndex(({ sql }) =>
    sql.startsWith("SELECT role FROM workspace_memberships"),
  );
  const updateIndex = value.state.queries.findIndex(({ sql }) =>
    sql.startsWith("UPDATE workspace_memberships"),
  );
  assert.ok(lockIndex >= 0 && updateIndex > lockIndex);
  assert.ok(updateIndex < value.state.auditQueryCounts[0]);
  const update = value.state.queries[updateIndex];
  assert.match(
    update.sql,
    /SET role = \$1, source = 'manual', source_provider_slug = NULL\s+WHERE user_id = \$2 AND workspace_id = \$3/,
  );
  assert.deepEqual(update.args, ["viewer", "2", "11111111-1111-1111-1111-111111111111"]);
  const [audit] = value.state.audits;
  assert.equal(audit.action, "MEMBER_ROLE_CHANGED");
  assert.deepEqual(audit.metadata, { role: "viewer", previous_role: "workspace_manager" });
  assert.equal(value.state.queries[value.state.auditQueryCounts[0]].sql, "COMMIT");

  await value.run();
  assert.equal(value.response.statusCode, 200);
  assert.equal(value.state.audits.length, 1);
});

test("reports a missing member without writing a role change", async () => {
  const value = fixture({ method: "patch", existingRole: null });
  await value.run();
  assert.equal(value.response.statusCode, 404);
  assert.equal(value.state.audits.length, 0);
});

test("removal records the actual removed role and a replay produces no event", async () => {
  const value = fixture({ method: "delete", existingRole: "workspace_manager" });
  await value.run();
  assert.equal(value.response.statusCode, 204);
  assert.equal(value.state.role, null);
  const [audit] = value.state.audits;
  assert.equal(audit.action, "MEMBER_REMOVED");
  assert.deepEqual(audit.metadata, { removed_role: "workspace_manager" });
  assert.equal(value.state.queries[value.state.auditQueryCounts[0]].sql, "COMMIT");

  await value.run();
  assert.equal(value.response.statusCode, 204);
  assert.equal(value.state.audits.length, 1);
});

for (const method of ["patch", "delete"]) {
  test(method + " rolls back a membership mutation when its audit insert fails", async () => {
    const value = fixture({ method, existingRole: "workspace_manager", auditFails: true });
    await value.run();
    assert.equal(value.response.statusCode, 500);
    assert.equal(value.state.role, "workspace_manager");
    assert.equal(value.state.queries.at(-1).sql, "ROLLBACK");
    assert.equal(value.state.audits.length, 0);
  });
}

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
      if (sql.includes("SELECT id, email"))
        return {
          rowCount: 1,
          rows: [{ id: "invite", email: "owned+alias@example.test" }],
        };
      if (sql.includes("INSERT INTO workspace_memberships")) {
        assert.match(sql, /w.created_by IS DISTINCT FROM \$1/);
        assert.match(sql, /WHERE workspace_memberships.role <> 'admin'/);
        if (owner || state.role === "admin") return { rowCount: 0, rows: [] };
        assert.deepEqual(args, ["user", "invite", "owned+alias@example.test"]);
        state.role = "viewer";
        return { rowCount: 1, rows: [{ workspace_id: "workspace", role: state.role }] };
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
      sql.includes("DELETE FROM workspace_invitations"),
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

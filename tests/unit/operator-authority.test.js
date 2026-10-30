"use strict";

// Authority is evaluated per request as the intersection of the connection's
// scopes, the role ceiling fixed at creation, the user's current role and the
// scope's own minimum role (ADR-0015 section 3). These tests are pure.

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const Ajv = require("ajv");
const addFormats = require("ajv-formats");

const connections = require(
  path.resolve(__dirname, "../../apps/api/services/operator/connections.js"),
);
const { effectiveWorkspaceRole } = require(
  path.resolve(__dirname, "../../apps/api/services/rbac.js"),
);
const projections = require(
  path.resolve(__dirname, "../../apps/api/services/operator/projections.js"),
);

const contractsDir = path.resolve(__dirname, "../../packages/contracts/mcp");
const catalog = JSON.parse(fs.readFileSync(path.join(contractsDir, "mcp-tool-catalog.json"), "utf8"));
const common = JSON.parse(fs.readFileSync(path.join(contractsDir, "mcp-common.schema.json"), "utf8"));
const readTools = JSON.parse(fs.readFileSync(path.join(contractsDir, "mcp-read-tools.schema.json"), "utf8"));

const ROLES = ["viewer", "workspace_manager", "admin"];
const RANK = { viewer: 1, workspace_manager: 2, admin: 3 };

function connection(overrides = {}) {
  return {
    id: "550e8400-e29b-41d4-a716-446655440001",
    scopes: ["mcp:identity:read", "mcp:certs:read", "mcp:agents:read", "mcp:jobs:read"],
    roleCeiling: "admin",
    ...overrides,
  };
}

describe("scope vocabulary", () => {
  it("matches the contract catalog exactly, including each minimum role", () => {
    const fromCatalog = Object.fromEntries(catalog.scopes.map((s) => [s.name, s.minRole]));
    assert.deepEqual(connections.SCOPE_MIN_ROLE, fromCatalog);
    assert.deepEqual([...common.definitions.scope.enum].sort(), [...connections.ALLOWED_SCOPES].sort());
  });

  it("makes a scope grantable exactly when an implemented tool uses it", () => {
    // The rule that keeps a premature grant from becoming live authority: a
    // scope opens only in the release that ships a route for it.
    const implemented = new Set(
      catalog.tools.filter((tool) => tool.routeStatus === "implemented").map((tool) => tool.scope),
    );
    for (const scope of implemented) {
      assert.ok(!connections.RESERVED_SCOPES.has(scope), `${scope} has an implemented tool, so it must be grantable`);
    }
    for (const tool of catalog.tools.filter((t) => t.routeStatus !== "implemented")) {
      if (implemented.has(tool.scope)) continue;
      assert.ok(connections.RESERVED_SCOPES.has(tool.scope), `${tool.name} scope ${tool.scope} must stay reserved`);
    }
  });

  it("keeps the broad lifecycle scope, and every riskier one, closed while only renewals exist", () => {
    for (const scope of ["mcp:lifecycle:request", "mcp:config:request", "mcp:ca-revoke", "mcp:ops:request"]) {
      assert.ok(connections.RESERVED_SCOPES.has(scope), `${scope} must stay reserved`);
      assert.throws(() => connections._test.normalizeScopes([scope]), (e) => e.code === connections.CONNECTION_SCOPE_INVALID);
    }
    assert.deepEqual(connections._test.normalizeScopes(["mcp:renew:request", "mcp:requests:read"]), [
      "mcp:renew:request",
      "mcp:requests:read",
    ]);
  });

  it("gives every tool a scope whose minimum role is at least the tool's own", () => {
    for (const tool of catalog.tools) {
      assert.equal(connections.SCOPE_MIN_ROLE[tool.scope], tool.minRole, tool.name);
    }
  });
});

describe("effectiveWorkspaceRole", () => {
  it("prefers a membership row over everything else", () => {
    assert.equal(effectiveWorkspaceRole({ membershipRole: "viewer", workspaceCreatedBy: 7, userId: 7 }), "viewer");
  });

  it("treats the workspace creator without a membership as admin", () => {
    assert.equal(effectiveWorkspaceRole({ membershipRole: null, workspaceCreatedBy: 7, userId: 7 }), "admin");
    assert.equal(effectiveWorkspaceRole({ membershipRole: null, workspaceCreatedBy: "7", userId: 7 }), "admin");
  });

  it("gives nothing to a stranger, and nothing for missing identifiers", () => {
    assert.equal(effectiveWorkspaceRole({ membershipRole: null, workspaceCreatedBy: 7, userId: 8 }), null);
    assert.equal(effectiveWorkspaceRole({ membershipRole: null, workspaceCreatedBy: null, userId: null }), null);
    assert.equal(effectiveWorkspaceRole({ membershipRole: null }), null);
    assert.equal(effectiveWorkspaceRole({}), null);
  });
});

describe("computeAuthority", () => {
  it("never exceeds the lower of the ceiling and the current role", () => {
    for (const ceiling of ROLES) {
      for (const current of ROLES) {
        const authority = connections.computeAuthority({
          connection: connection({ roleCeiling: ceiling, scopes: connections.ALLOWED_SCOPES }),
          currentRole: current,
        });
        const expected = RANK[ceiling] <= RANK[current] ? ceiling : current;
        assert.equal(authority.effectiveRole, expected, `ceiling ${ceiling}, current ${current}`);
        for (const scope of authority.scopes) {
          assert.ok(
            RANK[authority.effectiveRole] >= RANK[connections.SCOPE_MIN_ROLE[scope]],
            `${scope} granted to ${authority.effectiveRole}`,
          );
        }
      }
    }
  });

  it("applies a demotion immediately: manager-only scopes drop away", () => {
    const base = connection({ roleCeiling: "admin" });
    const asManager = connections.computeAuthority({ connection: base, currentRole: "workspace_manager" });
    assert.ok(asManager.scopes.includes("mcp:agents:read"));
    const asViewer = connections.computeAuthority({ connection: base, currentRole: "viewer" });
    assert.ok(!asViewer.scopes.includes("mcp:agents:read"));
    assert.ok(asViewer.scopes.includes("mcp:certs:read"));
  });

  it("does not widen on promotion beyond the ceiling", () => {
    const base = connection({ roleCeiling: "viewer", scopes: ["mcp:certs:read", "mcp:agents:read"] });
    const promoted = connections.computeAuthority({ connection: base, currentRole: "admin" });
    assert.equal(promoted.effectiveRole, "viewer");
    assert.deepEqual(promoted.scopes, ["mcp:certs:read"]);
  });

  it("grants nothing to a user with no role", () => {
    const authority = connections.computeAuthority({ connection: connection(), currentRole: null });
    assert.equal(authority.effectiveRole, null);
    assert.deepEqual(authority.scopes, []);
  });

  it("treats an unknown scope as admin-only rather than open", () => {
    const authority = connections.computeAuthority({
      connection: connection({ scopes: ["mcp:made-up"] }),
      currentRole: "workspace_manager",
    });
    assert.deepEqual(authority.scopes, []);
  });
});

describe("connection input rules", () => {
  const { resolveExpiry, normalizeName, normalizeScopes } = connections._test;

  it("defaults to 30 days and refuses past, malformed and over-90-day expiries", () => {
    const now = new Date("2026-10-19T12:00:00Z");
    assert.equal(
      resolveExpiry(undefined, now).getTime() - now.getTime(),
      connections.DEFAULT_LIFETIME_MS,
    );
    for (const bad of ["not a date", "2026-10-01T00:00:00Z", now.toISOString(), "2027-03-01T00:00:00Z"]) {
      assert.throws(() => resolveExpiry(bad, now), { code: connections.CONNECTION_EXPIRY_INVALID }, bad);
    }
    assert.doesNotThrow(() => resolveExpiry("2026-12-01T00:00:00Z", now));
  });

  it("refuses scopes that do not exist or are not available in this release", () => {
    assert.throws(() => normalizeScopes([]), { code: connections.CONNECTION_SCOPE_INVALID });
    assert.throws(() => normalizeScopes("mcp:certs:read"), { code: connections.CONNECTION_SCOPE_INVALID });
    assert.throws(() => normalizeScopes(["mcp:everything"]), { code: connections.CONNECTION_SCOPE_INVALID });
    for (const reserved of connections.RESERVED_SCOPES) {
      assert.throws(() => normalizeScopes([reserved]), { code: connections.CONNECTION_SCOPE_INVALID }, reserved);
    }
    assert.deepEqual(normalizeScopes(["mcp:certs:read", "mcp:certs:read"]), ["mcp:certs:read"]);
  });

  it("keeps secrets out of the connection name", () => {
    assert.equal(normalizeName("  Claude on my laptop "), "Claude on my laptop");
    assert.throws(() => normalizeName(""), { code: connections.CONNECTION_NAME_INVALID });
    assert.throws(() => normalizeName("x".repeat(129)), { code: connections.CONNECTION_NAME_INVALID });
    assert.throws(() => normalizeName(42), { code: connections.CONNECTION_NAME_INVALID });
    assert.throws(
      () => normalizeName(`ttopc_${"0123456789abcdef"}_${"a".repeat(64)}`),
      { code: connections.CONNECTION_NAME_INVALID },
    );
    assert.throws(
      () => normalizeName("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"),
      { code: connections.PRIVATE_KEY_MATERIAL_REJECTED },
    );
  });

  it("reports expiry in the status without a database", () => {
    const now = new Date("2026-10-19T12:00:00Z");
    const { connectionStatusFromRow } = connections._test;
    assert.equal(connectionStatusFromRow({ status: "active", expires_at: "2026-10-20T00:00:00Z" }, now), "active");
    assert.equal(connectionStatusFromRow({ status: "active", expires_at: "2026-10-19T11:59:59Z" }, now), "expired");
    assert.equal(connectionStatusFromRow({ status: "revoked", expires_at: "2027-01-01T00:00:00Z" }, now), "revoked");
  });
});

describe("whoami projection", () => {
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  ajv.addSchema(common);
  ajv.addSchema(readTools);
  const validate = ajv.getSchema(`${readTools.$id}#/definitions/tt_whoami_output`);

  const operator = {
    connectionId: "550e8400-e29b-41d4-a716-446655440001",
    userId: 4,
    workspaceId: "550e8400-e29b-41d4-a716-446655440000",
    scopes: ["mcp:identity:read", "mcp:certs:read"],
    role: "workspace_manager",
    roleCeiling: "workspace_manager",
    currentRole: "admin",
    expiresAt: "2026-11-18T12:00:00.000Z",
  };

  it("produces output that satisfies the published contract", () => {
    const body = projections.projectWhoami({
      operator,
      workspace: { id: operator.workspaceId, name: "Platform" },
      certops: { enabled: true, paused: false, approvalRequiredAlways: true },
    });
    assert.equal(validate(body), true, JSON.stringify(validate.errors));
    assert.equal(body.certops.mcpWritesEnabled, false);
    assert.equal(body.role.effective, "workspace_manager");
    assert.equal(body.role.current, "admin");
  });

  it("wraps the workspace name as untrusted data and never leaks the user id", () => {
    const body = projections.projectWhoami({
      operator,
      workspace: { id: operator.workspaceId, name: "x".repeat(600) },
      certops: { enabled: false, paused: true, approvalRequiredAlways: false },
    });
    assert.equal(body.workspace.name.untrusted, true);
    assert.equal(body.workspace.name.truncated, true);
    assert.equal(body.workspace.name.value.length, projections.MAX_UNTRUSTED_TEXT);
    assert.equal(JSON.stringify(body).includes("userId"), false);
    assert.equal(validate(body), true, JSON.stringify(validate.errors));
  });
});

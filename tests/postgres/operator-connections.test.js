"use strict";

// Real-PostgreSQL proof for operator connections (ADR-0015). Mocked clients
// cannot show lock ordering, constraint enforcement or live role changes, so
// these run against a disposable database whose name ends in _mcp_test.

const { before, after, beforeEach, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { pool } = require("../../apps/api/db/database");
const connections = require("../../apps/api/services/operator/connections");

let owner;
let manager;
let viewer;
let stranger;
let workspaceId;
let otherWorkspaceId;
let sequence = 0;

async function createUser(label) {
  const email = `${label}-${crypto.randomUUID()}@example.test`;
  const result = await pool.query(
    `INSERT INTO users (email, display_name, auth_method, password_hash, email_verified)
     VALUES ($1, $2, 'local', 'x', TRUE) RETURNING id`,
    [email, label],
  );
  return result.rows[0].id;
}

async function createWorkspace(createdBy) {
  const id = crypto.randomUUID();
  await pool.query("INSERT INTO workspaces (id, name, created_by) VALUES ($1, $2, $3)", [
    id,
    `ws-${++sequence}`,
    createdBy,
  ]);
  return id;
}

async function member(userId, workspace, role) {
  await pool.query(
    `INSERT INTO workspace_memberships (user_id, workspace_id, role) VALUES ($1, $2, $3)
     ON CONFLICT (user_id, workspace_id) DO UPDATE SET role = EXCLUDED.role`,
    [userId, workspace, role],
  );
}

function create(overrides = {}) {
  return connections.createConnection({
    workspaceId,
    userId: manager,
    name: `conn-${++sequence}`,
    scopes: ["mcp:identity:read", "mcp:certs:read"],
    roleCeiling: "workspace_manager",
    ...overrides,
  });
}

describe("operator connections on PostgreSQL", { concurrency: false }, () => {
  before(async () => {
    assert.match(process.env.DB_NAME || "", /_mcp_test$/, "Use a disposable *_mcp_test database");
    owner = await createUser("owner");
    manager = await createUser("manager");
    viewer = await createUser("viewer");
    stranger = await createUser("stranger");
    workspaceId = await createWorkspace(owner);
    otherWorkspaceId = await createWorkspace(owner);
    await member(manager, workspaceId, "workspace_manager");
    await member(viewer, workspaceId, "viewer");
  });

  after(async () => {
    await pool.query("DELETE FROM operator_connections WHERE workspace_id = ANY($1::uuid[])", [
      [workspaceId, otherWorkspaceId],
    ]);
    await pool.end();
  });

  beforeEach(async () => {
    await member(manager, workspaceId, "workspace_manager");
    await member(viewer, workspaceId, "viewer");
  });

  it("stores only a hash, and returns the credential exactly once", async () => {
    const { connection, plaintextCredential } = await create();
    assert.match(plaintextCredential, /^ttopc_[a-f0-9]{16}_[a-f0-9]{64}$/);
    const row = (
      await pool.query("SELECT * FROM operator_connections WHERE id = $1", [connection.id])
    ).rows[0];
    assert.match(row.credential_hash, /^[a-f0-9]{64}$/);
    assert.ok(!JSON.stringify(row).includes(plaintextCredential));
    assert.equal(row.credential_prefix, plaintextCredential.slice(0, "ttopc_".length + 16));
    assert.equal(JSON.stringify(connection).includes(plaintextCredential), false);
    assert.equal("credentialHash" in connection, false);
  });

  it("authenticates a fresh credential with live authority", async () => {
    const { connection, plaintextCredential } = await create();
    const outcome = await connections.authenticateCredential({ rawCredential: plaintextCredential });
    assert.equal(outcome.valid, true);
    assert.equal(outcome.connection.id, connection.id);
    assert.equal(outcome.authority.effectiveRole, "workspace_manager");
    assert.deepEqual(outcome.authority.scopes, ["mcp:identity:read", "mcp:certs:read"]);
  });

  it("refuses a wrong secret that shares a valid lookup prefix", async () => {
    const { plaintextCredential } = await create();
    const forged = `${plaintextCredential.slice(0, "ttopc_".length + 16)}_${"0".repeat(64)}`;
    assert.equal((await connections.authenticateCredential({ rawCredential: forged })).valid, false);
  });

  it("applies a demotion on the very next request", async () => {
    const { plaintextCredential } = await create({ scopes: ["mcp:certs:read", "mcp:agents:read"] });
    const before = await connections.authenticateCredential({ rawCredential: plaintextCredential });
    assert.ok(before.authority.scopes.includes("mcp:agents:read"));
    await member(manager, workspaceId, "viewer");
    const after = await connections.authenticateCredential({ rawCredential: plaintextCredential });
    assert.equal(after.valid, true);
    assert.equal(after.authority.effectiveRole, "viewer");
    assert.deepEqual(after.authority.scopes, ["mcp:certs:read"]);
  });

  it("does not widen on promotion beyond the ceiling", async () => {
    const { plaintextCredential } = await create({ userId: viewer, roleCeiling: "viewer", scopes: ["mcp:certs:read"] });
    await member(viewer, workspaceId, "admin");
    const outcome = await connections.authenticateCredential({ rawCredential: plaintextCredential });
    assert.equal(outcome.authority.effectiveRole, "viewer");
    assert.equal(outcome.authority.currentRole, "admin");
    await member(viewer, workspaceId, "viewer");
  });

  it("stops authenticating once the user loses all access", async () => {
    const { plaintextCredential } = await create();
    await pool.query("DELETE FROM workspace_memberships WHERE user_id = $1 AND workspace_id = $2", [manager, workspaceId]);
    assert.equal((await connections.authenticateCredential({ rawCredential: plaintextCredential })).valid, false);
  });

  it("honors the implicit workspace-owner rule and nothing broader", async () => {
    const { plaintextCredential } = await create({ userId: owner, roleCeiling: "admin", scopes: ["mcp:agents:read"] });
    const outcome = await connections.authenticateCredential({ rawCredential: plaintextCredential });
    assert.equal(outcome.authority.effectiveRole, "admin");
    await assert.rejects(
      create({ userId: stranger, roleCeiling: "viewer", scopes: ["mcp:certs:read"] }),
      { code: connections.CONNECTION_FORBIDDEN },
    );
  });

  it("never gives a system admin a workspace role", async () => {
    await pool.query("UPDATE users SET is_admin = TRUE WHERE id = $1", [stranger]);
    await assert.rejects(
      create({ userId: stranger, roleCeiling: "viewer", scopes: ["mcp:certs:read"] }),
      { code: connections.CONNECTION_FORBIDDEN },
    );
    await pool.query("UPDATE users SET is_admin = FALSE WHERE id = $1", [stranger]);
  });

  it("revokes idempotently and stops authenticating at once", async () => {
    const { connection, plaintextCredential } = await create();
    const first = await connections.revokeConnection({ workspaceId, connectionId: connection.id, revokedBy: owner });
    assert.equal(first.revokedNow, true);
    assert.equal(first.connection.status, "revoked");
    const second = await connections.revokeConnection({ workspaceId, connectionId: connection.id, revokedBy: owner });
    assert.equal(second.revokedNow, false);
    assert.equal(second.connection.revokedBy, owner);
    assert.equal((await connections.authenticateCredential({ rawCredential: plaintextCredential })).valid, false);
  });

  it("rotates the secret without changing identity, owner, scopes or expiry", async () => {
    const { connection, plaintextCredential } = await create();
    const rotated = await connections.rotateCredential({ workspaceId, connectionId: connection.id });
    assert.notEqual(rotated.plaintextCredential, plaintextCredential);
    assert.equal(rotated.connection.id, connection.id);
    assert.equal(rotated.connection.userId, connection.userId);
    assert.deepEqual(rotated.connection.scopes, connection.scopes);
    assert.equal(rotated.connection.expiresAt, connection.expiresAt);
    assert.equal(rotated.connection.roleCeiling, connection.roleCeiling);
    assert.ok(rotated.connection.credentialRotatedAt);
    assert.equal((await connections.authenticateCredential({ rawCredential: plaintextCredential })).valid, false);
    const fresh = await connections.authenticateCredential({ rawCredential: rotated.plaintextCredential });
    assert.equal(fresh.valid, true);
    assert.equal(fresh.connection.id, connection.id);
  });

  it("refuses to rotate a revoked or expired connection", async () => {
    const revoked = await create();
    await connections.revokeConnection({ workspaceId, connectionId: revoked.connection.id });
    assert.equal(await connections.rotateCredential({ workspaceId, connectionId: revoked.connection.id }), null);

    const expired = await create();
    await pool.query(
      "UPDATE operator_connections SET created_at = NOW() - INTERVAL '2 days', expires_at = NOW() - INTERVAL '1 second' WHERE id = $1",
      [expired.connection.id],
    );
    assert.equal(await connections.rotateCredential({ workspaceId, connectionId: expired.connection.id }), null);
  });

  it("keeps connections inside their workspace", async () => {
    const { connection } = await create();
    assert.equal(await connections.getConnection({ workspaceId: otherWorkspaceId, connectionId: connection.id }), null);
    const attempt = await connections.revokeConnection({
      workspaceId: otherWorkspaceId,
      connectionId: connection.id,
    });
    assert.equal(attempt.revokedNow, false);
    assert.equal(attempt.connection, null);
    assert.equal(
      (await connections.getConnection({ workspaceId, connectionId: connection.id })).status,
      "active",
    );
    assert.equal(await connections.rotateCredential({ workspaceId: otherWorkspaceId, connectionId: connection.id }), null);
    const listed = await connections.listConnections({ workspaceId: otherWorkspaceId });
    assert.ok(!listed.some((item) => item.id === connection.id));
  });

  it("lists only the requested user's connections when asked", async () => {
    const mine = await create({ userId: manager });
    const theirs = await create({ userId: viewer, roleCeiling: "viewer", scopes: ["mcp:certs:read"] });
    const forManager = await connections.listConnections({ workspaceId, userId: manager });
    assert.ok(forManager.some((item) => item.id === mine.connection.id));
    assert.ok(!forManager.some((item) => item.id === theirs.connection.id));
    const all = await connections.listConnections({ workspaceId });
    assert.ok(all.some((item) => item.id === theirs.connection.id));
  });

  it("issues unique credentials under concurrent creation", async () => {
    const created = await Promise.all(Array.from({ length: 12 }, () => create()));
    const credentials = new Set(created.map((item) => item.plaintextCredential));
    const prefixes = new Set(created.map((item) => item.connection.credentialPrefix));
    assert.equal(credentials.size, 12);
    assert.equal(prefixes.size, 12);
  });

  it("enforces the schema rules even for a manual insert", async () => {
    const base = [workspaceId, manager, "manual"];
    const insert = (overrides) =>
      pool.query(
        `INSERT INTO operator_connections
           (workspace_id, user_id, name, scopes, role_ceiling, credential_prefix, credential_hash, expires_at, status, revoked_at)
         VALUES ($1, $2, $3, $4::text[], $5, $6, $7, $8, $9, $10)`,
        [
          ...base,
          overrides.scopes ?? ["mcp:certs:read"],
          overrides.ceiling ?? "viewer",
          overrides.prefix ?? `ttopc_${crypto.randomBytes(8).toString("hex")}`,
          overrides.hash ?? crypto.randomBytes(32).toString("hex"),
          overrides.expires ?? new Date(Date.now() + 86400000),
          overrides.status ?? "active",
          overrides.revokedAt ?? null,
        ],
      );
    await assert.rejects(insert({ prefix: "ttagent_0123456789abcdef" }), /credential_prefix_check/);
    await assert.rejects(insert({ hash: "not-a-hash" }), /credential_hash_check/);
    await assert.rejects(insert({ ceiling: "root" }), /role_ceiling_check/);
    await assert.rejects(insert({ scopes: [] }), /scopes_check/);
    await assert.rejects(insert({ status: "revoked" }), /revoked_consistency_check/);
    await assert.rejects(insert({ expires: new Date(Date.now() - 1000) }), /expiry_after_creation_check/);
    await assert.rejects(insert({ expires: new Date(Date.now() + 91 * 86400000) }), /expiry_cap_check/);
  });

  describe("revocation ordering (ADR-0015 section 8)", () => {
    async function begin() {
      const client = await pool.connect();
      await client.query("BEGIN");
      return client;
    }
    const settled = (promise) =>
      Promise.race([promise.then(() => "done"), new Promise((resolve) => setTimeout(() => resolve("pending"), 400))]);

    it("makes a revocation wait for an authorization already in flight", async () => {
      const { connection, plaintextCredential } = await create();
      const authorizer = await begin();
      const revoker = await begin();
      try {
        const outcome = await connections.authenticateCredential({
          client: authorizer,
          rawCredential: plaintextCredential,
        });
        assert.equal(outcome.valid, true);

        const revoke = connections.revokeConnection({ client: revoker, workspaceId, connectionId: connection.id });
        assert.equal(await settled(revoke), "pending", "revocation must wait for the authorizing transaction");

        await authorizer.query("COMMIT");
        const done = await revoke;
        assert.equal(done.revokedNow, true);
        await revoker.query("COMMIT");
      } finally {
        await authorizer.query("ROLLBACK").catch(() => {});
        await revoker.query("ROLLBACK").catch(() => {});
        authorizer.release();
        revoker.release();
      }
      assert.equal((await connections.authenticateCredential({ rawCredential: plaintextCredential })).valid, false);
    });

    it("makes an authorization that starts after a revocation began wait, then fail", async () => {
      const { connection, plaintextCredential } = await create();
      const revoker = await begin();
      const authorizer = await begin();
      try {
        await connections.revokeConnection({ client: revoker, workspaceId, connectionId: connection.id });
        const authorize = connections.authenticateCredential({ client: authorizer, rawCredential: plaintextCredential });
        assert.equal(await settled(authorize), "pending", "authorization must wait for the revoking transaction");

        await revoker.query("COMMIT");
        const outcome = await authorize;
        assert.equal(outcome.valid, false, "no authorization may commit after revocation commits");
        await authorizer.query("COMMIT");
      } finally {
        await revoker.query("ROLLBACK").catch(() => {});
        await authorizer.query("ROLLBACK").catch(() => {});
        revoker.release();
        authorizer.release();
      }
    });
  });

  it("refuses a ceiling above the user's role and a scope above the ceiling", async () => {
    await assert.rejects(create({ userId: viewer, roleCeiling: "workspace_manager" }), {
      code: connections.CONNECTION_FORBIDDEN,
    });
    await assert.rejects(
      create({ userId: manager, roleCeiling: "viewer", scopes: ["mcp:agents:read"] }),
      { code: connections.CONNECTION_SCOPE_DENIED },
    );
  });

  it("expires on schedule and a database check caps the lifetime at 90 days", async () => {
    const { connection, plaintextCredential } = await create();
    await pool.query(
      "UPDATE operator_connections SET created_at = NOW() - INTERVAL '2 days', expires_at = NOW() - INTERVAL '1 second' WHERE id = $1",
      [connection.id],
    );
    assert.equal((await connections.authenticateCredential({ rawCredential: plaintextCredential })).valid, false);
    await assert.rejects(
      pool.query("UPDATE operator_connections SET expires_at = created_at + INTERVAL '91 days' WHERE id = $1", [connection.id]),
      /operator_connections_expiry_cap_check/,
    );
  });
});

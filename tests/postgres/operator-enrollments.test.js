"use strict";

// Enrollment grants on real PostgreSQL (ADR-0015 section 12). The properties
// that matter are all about what happens between issuing a grant and spending
// it: concurrent redemption, authority lost in the gap, expiry, revocation, and
// the fact that the redeemer chooses nothing.

const { before, after, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { pool } = require("../../apps/api/db/database");
const enrollments = require("../../apps/api/services/operator/enrollments");
const connections = require("../../apps/api/services/operator/connections");

let owner;
let manager;
let viewer;
let workspaceId;
let otherWorkspaceId;
let sequence = 0;

async function createUser(label) {
  const result = await pool.query(
    `INSERT INTO users (email, display_name, auth_method, password_hash, email_verified)
     VALUES ($1, $2, 'local', 'x', TRUE) RETURNING id`,
    [`${label}-${crypto.randomUUID()}@example.test`, label],
  );
  return result.rows[0].id;
}

async function createWorkspace(createdBy) {
  const id = crypto.randomUUID();
  await pool.query("INSERT INTO workspaces (id, name, created_by) VALUES ($1, $2, $3)", [id, `ws-${++sequence}`, createdBy]);
  return id;
}

async function member(userId, workspace, role) {
  await pool.query(
    `INSERT INTO workspace_memberships (user_id, workspace_id, role) VALUES ($1, $2, $3)
     ON CONFLICT (user_id, workspace_id) DO UPDATE SET role = EXCLUDED.role`,
    [userId, workspace, role],
  );
}

const grantFor = (overrides = {}) =>
  enrollments.createGrant({
    workspaceId,
    userId: manager,
    name: `grant-${++sequence}`,
    scopes: ["mcp:identity:read", "mcp:certs:read"],
    roleCeiling: "workspace_manager",
    ...overrides,
  });

async function redeemInTransaction(rawGrant, options = {}) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await enrollments.redeemGrant({ client, rawGrant, ...options });
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

const rejectsWith = (promise, code) => assert.rejects(promise, (error) => error.code === code);
const rowOf = async (grantId) =>
  (await pool.query("SELECT * FROM operator_enrollment_grants WHERE id = $1", [grantId])).rows[0];
const countConnections = async (name) =>
  (await pool.query("SELECT COUNT(*)::int AS n FROM operator_connections WHERE workspace_id = $1 AND name = $2", [workspaceId, name])).rows[0].n;

describe("operator enrollment grants on PostgreSQL", { concurrency: false }, () => {
  before(async () => {
    assert.match(process.env.DB_NAME || "", /_mcp_test$/, "Use a disposable *_mcp_test database");
    owner = await createUser("owner");
    manager = await createUser("manager");
    viewer = await createUser("viewer");
    workspaceId = await createWorkspace(owner);
    otherWorkspaceId = await createWorkspace(owner);
    await member(manager, workspaceId, "workspace_manager");
    await member(viewer, workspaceId, "viewer");
  });

  after(async () => {
    await pool.end();
  });

  describe("creating a grant", () => {
    it("stores only a hash, never the secret, and returns the secret once", async () => {
      const { grant, plaintextGrant } = await grantFor();
      assert.match(plaintextGrant, /^ttopg_[a-f0-9]{16}_[a-f0-9]{64}$/);
      const row = await rowOf(grant.id);
      assert.equal(row.grant_hash, crypto.createHash("sha256").update(plaintextGrant).digest("hex"));
      assert.equal(row.grant_prefix, plaintextGrant.slice(0, 22));
      assert.ok(!JSON.stringify(row).includes(plaintextGrant.slice(23)), "the secret must not be stored");
      assert.equal(grant.status, "pending");
      assert.ok(!("grantHash" in grant) && !("plaintextGrant" in grant));
    });

    it("lives ten minutes by default, can only be shorter, and never exceeds fifteen", async () => {
      const now = new Date();
      const normal = await grantFor({ now });
      assert.equal(Date.parse(normal.grant.expiresAt) - now.getTime(), 10 * 60 * 1000);
      const shorter = await grantFor({ now, ttlMs: 60 * 1000 });
      assert.equal(Date.parse(shorter.grant.expiresAt) - now.getTime(), 60 * 1000);
      const clamped = await grantFor({ now, ttlMs: 24 * 60 * 60 * 1000 });
      assert.equal(Date.parse(clamped.grant.expiresAt) - now.getTime(), 15 * 60 * 1000);
    });

    it("refuses what could never be redeemed, instead of failing ten minutes later", async () => {
      await rejectsWith(grantFor({ userId: viewer, roleCeiling: "workspace_manager" }), connections.CONNECTION_FORBIDDEN);
      await rejectsWith(grantFor({ scopes: ["mcp:agents:read"], roleCeiling: "viewer" }), connections.CONNECTION_SCOPE_DENIED);
      await rejectsWith(grantFor({ scopes: ["mcp:ops:request"] }), connections.CONNECTION_SCOPE_INVALID);
      await rejectsWith(grantFor({ scopes: ["mcp:nonsense"] }), connections.CONNECTION_SCOPE_INVALID);
      await rejectsWith(grantFor({ scopes: [] }), connections.CONNECTION_SCOPE_INVALID);
      await rejectsWith(grantFor({ name: "" }), connections.CONNECTION_NAME_INVALID);
      await rejectsWith(grantFor({ name: `x ttopc_${"a".repeat(16)}_${"b".repeat(64)}` }), connections.CONNECTION_NAME_INVALID);
      await rejectsWith(grantFor({ userId: await createUser("stranger") }), connections.CONNECTION_FORBIDDEN);
      for (const days of [0, 91, 1.5, "abc"]) {
        await rejectsWith(grantFor({ connectionLifetimeDays: days }), enrollments.ENROLLMENT_LIFETIME_INVALID);
      }
    });

    it("cannot be inserted with a long life, even by hand", async () => {
      const { grant } = await grantFor();
      await assert.rejects(
        pool.query("UPDATE operator_enrollment_grants SET expires_at = created_at + INTERVAL '2 hours' WHERE id = $1", [grant.id]),
        /operator_enrollment_grants_expiry_check/,
      );
      await assert.rejects(
        pool.query("UPDATE operator_enrollment_grants SET status = 'redeemed' WHERE id = $1", [grant.id]),
        /operator_enrollment_grants_state_check/,
      );
    });
  });

  describe("redeeming a grant", () => {
    it("creates exactly the connection the grant describes, once, and spends the grant", async () => {
      const { grant, plaintextGrant } = await grantFor({ connectionLifetimeDays: 14, name: "laptop assistant" });
      const redeemed = await redeemInTransaction(plaintextGrant);
      const c = redeemed.connection;
      assert.equal(c.workspaceId, workspaceId);
      assert.equal(c.userId, manager);
      assert.equal(c.name, "laptop assistant");
      assert.deepEqual(c.scopes, ["mcp:identity:read", "mcp:certs:read"]);
      assert.equal(c.roleCeiling, "workspace_manager");
      const days = (Date.parse(c.expiresAt) - Date.now()) / 86400000;
      assert.ok(days > 13.99 && days <= 14, `lifetime ${days}`);
      assert.match(redeemed.plaintextCredential, /^ttopc_[a-f0-9]{16}_[a-f0-9]{64}$/);

      const after = await rowOf(grant.id);
      assert.equal(after.status, "redeemed");
      assert.equal(after.redeemed_connection_id, c.id);
      assert.ok(after.redeemed_at);

      const auth = await connections.authenticateCredential({ rawCredential: redeemed.plaintextCredential });
      assert.equal(auth.valid, true, "the issued credential works immediately");
      assert.equal(auth.connection.id, c.id);
    });

    it("lets exactly one of many simultaneous redemptions win", async () => {
      const { plaintextGrant } = await grantFor({ name: "race" });
      const results = await Promise.allSettled(Array.from({ length: 8 }, () => redeemInTransaction(plaintextGrant)));
      const won = results.filter((r) => r.status === "fulfilled");
      const lost = results.filter((r) => r.status === "rejected");
      assert.equal(won.length, 1, "exactly one redemption succeeds");
      assert.equal(lost.length, 7);
      for (const r of lost) assert.equal(r.reason.code, enrollments.ENROLLMENT_USED);
      assert.equal(await countConnections("race"), 1, "exactly one connection exists");
    });

    it("holds a second redemption at the grant itself until the first finishes", async () => {
      // Deterministic proof of the row lock. The race above is timing
      // dependent, and the guarded UPDATE would still give one winner without
      // the lock, but only by failing late with a different error. With the
      // lock, the second redemption waits at the grant and then reads it as spent.
      const { plaintextGrant } = await grantFor({ name: "held" });
      const first = await pool.connect();
      try {
        await first.query("BEGIN");
        await enrollments.redeemGrant({ client: first, rawGrant: plaintextGrant });

        let settled = false;
        const second = redeemInTransaction(plaintextGrant).then(
          () => { settled = true; return { ok: true }; },
          (error) => { settled = true; return { ok: false, code: error.code }; },
        );
        await new Promise((resolve) => setTimeout(resolve, 400));
        assert.equal(settled, false, "the second redemption must be waiting on the grant");
        assert.equal(await countConnections("held"), 0, "and must not have created anything while it waits");

        await first.query("COMMIT");
        const outcome = await second;
        assert.deepEqual(outcome, { ok: false, code: enrollments.ENROLLMENT_USED });
        assert.equal(await countConnections("held"), 1);
      } finally {
        await first.query("ROLLBACK").catch(() => {});
        first.release();
      }
    });

    it("never yields a second credential from a spent grant", async () => {
      const { plaintextGrant } = await grantFor({ name: "once" });
      await redeemInTransaction(plaintextGrant);
      await rejectsWith(redeemInTransaction(plaintextGrant), enrollments.ENROLLMENT_USED);
      assert.equal(await countConnections("once"), 1);
    });

    it("refuses an expired grant and creates nothing", async () => {
      const { grant, plaintextGrant } = await grantFor({ name: "stale" });
      await rejectsWith(
        redeemInTransaction(plaintextGrant, { now: new Date(Date.now() + 16 * 60 * 1000) }),
        enrollments.ENROLLMENT_EXPIRED,
      );
      assert.equal(await countConnections("stale"), 0);
      assert.equal((await rowOf(grant.id)).status, "pending", "an expired grant is not marked spent");
    });

    it("refuses a revoked grant, and revoking is idempotent", async () => {
      const { grant, plaintextGrant } = await grantFor({ name: "pulled" });
      const first = await enrollments.revokeGrant({ workspaceId, grantId: grant.id, revokedBy: manager });
      assert.equal(first.status, "revoked");
      const second = await enrollments.revokeGrant({ workspaceId, grantId: grant.id, revokedBy: owner });
      assert.equal(second.status, "revoked");
      assert.equal(second.revokedBy, manager, "a second revoke does not rewrite who revoked it");
      await rejectsWith(redeemInTransaction(plaintextGrant), enrollments.ENROLLMENT_REVOKED);
      assert.equal(await countConnections("pulled"), 0);
    });

    it("will not revoke a grant that is already spent", async () => {
      const { grant, plaintextGrant } = await grantFor({ name: "spent" });
      await redeemInTransaction(plaintextGrant);
      const after = await enrollments.revokeGrant({ workspaceId, grantId: grant.id, revokedBy: manager });
      assert.equal(after.status, "redeemed");
    });

    it("re-checks the issuer's authority at redemption and refuses if it was lost", async () => {
      const lost = await grantFor({ name: "demoted" });
      await member(manager, workspaceId, "viewer");
      try {
        await rejectsWith(redeemInTransaction(lost.plaintextGrant), enrollments.ENROLLMENT_AUTHORITY_LOST);
      } finally {
        await member(manager, workspaceId, "workspace_manager");
      }
      assert.equal(await countConnections("demoted"), 0);
      assert.equal((await rowOf(lost.grant.id)).status, "pending", "the grant is not consumed by a refused redemption");

      const gone = await grantFor({ name: "left" });
      await pool.query("DELETE FROM workspace_memberships WHERE user_id = $1 AND workspace_id = $2", [manager, workspaceId]);
      try {
        await rejectsWith(redeemInTransaction(gone.plaintextGrant), enrollments.ENROLLMENT_AUTHORITY_LOST);
      } finally {
        await member(manager, workspaceId, "workspace_manager");
      }
      assert.equal(await countConnections("left"), 0);
    });

    it("lets the issuer redeem again after authority is restored within the grant's life", async () => {
      const { plaintextGrant } = await grantFor({ name: "restored" });
      await member(manager, workspaceId, "viewer");
      await rejectsWith(redeemInTransaction(plaintextGrant), enrollments.ENROLLMENT_AUTHORITY_LOST);
      await member(manager, workspaceId, "workspace_manager");
      const redeemed = await redeemInTransaction(plaintextGrant);
      assert.equal(redeemed.connection.name, "restored");
    });

    it("gives the redeemer no say over user, workspace, scopes or ceiling", async () => {
      const { plaintextGrant } = await grantFor({ name: "fixed", scopes: ["mcp:certs:read"], roleCeiling: "viewer" });
      const redeemed = await redeemInTransaction(plaintextGrant, {
        userId: owner,
        workspaceId: otherWorkspaceId,
        scopes: ["mcp:agents:read"],
        roleCeiling: "admin",
        name: "hijacked",
      });
      assert.equal(redeemed.connection.userId, manager);
      assert.equal(redeemed.connection.workspaceId, workspaceId);
      assert.deepEqual(redeemed.connection.scopes, ["mcp:certs:read"]);
      assert.equal(redeemed.connection.roleCeiling, "viewer");
      assert.equal(redeemed.connection.name, "fixed");
    });

    it("does not extend a connection past the 90 day cap even at the longest grant", async () => {
      const { plaintextGrant } = await grantFor({ name: "longest", connectionLifetimeDays: 90 });
      const redeemed = await redeemInTransaction(plaintextGrant);
      const days = (Date.parse(redeemed.connection.expiresAt) - Date.now()) / 86400000;
      assert.ok(days > 89.9 && days < 90, `lifetime ${days}`);
    });

    it("answers every malformed or unknown code the same way", async () => {
      const { plaintextGrant } = await grantFor({ name: "probe" });
      const wrongSecret = `${plaintextGrant.slice(0, 23)}${"0".repeat(64)}`;
      const unknown = `ttopg_${"f".repeat(16)}_${"0".repeat(64)}`;
      const inputs = [wrongSecret, unknown, "", "garbage", `ttopc_${"a".repeat(16)}_${"b".repeat(64)}`, plaintextGrant.slice(0, -1), null, undefined];
      for (const input of inputs) {
        await assert.rejects(redeemInTransaction(input), (error) => {
          assert.equal(error.code, enrollments.ENROLLMENT_INVALID, String(input));
          assert.equal(error.message, "Enrollment code is not valid");
          return true;
        });
      }
      assert.equal(await countConnections("probe"), 0);
    });

    it("refuses to run outside a transaction", async () => {
      const { plaintextGrant } = await grantFor({ name: "notx" });
      await rejectsWith(enrollments.redeemGrant({ rawGrant: plaintextGrant }), enrollments.ENROLLMENT_INVALID);
    });

    it("does not let one workspace's grant surface in another's listing", async () => {
      const mine = await grantFor({ name: "listed" });
      const listedHere = await enrollments.listGrants({ workspaceId });
      assert.ok(listedHere.some((g) => g.id === mine.grant.id));
      const listedThere = await enrollments.listGrants({ workspaceId: otherWorkspaceId });
      assert.ok(!listedThere.some((g) => g.id === mine.grant.id));
      assert.equal(await enrollments.getGrant({ workspaceId: otherWorkspaceId, grantId: mine.grant.id }), null);
      const own = await enrollments.listGrants({ workspaceId, userId: owner });
      assert.ok(!own.some((g) => g.id === mine.grant.id), "filtering by user excludes other people's grants");
    });

    it("leaves no credential or grant secret anywhere in the database after redemption", async () => {
      const { plaintextGrant } = await grantFor({ name: "traceless" });
      const redeemed = await redeemInTransaction(plaintextGrant);
      const secrets = [plaintextGrant.slice(23), redeemed.plaintextCredential.slice(23)];
      for (const table of ["operator_enrollment_grants", "operator_connections", "audit_events"]) {
        const dump = JSON.stringify((await pool.query(`SELECT * FROM ${table}`)).rows);
        for (const secret of secrets) assert.ok(!dump.includes(secret), `${table} holds a secret`);
      }
    });
  });
});

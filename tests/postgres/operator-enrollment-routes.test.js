"use strict";

// Enrollment over HTTP on real PostgreSQL (ADR-0015 section 12). Covers the
// session-only management routes, the single unauthenticated redemption route,
// credential-family isolation in both directions, and the full journey from a
// signed-in person creating a grant to the credential reading data.

const { before, after, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const express = require("../../apps/api/node_modules/express");
const request = require("supertest");
const { pool } = require("../../apps/api/db/database");
const { loadWorkspace, requireWorkspaceMembership } = require("../../apps/api/services/rbac");
const { guardOperatorCredentials } = require("../../apps/api/middleware/operator-connection-auth");
const { isOperatorBearerCsrfExemptRequest } = require("../../apps/api/middleware/csrf-exempt");

let app;
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

function buildApp() {
  const server = express();
  server.use(express.json());
  // Mirrors apps/api/index.js, which mounts the guard on both prefixes.
  server.use("/api", guardOperatorCredentials);
  server.use("/auth", guardOperatorCredentials);
  server.post("/auth/login", (req, res) => res.status(200).json({ reached: true }));
  server.use(
    "/api/v1/workspaces/:id",
    (req, res, next) => {
      const id = req.headers["x-test-user"];
      if (!id) return res.status(401).json({ error: "Not authenticated" });
      req.user = { id: Number(id) };
      return next();
    },
    loadWorkspace,
    requireWorkspaceMembership,
  );
  server.use(require("../../apps/api/routes/operator"));
  return server;
}

const enrollBase = (ws = workspaceId) => `/api/v1/workspaces/${ws}/operator/enrollments`;
const as = (userId) => ({ "x-test-user": String(userId) });

async function issue(userId, body = {}, ws = workspaceId) {
  return request(app)
    .post(enrollBase(ws))
    .set(as(userId))
    .send({ name: `grant-${++sequence}`, scopes: ["mcp:identity:read", "mcp:certs:read"], roleCeiling: "workspace_manager", ...body });
}

const redeem = (grant) => request(app).post("/api/v1/operator/enroll/redeem").set("Authorization", `Bearer ${grant}`);

async function lastAudit(action) {
  return (
    await pool.query(
      "SELECT actor_user_id, subject_user_id, metadata FROM audit_events WHERE workspace_id = $1 AND action = $2 ORDER BY occurred_at DESC LIMIT 1",
      [workspaceId, action],
    )
  ).rows[0];
}

describe("operator enrollment over HTTP on PostgreSQL", { concurrency: false }, () => {
  before(async () => {
    assert.match(process.env.DB_NAME || "", /_mcp_test$/, "Use a disposable *_mcp_test database");
    process.env.MCP_OPERATOR_INTERFACE_ENABLED = "true";
    process.env.CERTOPS_ENABLED = "true";
    owner = await createUser("owner");
    manager = await createUser("manager");
    viewer = await createUser("viewer");
    workspaceId = await createWorkspace(owner);
    otherWorkspaceId = await createWorkspace(owner);
    await member(manager, workspaceId, "workspace_manager");
    await member(viewer, workspaceId, "viewer");
    app = buildApp();
  });

  after(async () => {
    delete process.env.MCP_OPERATOR_INTERFACE_ENABLED;
    delete process.env.CERTOPS_ENABLED;
    await pool.end();
  });

  describe("creating and managing grants (session only)", () => {
    it("is dark by default: every enrollment route answers 404 until the flag is on", async () => {
      delete process.env.MCP_OPERATOR_INTERFACE_ENABLED;
      try {
        assert.equal((await issue(manager)).status, 404);
        assert.equal((await request(app).get(enrollBase()).set(as(manager))).status, 404);
        assert.equal((await redeem(`ttopg_${"a".repeat(16)}_${"b".repeat(64)}`)).status, 404);
      } finally {
        process.env.MCP_OPERATOR_INTERFACE_ENABLED = "true";
      }
    });

    it("creates a grant, shows the secret once with no-store, and audits the human", async () => {
      const response = await issue(manager, { name: "laptop", connectionLifetimeDays: 7 });
      assert.equal(response.status, 201);
      assert.equal(response.headers["cache-control"], "no-store");
      assert.match(response.body.grant, /^ttopg_[a-f0-9]{16}_[a-f0-9]{64}$/);
      assert.equal(response.body.enrollment.status, "pending");
      assert.equal(response.body.enrollment.connectionLifetimeDays, 7);
      assert.equal(response.body.enrollment.userId, manager);
      assert.ok(!JSON.stringify(response.body.enrollment).includes(response.body.grant.slice(23)));
      const audit = await lastAudit("OPERATOR_ENROLLMENT_CREATED");
      assert.equal(audit.actor_user_id, manager);
      assert.equal(audit.metadata.enrollment_id, response.body.enrollment.id);
      assert.ok(!JSON.stringify(audit.metadata).includes(response.body.grant.slice(23)), "the secret is never audited");
    });

    it("needs a session, and refuses an operator credential or a grant in its place", async () => {
      assert.equal((await request(app).post(enrollBase()).send({})).status, 401);
      const connection = await request(app)
        .post(`/api/v1/workspaces/${workspaceId}/operator/connections`)
        .set(as(manager))
        .send({ name: "c", scopes: ["mcp:certs:read"], roleCeiling: "workspace_manager" });
      const viaCredential = await request(app)
        .post(enrollBase())
        .set("Authorization", `Bearer ${connection.body.credential}`)
        .send({ name: "x", scopes: ["mcp:certs:read"], roleCeiling: "viewer" });
      assert.equal(viaCredential.status, 403);
      assert.equal(viaCredential.body.code, "OPERATOR_CONNECTION_ROUTE_FORBIDDEN");
      const spare = await issue(manager);
      const viaGrant = await request(app)
        .post(enrollBase())
        .set("Authorization", `Bearer ${spare.body.grant}`)
        .send({ name: "x", scopes: ["mcp:certs:read"], roleCeiling: "viewer" });
      assert.equal(viaGrant.status, 403, "a grant is only ever accepted at the redeem route");
    });

    it("refuses authority the person does not hold, with the connection route's codes", async () => {
      const tooHigh = await issue(viewer, { roleCeiling: "workspace_manager" });
      assert.equal(tooHigh.status, 403);
      const reserved = await issue(manager, { scopes: ["mcp:ops:request"] });
      assert.equal(reserved.status, 400);
      assert.equal(reserved.body.code, "OPERATOR_CONNECTION_SCOPE_INVALID");
      const badDays = await issue(manager, { connectionLifetimeDays: 400 });
      assert.equal(badDays.status, 400);
      assert.equal(badDays.body.code, "OPERATOR_ENROLLMENT_LIFETIME_INVALID");
      const key = await issue(manager, { name: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----" });
      assert.ok([400, 422].includes(key.status));
    });

    it("lets a member see only their own grants, and an admin see everyone's", async () => {
      const mine = await issue(manager, { name: "mine" });
      const theirs = await issue(owner, { name: "theirs", roleCeiling: "admin", scopes: ["mcp:certs:read"] });
      const seenByManager = (await request(app).get(enrollBase()).set(as(manager))).body.items.map((g) => g.id);
      assert.ok(seenByManager.includes(mine.body.enrollment.id));
      assert.ok(!seenByManager.includes(theirs.body.enrollment.id));
      const seenByOwner = (await request(app).get(enrollBase()).set(as(owner))).body.items.map((g) => g.id);
      assert.ok(seenByOwner.includes(mine.body.enrollment.id) && seenByOwner.includes(theirs.body.enrollment.id));
      for (const item of (await request(app).get(enrollBase()).set(as(owner))).body.items) {
        assert.ok(!("grantHash" in item) && !("grant" in item) && !("grantPrefix" in item));
      }
    });

    it("lets the issuer or an admin revoke a pending grant, audits it once, and hides it from others", async () => {
      const created = await issue(manager, { name: "to-revoke" });
      const id = created.body.enrollment.id;
      const stranger = await request(app).post(`${enrollBase()}/${id}/revoke`).set(as(viewer));
      assert.equal(stranger.status, 404, "another member cannot see or revoke it");
      const revoked = await request(app).post(`${enrollBase()}/${id}/revoke`).set(as(manager));
      assert.equal(revoked.status, 200);
      assert.equal(revoked.body.enrollment.status, "revoked");
      await request(app).post(`${enrollBase()}/${id}/revoke`).set(as(owner));
      const events = await pool.query(
        "SELECT COUNT(*)::int AS n FROM audit_events WHERE workspace_id = $1 AND action = 'OPERATOR_ENROLLMENT_REVOKED' AND metadata->>'enrollment_id' = $2",
        [workspaceId, id],
      );
      assert.equal(events.rows[0].n, 1, "revoking twice is audited once");
      assert.equal((await redeem(created.body.grant)).status, 410);
      assert.equal((await request(app).post(`${enrollBase()}/not-a-uuid/revoke`).set(as(manager))).status, 404);
    });

    it("keeps workspaces apart", async () => {
      const created = await issue(manager, { name: "scoped" });
      const id = created.body.enrollment.id;
      await member(manager, otherWorkspaceId, "workspace_manager");
      const viaOther = await request(app).post(`${enrollBase(otherWorkspaceId)}/${id}/revoke`).set(as(manager));
      assert.equal(viaOther.status, 404);
      const listed = await request(app).get(enrollBase(otherWorkspaceId)).set(as(manager));
      assert.ok(!listed.body.items.some((g) => g.id === id));
    });
  });

  describe("redeeming a grant (the one route with no connection credential)", () => {
    it("returns the credential once with no-store, and audits the redemption against the issuer", async () => {
      const created = await issue(manager, { name: "redeem-me", connectionLifetimeDays: 14 });
      const response = await redeem(created.body.grant);
      assert.equal(response.status, 201);
      assert.equal(response.headers["cache-control"], "no-store");
      assert.match(response.body.credential, /^ttopc_[a-f0-9]{16}_[a-f0-9]{64}$/);
      assert.equal(response.body.connection.name, "redeem-me");
      assert.equal(response.body.connection.userId, manager);
      assert.equal(JSON.stringify(response.body.connection).includes(response.body.credential), false);

      const audit = await lastAudit("OPERATOR_ENROLLMENT_REDEEMED");
      assert.equal(audit.actor_user_id, null, "nobody is signed in, so no actor is invented");
      assert.equal(audit.subject_user_id, manager);
      assert.equal(audit.metadata.connection_id, response.body.connection.id);
      const dump = JSON.stringify((await pool.query("SELECT metadata FROM audit_events WHERE workspace_id = $1", [workspaceId])).rows);
      assert.ok(!dump.includes(response.body.credential.slice(23)) && !dump.includes(created.body.grant.slice(23)));

      const listed = await request(app).get(enrollBase()).set(as(manager));
      const row = listed.body.items.find((g) => g.id === created.body.enrollment.id);
      assert.equal(row.status, "redeemed");
      assert.equal(row.redeemedConnectionId, response.body.connection.id);
    });

    it("works end to end: the issued credential immediately reads the workspace it was granted", async () => {
      const created = await issue(manager, { name: "journey" });
      const redeemed = await redeem(created.body.grant);
      const whoami = await request(app).get("/api/v1/operator/whoami").set("Authorization", `Bearer ${redeemed.body.credential}`);
      assert.equal(whoami.status, 200);
      assert.equal(whoami.body.workspace.id, workspaceId);
      assert.equal(whoami.body.connection.id, redeemed.body.connection.id);
      assert.equal(whoami.body.role.effective, "workspace_manager");
    });

    it("spends a grant once: the second attempt is a 409 and creates nothing", async () => {
      const created = await issue(manager, { name: "single-use" });
      assert.equal((await redeem(created.body.grant)).status, 201);
      const again = await redeem(created.body.grant);
      assert.equal(again.status, 409);
      assert.equal(again.body.code, "OPERATOR_ENROLLMENT_USED");
      const n = await pool.query("SELECT COUNT(*)::int AS n FROM operator_connections WHERE workspace_id = $1 AND name = 'single-use'", [workspaceId]);
      assert.equal(n.rows[0].n, 1);
    });

    it("lets one of many simultaneous requests win", async () => {
      const created = await issue(manager, { name: "http-race" });
      const results = await Promise.all(Array.from({ length: 6 }, () => redeem(created.body.grant)));
      assert.equal(results.filter((r) => r.status === 201).length, 1);
      assert.equal(results.filter((r) => r.status === 409).length, 5);
      const n = await pool.query("SELECT COUNT(*)::int AS n FROM operator_connections WHERE workspace_id = $1 AND name = 'http-race'", [workspaceId]);
      assert.equal(n.rows[0].n, 1);
    });

    it("answers 410 for expired and revoked grants, and 403 when the issuer lost access", async () => {
      const expired = await issue(manager, { name: "expired" });
      await pool.query(
        "UPDATE operator_enrollment_grants SET created_at = NOW() - INTERVAL '20 minutes', expires_at = NOW() - INTERVAL '10 minutes' WHERE id = $1",
        [expired.body.enrollment.id],
      );
      const e = await redeem(expired.body.grant);
      assert.equal(e.status, 410);
      assert.equal(e.body.code, "OPERATOR_ENROLLMENT_EXPIRED");

      const demoted = await issue(manager, { name: "demoted" });
      await member(manager, workspaceId, "viewer");
      try {
        const d = await redeem(demoted.body.grant);
        assert.equal(d.status, 403);
        assert.equal(d.body.code, "OPERATOR_ENROLLMENT_AUTHORITY_LOST");
      } finally {
        await member(manager, workspaceId, "workspace_manager");
      }
    });

    it("gives a probe nothing: unknown, malformed and wrong-family bearers all look identical", async () => {
      const real = await issue(manager, { name: "probe-target" });
      const wrongSecret = `${real.body.grant.slice(0, 23)}${"0".repeat(64)}`;
      const bodies = new Set();
      for (const bearer of [wrongSecret, `ttopg_${"f".repeat(16)}_${"0".repeat(64)}`, "ttopg_short", "ttopg_"]) {
        const response = await redeem(bearer);
        assert.equal(response.status, 401, bearer);
        bodies.add(JSON.stringify(response.body));
      }
      assert.equal(bodies.size, 1, "every failure before the secret is proven reads the same");
      const none = await request(app).post("/api/v1/operator/enroll/redeem");
      assert.equal(none.status, 401);
      assert.equal(JSON.stringify(none.body), [...bodies][0]);
    });

    it("ignores anything the caller sends in the body: the grant fixes everything", async () => {
      const created = await issue(manager, { name: "fixed", scopes: ["mcp:certs:read"], roleCeiling: "viewer" });
      const response = await redeem(created.body.grant).send({
        workspaceId: otherWorkspaceId,
        userId: owner,
        scopes: ["mcp:agents:read"],
        roleCeiling: "admin",
        name: "hijacked",
      });
      assert.equal(response.status, 201);
      assert.equal(response.body.connection.userId, manager);
      assert.deepEqual(response.body.connection.scopes, ["mcp:certs:read"]);
      assert.equal(response.body.connection.roleCeiling, "viewer");
      assert.equal(response.body.connection.name, "fixed");
    });

    it("refuses a redemption that arrives with a cookie", async () => {
      const created = await issue(manager, { name: "cookie" });
      const response = await redeem(created.body.grant).set("Cookie", "sid=1");
      assert.equal(response.status, 401);
      const still = await redeem(created.body.grant);
      assert.equal(still.status, 201, "the refused attempt did not spend the grant");
    });

    it("only accepts POST", async () => {
      const created = await issue(manager, { name: "verbs" });
      for (const method of ["get", "put", "delete", "patch"]) {
        const response = await request(app)[method]("/api/v1/operator/enroll/redeem").set("Authorization", `Bearer ${created.body.grant}`);
        assert.ok([403, 404, 405].includes(response.status), `${method} -> ${response.status}`);
      }
      assert.equal((await redeem(created.body.grant)).status, 201, "none of those spent the grant");
    });
  });

  describe("credential families stay apart", () => {
    it("refuses an internal worker call on every management route, since it has no user", async () => {
      // A worker call authenticates without a person. Creating a grant or a
      // connection must always be a person's act.
      const workerApp = express();
      workerApp.use(express.json());
      workerApp.use("/api/v1/workspaces/:id", (req, res, next) => {
        req.isWorkerCall = true;
        req.user = { id: Number(req.headers["x-test-user"]) };
        return next();
      }, loadWorkspace, requireWorkspaceMembership);
      workerApp.use(require("../../apps/api/routes/operator"));
      const body = { name: "w", scopes: ["mcp:certs:read"], roleCeiling: "viewer" };
      for (const [method, route] of [
        ["post", enrollBase()],
        ["get", enrollBase()],
        ["post", `${enrollBase()}/${crypto.randomUUID()}/revoke`],
        ["post", `/api/v1/workspaces/${workspaceId}/operator/connections`],
        ["get", `/api/v1/workspaces/${workspaceId}/operator/connections`],
      ]) {
        const response = await request(workerApp)[method](route).set(as(manager)).send(body);
        assert.equal(response.status, 403, `${method} ${route} -> ${response.status}`);
        assert.equal(response.body.code, "INSUFFICIENT_ROLE");
      }
    });

    it("never accepts a grant anywhere except the redeem route", async () => {
      const created = await issue(manager, { name: "family" });
      const bearer = { Authorization: `Bearer ${created.body.grant}` };
      for (const [method, route] of [
        ["get", "/api/v1/operator/whoami"],
        ["get", "/api/v1/operator/certificates"],
        ["get", "/api/v1/operator/jobs"],
        ["get", "/api/v1/workspaces"],
        ["get", `/api/v1/workspaces/${workspaceId}/operator/connections`],
        ["post", `/api/v1/workspaces/${workspaceId}/operator/connections`],
        ["post", "/api/v1/operator/enroll/redeem/extra"],
        ["post", "/api/v1/operator/enroll"],
        ["post", "/auth/login"],
      ]) {
        const response = await request(app)[method](route).set(bearer).send({});
        assert.equal(response.status, 403, `${method} ${route} -> ${response.status}`);
        assert.equal(response.body.code, "OPERATOR_CONNECTION_ROUTE_FORBIDDEN");
      }
      assert.equal((await redeem(created.body.grant)).status, 201, "all of that left the grant intact");
    });

    it("never accepts a connection credential at the redeem route, or on a read as a grant", async () => {
      const created = await issue(manager, { name: "reverse" });
      const connection = await redeem(created.body.grant);
      const asGrant = await request(app).post("/api/v1/operator/enroll/redeem").set("Authorization", `Bearer ${connection.body.credential}`);
      assert.equal(asGrant.status, 401);
      const asCredentialReadingWithGrantShape = await request(app)
        .get("/api/v1/operator/whoami")
        .set("Authorization", `Bearer ttopg_${"a".repeat(16)}_${"b".repeat(64)}`);
      assert.equal(asCredentialReadingWithGrantShape.status, 403);
    });

    it("does not let an agent bootstrap token or any other family reach the redeem route", async () => {
      for (const prefix of ["ttboot_", "ttagent_", "ttx_"]) {
        const response = await redeem(`${prefix}${"a".repeat(16)}_${"b".repeat(64)}`);
        assert.equal(response.status, 401, prefix);
      }
    });
  });

  describe("CSRF exemption", () => {
    const fakeRequest = (headers, method = "POST") => ({ method, headers });
    const grant = `Bearer ttopg_${"a".repeat(16)}_${"b".repeat(64)}`;
    const credential = `Bearer ttopc_${"a".repeat(16)}_${"b".repeat(64)}`;

    it("exempts a grant bearer at exactly the redeem route and nowhere else", () => {
      assert.equal(isOperatorBearerCsrfExemptRequest("/api/v1/operator/enroll/redeem", fakeRequest({ authorization: grant })), true);
      assert.equal(isOperatorBearerCsrfExemptRequest("/v1/operator/enroll/redeem", fakeRequest({ authorization: grant })), true);
      for (const path of [
        "/api/v1/operator/enroll/redeem/x",
        "/api/v1/operator/enroll",
        "/api/v1/operator/whoami",
        "/api/v1/workspaces/x/operator/enrollments",
        "/api/v1/operator/enroll/redeem/../whoami",
        "/api/v1/operator/ENROLL/redeem2",
      ]) {
        assert.equal(isOperatorBearerCsrfExemptRequest(path, fakeRequest({ authorization: grant })), false, path);
      }
    });

    it("never exempts a request that carries a cookie, a session or the wrong method", () => {
      assert.equal(isOperatorBearerCsrfExemptRequest("/api/v1/operator/enroll/redeem", fakeRequest({ authorization: grant, cookie: "sid=1" })), false);
      assert.equal(isOperatorBearerCsrfExemptRequest("/api/v1/operator/enroll/redeem", { ...fakeRequest({ authorization: grant }), cookies: { sid: "1" } }), false);
      assert.equal(isOperatorBearerCsrfExemptRequest("/api/v1/operator/enroll/redeem", fakeRequest({ authorization: grant }, "GET")), false);
      assert.equal(isOperatorBearerCsrfExemptRequest("/api/v1/operator/enroll/redeem", fakeRequest({})), false);
      assert.equal(isOperatorBearerCsrfExemptRequest("/api/v1/operator/enroll/redeem", fakeRequest({ authorization: credential })), false, "a connection credential is not a grant");
    });

    it("keeps the connection-credential exemption intact, and does not extend it to grants elsewhere", () => {
      assert.equal(isOperatorBearerCsrfExemptRequest("/api/v1/operator/certificates", fakeRequest({ authorization: credential })), true);
      assert.equal(isOperatorBearerCsrfExemptRequest("/api/v1/operator/certificates", fakeRequest({ authorization: grant })), false);
    });
  });

  // Tests are appended below.
});

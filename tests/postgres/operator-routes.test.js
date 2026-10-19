"use strict";

// HTTP-level proof for the operator interface on real PostgreSQL. A thin
// stand-in plays the session layer (it only sets req.user from a header); the
// real loadWorkspace, requireWorkspaceMembership, early guard, rollout gate,
// routes and database are exercised.

const { before, after, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const express = require("../../apps/api/node_modules/express");
const request = require("supertest");
const Ajv = require("ajv");
const addFormats = require("ajv-formats");
const { pool } = require("../../apps/api/db/database");
const { loadWorkspace, requireWorkspaceMembership } = require("../../apps/api/services/rbac");
const { guardOperatorCredentials } = require("../../apps/api/middleware/operator-connection-auth");

const contractsDir = path.resolve(__dirname, "../../packages/contracts/mcp");
const readJson = (name) => JSON.parse(fs.readFileSync(path.join(contractsDir, name), "utf8"));
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
ajv.addSchema(readJson("mcp-common.schema.json"));
const readTools = readJson("mcp-read-tools.schema.json");
ajv.addSchema(readTools);
const validateWhoami = ajv.getSchema(`${readTools.$id}#/definitions/tt_whoami_output`);

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
  server.use("/api", guardOperatorCredentials);
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

const base = () => `/api/v1/workspaces/${workspaceId}/operator/connections`;
const as = (userId) => ({ "x-test-user": String(userId) });

async function createConnection(userId, body = {}) {
  const response = await request(app)
    .post(base())
    .set(as(userId))
    .send({ name: `c-${++sequence}`, scopes: ["mcp:identity:read", "mcp:certs:read"], roleCeiling: "workspace_manager", ...body });
  return response;
}

async function lastAudit(action) {
  const result = await pool.query(
    "SELECT actor_user_id, subject_user_id, metadata FROM audit_events WHERE workspace_id = $1 AND action = $2 ORDER BY occurred_at DESC LIMIT 1",
    [workspaceId, action],
  );
  return result.rows[0];
}

describe("operator interface HTTP routes on PostgreSQL", { concurrency: false }, () => {
  before(async () => {
    assert.match(process.env.DB_NAME || "", /_mcp_test$/, "Use a disposable *_mcp_test database");
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
    await pool.end();
  });

  it("is dark by default: every operator route answers 404 until the flag is on", async () => {
    delete process.env.MCP_OPERATOR_INTERFACE_ENABLED;
    const list = await request(app).get(base()).set(as(manager));
    assert.equal(list.status, 404);
    assert.equal(list.body.code, "OPERATOR_INTERFACE_DISABLED");
    const created = await createConnection(manager);
    assert.equal(created.status, 404);
    const whoami = await request(app).get("/api/v1/operator/whoami");
    assert.equal(whoami.status, 404);
    process.env.MCP_OPERATOR_INTERFACE_ENABLED = "true";
  });

  it("creates a connection, shows the credential once, and audits the human", async () => {
    const response = await createConnection(manager);
    assert.equal(response.status, 201);
    assert.equal(response.headers["cache-control"], "no-store");
    assert.match(response.body.credential, /^ttopc_[a-f0-9]{16}_[a-f0-9]{64}$/);
    assert.equal(response.body.connection.userId, manager);
    assert.equal(JSON.stringify(response.body.connection).includes(response.body.credential), false);
    assert.ok(!("credentialHash" in response.body.connection));

    const audit = await lastAudit("OPERATOR_CONNECTION_CREATED");
    assert.equal(audit.actor_user_id, manager);
    assert.equal(audit.subject_user_id, manager);
    assert.equal(audit.metadata.connection_id, response.body.connection.id);
    assert.equal(JSON.stringify(audit.metadata).includes(response.body.credential), false);

    const listed = await request(app).get(base()).set(as(manager));
    assert.equal(JSON.stringify(listed.body).includes(response.body.credential), false);
  });

  it("answers whoami from the connection and satisfies the published contract", async () => {
    const { body } = await createConnection(manager);
    const response = await request(app).get("/api/v1/operator/whoami").set("Authorization", `Bearer ${body.credential}`);
    assert.equal(response.status, 200);
    assert.equal(validateWhoami(response.body), true, JSON.stringify(validateWhoami.errors));
    assert.equal(response.body.workspace.id, workspaceId);
    assert.equal(response.body.role.effective, "workspace_manager");
    assert.equal(response.body.certops.mcpWritesEnabled, false);
  });

  it("takes the workspace from the connection and ignores every attempt to name another", async () => {
    const { body } = await createConnection(manager);
    const response = await request(app)
      .get(`/api/v1/operator/whoami?workspace_id=${otherWorkspaceId}&workspaceId=${otherWorkspaceId}`)
      .set("Authorization", `Bearer ${body.credential}`)
      .set("X-Workspace-Id", otherWorkspaceId);
    assert.equal(response.status, 200);
    assert.equal(response.body.workspace.id, workspaceId);
  });

  it("refuses whoami without a credential, with a bad one, or with a session next to it", async () => {
    const { body } = await createConnection(manager);
    assert.equal((await request(app).get("/api/v1/operator/whoami")).status, 401);
    const bad = await request(app).get("/api/v1/operator/whoami").set("Authorization", `Bearer ttopc_${"0".repeat(16)}_${"0".repeat(64)}`);
    assert.equal(bad.status, 401);
    const mixed = await request(app)
      .get("/api/v1/operator/whoami")
      .set("Authorization", `Bearer ${body.credential}`)
      .set("Cookie", "connect.sid=abc");
    assert.equal(mixed.status, 401);
    assert.equal(mixed.body.code, "OPERATOR_CONNECTION_SESSION_FORBIDDEN");
  });

  it("denies a scope the connection does not hold", async () => {
    const { body } = await createConnection(manager, { scopes: ["mcp:certs:read"] });
    const response = await request(app).get("/api/v1/operator/whoami").set("Authorization", `Bearer ${body.credential}`);
    assert.equal(response.status, 403);
    assert.equal(response.body.code, "OPERATOR_CONNECTION_SCOPE_DENIED");
  });

  it("keeps a connection credential off the session-only management routes", async () => {
    const { body } = await createConnection(manager);
    for (const [method, route] of [
      ["get", base()],
      ["post", base()],
      ["post", `${base()}/${crypto.randomUUID()}/revoke`],
      ["post", `${base()}/${crypto.randomUUID()}/rotate`],
    ]) {
      const response = await request(app)[method](route).set("Authorization", `Bearer ${body.credential}`).send({});
      assert.equal(response.status, 403, `${method} ${route}`);
      assert.equal(response.body.code, "OPERATOR_CONNECTION_ROUTE_FORBIDDEN");
    }
  });

  it("reflects a demotion and a pause in the very next whoami", async () => {
    const { body } = await createConnection(manager);
    const call = () => request(app).get("/api/v1/operator/whoami").set("Authorization", `Bearer ${body.credential}`);
    assert.equal((await call()).body.role.effective, "workspace_manager");
    await member(manager, workspaceId, "viewer");
    const demoted = await call();
    assert.equal(demoted.body.role.current, "viewer");
    assert.equal(demoted.body.role.effective, "viewer");
    await member(manager, workspaceId, "workspace_manager");
    await pool.query("UPDATE workspaces SET certops_paused = TRUE WHERE id = $1", [workspaceId]);
    assert.equal((await call()).body.certops.paused, true);
    await pool.query("UPDATE workspaces SET certops_paused = FALSE WHERE id = $1", [workspaceId]);
  });

  it("rejects bad requests with stable codes and never stores a secret", async () => {
    const reserved = await createConnection(manager, { scopes: ["mcp:lifecycle:request"] });
    assert.equal(reserved.status, 400);
    assert.equal(reserved.body.code, "OPERATOR_CONNECTION_SCOPE_INVALID");
    const unknown = await createConnection(manager, { scopes: ["mcp:everything"] });
    assert.equal(unknown.status, 400);
    const ceiling = await createConnection(manager, { roleCeiling: "root" });
    assert.equal(ceiling.body.code, "OPERATOR_CONNECTION_ROLE_CEILING_INVALID");
    const tooHigh = await createConnection(viewer, { roleCeiling: "workspace_manager", scopes: ["mcp:certs:read"] });
    assert.equal(tooHigh.status, 403);
    const expiry = await createConnection(manager, { expiresAt: new Date(Date.now() + 91 * 86400000).toISOString() });
    assert.equal(expiry.body.code, "OPERATOR_CONNECTION_EXPIRY_INVALID");
    const named = await createConnection(manager, { name: `ttopc_${"0123456789abcdef"}_${"a".repeat(64)}` });
    assert.equal(named.status, 400);
    const pem = await createConnection(manager, {
      name: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
    });
    assert.equal(pem.status, 422);
    assert.equal((await request(app).post(base()).send({})).status, 401);
  });

  it("lets a member see their own connections and an admin see everyone's", async () => {
    const mine = await createConnection(viewer, { roleCeiling: "viewer", scopes: ["mcp:certs:read"] });
    const theirs = await createConnection(manager);
    const asViewer = await request(app).get(base()).set(as(viewer));
    const viewerIds = asViewer.body.items.map((item) => item.id);
    assert.ok(viewerIds.includes(mine.body.connection.id));
    assert.ok(!viewerIds.includes(theirs.body.connection.id));
    const asAdmin = await request(app).get(base()).set(as(owner));
    const adminIds = asAdmin.body.items.map((item) => item.id);
    assert.ok(adminIds.includes(mine.body.connection.id) && adminIds.includes(theirs.body.connection.id));
  });

  it("limits revocation to the owner or an admin, hides others, and kills the credential", async () => {
    const { body } = await createConnection(manager);
    const stranger = await request(app).post(`${base()}/${body.connection.id}/revoke`).set(as(viewer));
    assert.equal(stranger.status, 404);
    assert.equal((await request(app).get("/api/v1/operator/whoami").set("Authorization", `Bearer ${body.credential}`)).status, 200);

    const byAdmin = await request(app).post(`${base()}/${body.connection.id}/revoke`).set(as(owner));
    assert.equal(byAdmin.status, 200);
    assert.equal(byAdmin.body.connection.status, "revoked");
    assert.equal((await request(app).get("/api/v1/operator/whoami").set("Authorization", `Bearer ${body.credential}`)).status, 401);

    const audit = await lastAudit("OPERATOR_CONNECTION_REVOKED");
    assert.equal(audit.actor_user_id, owner);
    assert.equal(audit.subject_user_id, manager);

    const again = await request(app).post(`${base()}/${body.connection.id}/revoke`).set(as(owner));
    assert.equal(again.status, 200);
  });

  it("lets only the owner rotate, replaces the secret, and keeps the connection", async () => {
    const { body } = await createConnection(manager);
    const byAdmin = await request(app).post(`${base()}/${body.connection.id}/rotate`).set(as(owner));
    assert.equal(byAdmin.status, 404, "an admin must not be handed another user's new secret");

    const rotated = await request(app).post(`${base()}/${body.connection.id}/rotate`).set(as(manager));
    assert.equal(rotated.status, 200);
    assert.equal(rotated.headers["cache-control"], "no-store");
    assert.equal(rotated.body.connection.id, body.connection.id);
    assert.notEqual(rotated.body.credential, body.credential);
    assert.equal((await request(app).get("/api/v1/operator/whoami").set("Authorization", `Bearer ${body.credential}`)).status, 401);
    assert.equal((await request(app).get("/api/v1/operator/whoami").set("Authorization", `Bearer ${rotated.body.credential}`)).status, 200);
    const audit = await lastAudit("OPERATOR_CONNECTION_CREDENTIAL_ROTATED");
    assert.equal(audit.actor_user_id, manager);
    assert.equal(JSON.stringify(audit.metadata).includes(rotated.body.credential), false);

    await request(app).post(`${base()}/${body.connection.id}/revoke`).set(as(manager));
    const afterRevoke = await request(app).post(`${base()}/${body.connection.id}/rotate`).set(as(manager));
    assert.equal(afterRevoke.status, 409);
  });

  it("rejects malformed connection ids without touching the database", async () => {
    for (const action of ["revoke", "rotate"]) {
      const response = await request(app).post(`${base()}/not-a-uuid/${action}`).set(as(manager)).send({});
      assert.equal(response.status, 404);
    }
  });

  it("keeps workspaces apart: a member of one workspace cannot manage another's connections", async () => {
    const response = await request(app)
      .get(`/api/v1/workspaces/${otherWorkspaceId}/operator/connections`)
      .set(as(manager));
    assert.ok([403, 404].includes(response.status), `status ${response.status}`);
    const created = await request(app)
      .post(`/api/v1/workspaces/${otherWorkspaceId}/operator/connections`)
      .set(as(manager))
      .send({ name: "x", scopes: ["mcp:certs:read"], roleCeiling: "viewer" });
    assert.ok([403, 404].includes(created.status), `status ${created.status}`);
  });
});

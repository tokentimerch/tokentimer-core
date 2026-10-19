"use strict";

// Renew requests from an operator connection, on real PostgreSQL (ADR-0015).
//
// The properties under test are the ones that make an assistant's write safe:
// it can only ask, a different person must approve, a revocation or a pause
// always wins a race, a retry never repeats work, and nothing here can be made
// to skip a gate by what the caller sends.

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
const connections = require("../../apps/api/services/operator/connections");
const approvals = require("../../apps/api/services/certops/jobApprovals");
const { loadWorkspace, requireWorkspaceMembership } = require("../../apps/api/services/rbac");
const { guardOperatorCredentials } = require("../../apps/api/middleware/operator-connection-auth");

const contractsDir = path.resolve(__dirname, "../../packages/contracts/mcp");
const readJson = (name) => JSON.parse(fs.readFileSync(path.join(contractsDir, name), "utf8"));
const renewSchema = readJson("mcp-renew-tools.schema.json");
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
ajv.addSchema(readJson("mcp-common.schema.json"));
ajv.addSchema(renewSchema);
const valid = (name) => ajv.getSchema(`${renewSchema.$id}#/definitions/${name}`);

const WRITE = ["mcp:identity:read", "mcp:certs:read", "mcp:requests:read", "mcp:renew:request"];

let app;
let owner;
let manager;
let approver;
let viewer;
let workspaceId;
let otherWorkspaceId;
let certA;
let sequence = 0;
let credential;
let connectionId;

const profile = () => ({
  schemaVersion: 1,
  profileId: "profile-1",
  profileName: "web-tls",
  sanPolicy: { mode: "exact", sans: ["app.example.com"], allowWildcards: false },
  keyAlgorithm: "rsa",
  keySize: 2048,
  keyRotationPolicy: { rotateOnRenew: true },
  preferredChain: null,
  ca: { endpoint: "https://acme-v02.api.letsencrypt.org/directory", accountRef: null, eabRef: null },
  acme: { kind: "certbot", commandRef: "acme-renew-default" },
  dns: { provider: "cloudflare", zone: "example.com" },
  deploymentTargets: [{ type: "endpoint", reference: "host/web", certPath: "/etc/ssl/certs/app.pem", reloadService: "nginx" }],
  target: { type: "endpoint", reference: "host/web", certPath: "/etc/ssl/certs/app.pem" },
  verification: { host: "app.example.com", port: 443, requireMatch: true },
});

async function createUser(label) {
  const result = await pool.query(
    `INSERT INTO users (email, display_name, auth_method, password_hash, email_verified) VALUES ($1, $2, 'local', 'x', TRUE) RETURNING id`,
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

async function seedRenewable(workspace, label) {
  const fingerprint = crypto.createHash("sha256").update(`renew-${label}`).digest("hex");
  const profileRow = await pool.query(
    `INSERT INTO certificate_profiles (workspace_id, name, status, source, source_ref, issuer_id, renew_before_days, key_mode, public_metadata, created_by)
     VALUES ($1, $2, 'active', 'manual', $3, NULL, 30, 'agent-local', $4::jsonb, $5) RETURNING id`,
    [workspace, `profile-${label}`, `ref:${label}`, JSON.stringify({ renewalProfile: profile() }), owner],
  );
  const cert = await pool.query(
    `INSERT INTO managed_certificates
       (workspace_id, source, source_ref, fingerprint_sha256, common_name, issuer, not_after, key_mode, key_reference, subject_alt_names, profile_id)
     VALUES ($1, 'agent_filesystem', 'file:///SENTINEL_SOURCE/x.pem', $2, 'app.example.com', 'CN=Example CA', NOW() + INTERVAL '20 days',
             'agent-local', 'vault://SENTINEL_KEY_REF', ARRAY['app.example.com']::text[], $3) RETURNING id`,
    [workspace, fingerprint, profileRow.rows[0].id],
  );
  const identity = await pool.query(
    "SELECT id FROM certops_certificate_identities WHERE workspace_id = $1 AND fingerprint_sha256 = $2",
    [workspace, fingerprint],
  );
  return { managedId: cert.rows[0].id, identityId: identity.rows[0].id, fingerprint, profileId: profileRow.rows[0].id };
}

function buildApp() {
  const server = express();
  server.use(express.json());
  server.use("/api", guardOperatorCredentials);
  server.use("/auth", guardOperatorCredentials);
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

const as = (userId) => ({ "x-test-user": String(userId) });
const post = (route, body, who = credential) =>
  request(app).post(route).set("Authorization", `Bearer ${who}`).send(body);
const get = (route, who = credential) => request(app).get(route).set("Authorization", `Bearer ${who}`);

async function newConnection(userId, scopes = WRITE, roleCeiling = "workspace_manager") {
  const created = await connections.createConnection({ workspaceId, userId, name: `c-${++sequence}`, scopes, roleCeiling });
  return { credential: created.plaintextCredential, id: created.connection.id };
}

const preview = (identityId = certA.identityId, who = credential) => post("/api/v1/operator/renewals/preview", { identityId }, who);
const submit = (plan, requestId = crypto.randomUUID(), who = credential) =>
  post("/api/v1/operator/renewals/requests", { planId: plan.planId, planHash: plan.planHash, requestId }, who);

async function jobRow(jobId) {
  return (await pool.query("SELECT * FROM certificate_jobs WHERE id = $1", [jobId])).rows[0];
}
async function countJobs(subjectId) {
  return (await pool.query("SELECT COUNT(*)::int AS n FROM certificate_jobs WHERE workspace_id = $1 AND subject_id = $2 AND operation = 'renew'", [workspaceId, String(subjectId)])).rows[0].n;
}
// The per-CA capacity gate counts renewals in flight, which is shared state.
// Tests that need room start from nothing in flight, and the one that tests the
// gate itself fills it deliberately.
async function clearInFlight() {
  await pool.query(
    `UPDATE certificate_jobs SET status = 'cancelled', canceled_at = NOW(), updated_at = NOW()
      WHERE workspace_id = $1 AND operation = 'renew' AND status IN ('pending_approval','approved','pending','claimed','running')`,
    [workspaceId],
  );
}
async function setWorkspaceWrites(value) {
  await pool.query("UPDATE workspaces SET operator_writes_enabled = $2 WHERE id = $1", [workspaceId, value]);
}

describe("operator renew requests on PostgreSQL", { concurrency: false }, () => {
  before(async () => {
    assert.match(process.env.DB_NAME || "", /_mcp_test$/, "Use a disposable *_mcp_test database");
    process.env.MCP_OPERATOR_INTERFACE_ENABLED = "true";
    process.env.MCP_OPERATOR_WRITES_ENABLED = "true";
    process.env.CERTOPS_ENABLED = "true";
    owner = await createUser("owner");
    manager = await createUser("manager");
    approver = await createUser("approver");
    viewer = await createUser("viewer");
    workspaceId = await createWorkspace(owner);
    otherWorkspaceId = await createWorkspace(owner);
    await member(manager, workspaceId, "workspace_manager");
    await member(approver, workspaceId, "workspace_manager");
    await member(viewer, workspaceId, "viewer");
    certA = await seedRenewable(workspaceId, "a");
    await setWorkspaceWrites(true);
    app = buildApp();
    ({ credential, id: connectionId } = await newConnection(manager));
  });

  after(async () => {
    delete process.env.MCP_OPERATOR_INTERFACE_ENABLED;
    delete process.env.MCP_OPERATOR_WRITES_ENABLED;
    delete process.env.CERTOPS_ENABLED;
    await pool.end();
  });

  describe("the three write gates", () => {
    it("refuses every write route until the instance flag, the workspace setting and the scope are all on", async () => {
      const routes = [
        ["/api/v1/operator/renewals/preview", { identityId: certA.identityId }],
        ["/api/v1/operator/renewals/requests", { planId: crypto.randomUUID(), planHash: "a".repeat(64), requestId: crypto.randomUUID() }],
      ];
      const attempt = async () => {
        const out = [];
        for (const [route, body] of routes) out.push((await post(route, body)).body.code);
        return out;
      };
      try {
        delete process.env.MCP_OPERATOR_WRITES_ENABLED;
        assert.deepEqual(await attempt(), ["OPERATOR_WRITES_DISABLED", "OPERATOR_WRITES_DISABLED"], "instance flag off");
        process.env.MCP_OPERATOR_WRITES_ENABLED = "true";
        await setWorkspaceWrites(false);
        assert.deepEqual(await attempt(), ["OPERATOR_WRITES_DISABLED", "OPERATOR_WRITES_DISABLED"], "workspace setting off");
        await setWorkspaceWrites(true);
        const noScope = await newConnection(manager, ["mcp:identity:read", "mcp:certs:read"]);
        for (const [route, body] of routes) {
          const response = await post(route, body, noScope.credential);
          assert.equal(response.status, 403);
          assert.equal(response.body.code, "OPERATOR_CONNECTION_SCOPE_DENIED");
        }
      } finally {
        process.env.MCP_OPERATOR_WRITES_ENABLED = "true";
        await setWorkspaceWrites(true);
      }
      assert.equal((await preview()).status, 201, "and with all three on, it works");
    });

    it("is off by default for a new workspace and for a new instance", async () => {
      const fresh = await createWorkspace(owner);
      const row = await pool.query("SELECT operator_writes_enabled FROM workspaces WHERE id = $1", [fresh]);
      assert.equal(row.rows[0].operator_writes_enabled, false);
    });

    it("reports the real write state in whoami", async () => {
      assert.equal((await get("/api/v1/operator/whoami")).body.certops.mcpWritesEnabled, true);
      await setWorkspaceWrites(false);
      try {
        assert.equal((await get("/api/v1/operator/whoami")).body.certops.mcpWritesEnabled, false);
      } finally {
        await setWorkspaceWrites(true);
      }
    });

    it("never lets a connection change the workspace setting, only an admin with a session", async () => {
      const viaConnection = await request(app)
        .put(`/api/v1/workspaces/${workspaceId}/operator/settings`)
        .set("Authorization", `Bearer ${credential}`)
        .send({ writesEnabled: true });
      assert.equal(viaConnection.status, 403);
      const asManager = await request(app).put(`/api/v1/workspaces/${workspaceId}/operator/settings`).set(as(manager)).send({ writesEnabled: false });
      assert.equal(asManager.status, 403, "a manager is not enough");
      const asOwner = await request(app).put(`/api/v1/workspaces/${workspaceId}/operator/settings`).set(as(owner)).send({ writesEnabled: false });
      assert.equal(asOwner.status, 200);
      assert.equal((await request(app).get(`/api/v1/workspaces/${workspaceId}/operator/settings`).set(as(manager))).body.writesEnabled, false);
      await request(app).put(`/api/v1/workspaces/${workspaceId}/operator/settings`).set(as(owner)).send({ writesEnabled: true });
      const audit = await pool.query("SELECT COUNT(*)::int AS n FROM audit_events WHERE workspace_id = $1 AND action IN ('OPERATOR_WRITES_ENABLED','OPERATOR_WRITES_DISABLED')", [workspaceId]);
      assert.equal(audit.rows[0].n, 2, "both changes are audited");
      for (const body of [{}, { writesEnabled: "yes" }, { writesEnabled: true, extra: 1 }]) {
        assert.equal((await request(app).put(`/api/v1/workspaces/${workspaceId}/operator/settings`).set(as(owner)).send(body)).status, 400);
      }
    });
  });

  describe("previewing", () => {
    before(clearInFlight);
    it("returns a plan that matches the contract, and creates no job and contacts nothing", async () => {
      const before = await countJobs(certA.managedId);
      const response = await preview();
      assert.equal(response.status, 201);
      assert.equal(response.headers["cache-control"], "no-store");
      const check = valid("tt_preview_renew_output");
      assert.equal(check(response.body), true, JSON.stringify(check.errors));
      assert.equal(response.body.effect.issuerEffect, "contacts_issuer");
      assert.equal(response.body.effect.standingRenewal.createsAutomaticRenewal, false);
      assert.equal(response.body.effect.approvalAuthority, "other_manager_or_admin");
      assert.equal(await countJobs(certA.managedId), before, "a preview never creates a job");
      const text = JSON.stringify(response.body);
      for (const hidden of ["SENTINEL", "vault://", "file://", "/etc/ssl"]) assert.ok(!text.includes(hidden), hidden);
    });

    it("expires in ten minutes at most, and is stored with the facts it was computed from", async () => {
      const response = await preview();
      const ttl = Date.parse(response.body.expiresAt) - Date.now();
      assert.ok(ttl > 9 * 60 * 1000 && ttl <= 10 * 60 * 1000, `ttl ${ttl}`);
      const row = (await pool.query("SELECT * FROM operator_action_plans WHERE id = $1", [response.body.planId])).rows[0];
      assert.equal(row.connection_id, connectionId);
      assert.equal(row.bound_fingerprint_sha256, certA.fingerprint);
      assert.equal(row.bound_profile_id, certA.profileId);
      await assert.rejects(pool.query("UPDATE operator_action_plans SET expires_at = created_at + INTERVAL '2 hours' WHERE id = $1", [row.id]), /expiry_check/);
    });

    it("refuses what cannot be renewed, with a reason that names no internal detail", async () => {
      const unmanaged = crypto.createHash("sha256").update("unmanaged").digest("hex");
      await pool.query(
        `INSERT INTO managed_certificates (workspace_id, source, source_ref, fingerprint_sha256, common_name, key_mode, key_reference, not_after)
         VALUES ($1, 'agent_filesystem', 'file:///x', $2, 'no-profile.example.com', 'external-unknown', 'vault://k', NOW() + INTERVAL '30 days')`,
        [workspaceId, unmanaged],
      );
      const identity = (await pool.query("SELECT id FROM certops_certificate_identities WHERE workspace_id = $1 AND fingerprint_sha256 = $2", [workspaceId, unmanaged])).rows[0].id;
      const noProfile = await preview(identity);
      assert.equal(noProfile.status, 409);
      assert.ok(["OPERATOR_RENEWAL_NOT_POSSIBLE", "OPERATOR_CERTIFICATE_NOT_MANAGED"].includes(noProfile.body.code), noProfile.body.code);
      assert.ok(!JSON.stringify(noProfile.body).includes("vault://"));
      const rows = await pool.query("SELECT COUNT(*)::int AS n FROM operator_action_plans WHERE identity_id = $1", [identity]);
      assert.equal(rows.rows[0].n, 0, "a refused preview stores nothing");
    });

    it("answers one 404 for another workspace's certificate and a missing one", async () => {
      const other = await seedRenewable(otherWorkspaceId, "other");
      const bodies = new Set();
      for (const id of [other.identityId, crypto.randomUUID(), "not-a-uuid"]) {
        const response = await preview(id);
        assert.equal(response.status, 404, id);
        bodies.add(JSON.stringify(response.body));
      }
      assert.equal(bodies.size, 1);
    });

    it("refuses unknown, missing and misshapen input", async () => {
      for (const body of [{}, { identityId: certA.identityId, force: true }, { identityId: certA.identityId, workspaceId }, { identityId: 5 }, []]) {
        const response = await post("/api/v1/operator/renewals/preview", body);
        assert.equal(response.status, 400, JSON.stringify(body));
        assert.equal(response.body.code, "OPERATOR_VALIDATION_ERROR");
      }
    });
  });

  describe("submitting", () => {
    before(clearInFlight);
    // Each test here leaves one request waiting; stay under the shared cap.
    const { afterEach } = require("node:test");
    afterEach(clearInFlight);

    it("creates one ordinary job that waits for someone else, attributed to the person and the connection", async () => {
      const plan = (await preview()).body;
      const requestId = crypto.randomUUID();
      const response = await submit(plan, requestId);
      assert.equal(response.status, 201);
      const check = valid("tt_request_renew_output");
      assert.equal(check(response.body), true, JSON.stringify(check.errors));
      assert.equal(response.body.state, "pending_approval");
      assert.equal(response.body.replayed, false);
      assert.equal(response.body.requestId, requestId);

      const job = await jobRow(response.body.jobId);
      assert.equal(job.operation, "renew");
      assert.equal(job.status, "pending_approval", "it can never start without approval");
      assert.equal(job.requested_by_user_id, manager, "never null, never anonymous");
      assert.equal(job.requested_by_connection_id, connectionId);
      assert.equal(job.source, "api");
      assert.equal(job.subject_id, String(certA.managedId));
      assert.equal(job.approved_by_user_id, null);

      const audit = (await pool.query("SELECT actor_user_id, metadata FROM audit_events WHERE workspace_id = $1 AND action = 'OPERATOR_RENEW_REQUESTED' ORDER BY occurred_at DESC LIMIT 1", [workspaceId])).rows[0];
      assert.equal(audit.actor_user_id, manager);
      assert.equal(audit.metadata.via, "operator_connection");
      assert.equal(audit.metadata.connection_id, connectionId);
      assert.equal(audit.metadata.job_id, response.body.jobId);
    });

    it("takes exactly planId, planHash and requestId, so there is nowhere to put a bypass", async () => {
      const plan = (await preview()).body;
      const good = { planId: plan.planId, planHash: plan.planHash, requestId: crypto.randomUUID() };
      for (const extra of ["force", "skipApproval", "requiresApproval", "acknowledge", "status", "payload", "operation", "workspaceId", "mode", "idempotencyKey", "requestedByUserId"]) {
        const response = await post("/api/v1/operator/renewals/requests", { ...good, [extra]: extra === "requiresApproval" ? false : true });
        assert.equal(response.status, 400, extra);
        assert.equal(response.body.code, "OPERATOR_VALIDATION_ERROR");
      }
      assert.equal(await pool.query("SELECT COUNT(*)::int AS n FROM operator_action_requests WHERE plan_id = $1", [plan.planId]).then((r) => r.rows[0].n), 0, "nothing was created by any of those");
    });

    it("rejects a plan hash that is not the one previewed, and a plan from another connection", async () => {
      const plan = (await preview()).body;
      const wrong = await post("/api/v1/operator/renewals/requests", { planId: plan.planId, planHash: "0".repeat(64), requestId: crypto.randomUUID() });
      assert.equal(wrong.status, 409);
      assert.equal(wrong.body.code, "OPERATOR_PLAN_MISMATCH");

      const second = await newConnection(manager);
      const stolen = await submit(plan, crypto.randomUUID(), second.credential);
      assert.equal(stolen.status, 409);
      assert.equal(stolen.body.code, "OPERATOR_PLAN_MISMATCH", "another connection's plan looks exactly like a wrong one");
      const missing = await post("/api/v1/operator/renewals/requests", { planId: crypto.randomUUID(), planHash: plan.planHash, requestId: crypto.randomUUID() });
      assert.deepEqual(stolen.body, missing.body);
    });

    it("refuses an expired preview, but still replays a request made before it expired", async () => {
      const plan = (await preview()).body;
      const requestId = crypto.randomUUID();
      const first = await submit(plan, requestId);
      assert.equal(first.status, 201);
      await pool.query("UPDATE operator_action_plans SET created_at = NOW() - INTERVAL '20 minutes', expires_at = NOW() - INTERVAL '10 minutes' WHERE id = $1", [plan.planId]);
      const replay = await submit(plan, requestId);
      assert.equal(replay.status, 200, "a lost response is never answered with 'expired'");
      assert.equal(replay.body.replayed, true);
      const fresh = await submit(plan, crypto.randomUUID());
      assert.equal(fresh.status, 410);
      assert.equal(fresh.body.code, "OPERATOR_PLAN_EXPIRED");
    });
  });

  describe("approval by a different person", () => {
    const { afterEach } = require("node:test");
    before(clearInFlight);
    afterEach(clearInFlight);

    async function pendingRequest(c = credential, cert = certA) {
      const plan = (await preview(cert.identityId, c)).body;
      const response = await submit(plan, crypto.randomUUID(), c);
      assert.equal(response.status, 201, `submit failed: ${JSON.stringify(response.body)}`);
      return response.body;
    }
    const approve = (jobId, userId) => approvals.approveJob({ workspaceId, jobId, approverUserId: userId, reason: "ok" });

    it("cannot be approved by the person who owns the connection, whatever role they hold", async () => {
      const request = await pendingRequest();
      for (const self of [manager]) {
        await assert.rejects(approve(request.jobId, self), (e) => e.code === "CERTOPS_APPROVAL_SELF_APPROVAL_FORBIDDEN");
      }
      assert.equal((await jobRow(request.jobId)).status, "pending_approval");
      // Even if the same person is later promoted to admin.
      await member(manager, workspaceId, "admin");
      try {
        await assert.rejects(approve(request.jobId, manager), (e) => e.code === "CERTOPS_APPROVAL_SELF_APPROVAL_FORBIDDEN");
      } finally {
        await member(manager, workspaceId, "workspace_manager");
      }
    });

    it("can be approved by someone else, then reads as approved without a second copy of the state", async () => {
      const request = await pendingRequest();
      await approve(request.jobId, approver);
      const job = await jobRow(request.jobId);
      assert.equal(job.status, "pending", "now claimable by an agent, as any approved job is");
      assert.equal(job.approved_by_user_id, approver);
      const read = await get(`/api/v1/operator/requests/${request.requestRecordId}`);
      assert.equal(read.status, 200);
      assert.equal(read.body.state, "approved");
      assert.equal(valid("tt_get_action_request_output")(read.body), true);
    });

    it("shows a rejection to the requester, with a stable state", async () => {
      const request = await pendingRequest();
      await approvals.rejectJob({ workspaceId, jobId: request.jobId, approverUserId: approver, reason: "not now" });
      const read = await get(`/api/v1/operator/requests/${request.requestRecordId}`);
      assert.equal(read.body.state, "rejected");
    });

    it("lets the requester see only their own requests, with the same 404 for anyone else's", async () => {
      const mine = await pendingRequest();
      const other = await newConnection(manager);
      const seen = await get(`/api/v1/operator/requests/${mine.requestRecordId}`, other.credential);
      const none = await get(`/api/v1/operator/requests/${crypto.randomUUID()}`, other.credential);
      assert.equal(seen.status, 404);
      assert.deepEqual(seen.body, none.body);
      const listed = await get("/api/v1/operator/requests", other.credential);
      assert.ok(!JSON.stringify(listed.body).includes(mine.requestRecordId));
      const own = await get("/api/v1/operator/requests");
      const listCheck = valid("tt_list_my_requests_output");
      assert.equal(listCheck(own.body), true, JSON.stringify(listCheck.errors));
      assert.equal(own.body.completeness.totalKnown, true);
      assert.ok(own.body.items.some((r) => r.requestRecordId === mine.requestRecordId));
      for (const item of own.body.items) assert.equal(valid("requestRecord")(item), true);
    });

    it("refuses approval once the connection is revoked, so a model that was cut off cannot have its request run", async () => {
      const own = await newConnection(manager);
      const request = await pendingRequest(own.credential);
      await connections.revokeConnection({ workspaceId, connectionId: own.id, revokedBy: owner });
      const job = await jobRow(request.jobId);
      assert.equal(job.status, "cancelled", "revocation ends the unapproved request");
      await assert.rejects(approve(request.jobId, approver), (e) => ["CERTOPS_APPROVAL_JOB_NOT_PENDING_APPROVAL", "CERTOPS_APPROVAL_REQUEST_STALE"].includes(e.code));
    });

    it("refuses approval after the approval window, and after a connection expires", async () => {
      const request = await pendingRequest();
      await pool.query("UPDATE operator_action_requests SET approval_expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1", [request.requestRecordId]);
      await assert.rejects(approve(request.jobId, approver), (e) => e.code === "CERTOPS_APPROVAL_REQUEST_STALE");
      assert.equal((await get(`/api/v1/operator/requests/${request.requestRecordId}`)).body.state, "expired");

      const own = await newConnection(manager);
      const second = await pendingRequest(own.credential);
      await pool.query("ALTER TABLE operator_connections DISABLE TRIGGER ALL");
      try {
        await pool.query("UPDATE operator_connections SET created_at = NOW() - INTERVAL '40 days', expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1", [own.id]);
      } finally {
        await pool.query("ALTER TABLE operator_connections ENABLE TRIGGER ALL");
      }
      await assert.rejects(approve(second.jobId, approver), (e) => e.code === "CERTOPS_APPROVAL_REQUEST_STALE");
    });

    it("does not change how an ordinary job is approved", async () => {
      const plain = await pool.query(
        `INSERT INTO certificate_jobs (workspace_id, operation, status, source, payload, subject_type, subject_id, requested_by_user_id)
         VALUES ($1, 'noop', 'pending_approval', 'api', '{}'::jsonb, 'managed_certificate', $2, $3) RETURNING id`,
        [workspaceId, String(certA.managedId), owner],
      );
      const done = await approve(plain.rows[0].id, approver);
      assert.ok(done);
      assert.equal((await jobRow(plain.rows[0].id)).requested_by_connection_id, null);
    });
  });

  describe("the shared capacity and pause gates", () => {
    const { afterEach } = require("node:test");
    before(clearInFlight);
    afterEach(async () => {
      await clearInFlight();
      await pool.query("UPDATE workspaces SET certops_paused = FALSE WHERE id = $1", [workspaceId]);
    });

    it("stops unapproved assistant requests at half the shared cap, so people and the scheduler keep room", async () => {
      // The default per-CA cap is 5, so the assistant may have 2 waiting.
      const plan = (await preview()).body;
      const results = [];
      for (let i = 0; i < 5; i += 1) results.push(await submit(plan, crypto.randomUUID()));
      assert.equal(results.filter((r) => r.status === 201).length, 2, "exactly the workspace limit gets through");
      for (const refused of results.filter((r) => r.status !== 201)) {
        assert.equal(refused.status, 429);
        assert.equal(refused.body.code, "OPERATOR_PENDING_LIMIT");
      }
      // The point of the limit: a person can still renew right now.
      const personsRenewal = await pool.connect();
      try {
        await personsRenewal.query("BEGIN");
        const created = await require("../../apps/api/services/certops/jobs").manualRenewalJobCreator({
          certificateId: certA.managedId,
        })({
          client: personsRenewal,
          workspaceId,
          subjectType: "managed_certificate",
          subjectId: certA.managedId,
          payload: {},
          source: "api",
          requestedByUserId: owner,
          requiresApproval: false,
          idempotencyKey: `human-${crypto.randomUUID()}`,
          returnOutcome: true,
        });
        await personsRenewal.query("COMMIT");
        assert.ok((created.job || created).id, "a person's renewal still fits under the shared cap");
      } finally {
        personsRenewal.release();
      }
    });

    it("applies the limit across connections, so opening more of them gains nothing", async () => {
      const a = await newConnection(manager);
      const b = await newConnection(manager);
      const c = await newConnection(manager);
      let created = 0;
      for (const conn of [a, b, c, a, b, c]) {
        const plan = (await preview(certA.identityId, conn.credential)).body;
        const response = await submit(plan, crypto.randomUUID(), conn.credential);
        if (response.status === 201) created += 1;
      }
      assert.equal(created, 2, "two connections' worth of requests is the whole workspace's share");
    });

    it("lets withdrawing a request free its place straight away", async () => {
      const plan = (await preview()).body;
      const first = await submit(plan, crypto.randomUUID());
      const second = await submit(plan, crypto.randomUUID());
      assert.equal(first.status, 201);
      assert.equal(second.status, 201);
      assert.equal((await submit(plan, crypto.randomUUID())).status, 429);
      const cancelled = await post(`/api/v1/operator/requests/${first.body.requestRecordId}/cancel`, {});
      assert.equal(cancelled.status, 200);
      assert.equal(cancelled.body.state, "cancelled");
      assert.equal((await submit(plan, crypto.randomUUID())).status, 201);
    });

    it("refuses a submission while the workspace is paused, and a pause that commits first always wins", async () => {
      const plan = (await preview()).body;
      await pool.query("UPDATE workspaces SET certops_paused = TRUE WHERE id = $1", [workspaceId]);
      const response = await submit(plan, crypto.randomUUID());
      assert.equal(response.status, 409);
      assert.equal(response.body.code, "CERTOPS_WORKSPACE_PAUSED");
      assert.equal(await pool.query("SELECT COUNT(*)::int AS n FROM operator_action_requests WHERE plan_id = $1", [plan.planId]).then((r) => r.rows[0].n), 0);
    });
  });

  describe("identity, replay and staleness", () => {
    const { afterEach } = require("node:test");
    before(clearInFlight);
    afterEach(clearInFlight);

    it("replays an identical retry without a second job, and says it was a replay", async () => {
      const plan = (await preview()).body;
      const requestId = crypto.randomUUID();
      const first = await submit(plan, requestId);
      const again = await submit(plan, requestId);
      const third = await submit(plan, requestId);
      assert.equal(first.status, 201);
      assert.equal(again.status, 200);
      assert.equal(again.body.replayed, true);
      assert.equal(again.body.requestRecordId, first.body.requestRecordId);
      assert.equal(third.body.jobId, first.body.jobId);
      const jobs = await pool.query("SELECT COUNT(*)::int AS n FROM certificate_jobs WHERE requested_by_connection_id = $1 AND idempotency_key LIKE 'mcp-renew:%'", [connectionId]);
      const mine = await pool.query("SELECT COUNT(*)::int AS n FROM operator_action_requests WHERE connection_id = $1 AND request_id = $2", [connectionId, requestId]);
      assert.equal(mine.rows[0].n, 1);
      assert.ok(jobs.rows[0].n >= 1);
    });

    it("replays after the request reached a final state, and never resurrects withdrawn work", async () => {
      const plan = (await preview()).body;
      const requestId = crypto.randomUUID();
      const first = await submit(plan, requestId);
      await post(`/api/v1/operator/requests/${first.body.requestRecordId}/cancel`, {});
      const replay = await submit(plan, requestId);
      assert.equal(replay.status, 200);
      assert.equal(replay.body.state, "cancelled", "a retry does not bring cancelled work back");
      assert.equal((await jobRow(first.body.jobId)).status, "cancelled");
    });

    it("answers the same request id with different content as a conflict, and changes nothing", async () => {
      const planA = (await preview()).body;
      const planB = (await preview()).body;
      const requestId = crypto.randomUUID();
      assert.equal((await submit(planA, requestId)).status, 201);
      const conflict = await submit(planB, requestId);
      assert.equal(conflict.status, 409);
      assert.equal(conflict.body.code, "OPERATOR_IDEMPOTENCY_CONFLICT");
      // The hash is content-addressed: two previews of the same unchanged
      // certificate share one, so presenting the other plan's hash with this
      // plan's id is a genuine replay. A hash that really differs is the conflict.
      assert.equal(planA.planHash, planB.planHash, "previews of the same unchanged state hash identically");
      const wrongHash = await post("/api/v1/operator/renewals/requests", { planId: planA.planId, planHash: "f".repeat(64), requestId });
      assert.equal(wrongHash.status, 409);
      assert.equal(wrongHash.body.code, "OPERATOR_IDEMPOTENCY_CONFLICT");
    });

    it("never lets one connection adopt or see another's request id", async () => {
      const plan = (await preview()).body;
      const requestId = crypto.randomUUID();
      const mine = await submit(plan, requestId);
      const other = await newConnection(manager);
      const theirPlan = (await preview(certA.identityId, other.credential)).body;
      const theirs = await submit(theirPlan, requestId, other.credential);
      assert.equal(theirs.status, 201, "the same request id on another connection is a different request");
      assert.notEqual(theirs.body.requestRecordId, mine.body.requestRecordId);
      assert.notEqual(theirs.body.jobId, mine.body.jobId);
    });

    it("runs exactly one of many simultaneous identical submissions", async () => {
      const plan = (await preview()).body;
      const requestId = crypto.randomUUID();
      const results = await Promise.all(Array.from({ length: 6 }, () => submit(plan, requestId)));
      const created = results.filter((r) => r.status === 201);
      assert.equal(created.length, 1, "one creates it");
      assert.ok(results.every((r) => [200, 201].includes(r.status)), JSON.stringify(results.map((r) => r.status)));
      assert.equal(new Set(results.map((r) => r.body.requestRecordId)).size, 1);
      const n = await pool.query("SELECT COUNT(*)::int AS n FROM operator_action_requests WHERE connection_id = $1 AND request_id = $2", [connectionId, requestId]);
      assert.equal(n.rows[0].n, 1);
    });

    it("refuses a plan when the certificate changed since the preview", async () => {
      const plan = (await preview()).body;
      await pool.query("UPDATE managed_certificates SET profile_id = NULL WHERE id = $1", [certA.managedId]);
      try {
        const response = await submit(plan, crypto.randomUUID());
        assert.equal(response.status, 409);
        assert.equal(response.body.code, "OPERATOR_INTENT_STALE");
      } finally {
        await pool.query("UPDATE managed_certificates SET profile_id = $2 WHERE id = $1", [certA.managedId, certA.profileId]);
      }
      const retired = (await preview()).body;
      const row = await pool.query("SELECT identity_id FROM operator_action_plans WHERE id = $1", [retired.planId]);
      assert.equal(row.rows.length, 1);
    });
  });

  describe("races that must always resolve the safe way", () => {
    const { afterEach } = require("node:test");
    before(clearInFlight);
    afterEach(clearInFlight);

    it("a revocation that commits first always beats a submission, and the submission cannot slip in after", async () => {
      const own = await newConnection(manager);
      const plan = (await preview(certA.identityId, own.credential)).body;
      // Hold a submission open mid-transaction, as a slow request would.
      const holder = await pool.connect();
      try {
        await holder.query("BEGIN");
        const renewService = require("../../apps/api/services/operator/renewRequests");
        const operator = { connectionId: own.id, userId: manager, workspaceId };
        const held = await renewService.submitRenewRequest({ client: holder, operator, planId: plan.planId, planHash: plan.planHash, requestId: crypto.randomUUID() });

        let revokeDone = false;
        const revoke = connections.revokeConnection({ workspaceId, connectionId: own.id, revokedBy: owner }).then((r) => { revokeDone = true; return r; });
        await new Promise((resolve) => setTimeout(resolve, 400));
        assert.equal(revokeDone, false, "revocation waits for the in-flight authorization instead of racing past it");

        await holder.query("COMMIT");
        const revoked = await revoke;
        assert.equal(revoked.revokedNow, true);
        assert.equal(revoked.cancelledJobs, 1, "and then ends the request the submission created");
        assert.equal((await jobRow(held.jobId)).status, "cancelled");
      } finally {
        await holder.query("ROLLBACK").catch(() => {});
        holder.release();
      }
      const after = await post("/api/v1/operator/renewals/requests", { planId: plan.planId, planHash: plan.planHash, requestId: crypto.randomUUID() }, own.credential);
      assert.equal(after.status, 401, "nothing can be authorized after the revocation");
    });

    it("withdrawal and approval race on the job, and exactly one wins", async () => {
      const plan = (await preview()).body;
      const request = (await submit(plan, crypto.randomUUID())).body;
      const [withdrawn, approved] = await Promise.allSettled([
        post(`/api/v1/operator/requests/${request.requestRecordId}/cancel`, {}),
        approvals.approveJob({ workspaceId, jobId: request.jobId, approverUserId: approver, reason: "go" }),
      ]);
      const withdrewOk = withdrawn.status === "fulfilled" && withdrawn.value.status === 200;
      const approvedOk = approved.status === "fulfilled";
      assert.notEqual(withdrewOk, approvedOk, "never both, never neither");
      const final = (await jobRow(request.jobId)).status;
      assert.equal(final, withdrewOk ? "cancelled" : "pending");
      if (!withdrewOk) assert.equal(withdrawn.value.body.code, "OPERATOR_REQUEST_NOT_CANCELLABLE", "and it does not claim to have prevented anything");
    });

    it("lets a request be withdrawn even when writes are off or the workspace is paused", async () => {
      const plan = (await preview()).body;
      const request = (await submit(plan, crypto.randomUUID())).body;
      await setWorkspaceWrites(false);
      await pool.query("UPDATE workspaces SET certops_paused = TRUE WHERE id = $1", [workspaceId]);
      try {
        const response = await post(`/api/v1/operator/requests/${request.requestRecordId}/cancel`, {});
        assert.equal(response.status, 200, "taking a request back must not depend on new work being allowed");
        assert.equal(response.body.state, "cancelled");
        const blocked = await preview();
        assert.equal(blocked.status, 403, "while starting new work is still refused");
      } finally {
        await setWorkspaceWrites(true);
        await pool.query("UPDATE workspaces SET certops_paused = FALSE WHERE id = $1", [workspaceId]);
      }
    });

    it("lets only the owning connection withdraw, with the same answer as a missing request", async () => {
      const request = (await submit((await preview()).body, crypto.randomUUID())).body;
      const other = await newConnection(manager);
      const theirs = await post(`/api/v1/operator/requests/${request.requestRecordId}/cancel`, {}, other.credential);
      const missing = await post(`/api/v1/operator/requests/${crypto.randomUUID()}/cancel`, {}, other.credential);
      assert.equal(theirs.status, 404);
      assert.deepEqual(theirs.body, missing.body);
      assert.equal((await jobRow(request.jobId)).status, "pending_approval", "nothing was withdrawn");
    });

    it("does not let a demoted owner keep requesting", async () => {
      const own = await newConnection(manager);
      await member(manager, workspaceId, "viewer");
      try {
        const response = await post("/api/v1/operator/renewals/preview", { identityId: certA.identityId }, own.credential);
        assert.equal(response.status, 403);
        assert.equal(response.body.code, "OPERATOR_CONNECTION_SCOPE_DENIED");
      } finally {
        await member(manager, workspaceId, "workspace_manager");
      }
    });
  });

  // Tests are appended below.
});

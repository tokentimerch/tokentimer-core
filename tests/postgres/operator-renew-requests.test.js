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

// Preview and submit in one step, each with its own plan and request id.
const fileRequest = async (who = credential, identityId = certA.identityId) =>
  submit((await preview(identityId, who)).body, crypto.randomUUID(), who);
const mustFile = async (who = credential, identityId = certA.identityId) => {
  const response = await fileRequest(who, identityId);
  assert.equal(response.status, 201, `could not file a request: ${response.status} ${JSON.stringify(response.body)}`);
  return response.body;
};
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
async function restoreRoles() {
  await member(manager, workspaceId, "workspace_manager");
  await member(approver, workspaceId, "workspace_manager");
  await member(viewer, workspaceId, "viewer");
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

    it("refuses approval immediately after requester demotion or removal without a sweep", async () => {
      for (const removed of [false, true]) {
        await restoreRoles();
        await clearInFlight();
        const request = await mustFile();
        try {
          if (removed) await pool.query("DELETE FROM workspace_memberships WHERE workspace_id = $1 AND user_id = $2", [workspaceId, manager]);
          else await member(manager, workspaceId, "viewer");
          await assert.rejects(approvals.approveJob({ workspaceId, jobId: request.jobId, approverUserId: approver, reason: "reviewed" }), { code: "CERTOPS_APPROVAL_REQUEST_STALE" });
          assert.equal((await jobRow(request.jobId)).status, "pending_approval");
        } finally { await restoreRoles(); }
      }
    });

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
      const results = [];
      for (let i = 0; i < 5; i += 1) results.push(await fileRequest());
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
      const first = await fileRequest();
      const second = await fileRequest();
      assert.equal(first.status, 201);
      assert.equal(second.status, 201);
      assert.equal((await fileRequest()).status, 429);
      const cancelled = await post(`/api/v1/operator/requests/${first.body.requestRecordId}/cancel`, {});
      assert.equal(cancelled.status, 200);
      assert.equal(cancelled.body.state, "cancelled");
      assert.equal((await fileRequest()).status, 201);
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

  describe("resolved preview intent", () => {
    const { afterEach } = require("node:test");
    afterEach(clearInFlight);
    it("returns the known certificate name and expiry", async () => {
      const response = await preview();
      assert.equal(response.status, 201);
      assert.equal(response.body.effect.target.commonName.value, "app.example.com");
      assert.ok(response.body.effect.target.notAfter);
    });
    it("rejects an in-place edit of the previewed profile", async () => {
      const plan = (await preview()).body;
      const original = (await pool.query("SELECT public_metadata FROM certificate_profiles WHERE id = $1", [certA.profileId])).rows[0].public_metadata;
      try {
        await pool.query("UPDATE certificate_profiles SET public_metadata = jsonb_set(public_metadata, '{renewalProfile,keySize}', '4096') WHERE id = $1", [certA.profileId]);
        const response = await submit(plan, crypto.randomUUID());
        assert.equal(response.status, 409);
        assert.equal(response.body.code, "OPERATOR_INTENT_STALE");
        assert.equal((await pool.query("SELECT COUNT(*)::int AS n FROM operator_action_requests WHERE plan_id = $1", [plan.planId])).rows[0].n, 0);
      } finally {
        await pool.query("UPDATE certificate_profiles SET public_metadata = $2::jsonb WHERE id = $1", [certA.profileId, JSON.stringify(original)]);
      }
    });
    it("preserves human capacity when the configured cap is one", async () => {
      const previous = process.env.CERTOPS_RENEWAL_PER_CA_CAP;
      process.env.CERTOPS_RENEWAL_PER_CA_CAP = "1";
      try {
        const response = await submit((await preview()).body, crypto.randomUUID());
        assert.equal(response.status, 429);
        assert.equal(response.body.code, "OPERATOR_PENDING_LIMIT");
      } finally {
        if (previous === undefined) delete process.env.CERTOPS_RENEWAL_PER_CA_CAP;
        else process.env.CERTOPS_RENEWAL_PER_CA_CAP = previous;
      }
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

    async function waitForWorkspaceLock(waiter, holder) {
      const deadline = Date.now() + 5000;
      while (Date.now() < deadline) {
        const result = await pool.query("SELECT $2::int = ANY(pg_blocking_pids($1::int)) AS blocked", [waiter, holder]);
        if (result.rows[0].blocked) return;
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      assert.fail("the competing transaction did not wait for the workspace lock");
    }

    it("a write-disable transaction that commits first prevents a concurrent submission", async () => {
      const plan = (await preview()).body;
      const admin = await pool.connect();
      const submitter = await pool.connect();
      let pending;
      try {
        await admin.query("BEGIN");
        await submitter.query("BEGIN");
        const adminPid = (await admin.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
        const submitterPid = (await submitter.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
        // Use an explicit manager membership, so the owner fallback cannot
        // accidentally provide the workspace lock the write gate needs.
        await admin.query("SELECT id FROM workspaces WHERE id = $1 FOR UPDATE", [workspaceId]);
        await admin.query("UPDATE workspaces SET operator_writes_enabled = FALSE WHERE id = $1", [workspaceId]);
        pending = require("../../apps/api/services/operator/renewRequests").submitRenewRequest({
          client: submitter, operator: { connectionId, userId: manager, workspaceId },
          planId: plan.planId, planHash: plan.planHash, requestId: crypto.randomUUID(),
        }).then((value) => ({ value }), (error) => ({ error }));
        await waitForWorkspaceLock(submitterPid, adminPid);
        await require("../../apps/api/services/operator/requestMaintenance").endWaitingForWorkspace(admin, workspaceId);
        await admin.query("COMMIT");
        const outcome = await pending;
        assert.equal(outcome.error?.code, "OPERATOR_WRITES_DISABLED", JSON.stringify(outcome.value));
        const created = await submitter.query("SELECT COUNT(*)::int AS n FROM operator_action_requests WHERE plan_id = $1", [plan.planId]);
        assert.equal(created.rows[0].n, 0, "no request or job can slip past the completed disable sweep");
      } finally {
        await admin.query("ROLLBACK").catch(() => {});
        if (pending) await pending;
        await submitter.query("ROLLBACK").catch(() => {});
        admin.release();
        submitter.release();
        await setWorkspaceWrites(true);
      }
    });

    it("write-disable waits for an authorized submission and then cancels its pending job", async () => {
      const plan = (await preview()).body;
      const submitter = await pool.connect();
      const admin = await pool.connect();
      let disabling;
      try {
        await submitter.query("BEGIN");
        await admin.query("BEGIN");
        const submitterPid = (await submitter.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
        const adminPid = (await admin.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
        const created = await require("../../apps/api/services/operator/renewRequests").submitRenewRequest({
          client: submitter, operator: { connectionId, userId: manager, workspaceId },
          planId: plan.planId, planHash: plan.planHash, requestId: crypto.randomUUID(),
        });
        disabling = admin.query("SELECT id FROM workspaces WHERE id = $1 FOR UPDATE", [workspaceId]);
        await waitForWorkspaceLock(adminPid, submitterPid);
        await submitter.query("COMMIT");
        await disabling;
        await admin.query("UPDATE workspaces SET operator_writes_enabled = FALSE WHERE id = $1", [workspaceId]);
        const cancelled = await require("../../apps/api/services/operator/requestMaintenance").endWaitingForWorkspace(admin, workspaceId);
        await admin.query("COMMIT");
        assert.equal(cancelled, 1);
        assert.equal((await jobRow(created.jobId)).status, "cancelled");
        assert.equal((await get(`/api/v1/operator/requests/${created.requestRecordId}`)).body.state, "cancelled");
      } finally {
        await submitter.query("ROLLBACK").catch(() => {});
        if (disabling) await disabling.catch(() => {});
        await admin.query("ROLLBACK").catch(() => {});
        submitter.release();
        admin.release();
        await setWorkspaceWrites(true);
      }
    });

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

  describe("a preview is spent once", () => {
    const { afterEach } = require("node:test");
    before(clearInFlight);
    afterEach(clearInFlight);

    it("turns a second submission of the same preview away, with a stable code", async () => {
      const plan = (await preview()).body;
      assert.equal((await submit(plan, crypto.randomUUID())).status, 201);
      const again = await submit(plan, crypto.randomUUID());
      assert.equal(again.status, 409);
      assert.equal(again.body.code, "OPERATOR_PLAN_USED");
      assert.equal(await pool.query("SELECT COUNT(*)::int AS n FROM operator_action_requests WHERE plan_id = $1", [plan.planId]).then((r) => r.rows[0].n), 1);
    });

    it("lets exactly one of many simultaneous submissions of one preview through", async () => {
      const plan = (await preview()).body;
      const results = await Promise.all(Array.from({ length: 6 }, () => submit(plan, crypto.randomUUID())));
      assert.equal(results.filter((r) => r.status === 201).length, 1, JSON.stringify(results.map((r) => r.status)));
      for (const other of results.filter((r) => r.status !== 201)) assert.equal(other.body.code, "OPERATOR_PLAN_USED");
      const fromThisPlan = await pool.query(
        `SELECT COUNT(*)::int AS n FROM operator_action_requests r WHERE r.plan_id = $1 AND r.job_id IS NOT NULL`,
        [plan.planId],
      );
      assert.equal(fromThisPlan.rows[0].n, 1, "one preview is one order");
    });

    it("is also enforced by the database, so a bug elsewhere cannot spend a preview twice", async () => {
      const plan = (await preview()).body;
      const first = await submit(plan, crypto.randomUUID());
      assert.equal(first.status, 201);
      await assert.rejects(
        pool.query(
          `INSERT INTO operator_action_requests (workspace_id, connection_id, user_id, request_id, plan_id, plan_hash, operation, identity_id, subject_id, approval_expires_at)
           SELECT workspace_id, connection_id, user_id, gen_random_uuid(), plan_id, plan_hash, operation, identity_id, subject_id, approval_expires_at
             FROM operator_action_requests WHERE plan_id = $1`,
          [plan.planId],
        ),
        /uq_operator_action_requests_plan/,
      );
    });

    it("still replays the one request made from it", async () => {
      const plan = (await preview()).body;
      const requestId = crypto.randomUUID();
      const first = await submit(plan, requestId);
      const again = await submit(plan, requestId);
      assert.equal(again.status, 200);
      assert.equal(again.body.requestRecordId, first.body.requestRecordId);
    });
  });

  describe("requests that can no longer be approved or run", () => {
    const { afterEach } = require("node:test");
    const maintenance = require("../../apps/api/services/operator/requestMaintenance");
    before(async () => {
      await restoreRoles();
      await clearInFlight();
    });
    afterEach(async () => {
      await restoreRoles();
      await clearInFlight();
      await setWorkspaceWrites(true);
    });
    const lapse = (requestRecordId) =>
      pool.query("UPDATE operator_action_requests SET approval_expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1", [requestRecordId]);
    const run = async (fn) => {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const result = await fn(client);
        await client.query("COMMIT");
        return result;
      } finally {
        client.release();
      }
    };

    it("ends a request whose approval window closed, so it stops holding a slot, and says why", async () => {
      const request = await mustFile();
      await lapse(request.requestRecordId);
      assert.equal((await jobRow(request.jobId)).status, "pending_approval", "only a label until something ends it");
      const ended = await run((client) => maintenance.endLapsedWindows(client, workspaceId));
      assert.equal(ended, 1);
      const job = await jobRow(request.jobId);
      assert.equal(job.status, "cancelled", "terminal, so the scheduler and the per-CA cap are free of it");
      const read = (await get(`/api/v1/operator/requests/${request.requestRecordId}`)).body;
      assert.equal(read.state, "expired");
      assert.equal(read.stateReason, "approval_window_ended");
    });

    it("does not let a lapsed request hold the assistant's limit, even if the sweep never ran", async () => {
      const first = await mustFile();
      const second = await mustFile();
      assert.equal((await fileRequest()).status, 429, "the workspace limit is full");
      await lapse(first.requestRecordId);
      await lapse(second.requestRecordId);
      const fresh = await fileRequest();
      assert.equal(fresh.status, 201, "submitting ended the lapsed ones itself");
      assert.equal((await jobRow(first.jobId)).status, "cancelled");
      assert.equal((await jobRow(second.jobId)).status, "cancelled");
    });

    it("frees the certificate for the scheduler: no non-terminal renewal is left behind", async () => {
      const request = await mustFile();
      await lapse(request.requestRecordId);
      await run((client) => maintenance.sweepOperatorRequests({ client }));
      const open = await pool.query(
        "SELECT COUNT(*)::int AS n FROM certificate_jobs WHERE workspace_id = $1 AND subject_id = $2 AND operation = 'renew' AND status IN ('pending_approval','approved','pending','claimed','running')",
        [workspaceId, String(certA.managedId)],
      );
      assert.equal(open.rows[0].n, 0);
    });

    it("leaves a request still inside its window, and one a person already approved, alone", async () => {
      const waiting = await mustFile();
      const approvedOne = await mustFile();
      await approvals.approveJob({ workspaceId, jobId: approvedOne.jobId, approverUserId: approver, reason: "ok" });
      await lapse(approvedOne.requestRecordId);
      await run((client) => maintenance.sweepOperatorRequests({ client }));
      assert.equal((await jobRow(waiting.jobId)).status, "pending_approval");
      assert.equal((await jobRow(approvedOne.jobId)).status, "pending", "a person approved it, so a lapsed window does not undo that");
    });

    it("never waits on a request someone is working on, so a sweep cannot deadlock with an approval", async () => {
      const request = await mustFile();
      await lapse(request.requestRecordId);
      const holder = await pool.connect();
      try {
        await holder.query("BEGIN");
        await holder.query("SELECT 1 FROM operator_action_requests WHERE id = $1 FOR UPDATE", [request.requestRecordId]);
        const started = Date.now();
        const ended = await run((client) => maintenance.endLapsedWindows(client, workspaceId));
        assert.equal(ended, 0, "it skipped the row that was in use");
        assert.ok(Date.now() - started < 2000, "and did not wait for it");
      } finally {
        await holder.query("ROLLBACK");
        holder.release();
      }
      assert.equal(await run((client) => maintenance.endLapsedWindows(client, workspaceId)), 1, "next time it gets it");
    });

    it("ends the work of a connection that expired, including work a person already approved", async () => {
      const own = await newConnection(manager);
      const waiting = (await mustFile(own.credential));
      const approvedOne = (await mustFile(own.credential));
      await approvals.approveJob({ workspaceId, jobId: approvedOne.jobId, approverUserId: approver, reason: "ok" });
      await expireConnection(own.id);
      const ended = await run((client) => maintenance.endOrphanedRequests(client, workspaceId));
      assert.equal(ended, 2);
      for (const r of [waiting, approvedOne]) {
        assert.equal((await jobRow(r.jobId)).status, "cancelled");
        const read = await pool.query("SELECT state_override, state_reason FROM operator_action_requests WHERE job_id = $1", [r.jobId]);
        assert.equal(read.rows[0].state_override, "cancelled");
        assert.equal(read.rows[0].state_reason, "connection_expired");
      }
    });

    it("ends the work of someone who is no longer a manager, but not a request that an agent already holds", async () => {
      const own = await newConnection(manager);
      const request = (await mustFile(own.credential));
      await member(manager, workspaceId, "viewer");
      try {
        assert.equal(await run((client) => maintenance.endOrphanedRequests(client, workspaceId)), 1);
        assert.equal((await jobRow(request.jobId)).status, "cancelled");
      } finally {
        await member(manager, workspaceId, "workspace_manager");
      }
      const held = (await mustFile(own.credential));
      await approvals.approveJob({ workspaceId, jobId: held.jobId, approverUserId: approver, reason: "ok" });
      await pool.query("UPDATE certificate_jobs SET status = 'claimed', claim_id = gen_random_uuid() WHERE id = $1", [held.jobId]);
      await member(manager, workspaceId, "viewer");
      try {
        assert.equal(await run((client) => maintenance.endOrphanedRequests(client, workspaceId)), 0);
        assert.equal((await jobRow(held.jobId)).status, "claimed", "work an agent holds runs on, to be reconciled by the existing paths");
      } finally {
        await member(manager, workspaceId, "workspace_manager");
        await pool.query("UPDATE certificate_jobs SET status = 'cancelled' WHERE id = $1", [held.jobId]);
      }
    });

    it("leaves work an agent already holds when its connection expires, to be reconciled by the existing paths", async () => {
      const own = await newConnection(manager);
      const held = await mustFile(own.credential);
      await approvals.approveJob({ workspaceId, jobId: held.jobId, approverUserId: approver, reason: "ok" });
      await pool.query("UPDATE certificate_jobs SET status = 'claimed', claim_id = gen_random_uuid() WHERE id = $1", [held.jobId]);
      await expireConnection(own.id);
      assert.equal(await run((client) => maintenance.endOrphanedRequests(client, workspaceId)), 0);
      assert.equal((await jobRow(held.jobId)).status, "claimed", "ending a claimed job here would strand an agent mid-run");
      const row = await pool.query("SELECT state_override FROM operator_action_requests WHERE job_id = $1", [held.jobId]);
      assert.equal(row.rows[0].state_override, null, "and the request is not relabelled as ended");
      await pool.query("UPDATE certificate_jobs SET status = 'cancelled' WHERE id = $1", [held.jobId]);
    });

    it("ends the waiting requests the moment an admin switches assistant writes off, and leaves approved ones", async () => {
      const waiting = await mustFile();
      const approvedOne = await mustFile();
      await approvals.approveJob({ workspaceId, jobId: approvedOne.jobId, approverUserId: approver, reason: "ok" });
      const off = await request(app).put(`/api/v1/workspaces/${workspaceId}/operator/settings`).set(as(owner)).send({ writesEnabled: false });
      assert.equal(off.status, 200);
      assert.equal((await jobRow(waiting.jobId)).status, "cancelled");
      const read = await pool.query("SELECT state_override, state_reason FROM operator_action_requests WHERE job_id = $1", [waiting.jobId]);
      assert.equal(read.rows[0].state_reason, "writes_disabled");
      assert.equal((await jobRow(approvedOne.jobId)).status, "pending", "a person approved it; that stands");
      await request(app).put(`/api/v1/workspaces/${workspaceId}/operator/settings`).set(as(owner)).send({ writesEnabled: true });
    });

    // eslint-disable-next-line no-inner-declarations
    async function expireConnection(id) {
      await pool.query("ALTER TABLE operator_connections DISABLE TRIGGER ALL");
      try {
        await pool.query("UPDATE operator_connections SET created_at = NOW() - INTERVAL '40 days', expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1", [id]);
      } finally {
        await pool.query("ALTER TABLE operator_connections ENABLE TRIGGER ALL");
      }
    }
  });

  describe("an agent will not start work from a connection that has ended", () => {
    const { afterEach } = require("node:test");
    const dispatch = require("../../apps/api/services/certops/agentDispatch");
    let agentRow;
    before(async () => {
      await restoreRoles();
      await clearInFlight();
      const made = await pool.query(
        `INSERT INTO certops_agents (workspace_id, agent_id, name, agent_version, protocol_version, credential_prefix, credential_hash,
                                     status, declared_capabilities, capabilities_updated_at, last_seen_at, supported_operations,
                                     declared_target_selectors, declared_command_profile_names, supported_dns_providers)
         VALUES ($1, $2, 'claim-agent', '0.18.0', '1.0.0', $3, $4, 'active', '[]'::jsonb, NOW(), NOW(), '["renew"]'::jsonb,
                 '["host/web"]'::jsonb, '["acme-renew-default"]'::jsonb, '["cloudflare"]'::jsonb)
         RETURNING id, agent_id`,
        [workspaceId, `claim-${crypto.randomUUID()}`, `ttagent_${crypto.randomBytes(8).toString("hex")}`, crypto.randomBytes(32).toString("hex")],
      );
      agentRow = made.rows[0];
    });
    afterEach(async () => {
      await restoreRoles();
      await clearInFlight();
    });

    // Signing is the one dependency stubbed; the selection SQL under test is real.
    const claim = () =>
      dispatch.claimJobs({
        agent: { id: agentRow.id, workspaceId, agentId: agentRow.agent_id, status: "active", protocolVersion: "1.0.0", agentVersion: "0.18.0" },
        body: { supportedActions: ["renew"], supportedDnsProviders: ["cloudflare"], maxJobs: 5 },
        deps: {
          // Return whatever id the claim handed to signing, whatever it is named.
          signJobForDispatch: ({ job }) => Promise.resolve({ jobId: job.jobId || job.id || job.job_id }),
          enforceAgentSequence: async () => {},
          computeAgentCompatibility: () => ({ compatibilityState: "compatible" }),
        },
      });
    const approved = async (who = credential) => {
      const request = await mustFile(who);
      await approvals.approveJob({ workspaceId, jobId: request.jobId, approverUserId: approver, reason: "ok" });
      return request;
    };
    const expire = async (id) => {
      await pool.query("ALTER TABLE operator_connections DISABLE TRIGGER ALL");
      try {
        await pool.query("UPDATE operator_connections SET created_at = NOW() - INTERVAL '40 days', expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1", [id]);
      } finally {
        await pool.query("ALTER TABLE operator_connections ENABLE TRIGGER ALL");
      }
    };

    it("claims an approved request from a live connection, which proves the harness really claims", async () => {
      const request = await approved();
      const result = await claim();
      assert.deepEqual(result.jobs.map((j) => j.jobId), [request.jobId]);
      assert.equal((await jobRow(request.jobId)).status, "claimed");
    });

    it("does not claim approved work once the connection has expired", async () => {
      const own = await newConnection(manager);
      const request = await approved(own.credential);
      await expire(own.id);
      const result = await claim();
      assert.deepEqual(result.jobs, [], "the person approved it, but the connection that asked is gone");
      assert.equal((await jobRow(request.jobId)).status, "pending", "and the job was not touched by the attempt");
    });

    it("does not claim approved work once the connection is revoked, even if something else left the job pending", async () => {
      const own = await newConnection(manager);
      const request = await approved(own.credential);
      await pool.query("UPDATE operator_connections SET status = 'revoked', revoked_at = NOW() WHERE id = $1", [own.id]);
      assert.deepEqual((await claim()).jobs, []);
      assert.equal((await jobRow(request.jobId)).status, "pending");
    });

    it("does not claim approved work after requester demotion or removal without a sweep", async () => {
      for (const removed of [false, true]) {
        await clearInFlight();
        await restoreRoles();
        const request = await approved();
        try {
          if (removed) await pool.query("DELETE FROM workspace_memberships WHERE workspace_id = $1 AND user_id = $2", [workspaceId, manager]);
          else await member(manager, workspaceId, "viewer");
          assert.deepEqual((await claim()).jobs, []);
          assert.equal((await jobRow(request.jobId)).status, "pending");
        } finally { await restoreRoles(); }
      }
    });

    it("skips a connection or membership being changed concurrently instead of deadlocking", async () => {
      for (const membership of [false, true]) {
        await clearInFlight();
        const request = await approved();
        const holder = await pool.connect();
        try {
          await holder.query("BEGIN");
          if (membership) await holder.query("UPDATE workspace_memberships SET role = 'viewer' WHERE workspace_id = $1 AND user_id = $2", [workspaceId, manager]);
          else await holder.query("UPDATE operator_connections SET status = 'revoked', revoked_at = NOW() WHERE id = $1", [connectionId]);
          assert.deepEqual((await claim()).jobs, []);
          assert.equal((await jobRow(request.jobId)).status, "pending");
          await holder.query("ROLLBACK");
          assert.deepEqual((await claim()).jobs.map(j => j.jobId), [request.jobId]);
        } finally { await holder.query("ROLLBACK"); holder.release(); }
      }
    });

    it("still claims ordinary work that came from nobody's connection, so existing behaviour is unchanged", async () => {
      // A job a person creates, through the same service, with no connection.
      const person = await pool.connect();
      let plainId;
      try {
        await person.query("BEGIN");
        const created = await require("../../apps/api/services/certops/jobs").manualRenewalJobCreator({ certificateId: certA.managedId })({
          client: person,
          workspaceId,
          subjectType: "managed_certificate",
          subjectId: certA.managedId,
          payload: {},
          source: "api",
          requestedByUserId: owner,
          requiresApproval: false,
          idempotencyKey: `plain-${crypto.randomUUID()}`,
          returnOutcome: true,
        });
        plainId = (created.job || created).id;
        await person.query("COMMIT");
      } finally {
        person.release();
      }
      assert.equal((await jobRow(plainId)).requested_by_connection_id, null);
      const result = await claim();
      assert.ok(result.jobs.some((j) => j.jobId === plainId), "a job with no connection is claimed as before");
    });
  });

  // Tests are appended below.
});

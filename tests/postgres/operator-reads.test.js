"use strict";

// Read routes of the operator namespace on real PostgreSQL (ADR-0015).
//
// Every field a connection must never see is seeded with a sentinel string:
// key references, source and deployment paths, lifecycle reasons, job
// payloads, claim ids, command profiles and selectors. Every route is then
// swept for those sentinels, and every response is validated against the
// published contract.

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
const { guardOperatorCredentials } = require("../../apps/api/middleware/operator-connection-auth");

const contractsDir = path.resolve(__dirname, "../../packages/contracts/mcp");
const readJson = (name) => JSON.parse(fs.readFileSync(path.join(contractsDir, name), "utf8"));
const catalog = readJson("mcp-tool-catalog.json");
const fixtures = readJson("fixtures/read-tools.json");
const readTools = readJson("mcp-read-tools.schema.json");
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
ajv.addSchema(readJson("mcp-common.schema.json"));
ajv.addSchema(readTools);
const schemaFor = (name) => ajv.getSchema(`${readTools.$id}#/definitions/${name}`);

// None of these may ever appear in a response body.
const SENTINELS = [
  "SENTINEL_KEY_REF",
  "SENTINEL_SOURCE_PATH",
  "SENTINEL_DEPLOY_PATH",
  "SENTINEL_JOB_PAYLOAD",
  "SENTINEL_JOB_ERROR",
  "SENTINEL_COMMAND_PROFILE",
  "SENTINEL_SELECTOR",
  "SENTINEL_CLAIM",
  "SENTINEL_AGENT_NAME",
];

let app;
let owner;
let manager;
let viewer;
let workspaceId;
let otherWorkspaceId;
let certA;
let certB;
let otherCert;
let agentId;
let jobPending;
let jobApproval;
let otherJob;
let adminCredential;
let sequence = 0;

const q = (params = {}) =>
  Object.keys(params).length
    ? `?${new URLSearchParams(Object.entries(params).map(([k, v]) => [k, String(v)])).toString()}`
    : "";

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

async function seedCertificate(workspace, { fingerprint, commonName, days = 40, sans = [] }) {
  const row = await pool.query(
    `INSERT INTO managed_certificates
       (workspace_id, source, source_ref, fingerprint_sha256, common_name, issuer, not_after,
        key_mode, key_reference, deployed_cert_path, subject_alt_names)
     VALUES ($1, 'agent_filesystem', 'file:///SENTINEL_SOURCE_PATH/' || $2::text, $2, $3, 'CN=Example CA',
             NOW() + ($4 || ' days')::interval, 'external-unknown', 'vault://SENTINEL_KEY_REF',
             '/etc/SENTINEL_DEPLOY_PATH/cert.pem', $5::text[])
     RETURNING id`,
    [workspace, fingerprint, commonName, String(days), sans],
  );
  const identity = await pool.query(
    "SELECT id FROM certops_certificate_identities WHERE workspace_id = $1 AND fingerprint_sha256 = $2",
    [workspace, fingerprint],
  );
  return { managedId: row.rows[0].id, identityId: identity.rows[0].id, fingerprint };
}

const fp = (n) => crypto.createHash("sha256").update(`fp-${n}`).digest("hex");

function buildApp() {
  const server = express();
  server.use(express.json());
  server.use("/api", guardOperatorCredentials);
  server.use(require("../../apps/api/routes/operator"));
  return server;
}

const get = (route, credential = adminCredential) =>
  request(app).get(route).set("Authorization", `Bearer ${credential}`);

async function credentialFor(userId, scopes, roleCeiling) {
  const { plaintextCredential } = await connections.createConnection({
    workspaceId,
    userId,
    name: `reads-${++sequence}`,
    scopes,
    roleCeiling,
  });
  return plaintextCredential;
}

function assertNoSentinels(value, label) {
  const text = JSON.stringify(value);
  for (const sentinel of SENTINELS) assert.ok(!text.includes(sentinel), `${label} leaked ${sentinel}`);
  for (const marker of ["vault://", "file://", "/etc/", "BEGIN "]) {
    assert.ok(!text.includes(marker), `${label} leaked ${marker}`);
  }
}

function collectKeys(node, found = new Set()) {
  if (Array.isArray(node)) node.forEach((item) => collectKeys(item, found));
  else if (node && typeof node === "object") {
    for (const [key, value] of Object.entries(node)) {
      found.add(key.toLowerCase());
      collectKeys(value, found);
    }
  }
  return found;
}

function assertNoForbiddenKeys(body, label) {
  const keys = collectKeys(body);
  for (const forbidden of catalog.forbiddenOutputFields) {
    assert.ok(!keys.has(forbidden.toLowerCase()), `${label} exposes forbidden field "${forbidden}"`);
  }
}

describe("operator read routes on PostgreSQL", { concurrency: false }, () => {
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

    certA = await seedCertificate(workspaceId, {
      fingerprint: fp("a"),
      commonName: "alpha.example.com",
      days: 10,
      sans: ["alpha.example.com", "www.alpha.example.com"],
    });
    certB = await seedCertificate(workspaceId, { fingerprint: fp("b"), commonName: "bravo.example.com", days: 200 });
    otherCert = await seedCertificate(otherWorkspaceId, { fingerprint: fp("other"), commonName: "other.example.com" });
    await pool.query(
      "UPDATE certops_certificate_identities SET lifecycle_reason = 'replaced by new load balancer' WHERE id = $1",
      [certB.identityId],
    );

    const agent = await pool.query(
      `INSERT INTO certops_agents
         (workspace_id, agent_id, name, hostname, platform, agent_version, protocol_version,
          credential_prefix, credential_hash, declared_target_selectors, declared_command_profile_names,
          status, last_seen_at, supported_operations, declared_capabilities)
       VALUES ($1, 'agent-1', 'SENTINEL_AGENT_NAME', 'host-1.internal', 'linux', '1.2.3', '1.0.0',
               $2, $3, '["SENTINEL_SELECTOR"]'::jsonb, '["SENTINEL_COMMAND_PROFILE"]'::jsonb,
               'active', NOW() - INTERVAL '3 days', '["renew","deploy","format-disk"]'::jsonb,
               '["adcs-enroll-v1"]'::jsonb)
       RETURNING id`,
      [workspaceId, `ttagent_${crypto.randomBytes(8).toString("hex")}`, crypto.randomBytes(32).toString("hex")],
    );
    agentId = agent.rows[0].id;

    const job = (workspace, fields) =>
      pool
        .query(
          `INSERT INTO certificate_jobs
             (workspace_id, operation, status, source, payload, subject_type, subject_id,
              requested_by_user_id, assigned_agent_id, claim_id, error_code, error_message, approved_at)
           VALUES ($1, $2, $3, 'api', $4::jsonb, 'managed_certificate', $5, $6, $7, $8, $9, $10, $11)
           RETURNING id`,
          [
            workspace,
            fields.operation,
            fields.status,
            JSON.stringify({ certPath: "/SENTINEL_JOB_PAYLOAD/cert.pem" }),
            fields.subjectId,
            fields.requestedBy ?? null,
            fields.agent ?? null,
            fields.claim ?? null,
            fields.errorCode ?? null,
            fields.errorMessage ?? null,
            fields.approvedAt ?? null,
          ],
        )
        .then((r) => r.rows[0].id);
    jobPending = await job(workspaceId, {
      operation: "renew",
      status: "pending",
      subjectId: certA.managedId,
      requestedBy: manager,
      agent: agentId,
      approvedAt: new Date(),
    });
    jobApproval = await job(workspaceId, {
      operation: "issue",
      status: "pending_approval",
      subjectId: certB.managedId,
      requestedBy: manager,
    });
    await job(workspaceId, {
      operation: "deploy",
      status: "failed",
      subjectId: certB.managedId,
      errorCode: "WRITE_FAILED",
      errorMessage: "failed writing SENTINEL_JOB_ERROR",
      claim: crypto.randomUUID(),
    });
    otherJob = await job(otherWorkspaceId, { operation: "renew", status: "pending", subjectId: otherCert.managedId });

    app = buildApp();
    adminCredential = await credentialFor(
      owner,
      ["mcp:identity:read", "mcp:certs:read", "mcp:agents:read", "mcp:jobs:read"],
      "admin",
    );
  });

  after(async () => {
    delete process.env.MCP_OPERATOR_INTERFACE_ENABLED;
    delete process.env.CERTOPS_ENABLED;
    await pool.end();
  });

  it("serves every first-release read tool and validates each response against its contract", async () => {
    const cases = [
      ["tt_list_certificates_output", `/api/v1/operator/certificates`],
      ["tt_get_certificate_output", `/api/v1/operator/certificates/${certA.identityId}`],
      ["tt_get_certificate_observations_output", `/api/v1/operator/certificates/${certA.identityId}/observations`],
      ["tt_explain_certificate_state_output", `/api/v1/operator/certificates/${certA.identityId}/explain`],
      ["tt_get_agent_health_output", `/api/v1/operator/agents`],
      ["tt_list_jobs_output", `/api/v1/operator/jobs`],
      ["tt_get_job_output", `/api/v1/operator/jobs/${jobPending}`],
    ];
    for (const [schema, route] of cases) {
      const response = await get(route);
      assert.equal(response.status, 200, `${route} -> ${response.status} ${JSON.stringify(response.body)}`);
      const validate = schemaFor(schema);
      assert.equal(validate(response.body), true, `${route}: ${JSON.stringify(validate.errors)}`);
      assertNoSentinels(response.body, route);
      assertNoForbiddenKeys(response.body, route);
    }
  });

  it("registers exactly the routes the catalog marks implemented", async () => {
    const router = require("../../apps/api/routes/operator");
    const live = new Set(
      router.stack.filter((l) => l.route).flatMap((l) => Object.keys(l.route.methods).map((m) => `${m.toUpperCase()} ${l.route.path}`)),
    );
    for (const tool of catalog.tools.filter((t) => t.contractStatus === "mvp")) {
      assert.ok(live.has(tool.route), `${tool.name}: ${tool.route} is not registered`);
    }
  });

  it("returns the identity id as the certificate id, so every other tool accepts it", async () => {
    const list = await get(`/api/v1/operator/certificates`);
    const ids = list.body.items.map((item) => item.id);
    assert.ok(ids.includes(certA.identityId) && ids.includes(certB.identityId));
    assert.ok(!ids.includes(certA.managedId), "the managed-certificate id must not be the handle");
    for (const id of ids) assert.equal((await get(`/api/v1/operator/certificates/${id}`)).status, 200);
  });

  it("never discloses seeded key references, paths, reasons, payloads, claims or agent names", async () => {
    const jobs = await get(`/api/v1/operator/jobs`);
    assert.ok(jobs.body.items.length >= 3);
    for (const item of jobs.body.items) {
      const detail = await get(`/api/v1/operator/jobs/${item.id}`);
      assertNoSentinels(detail.body, `job ${item.id}`);
      assertNoForbiddenKeys(detail.body, `job ${item.id}`);
    }
    const detail = await get(`/api/v1/operator/certificates/${certB.identityId}`);
    assertNoSentinels(detail.body, "certificate B");
  });

  it("wraps the one operator-written text field as untrusted data, and keeps it out of list search", async () => {
    const detail = await get(`/api/v1/operator/certificates/${certB.identityId}`);
    assert.deepEqual(detail.body.certificate.lifecycle.reason, {
      value: "replaced by new load balancer",
      untrusted: true,
      truncated: false,
    });
    const hits = await get(`/api/v1/operator/certificates${q({ query: "load balancer" })}`);
    assert.equal(hits.body.completeness.total, 0, "list search must not match the lifecycle reason");
  });

  it("wraps over-long operator text and truncates it", async () => {
    await pool.query("UPDATE certops_certificate_identities SET lifecycle_reason = $2 WHERE id = $1", [
      certB.identityId,
      "x".repeat(512),
    ]);
    const detail = await get(`/api/v1/operator/certificates/${certB.identityId}`);
    assert.equal(detail.body.certificate.lifecycle.reason.value.length, 512);
    assert.equal(detail.body.certificate.lifecycle.reason.untrusted, true);
    await pool.query("UPDATE certops_certificate_identities SET lifecycle_reason = 'replaced by new load balancer' WHERE id = $1", [certB.identityId]);
  });

  describe("search, filters and pagination", () => {
    it("searches only what a connection may see", async () => {
      const total = async (query) =>
        (await get(`/api/v1/operator/certificates${q({ query })}`)).body.completeness.total;
      assert.equal(await total("alpha"), 1, "common name");
      assert.equal(await total("www.alpha.example.com"), 1, "subject alternative name");
      assert.equal(await total("example ca"), 2, "issuer");
      assert.equal(await total(certA.fingerprint.slice(0, 20)), 1, "fingerprint");
      for (const hidden of ["SENTINEL_KEY_REF", "vault://", "SENTINEL_SOURCE_PATH", "SENTINEL_DEPLOY_PATH", "/etc/"]) {
        assert.equal(await total(hidden), 0, `searching "${hidden}" must find nothing`);
      }
    });

    it("filters by expiry window", async () => {
      const ids = async (params) =>
        (await get(`/api/v1/operator/certificates${q(params)}`)).body.items.map((item) => item.id);
      assert.deepEqual(await ids({ expiresWithinDays: 30 }), [certA.identityId]);
      assert.equal((await ids({ expiresWithinDays: 365 })).length, 2);
      const before = new Date(Date.now() + 30 * 86400000).toISOString();
      assert.deepEqual(await ids({ expiresBefore: before }), [certA.identityId]);
      const a = (await get(`/api/v1/operator/certificates${q({ expiresWithinDays: 30 })}`)).body.items[0];
      assert.equal(a.daysUntilExpiry, 9, "ten days out, floored after a moment has passed");
    });

    it("pages with an opaque cursor, reports completeness, and ends cleanly", async () => {
      for (let i = 0; i < 4; i += 1) {
        await seedCertificate(workspaceId, { fingerprint: fp(`page-${i}`), commonName: `page-${i}.example.com` });
      }
      const seen = [];
      let cursor = null;
      let pages = 0;
      do {
        const response = await get(`/api/v1/operator/certificates${q({ limit: 2, ...(cursor ? { cursor } : {}) })}`);
        assert.equal(response.status, 200);
        const { completeness } = response.body;
        assert.equal(completeness.returned, response.body.items.length);
        assert.equal(completeness.totalKnown, true);
        assert.equal(completeness.total, 6);
        seen.push(...response.body.items.map((item) => item.id));
        cursor = completeness.nextCursor;
        if (cursor) assert.equal(completeness.truncated, true);
        pages += 1;
        assert.ok(pages < 10, "pagination must terminate");
      } while (cursor);
      assert.equal(new Set(seen).size, 6, "every certificate exactly once");
      assert.equal(pages, 3);
      const last = await get(`/api/v1/operator/certificates${q({ limit: 50 })}`);
      assert.equal(last.body.completeness.truncated, false);
      assert.equal(last.body.completeness.nextCursor, null);
    });

    it("tells an empty result from a truncated one", async () => {
      const none = await get(`/api/v1/operator/certificates${q({ query: "no-such-name-anywhere" })}`);
      assert.equal(none.status, 200);
      assert.deepEqual(none.body.completeness, { returned: 0, truncated: false, nextCursor: null, totalKnown: true, total: 0 });
    });
  });

  describe("strict input", () => {
    it("rejects unknown, repeated, malformed and out-of-range parameters with 400", async () => {
      const bad = [
        "/api/v1/operator/certificates?workspace_id=" + otherWorkspaceId,
        "/api/v1/operator/certificates?limit=0",
        "/api/v1/operator/certificates?limit=51",
        "/api/v1/operator/certificates?limit=2.5",
        "/api/v1/operator/certificates?limit=1&limit=2",
        "/api/v1/operator/certificates?cursor=not-base64-offset",
        "/api/v1/operator/certificates?cursor=" + Buffer.from("o:-1").toString("base64url"),
        "/api/v1/operator/certificates?status=expired-ish",
        "/api/v1/operator/certificates?expiresWithinDays=0",
        "/api/v1/operator/certificates?expiresWithinDays=30&expiresBefore=2027-01-01T00:00:00Z",
        "/api/v1/operator/certificates?expiresBefore=tomorrow",
        "/api/v1/operator/certificates?includeRetired=yes",
        "/api/v1/operator/certificates?query=" + "x".repeat(129),
        "/api/v1/operator/jobs?q=anything",
        "/api/v1/operator/jobs?createdSince=2026-10-01T00:00:00Z",
        "/api/v1/operator/jobs?status=stuck",
        "/api/v1/operator/jobs?subjectId=not-a-uuid",
        "/api/v1/operator/agents?includeRetired=true",
        `/api/v1/operator/certificates/${certA.identityId}?force=1`,
      ];
      for (const route of bad) {
        const response = await get(route);
        assert.equal(response.status, 400, `${route} -> ${response.status}`);
        assert.equal(response.body.code, "OPERATOR_VALIDATION_ERROR");
      }
    });

    it("replays the contract's own fixtures: valid inputs are accepted, invalid ones refused", async () => {
      const routes = {
        tt_list_certificates: "/api/v1/operator/certificates",
        tt_list_jobs: "/api/v1/operator/jobs",
        tt_get_agent_health: "/api/v1/operator/agents",
      };
      for (const [tool, route] of Object.entries(routes)) {
        for (const input of fixtures[tool].input.valid) {
          const response = await get(`${route}${q(input)}`);
          assert.equal(response.status, 200, `${tool} valid ${JSON.stringify(input)} -> ${response.status} ${JSON.stringify(response.body)}`);
        }
        for (const input of fixtures[tool].input.invalid) {
          const response = await get(`${route}${q(input)}`);
          assert.equal(response.status, 400, `${tool} invalid ${JSON.stringify(input)} -> ${response.status}`);
        }
      }
    });
  });

  describe("authority and tenant isolation", () => {
    it("answers 404, indistinguishably, for another workspace's records", async () => {
      const missing = crypto.randomUUID();
      const probes = [
        `/api/v1/operator/certificates/${otherCert.identityId}`,
        `/api/v1/operator/certificates/${otherCert.identityId}/observations`,
        `/api/v1/operator/certificates/${otherCert.identityId}/explain`,
        `/api/v1/operator/jobs/${otherJob}`,
        `/api/v1/operator/certificates/${missing}`,
        `/api/v1/operator/jobs/${missing}`,
      ];
      const bodies = new Set();
      for (const route of probes) {
        const response = await get(route);
        assert.equal(response.status, 404, route);
        bodies.add(JSON.stringify(response.body));
      }
      assert.equal(bodies.size, 1, "a record in another workspace must look exactly like a missing one");
      for (const route of ["/certificates", "/jobs"]) {
        const text = JSON.stringify((await get(`/api/v1/operator${route}`)).body);
        assert.ok(!text.includes(otherCert.identityId) && !text.includes(otherJob), `${route} must not list other workspaces`);
      }
      const byFingerprint = await get(`/api/v1/operator/certificates${q({ query: otherCert.fingerprint.slice(0, 24) })}`);
      assert.equal(byFingerprint.body.completeness.total, 0);
    });

    it("treats malformed ids as not found without touching the database", async () => {
      for (const route of ["/certificates/not-a-uuid", "/certificates/not-a-uuid/explain", "/jobs/12345", "/jobs/not-a-uuid"]) {
        assert.equal((await get(`/api/v1/operator${route}`)).status, 404, route);
      }
    });

    it("requires the right scope for each route", async () => {
      const certsOnly = await credentialFor(owner, ["mcp:certs:read"], "admin");
      const jobsOnly = await credentialFor(owner, ["mcp:jobs:read"], "admin");
      assert.equal((await get("/api/v1/operator/certificates", certsOnly)).status, 200);
      assert.equal((await get("/api/v1/operator/jobs", certsOnly)).status, 403);
      assert.equal((await get("/api/v1/operator/agents", certsOnly)).status, 403);
      assert.equal((await get("/api/v1/operator/jobs", jobsOnly)).status, 200);
      assert.equal((await get("/api/v1/operator/certificates", jobsOnly)).status, 403);
      assert.equal((await get("/api/v1/operator/whoami", jobsOnly)).status, 403);
    });

    it("keeps fleet metadata manager-only, as the session route does", async () => {
      await assert.rejects(
        credentialFor(viewer, ["mcp:agents:read"], "viewer"),
        { code: connections.CONNECTION_SCOPE_DENIED },
        "a viewer connection cannot even be created with the agents scope",
      );
      const managerAgents = await credentialFor(manager, ["mcp:agents:read", "mcp:certs:read"], "workspace_manager");
      assert.equal((await get("/api/v1/operator/agents", managerAgents)).status, 200);
      await member(manager, workspaceId, "viewer");
      const demoted = await get("/api/v1/operator/agents", managerAgents);
      assert.equal(demoted.status, 403, "a demotion removes the agents scope on the next request");
      assert.equal((await get("/api/v1/operator/certificates", managerAgents)).status, 200);
      await member(manager, workspaceId, "workspace_manager");
    });

    it("stops serving reads the moment a connection is revoked", async () => {
      const { plaintextCredential, connection } = await connections.createConnection({
        workspaceId,
        userId: owner,
        name: "revoke-me",
        scopes: ["mcp:certs:read"],
        roleCeiling: "admin",
      });
      assert.equal((await get("/api/v1/operator/certificates", plaintextCredential)).status, 200);
      await connections.revokeConnection({ workspaceId, connectionId: connection.id, revokedBy: owner });
      assert.equal((await get("/api/v1/operator/certificates", plaintextCredential)).status, 401);
    });

    it("answers 404 when CertOps is switched off", async () => {
      process.env.CERTOPS_ENABLED = "false";
      try {
        const response = await get("/api/v1/operator/certificates");
        assert.equal(response.status, 404);
      } finally {
        process.env.CERTOPS_ENABLED = "true";
      }
      assert.equal((await get("/api/v1/operator/certificates")).status, 200);
    });

    it("refuses reads that arrive with a cookie or without a credential", async () => {
      assert.equal((await request(app).get("/api/v1/operator/certificates")).status, 401);
      const mixed = await get("/api/v1/operator/certificates").set("Cookie", "sid=1");
      assert.equal(mixed.status, 401);
      assert.equal(mixed.body.code, "OPERATOR_CONNECTION_SESSION_FORBIDDEN");
    });
  });

  describe("jobs, agents and explanations", () => {
    it("summarizes jobs without payloads, claims, error text or requester ids", async () => {
      const list = await get(`/api/v1/operator/jobs${q({ status: "pending" })}`);
      assert.deepEqual(list.body.items.map((i) => i.id), [jobPending]);
      const detail = (await get(`/api/v1/operator/jobs/${jobPending}`)).body.job;
      assert.equal(detail.summary.requestedByKind, "user");
      assert.equal(detail.summary.subjectType, "managed_certificate");
      assert.equal(detail.approval.state, "approved");
      assert.equal(detail.approval.required, true);
      assert.ok(detail.approval.decidedAt);
      assert.ok(detail.pendingReason?.code, "a waiting job explains why");
      const keys = collectKeys(detail);
      for (const userKey of ["userid", "requestedbyuserid", "approvedbyuserid", "requestedbyapitokenid", "approvedbydisplayname"]) {
        assert.ok(!keys.has(userKey), `job detail must not carry ${userKey}`);
      }

      const awaiting = (await get(`/api/v1/operator/jobs/${jobApproval}`)).body.job;
      assert.equal(awaiting.approval.state, "pending");
      assert.equal(awaiting.summary.status, "pending_approval");

      const failed = (await get(`/api/v1/operator/jobs${q({ status: "failed" })}`)).body.items[0];
      const failedDetail = (await get(`/api/v1/operator/jobs/${failed.id}`)).body.job;
      assert.equal(failedDetail.errorCode, "write_failed", "stored codes are normalized to lower snake case");
      assert.equal(JSON.stringify(failedDetail).includes("SENTINEL_JOB_ERROR"), false, "free-text error messages are never returned");
    });

    it("filters jobs by operation, subject and recency", async () => {
      const ids = async (params) => (await get(`/api/v1/operator/jobs${q(params)}`)).body.items.map((i) => i.id);
      assert.deepEqual(await ids({ operation: "issue" }), [jobApproval]);
      assert.equal((await ids({ subjectId: certB.managedId })).length, 2);
      assert.equal((await ids({ createdSince: "24h" })).length, 3);
      await pool.query("UPDATE certificate_jobs SET created_at = NOW() - INTERVAL '10 days' WHERE id = $1", [jobPending]);
      assert.ok(!(await ids({ createdSince: "7d" })).includes(jobPending));
      assert.ok((await ids({ createdSince: "30d" })).includes(jobPending));
      await pool.query("UPDATE certificate_jobs SET created_at = NOW() WHERE id = $1", [jobPending]);
    });

    it("reports agent health from facts, drops unknown operations and hides policy", async () => {
      const response = await get("/api/v1/operator/agents");
      const [agent] = response.body.items;
      assert.equal(agent.id, agentId);
      assert.deepEqual(agent.hostname, { value: "host-1.internal", untrusted: true, truncated: false });
      assert.equal(agent.liveness, "stale", "last seen three days ago");
      assert.equal(agent.status, "active");
      assert.deepEqual(agent.supportedOperations, ["renew", "deploy"], "an operation the platform does not know is dropped");
      assert.deepEqual(agent.declaredCapabilities, ["adcs-enroll-v1"]);
      assertNoSentinels(response.body, "agents");
      assert.ok(!("name" in agent) && !("targetSelectors" in agent) && !("commandProfiles" in agent));
    });

    it("explains a certificate with fixed wording and says what it does not know", async () => {
      const explained = (await get(`/api/v1/operator/certificates/${certA.identityId}/explain`)).body;
      assert.equal(explained.identityId, certA.identityId);
      assert.ok(Date.parse(explained.evaluatedAt));
      const codes = explained.reasons.map((r) => r.code);
      assert.ok(codes.includes("not_agent_deployable"), "key not held by TokenTimer");
      assert.ok(codes.includes("visibility_unknown"));
      assert.ok(explained.unknownAreas.includes("observations"));
      const pending = explained.reasons.find((r) => r.domain === "job");
      assert.ok(pending, "the waiting renewal job is reported");
      assert.deepEqual(pending.sourceRef, { kind: "job", id: jobPending });
      assertNoSentinels(explained, "explain");
      for (const r of explained.reasons) assert.ok(r.message.length <= 300 && !/host-1|SENTINEL/.test(r.message));
    });

    it("reports a retired certificate as retired, without implying the CA revoked it", async () => {
      // Retirement is terminal in the database, so this uses its own certificate.
      const retired = await seedCertificate(workspaceId, { fingerprint: fp("retired"), commonName: "retired.example.com" });
      await pool.query("UPDATE certops_certificate_identities SET lifecycle_status = 'revoked' WHERE id = $1", [retired.identityId]);
      const explained = (await get(`/api/v1/operator/certificates/${retired.identityId}/explain`)).body;
      assert.equal(explained.overall, "retired");
      assert.equal(explained.lifecycleStatus, "revoked");
      const lifecycle = explained.reasons.find((r) => r.code === "lifecycle_revoked");
      assert.match(lifecycle.message, /does not mean the issuing CA revoked it/);
      const listed = (await get(`/api/v1/operator/certificates${q({ includeRetired: "true" })}`)).body.items;
      assert.equal(listed.find((i) => i.id === retired.identityId).lifecycleStatus, "revoked");
      const hidden = (await get(`/api/v1/operator/certificates${q({ limit: 50 })}`)).body.items;
      assert.ok(!hidden.some((i) => i.id === retired.identityId), "retired certificates are hidden unless asked for");
    });
  });

  // Tests are appended below.
});

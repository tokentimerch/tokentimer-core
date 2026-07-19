const crypto = require("crypto");
const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("module");
const supertest = require("supertest");
const Ajv = require("ajv");
const addFormats = require("ajv-formats");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();
const {
  createApiToken,
  getApiTokenById,
} = require("../../apps/api/services/certops/apiTokens");
const {
  createCertificateJob,
  getCertificateJobById,
  listCertificateJobLog,
} = require("../../apps/api/services/certops/jobs");
const {
  getCertificateEvidenceById,
  listCertificateEvidence,
} = require("../../apps/api/services/certops/evidence");
const {
  createCsrfExemptMiddleware,
  isCertOpsMachineTokenCsrfExemptPath,
} = require("../../apps/api/middleware/csrf-exempt");
const {
  createCertOpsExecutorRouter,
} = require("../../apps/api/routes/certops-executor");
const {
  CERTOPS_EXECUTOR_EVENTS_PATH,
  CERTOPS_EXECUTOR_EVENT_BODY_LIMIT_BYTES,
  createCertOpsMachineWritePreParserBoundary,
} = require("../../apps/api/middleware/certops-executor-body-parser");

const apiRequire = createRequire(
  require.resolve("../../apps/api/package.json"),
);
const swaggerJsdocRequire = createRequire(apiRequire.resolve("swagger-jsdoc"));
const yaml = swaggerJsdocRequire("yaml");
const express = apiRequire("express");

const openApiDocument = yaml.parse(
  fs.readFileSync(
    path.resolve(__dirname, "../../packages/contracts/openapi/openapi.yaml"),
    "utf8",
  ),
);
const openApiAjv = new Ajv({ allErrors: true, strict: false });
addFormats(openApiAjv);
const validateExecutorAcceptedResponse = openApiAjv.compile(
  openApiDocument.components.schemas.CertOpsExecutorEventAcceptedResponse,
);

const PRIVATE_KEY_PEM =
  "-----BEGIN RSA PRIVATE KEY-----\nRkFLRS1OT1QtQS1SRUFMLUtFWQ==\n-----END RSA PRIVATE KEY-----";
const ENCRYPTED_PKCS8_DER = Buffer.from([
  0x30, 0x13,
  0x30, 0x0b,
  0x06, 0x07, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37,
  0x05, 0x00,
  0x04, 0x04, 0xde, 0xad, 0xbe, 0xef,
]);

function expectAcceptedResponseMatchesOpenApi(response) {
  expect(
    validateExecutorAcceptedResponse(response.body),
    JSON.stringify(validateExecutorAcceptedResponse.errors),
  ).to.equal(true);
}

function derLength(length) {
  if (length < 128) return Buffer.from([length]);
  const bytes = [];
  for (let remaining = length; remaining > 0; remaining >>>= 8) {
    bytes.unshift(remaining & 0xff);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function derTlv(tag, content) {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

function longOidEncryptedPkcs8Der() {
  const oid = Buffer.concat([
    Buffer.from([0x2a]),
    Buffer.alloc(128, 0x81),
    Buffer.from([0x01]),
  ]);
  const algorithm = derTlv(0x30, derTlv(0x06, oid));
  return derTlv(
    0x30,
    Buffer.concat([algorithm, derTlv(0x04, Buffer.from([0xde, 0xad]))]),
  );
}

async function createWorkspacePair(label) {
  const ownerEmail = `${label}-${Date.now()}-${crypto.randomUUID()}@example.com`;
  const owner = await TestUtils.execQuery(
    `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
     VALUES ($1, $2, $3, $4, 'local', TRUE)
     RETURNING id`,
    [
      ownerEmail.toLowerCase(),
      ownerEmail,
      label,
      "not-used-in-certops-executor-events-test",
    ],
  );
  const ownerId = owner.rows[0].id;
  const workspaceA = crypto.randomUUID();
  const workspaceB = crypto.randomUUID();

  await TestUtils.execQuery(
    `INSERT INTO workspaces (id, name, created_by, plan)
     VALUES ($1, $2, $3, 'oss'), ($4, $5, $3, 'oss')`,
    [
      workspaceA,
      `${label} A`,
      ownerId,
      workspaceB,
      `${label} B`,
    ],
  );

  return { ownerId, workspaceA, workspaceB };
}

async function cleanupWorkspacePair(ownerId, workspaceIds) {
  await TestUtils.execQuery(
    "DELETE FROM audit_events WHERE workspace_id = ANY($1::uuid[])",
    [workspaceIds],
  );
  await TestUtils.execQuery(
    "DELETE FROM certificate_executor_events WHERE workspace_id = ANY($1::uuid[])",
    [workspaceIds],
  );
  await TestUtils.execQuery(
    "DELETE FROM certificate_evidence WHERE workspace_id = ANY($1::uuid[])",
    [workspaceIds],
  );
  await TestUtils.execQuery(
    "DELETE FROM certificate_job_log WHERE workspace_id = ANY($1::uuid[])",
    [workspaceIds],
  );
  await TestUtils.execQuery(
    "DELETE FROM certificate_jobs WHERE workspace_id = ANY($1::uuid[])",
    [workspaceIds],
  );
  await TestUtils.execQuery(
    "DELETE FROM api_tokens WHERE workspace_id = ANY($1::uuid[])",
    [workspaceIds],
  );
  await TestUtils.execQuery("DELETE FROM workspaces WHERE id = ANY($1::uuid[])", [
    workspaceIds,
  ]);
  await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
}

function buildExecutorApp({
  rateLimitOptions,
  csrf = false,
  authMiddleware,
  certOpsEnabledMiddleware,
} = {}) {
  const app = express();
  app.use(
    createCertOpsMachineWritePreParserBoundary({
      rateLimitOptions: rateLimitOptions || { windowMs: 60_000, max: 100 },
    }),
  );
  app.use(express.json());

  if (csrf) {
    app.use(
      "/api",
      createCsrfExemptMiddleware((_req, res) =>
        res.status(403).json({
          error: "Invalid CSRF token",
          code: "EBADCSRFTOKEN",
        }),
        { allowPath: isCertOpsMachineTokenCsrfExemptPath },
      ),
    );
  }

  app.use(
    createCertOpsExecutorRouter({
      rateLimitOptions: rateLimitOptions || { windowMs: 60_000, max: 100 },
      authMiddleware,
      certOpsEnabledMiddleware,
    }),
  );
  app.post("/api/v1/workspaces/:id/certops/unrelated-write", (_req, res) =>
    res.status(200).json({ ok: true }),
  );
  app.use((err, _req, res, next) => {
    if (res.headersSent) return next(err);
    return res.status(500).json({
      error: "Internal test harness error",
      code: err?.code || "INTERNAL_ERROR",
    });
  });

  return app;
}

async function createScopedToken({ workspaceId, ownerId, scopes }) {
  return createApiToken({
    workspaceId,
    name: "Executor",
    scopes,
    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
    createdBy: ownerId,
  });
}

async function createJob({ workspaceId, ownerId, status = "pending" }) {
  return createCertificateJob({
    workspaceId,
    operation: "deploy",
    source: "api",
    subjectType: "managed_certificate",
    subjectId: `cert-${crypto.randomUUID()}`,
    payload: {
      deploymentTarget: "kubernetes/default/web-cert",
      fingerprintSha256:
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
    status,
    requestedByUserId: ownerId,
  });
}

function eventPayload({ workspaceId, jobId, eventType = "job.started", status = "running", ...overrides }) {
  return {
    schemaVersion: 1,
    eventId: `event-${crypto.randomUUID()}`,
    workspaceId,
    jobId,
    eventType,
    status,
    occurredAt: new Date().toISOString(),
    message: "Executor event accepted",
    metadata: [{ name: "executor", value: "test-executor" }],
    ...overrides,
  };
}

async function countJobArtifacts({ workspaceId, jobId }) {
  const logs = await listCertificateJobLog({ workspaceId, jobId });
  const evidence = await listCertificateEvidence({ workspaceId, jobId });
  const executorEvents = await TestUtils.execQuery(
    `SELECT COUNT(*)::int AS count
       FROM certificate_executor_events
      WHERE workspace_id = $1
        AND job_id = $2`,
    [workspaceId, jobId],
  );
  return {
    logs: logs.items.length,
    evidence: evidence.items.length,
    executorEvents: executorEvents.rows[0].count,
  };
}

async function countExecutorEventRecords({ workspaceId, jobId }) {
  const result = await TestUtils.execQuery(
    `SELECT COUNT(*)::integer AS count
       FROM certificate_executor_events
      WHERE workspace_id = $1
        AND job_id = $2`,
    [workspaceId, jobId],
  );
  return result.rows[0].count;
}

async function auditActionCounts({ workspaceId, jobId = null }) {
  const result = await TestUtils.execQuery(
    `SELECT action, COUNT(*)::integer AS count
       FROM audit_events
      WHERE workspace_id = $1
        AND ($2::text IS NULL OR metadata->>'jobId' = $2)
      GROUP BY action`,
    [workspaceId, jobId],
  );
  return Object.fromEntries(result.rows.map((row) => [row.action, row.count]));
}

async function listCertOpsAuditEvents(workspaceId) {
  const rows = await TestUtils.execQuery(
    `SELECT action, metadata
       FROM audit_events
      WHERE workspace_id = $1
        AND action LIKE 'CERTOPS_%'
      ORDER BY id ASC`,
    [workspaceId],
  );
  return rows.rows;
}

function expectNoSensitiveValues(body, rawToken, extraForbidden = []) {
  const serialized = JSON.stringify(body);
  expect(serialized).to.not.include(rawToken);
  expect(serialized).to.not.include(`Bearer ${rawToken}`);
  expect(serialized).to.not.include("Authorization");
  expect(serialized).to.not.include("token_hash");
  expect(serialized).to.not.include("PRIVATE KEY");
  expect(serialized).to.not.include("password=swordfish");
  for (const value of extraForbidden) {
    expect(serialized).to.not.include(value);
  }
}

describe("CertOps executor event ingestion", function () {
  this.timeout(60000);

  before(async () => {
    await runMigrations();
  });

  it("requires a valid machine token with certops:events:write scope", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-auth",
    );

    try {
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const scoped = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write"],
      });
      const jobsOnly = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:jobs:read"],
      });
      const app = buildExecutorApp();
      const route = "/api/v1/certops/executor/events";
      const payload = eventPayload({ workspaceId: workspaceA, jobId: job.id });

      const missing = await supertest(app).post(route).send(payload);
      expect(missing.status).to.equal(401);
      expect(missing.body.code).to.equal("CERTOPS_API_TOKEN_UNAUTHORIZED");

      const malformed = await supertest(app)
        .post(route)
        .set("Authorization", "Bearer ttx__bad")
        .send(payload);
      expect(malformed.status).to.equal(401);
      expect(JSON.stringify(malformed.body)).to.not.include("ttx__bad");

      const missingScope = await supertest(app)
        .post(route)
        .set("Authorization", `Bearer ${jobsOnly.plaintextToken}`)
        .send(payload);
      expect(missingScope.status).to.equal(403);
      expect(missingScope.body.code).to.equal("CERTOPS_API_TOKEN_SCOPE_DENIED");
      expectNoSensitiveValues(missingScope.body, jobsOnly.plaintextToken);

      const wrongWorkspaceHint = await supertest(app)
        .post(route)
        .set("Authorization", `Bearer ${scoped.plaintextToken}`)
        .send(eventPayload({ workspaceId: workspaceB, jobId: job.id }));
      expect(wrongWorkspaceHint.status).to.equal(401);
      expectNoSensitiveValues(wrongWorkspaceHint.body, scoped.plaintextToken);

      const ok = await supertest(app)
        .post(route)
        .set("Authorization", `Bearer ${scoped.plaintextToken}`)
        .send(payload);
      expect(ok.status).to.equal(202);
      expect(ok.body.ok).to.equal(true);
      expect(ok.body.eventId).to.be.a("string").that.is.not.empty;
      expect(ok.body.jobId).to.equal(job.id);
      expect(ok.body.status).to.equal("running");
      expect(ok.body.evidenceId).to.equal(null);
      expect(ok.body.accepted).to.equal(undefined);
      expect(ok.body.code).to.equal(undefined);
      expect(ok.body.user).to.equal(undefined);
      expect(ok.body.authenticated).to.equal(undefined);
      expectNoSensitiveValues(ok.body, scoped.plaintextToken);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("rejects oversized executor JSON before authentication or route handling", async () => {
    const response = await supertest(buildExecutorApp())
      .post(CERTOPS_EXECUTOR_EVENTS_PATH)
      .set("Content-Type", "application/json")
      .send(
        `{"payload":"${"a".repeat(CERTOPS_EXECUTOR_EVENT_BODY_LIMIT_BYTES)}"}`,
      );

    expect(response.status).to.equal(413);
    expect(response.body).to.deep.equal({
      error: "Executor event payload is too large",
      code: "CERTOPS_EXECUTOR_EVENT_BODY_TOO_LARGE",
    });
  });

  it("applies the dedicated pre-parser boundary to every exact machine write route", async () => {
    const jobId = crypto.randomUUID();
    for (const executorRoute of [
      "/api/v1/certops/executor/events",
      "/API/v1/CertOps/Executor/Events/",
      `/api/v1/certops/jobs/${jobId}/events`,
      `/API/v1/CertOps/Jobs/${jobId}/Events/`,
      `/api/v1/certops/jobs/${jobId}/evidence`,
      `/API/v1/CertOps/Jobs/${jobId}/Evidence/`,
    ]) {
      let authCalls = 0;
      const app = buildExecutorApp({
        rateLimitOptions: { windowMs: 60_000, max: 2 },
        authMiddleware: (_req, _res, next) => {
          authCalls += 1;
          return next();
        },
      });

      const malformed = await supertest(app)
        .post(executorRoute)
        .set("Content-Type", "application/json")
        .send('{"payload":');
      expect(malformed.status).to.equal(400);
      expect(malformed.body.code).to.equal("CERTOPS_EXECUTOR_EVENT_INVALID");
      expect(authCalls).to.equal(0);

      const oversized = await supertest(app)
        .post(executorRoute)
        .set("Content-Type", "application/json")
        .send(
          `{"payload":"${"a".repeat(CERTOPS_EXECUTOR_EVENT_BODY_LIMIT_BYTES)}"}`,
        );
      expect(oversized.status).to.equal(413);
      expect(oversized.body.code).to.equal(
        "CERTOPS_EXECUTOR_EVENT_BODY_TOO_LARGE",
      );
      expect(authCalls).to.equal(0);

      const blocked = await supertest(app)
        .post(executorRoute)
        .send({ public: true });
      expect(blocked.status).to.equal(429);
      expect(blocked.body.code).to.equal("CERTOPS_MACHINE_RATE_LIMITED");
      expect(authCalls).to.equal(0);
    }
  });

  it("hides executor ingestion when CertOps is disabled before token validation or persistence", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-disabled",
    );

    try {
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write"],
      });
      let authCalls = 0;
      const app = buildExecutorApp({
        certOpsEnabledMiddleware: (_req, res) =>
          res.status(404).json({ error: "Endpoint not found", code: "NOT_FOUND" }),
        authMiddleware: (_req, _res, next) => {
          authCalls += 1;
          return next();
        },
      });
      const before = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      const response = await supertest(app)
        .post("/api/v1/certops/executor/events")
        .set("Authorization", `Bearer ${token.plaintextToken}`)
        .send(eventPayload({ workspaceId: workspaceA, jobId: job.id }));
      const after = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      const persistedToken = await getApiTokenById({
        workspaceId: workspaceA,
        tokenId: token.token.id,
      });

      expect(response.status).to.equal(404);
      expect(response.body).to.deep.equal({
        error: "Endpoint not found",
        code: "NOT_FOUND",
      });
      expect(authCalls).to.equal(0);
      expect(after).to.deep.equal(before);
      expect(
        await countExecutorEventRecords({
          workspaceId: workspaceA,
          jobId: job.id,
        }),
      ).to.equal(0);
      expect(persistedToken.lastUsedAt).to.equal(null);
      expectNoSensitiveValues(response.body, token.plaintextToken);

    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("requires evidence write scope for aggregate executor evidence payloads", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-evidence-scope",
    );

    try {
      const app = buildExecutorApp();
      const route = "/api/v1/certops/executor/events";
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const eventsOnly = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write"],
      });
      const evidenceOnly = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:evidence:write"],
      });
      const combined = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write", "certops:evidence:write"],
      });

      const started = await supertest(app)
        .post(route)
        .set("Authorization", `Bearer ${eventsOnly.plaintextToken}`)
        .send(eventPayload({ workspaceId: workspaceA, jobId: job.id }));
      expect(started.status).to.equal(202);

      const evidenceEventBefore = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      const evidenceEventDenied = await supertest(app)
        .post(route)
        .set("Authorization", `Bearer ${eventsOnly.plaintextToken}`)
        .send(
          eventPayload({
            workspaceId: workspaceA,
            jobId: job.id,
            eventId: `event-${crypto.randomUUID()}`,
            eventType: "evidence.attached",
            status: "accepted",
            evidence: [{ eventType: "certificate.observed" }],
          }),
        );
      const evidenceEventAfter = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(evidenceEventDenied.status).to.equal(403);
      expect(evidenceEventDenied.body.code).to.equal(
        "CERTOPS_API_TOKEN_SCOPE_DENIED",
      );
      expect(evidenceEventAfter).to.deep.equal(evidenceEventBefore);
      expectNoSensitiveValues(evidenceEventDenied.body, eventsOnly.plaintextToken);

      const evidenceArrayDenied = await supertest(app)
        .post(route)
        .set("Authorization", `Bearer ${eventsOnly.plaintextToken}`)
        .send(
          eventPayload({
            workspaceId: workspaceA,
            jobId: job.id,
            eventId: `event-${crypto.randomUUID()}`,
            eventType: "job.progress",
            status: "running",
            evidence: [
              {
                schemaVersion: 1,
                evidenceId: `evidence-${crypto.randomUUID()}`,
                jobId: job.id,
                workspaceId: workspaceA,
                certificateId: "cert-1",
                eventType: "certificate.observed",
                source: "executor",
                observedAt: new Date().toISOString(),
              },
            ],
          }),
        );
      const evidenceArrayAfter = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(evidenceArrayDenied.status).to.equal(403);
      expect(evidenceArrayDenied.body.code).to.equal(
        "CERTOPS_API_TOKEN_SCOPE_DENIED",
      );
      expect(evidenceArrayAfter).to.deep.equal(evidenceEventBefore);
      expectNoSensitiveValues(evidenceArrayDenied.body, eventsOnly.plaintextToken);

      const privateKeyBefore = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      const privateKeyRejected = await supertest(app)
        .post(route)
        .set("Authorization", `Bearer ${eventsOnly.plaintextToken}`)
        .send(
          eventPayload({
            workspaceId: workspaceA,
            jobId: job.id,
            eventId: `event-${crypto.randomUUID()}`,
            eventType: "evidence.attached",
            status: "accepted",
            evidence: [
              {
                schemaVersion: 1,
                eventType: "certificate.observed",
                source: "executor",
                observedAt: new Date().toISOString(),
                output: PRIVATE_KEY_PEM,
              },
            ],
          }),
        );
      const privateKeyAfter = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(privateKeyRejected.status).to.equal(422);
      expect(privateKeyRejected.body.code).to.equal(
        "PRIVATE_KEY_MATERIAL_REJECTED",
      );
      expect(privateKeyAfter).to.deep.equal(privateKeyBefore);
      expectNoSensitiveValues(privateKeyRejected.body, eventsOnly.plaintextToken);

      const attached = await supertest(app)
        .post(route)
        .set("Authorization", `Bearer ${combined.plaintextToken}`)
        .send(
          eventPayload({
            workspaceId: workspaceA,
            jobId: job.id,
            eventId: `event-${crypto.randomUUID()}`,
            eventType: "evidence.attached",
            status: "accepted",
            evidence: [
              {
                schemaVersion: 1,
                evidenceId: `evidence-${crypto.randomUUID()}`,
                jobId: job.id,
                workspaceId: workspaceA,
                certificateId: "cert-1",
                eventType: "certificate.observed",
                source: "executor",
                observedAt: new Date().toISOString(),
              },
            ],
          }),
        );
      expect(attached.status).to.equal(202);
      expect(attached.body.evidenceIds).to.have.length(1);
      expectNoSensitiveValues(attached.body, combined.plaintextToken);

      const evidenceOnlyAggregateDenied = await supertest(app)
        .post(route)
        .set("Authorization", `Bearer ${evidenceOnly.plaintextToken}`)
        .send(
          eventPayload({
            workspaceId: workspaceA,
            jobId: job.id,
            eventId: `event-${crypto.randomUUID()}`,
            eventType: "job.started",
            status: "running",
          }),
        );
      expect(evidenceOnlyAggregateDenied.status).to.equal(403);
      expect(evidenceOnlyAggregateDenied.body.code).to.equal(
        "CERTOPS_API_TOKEN_SCOPE_DENIED",
      );
      expectNoSensitiveValues(
        evidenceOnlyAggregateDenied.body,
        evidenceOnly.plaintextToken,
      );
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("rejects empty evidence operations before idempotency, audit, or job side effects", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-required-evidence",
    );

    try {
      const app = buildExecutorApp();
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write", "certops:evidence:write"],
      });
      const auth = `Bearer ${token.plaintextToken}`;
      const aggregateRoute = "/api/v1/certops/executor/events";
      const eventRoute = `/api/v1/certops/jobs/${job.id}/events`;
      const evidenceRoute = `/api/v1/certops/jobs/${job.id}/evidence`;
      const requests = [
        {
          route: aggregateRoute,
          body: eventPayload({
            workspaceId: workspaceA,
            jobId: job.id,
            eventType: "evidence.attached",
            status: "accepted",
          }),
        },
        {
          route: aggregateRoute,
          body: eventPayload({
            workspaceId: workspaceA,
            jobId: job.id,
            eventType: "evidence.attached",
            status: "accepted",
            evidence: null,
          }),
        },
        {
          route: aggregateRoute,
          body: eventPayload({
            workspaceId: workspaceA,
            jobId: job.id,
            eventType: "evidence.attached",
            status: "accepted",
            evidence: [],
          }),
        },
        {
          route: aggregateRoute,
          body: eventPayload({
            workspaceId: workspaceA,
            jobId: job.id,
            eventType: "evidence.attached",
            status: "accepted",
            evidence: "   ",
          }),
        },
        {
          route: eventRoute,
          body: {
            schemaVersion: 1,
            eventId: `event-${crypto.randomUUID()}`,
            eventType: "evidence.attached",
            status: "accepted",
            occurredAt: new Date().toISOString(),
          },
        },
        {
          route: evidenceRoute,
          body: {
            schemaVersion: 1,
            eventId: `event-${crypto.randomUUID()}`,
            occurredAt: new Date().toISOString(),
          },
        },
      ];

      const artifactsBefore = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      const auditsBefore = await auditActionCounts({
        workspaceId: workspaceA,
        jobId: job.id,
      });

      for (const request of requests) {
        const response = await supertest(app)
          .post(request.route)
          .set("Authorization", auth)
          .send(request.body);

        expect(response.status).to.equal(400);
        expect(response.body.code).to.equal("CERTOPS_EVIDENCE_INVALID");
        expectNoSensitiveValues(response.body, token.plaintextToken);
      }

      expect(
        await countJobArtifacts({ workspaceId: workspaceA, jobId: job.id }),
      ).to.deep.equal(artifactsBefore);
      expect(
        await auditActionCounts({ workspaceId: workspaceA, jobId: job.id }),
      ).to.deep.equal(auditsBefore);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("preserves private-key rejection precedence over empty evidence on every machine route", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-empty-evidence-key-material",
    );

    try {
      const app = buildExecutorApp();
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write", "certops:evidence:write"],
      });
      const auth = `Bearer ${token.plaintextToken}`;
      const requests = [
        {
          route: "/api/v1/certops/executor/events",
          body: eventPayload({
            workspaceId: workspaceA,
            jobId: job.id,
            eventType: "evidence.attached",
            status: "accepted",
            evidence: [],
            message: PRIVATE_KEY_PEM,
          }),
        },
        {
          route: `/api/v1/certops/jobs/${job.id}/events`,
          body: {
            schemaVersion: 1,
            eventId: `event-${crypto.randomUUID()}`,
            eventType: "evidence.attached",
            status: "accepted",
            occurredAt: new Date().toISOString(),
            evidence: [],
            message: PRIVATE_KEY_PEM,
          },
        },
        {
          route: `/api/v1/certops/jobs/${job.id}/evidence`,
          body: {
            schemaVersion: 1,
            eventId: `event-${crypto.randomUUID()}`,
            occurredAt: new Date().toISOString(),
            evidence: [],
            message: PRIVATE_KEY_PEM,
          },
        },
      ];

      for (const request of requests) {
        const beforeArtifacts = await countJobArtifacts({
          workspaceId: workspaceA,
          jobId: job.id,
        });
        const beforeStatus = (
          await getCertificateJobById({ workspaceId: workspaceA, jobId: job.id })
        ).status;
        const beforeAudits = await auditActionCounts({ workspaceId: workspaceA });

        const response = await supertest(app)
          .post(request.route)
          .set("Authorization", auth)
          .send(request.body);

        const afterAudits = await auditActionCounts({ workspaceId: workspaceA });
        expect(response.status).to.equal(422);
        expect(response.body.code).to.equal("PRIVATE_KEY_MATERIAL_REJECTED");
        expectNoSensitiveValues(response.body, token.plaintextToken, [PRIVATE_KEY_PEM]);
        expect(
          await countJobArtifacts({ workspaceId: workspaceA, jobId: job.id }),
        ).to.deep.equal(beforeArtifacts);
        expect(
          (
            await getCertificateJobById({ workspaceId: workspaceA, jobId: job.id })
          ).status,
        ).to.equal(beforeStatus);
        expect(afterAudits.CERTOPS_KEY_MATERIAL_REJECTED || 0).to.equal(
          (beforeAudits.CERTOPS_KEY_MATERIAL_REJECTED || 0) + 1,
        );
        for (const action of [
          "CERTOPS_EXECUTOR_EVENT_ACCEPTED",
          "CERTOPS_EVIDENCE_ACCEPTED",
          "CERTOPS_EVIDENCE_REJECTED",
          "CERTOPS_GENERIC_SECRET_REDACTION_APPLIED",
        ]) {
          expect(afterAudits[action] || 0).to.equal(beforeAudits[action] || 0);
        }
      }
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("preserves private-key rejection precedence over the route's base scope on every machine route", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-wrong-scope-key-material",
    );

    try {
      const app = buildExecutorApp();
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      // Read-only token: valid and workspace-bound, but missing the base
      // write scope required by every executor route.
      const readOnly = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:read"],
      });
      // Evidence-only token: passes the evidence route's base scope but not
      // the two event routes' base scope.
      const evidenceOnly = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:evidence:write"],
      });
      const requests = [
        {
          route: "/api/v1/certops/executor/events",
          tokens: [readOnly, evidenceOnly],
          body: eventPayload({
            workspaceId: workspaceA,
            jobId: job.id,
            message: PRIVATE_KEY_PEM,
          }),
        },
        {
          route: `/api/v1/certops/jobs/${job.id}/events`,
          tokens: [readOnly, evidenceOnly],
          body: {
            schemaVersion: 1,
            eventId: `event-${crypto.randomUUID()}`,
            eventType: "renewal.started",
            status: "running",
            occurredAt: new Date().toISOString(),
            message: PRIVATE_KEY_PEM,
          },
        },
        {
          route: `/api/v1/certops/jobs/${job.id}/evidence`,
          tokens: [readOnly],
          body: {
            schemaVersion: 1,
            eventId: `event-${crypto.randomUUID()}`,
            occurredAt: new Date().toISOString(),
            evidence: [{ type: "log", output: "renewal log" }],
            message: PRIVATE_KEY_PEM,
          },
        },
      ];

      for (const request of requests) {
        for (const token of request.tokens) {
          const beforeArtifacts = await countJobArtifacts({
            workspaceId: workspaceA,
            jobId: job.id,
          });
          const beforeStatus = (
            await getCertificateJobById({
              workspaceId: workspaceA,
              jobId: job.id,
            })
          ).status;
          const beforeAudits = await auditActionCounts({
            workspaceId: workspaceA,
          });

          const withKeyMaterial = await supertest(app)
            .post(request.route)
            .set("Authorization", `Bearer ${token.plaintextToken}`)
            .send({ ...request.body, eventId: `event-${crypto.randomUUID()}` });

          const afterAudits = await auditActionCounts({
            workspaceId: workspaceA,
          });
          expect(withKeyMaterial.status).to.equal(422);
          expect(withKeyMaterial.body.code).to.equal(
            "PRIVATE_KEY_MATERIAL_REJECTED",
          );
          expectNoSensitiveValues(withKeyMaterial.body, token.plaintextToken, [
            PRIVATE_KEY_PEM,
          ]);
          expect(
            await countJobArtifacts({ workspaceId: workspaceA, jobId: job.id }),
          ).to.deep.equal(beforeArtifacts);
          expect(
            (
              await getCertificateJobById({
                workspaceId: workspaceA,
                jobId: job.id,
              })
            ).status,
          ).to.equal(beforeStatus);
          expect(afterAudits.CERTOPS_KEY_MATERIAL_REJECTED || 0).to.equal(
            (beforeAudits.CERTOPS_KEY_MATERIAL_REJECTED || 0) + 1,
          );

          // Without key material the same underscoped token gets the scope
          // denial: deferral must not weaken the route's scope enforcement.
          const withoutKeyMaterial = await supertest(app)
            .post(request.route)
            .set("Authorization", `Bearer ${token.plaintextToken}`)
            .send({
              ...request.body,
              eventId: `event-${crypto.randomUUID()}`,
              message: "no key material",
            });
          expect(withoutKeyMaterial.status).to.equal(403);
          expect(withoutKeyMaterial.body.code).to.equal(
            "CERTOPS_API_TOKEN_SCOPE_DENIED",
          );
          expect(
            await countJobArtifacts({ workspaceId: workspaceA, jobId: job.id }),
          ).to.deep.equal(beforeArtifacts);
        }
      }
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("fails closed when a combined empty-evidence key-material audit cannot be written", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-empty-evidence-key-audit-failure",
    );

    try {
      const app = buildExecutorApp();
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write", "certops:evidence:write"],
      });
      const body = eventPayload({
        workspaceId: workspaceA,
        jobId: job.id,
        eventType: "evidence.attached",
        status: "accepted",
        evidence: [],
        message: PRIVATE_KEY_PEM,
      });
      const beforeArtifacts = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      const beforeStatus = (
        await getCertificateJobById({ workspaceId: workspaceA, jobId: job.id })
      ).status;
      const beforeAudits = await auditActionCounts({ workspaceId: workspaceA });

      await TestUtils.execQuery(`
        CREATE OR REPLACE FUNCTION fail_certops_executor_key_material_audit_for_test()
        RETURNS trigger AS $$
        BEGIN
          IF NEW.action = 'CERTOPS_KEY_MATERIAL_REJECTED' THEN
            RAISE EXCEPTION 'forced CertOps executor key-material audit failure';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
      `);
      await TestUtils.execQuery(`
        CREATE TRIGGER fail_certops_executor_key_material_audit_for_test_trigger
        BEFORE INSERT ON audit_events
        FOR EACH ROW
        EXECUTE FUNCTION fail_certops_executor_key_material_audit_for_test();
      `);

      try {
        const response = await supertest(app)
          .post("/api/v1/certops/executor/events")
          .set("Authorization", `Bearer ${token.plaintextToken}`)
          .send(body);

        expect(response.status).to.equal(503);
        expect(response.body.code).to.equal("CERTOPS_SECURITY_AUDIT_UNAVAILABLE");
        expectNoSensitiveValues(response.body, token.plaintextToken, [PRIVATE_KEY_PEM]);
        expect(
          await countJobArtifacts({ workspaceId: workspaceA, jobId: job.id }),
        ).to.deep.equal(beforeArtifacts);
        expect(
          (
            await getCertificateJobById({ workspaceId: workspaceA, jobId: job.id })
          ).status,
        ).to.equal(beforeStatus);
        expect(
          await auditActionCounts({ workspaceId: workspaceA }),
        ).to.deep.equal(beforeAudits);
      } finally {
        await TestUtils.execQuery(
          "DROP TRIGGER IF EXISTS fail_certops_executor_key_material_audit_for_test_trigger ON audit_events",
        );
        await TestUtils.execQuery(
          "DROP FUNCTION IF EXISTS fail_certops_executor_key_material_audit_for_test()",
        );
      }
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("applies the machine-token rate limiter", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-rate-limit",
    );

    try {
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write"],
      });
      const app = buildExecutorApp({ rateLimitOptions: { windowMs: 60_000, max: 1 } });
      const route = "/api/v1/certops/executor/events";
      const auth = `Bearer ${token.plaintextToken}`;

      const first = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(eventPayload({ workspaceId: workspaceA, jobId: job.id, eventType: "job.progress" }));
      const second = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(eventPayload({ workspaceId: workspaceA, jobId: job.id, eventType: "job.progress" }));

      expect(first.status).to.equal(202);
      expect(second.status).to.equal(429);
      expect(second.body.code).to.equal("CERTOPS_MACHINE_RATE_LIMITED");
      expectNoSensitiveValues(second.body, token.plaintextToken);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("is CSRF-exempt only for the executor machine-token namespace", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-csrf",
    );

    try {
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write"],
      });
      const app = buildExecutorApp({ csrf: true });

      const accepted = await supertest(app)
        .post("/api/v1/certops/executor/events")
        .set("Authorization", `Bearer ${token.plaintextToken}`)
        .send(eventPayload({ workspaceId: workspaceA, jobId: job.id }));
      expect(accepted.status).to.equal(202);

      const perJobAccepted = await supertest(app)
        .post(`/api/v1/certops/jobs/${job.id}/events`)
        .set("Authorization", `Bearer ${token.plaintextToken}`)
        .send({
          schemaVersion: 1,
          eventId: `event-${crypto.randomUUID()}`,
          eventType: "job.progress",
          status: "running",
          occurredAt: new Date().toISOString(),
        });
      expect(perJobAccepted.status).to.equal(202);

      const unrelated = await supertest(app)
        .post(`/api/v1/workspaces/${workspaceA}/certops/unrelated-write`)
        .send({});
      expect(unrelated.status).to.equal(403);
      expect(unrelated.body.code).to.equal("EBADCSRFTOKEN");
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("supports per-job machine-token event and evidence routes with path job scope", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-per-job",
    );

    try {
      const app = buildExecutorApp();
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const eventsToken = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write"],
      });
      const evidenceToken = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:evidence:write"],
      });
      const readOnlyToken = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:read"],
      });
      const eventRoute = `/api/v1/certops/jobs/${job.id}/events`;
      const evidenceRoute = `/api/v1/certops/jobs/${job.id}/evidence`;
      const eventAuth = `Bearer ${eventsToken.plaintextToken}`;
      const evidenceAuth = `Bearer ${evidenceToken.plaintextToken}`;

      const eventBody = {
        schemaVersion: 1,
        eventId: `event-${crypto.randomUUID()}`,
        eventType: "job.started",
        status: "running",
        occurredAt: new Date().toISOString(),
        message: "Per-job event accepted",
      };

      const accepted = await supertest(app)
        .post(eventRoute)
        .set("Authorization", eventAuth)
        .send(eventBody);
      const duplicate = await supertest(app)
        .post(eventRoute)
        .set("Authorization", eventAuth)
        .send(eventBody);

      expect(accepted.status).to.equal(202);
      expect(accepted.body.status).to.equal("running");
      expectAcceptedResponseMatchesOpenApi(accepted);
      expect(duplicate.status).to.equal(202);
      expect(duplicate.body.duplicate).to.equal(true);
      expectAcceptedResponseMatchesOpenApi(duplicate);
      expect(
        await countJobArtifacts({ workspaceId: workspaceA, jobId: job.id }),
      ).to.deep.include({ logs: 1, executorEvents: 1 });
      expect(
        (await getCertificateJobById({ workspaceId: workspaceA, jobId: job.id }))
          .status,
      ).to.equal("running");

      const readOnlyDenied = await supertest(app)
        .post(eventRoute)
        .set("Authorization", `Bearer ${readOnlyToken.plaintextToken}`)
        .send({
          ...eventBody,
          eventId: `event-${crypto.randomUUID()}`,
        });
      expect(readOnlyDenied.status).to.equal(403);
      expect(readOnlyDenied.body.code).to.equal(
        "CERTOPS_API_TOKEN_SCOPE_DENIED",
      );

      const eventsOnlyBefore = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      const eventsOnlyAuditsBefore = await auditActionCounts({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      const eventsOnlyEvidenceDenied = await supertest(app)
        .post(eventRoute)
        .set("Authorization", eventAuth)
        .send({
          ...eventBody,
          eventId: `event-${crypto.randomUUID()}`,
          eventType: "evidence.attached",
          status: "accepted",
          evidence: [
            {
              schemaVersion: 1,
              evidenceId: `evidence-${crypto.randomUUID()}`,
              eventType: "certificate.observed",
              source: "executor",
              observedAt: new Date().toISOString(),
              summary: "ordinary public evidence",
            },
          ],
        });
      expect(eventsOnlyEvidenceDenied.status).to.equal(403);
      expect(eventsOnlyEvidenceDenied.body.code).to.equal(
        "CERTOPS_API_TOKEN_SCOPE_DENIED",
      );
      expect(
        await countJobArtifacts({ workspaceId: workspaceA, jobId: job.id }),
      ).to.deep.equal(eventsOnlyBefore);
      expect(
        await auditActionCounts({ workspaceId: workspaceA, jobId: job.id }),
      ).to.deep.equal(eventsOnlyAuditsBefore);

      const perJobPrivateKeyDenied = await supertest(app)
        .post(eventRoute)
        .set("Authorization", eventAuth)
        .send({
          ...eventBody,
          eventId: `event-${crypto.randomUUID()}`,
          eventType: "evidence.attached",
          status: "accepted",
          evidence: [
            {
              schemaVersion: 1,
              evidenceId: `evidence-${crypto.randomUUID()}`,
              eventType: "certificate.observed",
              source: "executor",
              observedAt: new Date().toISOString(),
              privateKey: PRIVATE_KEY_PEM,
            },
          ],
        });
      expect(perJobPrivateKeyDenied.status).to.equal(422);
      expect(perJobPrivateKeyDenied.body.code).to.equal(
        "PRIVATE_KEY_MATERIAL_REJECTED",
      );
      expect(
        await countJobArtifacts({ workspaceId: workspaceA, jobId: job.id }),
      ).to.deep.equal(eventsOnlyBefore);

      for (const [body, status, code] of [
        [{ ...eventBody, eventId: `event-${crypto.randomUUID()}`, jobId: crypto.randomUUID() }, 400, "CERTOPS_EXECUTOR_EVENT_INVALID"],
        [{ ...eventBody, eventId: `event-${crypto.randomUUID()}`, workspaceId: workspaceB }, 403, "CERTOPS_EXECUTOR_WORKSPACE_MISMATCH"],
      ]) {
        const before = await countJobArtifacts({
          workspaceId: workspaceA,
          jobId: job.id,
        });
        const response = await supertest(app)
          .post(eventRoute)
          .set("Authorization", eventAuth)
          .send(body);
        const after = await countJobArtifacts({
          workspaceId: workspaceA,
          jobId: job.id,
        });
        expect(response.status).to.equal(status);
        expect(response.body.code).to.equal(code);
        expect(after).to.deep.equal(before);
        expectNoSensitiveValues(response.body, eventsToken.plaintextToken);
      }

      const eventsTokenDeniedOnEvidence = await supertest(app)
        .post(evidenceRoute)
        .set("Authorization", eventAuth)
        .send({
          schemaVersion: 1,
          eventId: `event-${crypto.randomUUID()}`,
          occurredAt: new Date().toISOString(),
          evidence: [],
        });
      expect(eventsTokenDeniedOnEvidence.status).to.equal(403);
      expect(eventsTokenDeniedOnEvidence.body.code).to.equal(
        "CERTOPS_API_TOKEN_SCOPE_DENIED",
      );

      const evidencePayload = {
        schemaVersion: 1,
        eventId: `event-${crypto.randomUUID()}`,
        occurredAt: new Date().toISOString(),
        evidence: [
          {
            eventType: "certificate.observed",
            output: "executor finished password=swordfish",
          },
        ],
      };
      const evidenceResponse = await supertest(app)
        .post(evidenceRoute)
        .set("Authorization", evidenceAuth)
        .send(evidencePayload);
      expect(evidenceResponse.status).to.equal(202);
      expect(evidenceResponse.body.evidenceIds).to.have.length(1);
      expectAcceptedResponseMatchesOpenApi(evidenceResponse);
      expectNoSensitiveValues(evidenceResponse.body, evidenceToken.plaintextToken);

      const evidence = await listCertificateEvidence({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      const outputEvidence = evidence.items.find(
        (item) => item.id === evidenceResponse.body.evidenceIds[0],
      );
      expect(outputEvidence.redactedOutput).to.include("[REDACTED]");
      expect(outputEvidence.redactedOutput).to.not.include("swordfish");
      expect(outputEvidence.outputTruncated).to.equal(false);
      expect(outputEvidence.outputSha256).to.match(/^[a-f0-9]{64}$/);
      expect(outputEvidence.outputSizeBytes).to.equal(
        Buffer.byteLength("executor finished password=[REDACTED]"),
      );
      expect(outputEvidence.outputRedactionApplied).to.equal(true);
      expect(outputEvidence.outputRedactionCount).to.be.greaterThan(0);
      expect(outputEvidence.metadata.redaction).to.deep.equal({
        applied: true,
        count: outputEvidence.outputRedactionCount,
      });
      expect(JSON.stringify(outputEvidence)).to.not.include("swordfish");

      const fetchedEvidence = await getCertificateEvidenceById({
        workspaceId: workspaceA,
        evidenceId: outputEvidence.id,
      });
      expect(fetchedEvidence.outputRedactionApplied).to.equal(true);
      expect(fetchedEvidence.outputRedactionCount).to.equal(
        outputEvidence.outputRedactionCount,
      );
      expect(fetchedEvidence.metadata.redaction).to.deep.equal({
        applied: true,
        count: outputEvidence.outputRedactionCount,
      });
      expect(JSON.stringify(fetchedEvidence)).to.not.include("swordfish");

      const oversizedBefore = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      const oversized = await supertest(app)
        .post(evidenceRoute)
        .set("Authorization", evidenceAuth)
        .send({
          schemaVersion: 1,
          eventId: `event-${crypto.randomUUID()}`,
          occurredAt: new Date().toISOString(),
          evidence: [
            {
              schemaVersion: 1,
              eventType: "certificate.observed",
              source: "executor",
              observedAt: new Date().toISOString(),
              output: "a".repeat(65537),
            },
          ],
        });
      const oversizedAfter = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(oversized.status).to.equal(413);
      expect(oversized.body.code).to.equal("CERTOPS_EVIDENCE_OUTPUT_TOO_LARGE");
      expect(oversizedAfter).to.deep.equal(oversizedBefore);
      expectNoSensitiveValues(oversized.body, evidenceToken.plaintextToken);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("persists lifecycle events through job services", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-lifecycle",
    );

    try {
      const app = buildExecutorApp();
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write"],
      });
      const route = "/api/v1/certops/executor/events";

      const startedJob = await createJob({ workspaceId: workspaceA, ownerId });
      const started = await supertest(app)
        .post(route)
        .set("Authorization", `Bearer ${token.plaintextToken}`)
        .send(eventPayload({ workspaceId: workspaceA, jobId: startedJob.id }));
      expect(started.status).to.equal(202);
      expect(started.body.status).to.equal("running");
      expect(
        (await getCertificateJobById({
          workspaceId: workspaceA,
          jobId: startedJob.id,
        })).status,
      ).to.equal("running");

      const completedJob = await createJob({
        workspaceId: workspaceA,
        ownerId,
        status: "running",
      });
      const completed = await supertest(app)
        .post(route)
        .set("Authorization", `Bearer ${token.plaintextToken}`)
        .send(
          eventPayload({
            workspaceId: workspaceA,
            jobId: completedJob.id,
            eventType: "job.completed",
            status: "succeeded",
          }),
        );
      expect(completed.status).to.equal(202);
      expect(completed.body.status).to.equal("succeeded");
      expect(
        (await getCertificateJobById({
          workspaceId: workspaceA,
          jobId: completedJob.id,
        })).status,
      ).to.equal("succeeded");

      const failedJob = await createJob({
        workspaceId: workspaceA,
        ownerId,
        status: "running",
      });
      const failed = await supertest(app)
        .post(route)
        .set("Authorization", `Bearer ${token.plaintextToken}`)
        .send(
          eventPayload({
            workspaceId: workspaceA,
            jobId: failedJob.id,
            eventType: "job.failed",
            status: "failed",
          }),
        );
      expect(failed.status).to.equal(202);
      expect(failed.body.status).to.equal("failed");

      const progressJob = await createJob({ workspaceId: workspaceA, ownerId });
      const progress = await supertest(app)
        .post(route)
        .set("Authorization", `Bearer ${token.plaintextToken}`)
        .send(
          eventPayload({
            workspaceId: workspaceA,
            jobId: progressJob.id,
            eventType: "job.progress",
            status: "running",
          }),
        );
      expect(progress.status).to.equal(202);
      expect(progress.body.status).to.equal("pending");
      expect(
        (await getCertificateJobById({
          workspaceId: workspaceA,
          jobId: progressJob.id,
        })).status,
      ).to.equal("pending");

      const logs = await listCertificateJobLog({
        workspaceId: workspaceA,
        jobId: startedJob.id,
      });
      expect(logs.items.map((item) => item.eventType)).to.include("job.started");
      expect(logs.items[0].createdByApiTokenId).to.equal(token.token.id);
      expectNoSensitiveValues(started.body, token.plaintextToken);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("rejects eventType and status mismatches before any persistence", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-status-mismatch",
    );

    try {
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write", "certops:evidence:write"],
      });
      const app = buildExecutorApp();

      for (const [eventType, status] of [
        ["job.completed", "failed"],
        ["job.failed", "succeeded"],
        ["job.started", "succeeded"],
      ]) {
        const before = await countJobArtifacts({
          workspaceId: workspaceA,
          jobId: job.id,
        });
        const response = await supertest(app)
          .post("/api/v1/certops/executor/events")
          .set("Authorization", `Bearer ${token.plaintextToken}`)
          .send(
            eventPayload({
              workspaceId: workspaceA,
              jobId: job.id,
              eventType,
              status,
            }),
          );
        const after = await countJobArtifacts({
          workspaceId: workspaceA,
          jobId: job.id,
        });

        expect(response.status).to.equal(400);
        expect(response.body.code).to.equal(
          "CERTOPS_EXECUTOR_EVENT_STATUS_MISMATCH",
        );
        expect(after).to.deep.equal(before);
        expect(
          await countExecutorEventRecords({
            workspaceId: workspaceA,
            jobId: job.id,
          }),
        ).to.equal(0);
        expect(
          (
            await getCertificateJobById({
              workspaceId: workspaceA,
              jobId: job.id,
            })
          ).status,
        ).to.equal("pending");
        expectNoSensitiveValues(response.body, token.plaintextToken);
      }
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("requires evidence scope before scanning or persisting evidence-bearing events", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-evidence-scope",
    );

    try {
      const eventsToken = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write"],
      });
      const evidenceToken = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write", "certops:evidence:write"],
      });
      const app = buildExecutorApp();
      const lifecycleJob = await createJob({ workspaceId: workspaceA, ownerId });
      const evidenceJob = await createJob({ workspaceId: workspaceA, ownerId });
      const validEvidence = {
        schemaVersion: 1,
        evidenceId: `evidence-${crypto.randomUUID()}`,
        jobId: evidenceJob.id,
        workspaceId: workspaceA,
        certificateId: "cert-1",
        eventType: "certificate.observed",
        source: "executor",
        observedAt: new Date().toISOString(),
      };

      const lifecycle = await supertest(app)
        .post("/api/v1/certops/executor/events")
        .set("Authorization", `Bearer ${eventsToken.plaintextToken}`)
        .send(eventPayload({ workspaceId: workspaceA, jobId: lifecycleJob.id }));
      expect(lifecycle.status).to.equal(202);

      for (const [body, expectedStatus, expectedCode] of [
        [
          eventPayload({
            workspaceId: workspaceA,
            jobId: evidenceJob.id,
            eventType: "evidence.attached",
            status: "accepted",
            evidence: [validEvidence],
          }),
          403,
          "CERTOPS_API_TOKEN_SCOPE_DENIED",
        ],
        [
          eventPayload({
            workspaceId: workspaceA,
            jobId: evidenceJob.id,
            eventType: "job.progress",
            status: "running",
            evidence: [validEvidence],
          }),
          403,
          "CERTOPS_API_TOKEN_SCOPE_DENIED",
        ],
        [
          eventPayload({
            workspaceId: workspaceA,
            jobId: evidenceJob.id,
            eventType: "job.progress",
            status: "running",
            evidence: [{ ...validEvidence, privateKey: PRIVATE_KEY_PEM }],
          }),
          422,
          "PRIVATE_KEY_MATERIAL_REJECTED",
        ],
      ]) {
        const before = await countJobArtifacts({
          workspaceId: workspaceA,
          jobId: evidenceJob.id,
        });
        const response = await supertest(app)
          .post("/api/v1/certops/executor/events")
          .set("Authorization", `Bearer ${eventsToken.plaintextToken}`)
          .send(body);
        const after = await countJobArtifacts({
          workspaceId: workspaceA,
          jobId: evidenceJob.id,
        });

        expect(response.status).to.equal(expectedStatus);
        expect(response.body.code).to.equal(expectedCode);
        expect(after).to.deep.equal(before);
        expect(
          await countExecutorEventRecords({
            workspaceId: workspaceA,
            jobId: evidenceJob.id,
          }),
        ).to.equal(0);
        expectNoSensitiveValues(response.body, eventsToken.plaintextToken);
      }

      const accepted = await supertest(app)
        .post("/api/v1/certops/executor/events")
        .set("Authorization", `Bearer ${evidenceToken.plaintextToken}`)
        .send(
          eventPayload({
            workspaceId: workspaceA,
            jobId: evidenceJob.id,
            eventType: "evidence.attached",
            status: "accepted",
            evidence: [validEvidence],
          }),
        );
      expect(accepted.status).to.equal(202);
      expect(accepted.body.evidenceId).to.be.a("string").that.is.not.empty;
      expectNoSensitiveValues(accepted.body, evidenceToken.plaintextToken);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("does not reopen terminal jobs when late lifecycle events arrive", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-terminal",
    );

    try {
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write"],
      });
      const app = buildExecutorApp();
      const route = "/api/v1/certops/executor/events";

      const terminalCases = [
        {
          initialStatus: "running",
          terminalEventType: "job.completed",
          terminalStatus: "succeeded",
          timestamp: "completedAt",
        },
        {
          initialStatus: "running",
          terminalEventType: "job.failed",
          terminalStatus: "failed",
          timestamp: "completedAt",
        },
        {
          initialStatus: "cancelled",
          terminalEventType: null,
          terminalStatus: "cancelled",
          timestamp: "cancelledAt",
        },
        {
          initialStatus: "rejected",
          terminalEventType: null,
          terminalStatus: "rejected",
          timestamp: null,
        },
        {
          initialStatus: "blocked",
          terminalEventType: null,
          terminalStatus: "blocked",
          timestamp: "completedAt",
        },
      ];

      for (const terminalCase of terminalCases) {
        const job = await createJob({
          workspaceId: workspaceA,
          ownerId,
          status: terminalCase.initialStatus,
        });

        if (terminalCase.terminalEventType) {
          const terminal = await supertest(app)
            .post(route)
            .set("Authorization", `Bearer ${token.plaintextToken}`)
            .send(
              eventPayload({
                workspaceId: workspaceA,
                jobId: job.id,
                eventType: terminalCase.terminalEventType,
                status: terminalCase.terminalStatus,
              }),
            );
          expect(terminal.status).to.equal(202);
        }

        const beforeJob = await getCertificateJobById({
          workspaceId: workspaceA,
          jobId: job.id,
        });
        const beforeArtifacts = await countJobArtifacts({
          workspaceId: workspaceA,
          jobId: job.id,
        });
        const late = await supertest(app)
          .post(route)
          .set("Authorization", `Bearer ${token.plaintextToken}`)
          .send(
            eventPayload({
              workspaceId: workspaceA,
              jobId: job.id,
              eventType: "job.started",
              status: "running",
            }),
          );
        const afterJob = await getCertificateJobById({
          workspaceId: workspaceA,
          jobId: job.id,
        });
        const afterArtifacts = await countJobArtifacts({
          workspaceId: workspaceA,
          jobId: job.id,
        });

        expect(late.status).to.equal(202);
        expect(late.body.status).to.equal(terminalCase.terminalStatus);
        expect(afterJob.status).to.equal(terminalCase.terminalStatus);
        if (terminalCase.timestamp) {
          expect(afterJob[terminalCase.timestamp]).to.equal(
            beforeJob[terminalCase.timestamp],
          );
          expect(afterJob[terminalCase.timestamp]).to.be.a("string").that.is
            .not.empty;
        }
        expect(afterJob.errorCode).to.equal(beforeJob.errorCode);
        expect(afterJob.errorMessage).to.equal(beforeJob.errorMessage);
        expect(afterArtifacts).to.deep.equal({
          logs: beforeArtifacts.logs + 1,
          evidence: beforeArtifacts.evidence,
          executorEvents: beforeArtifacts.executorEvents + 1,
        });
        const logs = await listCertificateJobLog({
          workspaceId: workspaceA,
          jobId: job.id,
        });
        expect(logs.items[0].eventType).to.equal("job.started");
        expect(logs.items[0].metadata.jobStatusTransitionIgnored).to.equal(
          true,
        );
        expectNoSensitiveValues(late.body, token.plaintextToken);
      }
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("logs stale active lifecycle events without regressing the job or duplicating retries", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-stale-active",
    );

    try {
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write"],
      });
      const app = buildExecutorApp();
      const route = "/api/v1/certops/executor/events";
      const auth = `Bearer ${token.plaintextToken}`;
      const running = await createJob({
        workspaceId: workspaceA,
        ownerId,
        status: "running",
      });
      const staleClaim = eventPayload({
        workspaceId: workspaceA,
        jobId: running.id,
        eventType: "job.accepted",
        status: "claimed",
      });

      const accepted = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(staleClaim);
      const replay = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(staleClaim);
      const afterStale = await getCertificateJobById({
        workspaceId: workspaceA,
        jobId: running.id,
      });
      const logs = await listCertificateJobLog({
        workspaceId: workspaceA,
        jobId: running.id,
      });

      expect(accepted.status).to.equal(202);
      expect(accepted.body.status).to.equal("running");
      expect(replay.status).to.equal(202);
      expect(replay.body.duplicate).to.equal(true);
      expect(afterStale.status).to.equal("running");
      expect(afterStale.startedAt).to.be.a("string").that.is.not.empty;
      expect(logs.items).to.have.length(1);
      expect(logs.items[0].metadata.jobStatusTransitionIgnored).to.equal(true);
      expect(logs.items[0].metadata.jobStatusTransitionIgnoredReason).to.equal(
        "active_regression",
      );
      expect(
        await countJobArtifacts({ workspaceId: workspaceA, jobId: running.id }),
      ).to.deep.equal({ logs: 1, evidence: 0, executorEvents: 1 });

      const rejected = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(
          eventPayload({
            workspaceId: workspaceA,
            jobId: running.id,
            eventType: "job.rejected",
            status: "rejected",
          }),
        );
      expect(rejected.status).to.equal(202);
      expect(rejected.body.status).to.equal("rejected");

      const pending = await createJob({ workspaceId: workspaceA, ownerId });
      const concurrent = await Promise.all([
        supertest(app)
          .post(route)
          .set("Authorization", auth)
          .send(
            eventPayload({
              workspaceId: workspaceA,
              jobId: pending.id,
              eventType: "job.started",
              status: "running",
            }),
          ),
        supertest(app)
          .post(route)
          .set("Authorization", auth)
          .send(
            eventPayload({
              workspaceId: workspaceA,
              jobId: pending.id,
              eventType: "job.accepted",
              status: "claimed",
            }),
          ),
      ]);
      expect(concurrent.map((response) => response.status)).to.deep.equal([
        202,
        202,
      ]);
      expect(
        (await getCertificateJobById({ workspaceId: workspaceA, jobId: pending.id }))
          .status,
      ).to.equal("running");
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("processes executor events atomically and idempotently", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-idempotency",
    );

    try {
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write", "certops:evidence:write"],
      });
      const app = buildExecutorApp();
      const route = "/api/v1/certops/executor/events";
      const auth = `Bearer ${token.plaintextToken}`;

      const replayJob = await createJob({ workspaceId: workspaceA, ownerId });
      const replayPayload = eventPayload({
        workspaceId: workspaceA,
        jobId: replayJob.id,
      });
      const first = await supertest(app).post(route).set("Authorization", auth).send(replayPayload);
      const afterFirst = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: replayJob.id,
      });
      const replay = await supertest(app).post(route).set("Authorization", auth).send(replayPayload);
      const afterReplay = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: replayJob.id,
      });

      expect(first.status).to.equal(202);
      expect(first.body.duplicate).to.equal(false);
      expect(first.body.idempotent).to.equal(false);
      expect(replay.status).to.equal(202);
      expect(replay.body.eventId).to.equal(first.body.eventId);
      expect(replay.body.logId).to.equal(first.body.logId);
      expect(replay.body.evidenceIds).to.deep.equal(first.body.evidenceIds);
      expect(replay.body.duplicate).to.equal(true);
      expect(replay.body.idempotent).to.equal(true);
      expect(afterReplay).to.deep.equal(afterFirst);
      expect(
        await countExecutorEventRecords({
          workspaceId: workspaceA,
          jobId: replayJob.id,
        }),
      ).to.equal(1);
      expect(
        await auditActionCounts({
          workspaceId: workspaceA,
          jobId: replayJob.id,
        }),
      ).to.deep.equal({ CERTOPS_EXECUTOR_EVENT_ACCEPTED: 1 });
      expectNoSensitiveValues(replay.body, token.plaintextToken);

      const conflictJob = await createJob({ workspaceId: workspaceA, ownerId });
      const conflictPayload = eventPayload({
        workspaceId: workspaceA,
        jobId: conflictJob.id,
        eventType: "job.progress",
        status: "running",
      });
      const conflictFirst = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(conflictPayload);
      const beforeConflict = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: conflictJob.id,
      });
      const conflict = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send({ ...conflictPayload, status: "claimed" });
      const afterConflict = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: conflictJob.id,
      });

      expect(conflictFirst.status).to.equal(202);
      expect(conflict.status).to.equal(409);
      expect(conflict.body.code).to.equal(
        "CERTOPS_EXECUTOR_EVENT_CONFLICT",
      );
      expect(afterConflict).to.deep.equal(beforeConflict);
      expectNoSensitiveValues(conflict.body, token.plaintextToken);

      const metadataConflictJob = await createJob({
        workspaceId: workspaceA,
        ownerId,
      });
      const metadataConflictPayload = eventPayload({
        workspaceId: workspaceA,
        jobId: metadataConflictJob.id,
        eventType: "job.progress",
        status: "running",
        metadata: [{ name: "observation", value: "first public value" }],
      });
      const metadataConflictFirst = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(metadataConflictPayload);
      const beforeMetadataConflict = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: metadataConflictJob.id,
      });
      const metadataConflict = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send({
          ...metadataConflictPayload,
          metadata: [{ name: "observation", value: "different public value" }],
        });
      const afterMetadataConflict = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: metadataConflictJob.id,
      });

      expect(metadataConflictFirst.status).to.equal(202);
      expect(metadataConflict.status).to.equal(409);
      expect(metadataConflict.body.code).to.equal(
        "CERTOPS_EXECUTOR_EVENT_CONFLICT",
      );
      expect(afterMetadataConflict).to.deep.equal(beforeMetadataConflict);
      expectNoSensitiveValues(metadataConflict.body, token.plaintextToken);

      const evidenceJob = await createJob({ workspaceId: workspaceA, ownerId });
      const evidencePayload = eventPayload({
        workspaceId: workspaceA,
        jobId: evidenceJob.id,
        eventType: "evidence.attached",
        status: "accepted",
        evidence: [
          {
            schemaVersion: 1,
            evidenceId: `evidence-${crypto.randomUUID()}`,
            jobId: evidenceJob.id,
            workspaceId: workspaceA,
            certificateId: "cert-1",
            eventType: "certificate.observed",
            source: "executor",
            observedAt: new Date().toISOString(),
            summary: "Initial public observation",
          },
        ],
      });
      const evidenceFirst = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(evidencePayload);
      const beforeEvidenceConflict = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: evidenceJob.id,
      });
      const evidenceConflict = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send({
          ...evidencePayload,
          evidence: [
            { ...evidencePayload.evidence[0], summary: "Changed public observation" },
          ],
        });
      const afterEvidenceConflict = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: evidenceJob.id,
      });

      expect(evidenceFirst.status).to.equal(202);
      expect(evidenceConflict.status).to.equal(409);
      expect(evidenceConflict.body.code).to.equal(
        "CERTOPS_EXECUTOR_EVENT_CONFLICT",
      );
      expect(afterEvidenceConflict).to.deep.equal(beforeEvidenceConflict);
      expect(
        await auditActionCounts({
          workspaceId: workspaceA,
          jobId: evidenceJob.id,
        }),
      ).to.deep.equal({
        CERTOPS_EVIDENCE_ACCEPTED: 1,
        CERTOPS_EXECUTOR_EVENT_ACCEPTED: 1,
      });

      const rollbackJob = await createJob({ workspaceId: workspaceA, ownerId });
      const beforeRollback = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: rollbackJob.id,
      });
      const rollback = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(
          eventPayload({
            workspaceId: workspaceA,
            jobId: rollbackJob.id,
            eventType: "evidence.attached",
            status: "accepted",
            evidence: [
              {
                schemaVersion: 1,
                evidenceId: `evidence-${crypto.randomUUID()}`,
                jobId: rollbackJob.id,
                workspaceId: workspaceA,
                eventType: "not-a-valid-evidence-type",
                source: "executor",
                observedAt: new Date().toISOString(),
              },
            ],
          }),
        );
      const afterRollback = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: rollbackJob.id,
      });

      expect(rollback.status).to.equal(400);
      expect(rollback.body.code).to.equal("CERTOPS_EVIDENCE_TYPE_INVALID");
      expect(afterRollback).to.deep.equal(beforeRollback);
      expect(
        await countExecutorEventRecords({
          workspaceId: workspaceA,
          jobId: rollbackJob.id,
        }),
      ).to.equal(0);
      expectNoSensitiveValues(rollback.body, token.plaintextToken);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("uses stable sanitized client semantics for idempotent retries", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-sanitized-idempotency",
    );

    try {
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write", "certops:evidence:write"],
      });
      const app = buildExecutorApp();
      const route = "/api/v1/certops/executor/events";
      const auth = `Bearer ${token.plaintextToken}`;
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const occurredAt = new Date().toISOString();
      const payload = eventPayload({
        workspaceId: workspaceA,
        jobId: job.id,
        eventId: `event-${crypto.randomUUID()}`,
        eventType: "evidence.attached",
        status: "accepted",
        occurredAt,
        message: "password=first-value",
        metadata: [
          {
            name: "executorNote",
            value: "Authorization: Bearer first-value",
          },
        ],
        evidence: [
          {
            schemaVersion: 1,
            evidenceId: `evidence-${crypto.randomUUID()}`,
            jobId: job.id,
            workspaceId: workspaceA,
            certificateId: "cert-1",
            eventType: "certificate.observed",
            source: "executor",
            observedAt: occurredAt,
            summary: "credential=first-value",
            metadata: [{ name: "cookieHeader", value: "first-value" }],
            redactionApplied: true,
          },
        ],
      });
      const retryPayload = {
        ...payload,
        message: "password=second-value",
        metadata: [
          {
            value: "Authorization: Bearer second-value",
            name: "executorNote",
          },
        ],
        evidence: [
          {
            ...payload.evidence[0],
            summary: "credential=second-value",
            metadata: [{ name: "cookie_header", value: "second-value" }],
            redactionApplied: false,
          },
        ],
      };

      const first = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(payload);
      const retry = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(retryPayload);

      expect(first.status).to.equal(202);
      expect(retry.status).to.equal(202);
      expect(retry.body.duplicate).to.equal(true);
      expect(retry.body.eventId).to.equal(first.body.eventId);
      expect(
        await countJobArtifacts({ workspaceId: workspaceA, jobId: job.id }),
      ).to.deep.equal({ logs: 1, evidence: 1, executorEvents: 1 });
      expect(
        await auditActionCounts({ workspaceId: workspaceA, jobId: job.id }),
      ).to.deep.equal({
        CERTOPS_EVIDENCE_ACCEPTED: 1,
        CERTOPS_EXECUTOR_EVENT_ACCEPTED: 1,
        CERTOPS_GENERIC_SECRET_REDACTION_APPLIED: 1,
      });

      const logs = await listCertificateJobLog({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      const evidence = await listCertificateEvidence({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      const audits = await TestUtils.execQuery(
        `SELECT action, metadata
           FROM audit_events
          WHERE workspace_id = $1
            AND metadata->>'jobId' = $2
          ORDER BY action ASC`,
        [workspaceA, job.id],
      );
      const serialized = JSON.stringify({
        first: first.body,
        retry: retry.body,
        logs: logs.items,
        evidence: evidence.items,
        audits: audits.rows,
      });
      expect(serialized).to.include("[REDACTED]");
      expect(serialized).to.not.include("first-value");
      expect(serialized).to.not.include("second-value");
      expect(logs.items[0].metadata.redactedFields).to.deep.equal([
        "authorization",
        "generic-secret",
      ]);
      expect(evidence.items[0].metadata.redactedFields).to.deep.equal([
        "cookie",
        "generic-secret",
      ]);
      const redactionAudit = audits.rows.find(
        (row) =>
          row.action === "CERTOPS_GENERIC_SECRET_REDACTION_APPLIED",
      );
      expect(redactionAudit.metadata.redactedFields).to.deep.equal([
        "authorization",
        "cookie",
        "generic-secret",
      ]);
      expectNoSensitiveValues(retry.body, token.plaintextToken, [
        "first-value",
        "second-value",
      ]);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("uses post-redaction evidence output for idempotency without persisting raw output", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-output-idempotency",
    );

    try {
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write", "certops:evidence:write"],
      });
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const app = buildExecutorApp();
      const route = "/api/v1/certops/executor/events";
      const auth = `Bearer ${token.plaintextToken}`;
      const eventId = `event-${crypto.randomUUID()}`;
      const payload = eventPayload({
        workspaceId: workspaceA,
        jobId: job.id,
        eventId,
        eventType: "evidence.attached",
        status: "accepted",
        evidence: [
          {
            schemaVersion: 1,
            evidenceId: `evidence-${crypto.randomUUID()}`,
            jobId: job.id,
            workspaceId: workspaceA,
            eventType: "certificate.observed",
            source: "executor",
            observedAt: new Date().toISOString(),
            output: "deployment password=first-value",
          },
        ],
      });
      const sanitizedRetry = {
        ...payload,
        evidence: [
          { ...payload.evidence[0], output: "deployment password=second-value" },
        ],
      };

      const first = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(payload);
      const retry = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(sanitizedRetry);
      const afterRetry = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      const conflict = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send({
          ...payload,
          evidence: [
            { ...payload.evidence[0], output: "different public deployment result" },
          ],
        });

      expect(first.status).to.equal(202);
      expect(retry.status).to.equal(202);
      expect(retry.body.duplicate).to.equal(true);
      expect(conflict.status).to.equal(409);
      expect(conflict.body.code).to.equal("CERTOPS_EXECUTOR_EVENT_CONFLICT");
      expect(
        await countJobArtifacts({ workspaceId: workspaceA, jobId: job.id }),
      ).to.deep.equal(afterRetry);

      const evidence = await listCertificateEvidence({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      const serialized = JSON.stringify({
        first: first.body,
        retry: retry.body,
        conflict: conflict.body,
        evidence: evidence.items,
      });
      expect(serialized).to.include("[REDACTED]");
      expect(serialized).to.not.include("first-value");
      expect(serialized).to.not.include("second-value");
      expectNoSensitiveValues(conflict.body, token.plaintextToken, [
        "first-value",
        "second-value",
      ]);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("serializes concurrent different event IDs without terminal regression", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-concurrent-lifecycle",
    );

    try {
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write", "certops:evidence:write"],
      });
      const job = await createJob({
        workspaceId: workspaceA,
        ownerId,
        status: "running",
      });
      const app = buildExecutorApp();
      const route = "/api/v1/certops/executor/events";
      const auth = `Bearer ${token.plaintextToken}`;
      const completed = eventPayload({
        workspaceId: workspaceA,
        jobId: job.id,
        eventType: "job.completed",
        status: "succeeded",
      });
      const lateStarted = eventPayload({
        workspaceId: workspaceA,
        jobId: job.id,
        eventType: "job.started",
        status: "running",
      });

      const responses = await Promise.all(
        [completed, lateStarted].map((body) =>
          supertest(app).post(route).set("Authorization", auth).send(body),
        ),
      );
      const persisted = await getCertificateJobById({
        workspaceId: workspaceA,
        jobId: job.id,
      });

      expect(responses.map((response) => response.status)).to.deep.equal([
        202,
        202,
      ]);
      expect(persisted.status).to.equal("succeeded");
      expect(persisted.completedAt).to.be.a("string").that.is.not.empty;
      expect(
        await countJobArtifacts({ workspaceId: workspaceA, jobId: job.id }),
      ).to.deep.equal({ logs: 2, evidence: 0, executorEvents: 2 });
      expect(
        await auditActionCounts({ workspaceId: workspaceA, jobId: job.id }),
      ).to.deep.equal({ CERTOPS_EXECUTOR_EVENT_ACCEPTED: 2 });
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("resolves genuinely concurrent identical-payload requests to exactly one write, without deadlocking", async () => {
    // Regression test for a lock-upgrade deadlock (Postgres 40P01): the
    // executor event ingestion used to take `SELECT ... FOR SHARE` on the
    // certificate_jobs row, while updateCertificateJobStatus() later in the
    // same transaction runs an `UPDATE certificate_jobs ...` against that
    // same row (needing an exclusive lock). Two concurrent requests for the
    // same job could each hold the shared lock and then each block upgrading
    // to exclusive, deadlocking. Fixed by taking `FOR UPDATE` upfront (see
    // apps/api/services/certops/executorEvents.js) so concurrent events on
    // one job serialize instead of deadlocking.
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-concurrency",
    );

    try {
      const app = buildExecutorApp();
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write", "certops:evidence:write"],
      });
      const route = "/api/v1/certops/executor/events";
      const auth = `Bearer ${token.plaintextToken}`;
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const payload = eventPayload({ workspaceId: workspaceA, jobId: job.id });

      const responses = await Promise.all(
        Array.from({ length: 4 }, () =>
          supertest(app).post(route).set("Authorization", auth).send(payload),
        ),
      );

      for (const res of responses) {
        expect(
          res.status,
          `expected 202, got ${res.status}: ${JSON.stringify(res.body)}`,
        ).to.equal(202);
      }
      const originals = responses.filter((res) => res.body.duplicate !== true);
      const replays = responses.filter((res) => res.body.duplicate === true);
      expect(
        originals.length,
        "exactly one concurrent request should win as the original write",
      ).to.equal(1);
      expect(replays.length).to.equal(3);

      const logs = await listCertificateJobLog({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(
        logs.items.length,
        "no duplicate job-log row should be created by the race",
      ).to.equal(1);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("resolves two different lifecycle events racing for the same job to exactly one terminal state, without deadlocking", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-concurrency-terminal",
    );

    try {
      const app = buildExecutorApp();
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write", "certops:evidence:write"],
      });
      const route = "/api/v1/certops/executor/events";
      const auth = `Bearer ${token.plaintextToken}`;
      const job = await createJob({ workspaceId: workspaceA, ownerId });

      // job.started first, so the job is "running" (non-terminal) before
      // the completed/failed race below.
      await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(
          eventPayload({
            workspaceId: workspaceA,
            jobId: job.id,
            eventType: "job.started",
            status: "running",
          }),
        );

      const [completedRes, failedRes] = await Promise.all([
        supertest(app)
          .post(route)
          .set("Authorization", auth)
          .send(
            eventPayload({
              workspaceId: workspaceA,
              jobId: job.id,
              eventType: "job.completed",
              status: "succeeded",
            }),
          ),
        supertest(app)
          .post(route)
          .set("Authorization", auth)
          .send(
            eventPayload({
              workspaceId: workspaceA,
              jobId: job.id,
              eventType: "job.failed",
              status: "failed",
            }),
          ),
      ]);

      expect(
        completedRes.status,
        `job.completed should be 202: ${JSON.stringify(completedRes.body)}`,
      ).to.equal(202);
      expect(
        failedRes.status,
        `job.failed should be 202: ${JSON.stringify(failedRes.body)}`,
      ).to.equal(202);

      const finalJob = await getCertificateJobById({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(["succeeded", "failed"]).to.include(finalJob.status);
      expect(completedRes.body.status).to.equal(finalJob.status);
      expect(failedRes.body.status).to.equal(finalJob.status);

      const logs = await listCertificateJobLog({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(
        logs.items.length,
        "job.started, job.completed, and job.failed should all still be logged",
      ).to.equal(3);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("scopes the same executor event ID independently by job and workspace", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-id-scope",
    );

    try {
      const tokenA = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write"],
      });
      const tokenB = await createScopedToken({
        workspaceId: workspaceB,
        ownerId,
        scopes: ["certops:events:write"],
      });
      const [jobA1, jobA2, jobB] = await Promise.all([
        createJob({ workspaceId: workspaceA, ownerId }),
        createJob({ workspaceId: workspaceA, ownerId }),
        createJob({ workspaceId: workspaceB, ownerId }),
      ]);
      const eventId = `event-${crypto.randomUUID()}`;
      const app = buildExecutorApp();
      const route = "/api/v1/certops/executor/events";
      const requests = [
        [tokenA, workspaceA, jobA1],
        [tokenA, workspaceA, jobA2],
        [tokenB, workspaceB, jobB],
      ].map(([token, workspaceId, job]) =>
        supertest(app)
          .post(route)
          .set("Authorization", `Bearer ${token.plaintextToken}`)
          .send(eventPayload({ workspaceId, jobId: job.id, eventId })),
      );

      const responses = await Promise.all(requests);
      expect(responses.map((response) => response.status)).to.deep.equal([
        202,
        202,
        202,
      ]);
      for (const [workspaceId, job] of [
        [workspaceA, jobA1],
        [workspaceA, jobA2],
        [workspaceB, jobB],
      ]) {
        expect(
          await countExecutorEventRecords({ workspaceId, jobId: job.id }),
        ).to.equal(1);
      }
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("creates sanitized evidence and appends evidence.attached logs", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-evidence",
    );

    try {
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write", "certops:evidence:write"],
      });
      const response = await supertest(buildExecutorApp())
        .post("/api/v1/certops/executor/events")
        .set("Authorization", `Bearer ${token.plaintextToken}`)
        .send(
          eventPayload({
            workspaceId: workspaceA,
            jobId: job.id,
            eventType: "evidence.attached",
            status: "accepted",
            evidence: [
              {
                schemaVersion: 1,
                evidenceId: `evidence-${crypto.randomUUID()}`,
                jobId: job.id,
                workspaceId: workspaceA,
                certificateId: "cert-1",
                eventType: "certificate.observed",
                source: "executor",
                observedAt: new Date().toISOString(),
                fingerprintSha256:
                  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                summary: "Observed public certificate fingerprint",
                artifactRefs: [
                  {
                    type: "report",
                    reference: "reports/certops/public-observation.json",
                    sha256:
                      "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                  },
                  {
                    type: "log",
                    reference: "executor-log-1",
                    sha256: null,
                  },
                ],
                metadata: [{ name: "issuer", value: "TokenTimer Test CA" }],
              },
            ],
          }),
        );

      expect(response.status).to.equal(202);
      expect(response.body.evidenceId).to.be.a("string").that.is.not.empty;
      expectAcceptedResponseMatchesOpenApi(response);
      const evidence = await listCertificateEvidence({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(evidence.items).to.have.length(1);
      expect(evidence.items[0]).to.include({
        evidenceType: "certificate.observed",
        subjectType: "managed_certificate",
        subjectId: "cert-1",
        createdByApiTokenId: token.token.id,
      });
      expect(evidence.items[0].metadata.issuer).to.equal("TokenTimer Test CA");
      expect(evidence.items[0].metadata.artifactRefs).to.deep.equal([
        {
          type: "report",
          reference: "reports/certops/public-observation.json",
          sha256:
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        },
        {
          type: "log",
          reference: "executor-log-1",
          sha256: null,
        },
      ]);

      const logs = await listCertificateJobLog({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(logs.items.map((item) => item.eventType)).to.include(
        "evidence.attached",
      );
      expectNoSensitiveValues(response.body, token.plaintextToken);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("rejects malformed evidence artifactRefs before job log or evidence persistence", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-artifact-refs",
    );

    try {
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write", "certops:evidence:write"],
      });
      const app = buildExecutorApp();
      const route = "/api/v1/certops/executor/events";
      const auth = `Bearer ${token.plaintextToken}`;

      function eventWithArtifactRefs(artifactRefs) {
        return eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          eventType: "evidence.attached",
          status: "accepted",
          evidence: [
            {
              schemaVersion: 1,
              evidenceId: `evidence-${crypto.randomUUID()}`,
              jobId: job.id,
              workspaceId: workspaceA,
              certificateId: "cert-1",
              eventType: "certificate.observed",
              source: "executor",
              observedAt: new Date().toISOString(),
              artifactRefs,
            },
          ],
        });
      }

      async function expectArtifactRefsRejected({
        artifactRefs,
        status = 400,
        code = "CERTOPS_EXECUTOR_EVENT_INVALID",
        forbidden = [],
      }) {
        const before = await countJobArtifacts({
          workspaceId: workspaceA,
          jobId: job.id,
        });
        const response = await supertest(app)
          .post(route)
          .set("Authorization", auth)
          .send(eventWithArtifactRefs(artifactRefs));
        const after = await countJobArtifacts({
          workspaceId: workspaceA,
          jobId: job.id,
        });

        expect(response.status).to.equal(status);
        expect(response.status).to.not.equal(500);
        expect(response.body.code).to.equal(code);
        expect(response.body.code).to.not.equal("INTERNAL_ERROR");
        expect(after).to.deep.equal(before);
        expectNoSensitiveValues(response.body, token.plaintextToken, forbidden);
      }

      const validArtifactRef = {
        type: "report",
        reference: "reports/certops/public-observation.json",
        sha256:
          "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      };

      await expectArtifactRefsRejected({
        artifactRefs: Array.from({ length: 17 }, () => validArtifactRef),
      });

      await expectArtifactRefsRejected({
        artifactRefs: [{ ...validArtifactRef, type: "archive" }],
      });

      await expectArtifactRefsRejected({
        artifactRefs: [{ type: "log" }],
      });

      await expectArtifactRefsRejected({
        artifactRefs: [{ ...validArtifactRef, reference: "a".repeat(513) }],
      });

      await expectArtifactRefsRejected({
        artifactRefs: [{ ...validArtifactRef, sha256: "not-a-sha256" }],
      });

      await expectArtifactRefsRejected({
        artifactRefs: [{ ...validArtifactRef, extra: "not-allowed" }],
      });

      const before = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      const redacted = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(
          eventWithArtifactRefs([
            { type: "log", reference: "password=swordfish" },
          ]),
        );
      const after = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(redacted.status).to.equal(202);
      expect(after.logs).to.equal(before.logs + 1);
      expect(after.evidence).to.equal(before.evidence + 1);
      expect(after.executorEvents).to.equal(before.executorEvents + 1);
      const evidence = await listCertificateEvidence({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(evidence.items[0].metadata.artifactRefs[0].reference).to.equal(
        "password=[REDACTED]",
      );
      expect(evidence.items[0].metadata.redactionApplied).to.equal(true);
      expectNoSensitiveValues(redacted.body, token.plaintextToken, [
        "password=swordfish",
      ]);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("returns safe errors for missing jobs and malformed events", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-errors",
    );

    try {
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write"],
      });
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const app = buildExecutorApp();
      const route = "/api/v1/certops/executor/events";
      const auth = `Bearer ${token.plaintextToken}`;

      const missingJob = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(eventPayload({ workspaceId: workspaceA, jobId: crypto.randomUUID() }));
      expect(missingJob.status).to.equal(404);
      expect(missingJob.body.code).to.equal("CERTOPS_JOB_NOT_FOUND");

      const invalidType = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(
          eventPayload({
            workspaceId: workspaceA,
            jobId: job.id,
            eventType: "job.created",
          }),
        );
      expect(invalidType.status).to.equal(400);
      expect(invalidType.body.code).to.equal(
        "CERTOPS_EXECUTOR_EVENT_TYPE_INVALID",
      );

      const invalidStatus = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(
          eventPayload({
            workspaceId: workspaceA,
            jobId: job.id,
            status: "queued",
          }),
        );
      expect(invalidStatus.status).to.equal(400);
      expect(invalidStatus.body.code).to.equal("CERTOPS_JOB_STATUS_INVALID");
      expectNoSensitiveValues(invalidStatus.body, token.plaintextToken);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("rejects malformed IDs and metadata at the route boundary", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-boundary",
    );

    try {
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write", "certops:evidence:write"],
      });
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const app = buildExecutorApp();
      const route = "/api/v1/certops/executor/events";
      const auth = `Bearer ${token.plaintextToken}`;

      async function expectRejectedWithoutPersistence({
        body,
        status,
        statuses,
        code,
        forbidden = [],
      }) {
        const before = await countJobArtifacts({
          workspaceId: workspaceA,
          jobId: job.id,
        });
        const response = await supertest(app)
          .post(route)
          .set("Authorization", auth)
          .send(body);
        const after = await countJobArtifacts({
          workspaceId: workspaceA,
          jobId: job.id,
        });

        if (statuses) {
          expect(response.status).to.be.oneOf(statuses);
        } else {
          expect(response.status).to.equal(status);
        }
        expect(response.status).to.not.equal(500);
        expect(response.body.code).to.not.equal("INTERNAL_ERROR");
        if (code) expect(response.body.code).to.equal(code);
        expect(after).to.deep.equal(before);
        expectNoSensitiveValues(response.body, token.plaintextToken, forbidden);
        return response;
      }

      function validEvidenceItem(overrides = {}) {
        return {
          schemaVersion: 1,
          evidenceId: `evidence-${crypto.randomUUID()}`,
          jobId: job.id,
          workspaceId: workspaceA,
          certificateId: "cert-1",
          eventType: "certificate.observed",
          source: "executor",
          observedAt: new Date().toISOString(),
          ...overrides,
        };
      }

      await expectRejectedWithoutPersistence({
        body: eventPayload({ workspaceId: workspaceA, jobId: "not-a-uuid" }),
        status: 400,
      });

      await expectRejectedWithoutPersistence({
        body: eventPayload({ workspaceId: "not-a-uuid", jobId: job.id }),
        statuses: [400, 401, 403],
      });

      await expectRejectedWithoutPersistence({
        body: eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          eventId: "a".repeat(129),
        }),
        status: 400,
        code: "CERTOPS_EXECUTOR_EVENT_INVALID",
      });

      await expectRejectedWithoutPersistence({
        body: eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          eventId: "event/bad",
        }),
        status: 400,
        code: "CERTOPS_EXECUTOR_EVENT_INVALID",
      });

      for (const occurredAt of [
        "2026-02-30T12:00:00Z",
        "2201-01-01T00:00:00Z",
      ]) {
        await expectRejectedWithoutPersistence({
          body: eventPayload({ workspaceId: workspaceA, jobId: job.id, occurredAt }),
          status: 400,
          code: "CERTOPS_EXECUTOR_EVENT_INVALID",
        });
      }

      await expectRejectedWithoutPersistence({
        body: eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          unexpectedPublicField: "ignored-before-hardening",
        }),
        status: 400,
        code: "CERTOPS_EXECUTOR_EVENT_INVALID",
        forbidden: ["ignored-before-hardening"],
      });

      await expectRejectedWithoutPersistence({
        body: eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          credential: "password=swordfish",
        }),
        status: 400,
        code: "CERTOPS_EXECUTOR_EVENT_INVALID",
        forbidden: ["password=swordfish"],
      });

      await expectRejectedWithoutPersistence({
        body: eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          privateKeyPem: "not-allowed",
        }),
        status: 422,
        code: "PRIVATE_KEY_MATERIAL_REJECTED",
        forbidden: ["privateKeyPem"],
      });

      await expectRejectedWithoutPersistence({
        body: eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          eventType: "evidence.attached",
          status: "accepted",
          evidence: [
            validEvidenceItem({
              unexpectedPublicField: "ignored-before-hardening",
            }),
          ],
        }),
        status: 400,
        code: "CERTOPS_EXECUTOR_EVENT_INVALID",
        forbidden: ["ignored-before-hardening"],
      });

      await expectRejectedWithoutPersistence({
        body: eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          eventType: "evidence.attached",
          status: "accepted",
          evidence: [
            validEvidenceItem({
              privateKeyPem: "not-allowed",
            }),
          ],
        }),
        status: 422,
        code: "PRIVATE_KEY_MATERIAL_REJECTED",
        forbidden: ["privateKeyPem", "not-allowed"],
      });

      for (const evidenceOverrides of [
        { source: "arbitrary-source" },
        { status: "unknown-status" },
        { fingerprintSha256: "not-a-fingerprint" },
        { fingerprintSha256: "a".repeat(63) },
        { fingerprintSha256: "a".repeat(65) },
        { fingerprintSha256: "A".repeat(64) },
      ]) {
        await expectRejectedWithoutPersistence({
          body: eventPayload({
            workspaceId: workspaceA,
            jobId: job.id,
            eventType: "evidence.attached",
            status: "accepted",
            evidence: [validEvidenceItem(evidenceOverrides)],
          }),
          status: 400,
          code: "CERTOPS_EXECUTOR_EVENT_INVALID",
        });
      }

      await expectRejectedWithoutPersistence({
        body: eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          metadata: Array.from({ length: 33 }, (_value, index) => ({
            name: `m${index}`,
            value: index,
          })),
        }),
        status: 400,
        code: "CERTOPS_EXECUTOR_EVENT_INVALID",
      });

      await expectRejectedWithoutPersistence({
        body: eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          metadata: [{ name: "a".repeat(65), value: "too-long-name" }],
        }),
        status: 400,
        code: "CERTOPS_EXECUTOR_EVENT_INVALID",
      });

      await expectRejectedWithoutPersistence({
        body: eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          metadata: [{ name: "privateKey", value: "not-allowed" }],
        }),
        status: 422,
        code: "PRIVATE_KEY_MATERIAL_REJECTED",
        forbidden: ["privateKey"],
      });

      await expectRejectedWithoutPersistence({
        body: eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          metadata: [{ name: "longValue", value: "a".repeat(513) }],
        }),
        status: 400,
        code: "CERTOPS_EXECUTOR_EVENT_INVALID",
      });

      for (const value of [{ nested: "object" }, ["array"]]) {
        await expectRejectedWithoutPersistence({
          body: eventPayload({
            workspaceId: workspaceA,
            jobId: job.id,
            metadata: [{ name: "badValue", value }],
          }),
          status: 400,
          code: "CERTOPS_EXECUTOR_EVENT_INVALID",
        });
      }

      const safe = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(
          eventPayload({
            workspaceId: workspaceA,
            jobId: job.id,
            eventType: "job.progress",
            status: "running",
            metadata: [
              { name: "executor", value: "test-executor" },
              { name: "attempt", value: 2 },
              { name: "canary", value: true },
            ],
          }),
        );
      expect(safe.status).to.equal(202);
      const logs = await listCertificateJobLog({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      const progressLog = logs.items.find(
        (item) => item.eventType === "job.progress",
      );
      expect(progressLog.metadata).to.include({
        executor: "test-executor",
        attempt: 2,
        canary: true,
      });
      expectNoSensitiveValues(safe.body, token.plaintextToken);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("enforces workspace isolation through the authenticated token workspace", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-isolation",
    );

    try {
      const jobB = await createJob({ workspaceId: workspaceB, ownerId });
      const tokenA = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write"],
      });
      const response = await supertest(buildExecutorApp())
        .post("/api/v1/certops/executor/events")
        .set("Authorization", `Bearer ${tokenA.plaintextToken}`)
        .send(eventPayload({ workspaceId: workspaceA, jobId: jobB.id }));

      expect(response.status).to.equal(404);
      expect(response.body.code).to.equal("CERTOPS_JOB_NOT_FOUND");

      const jobBStatus = await getCertificateJobById({
        workspaceId: workspaceB,
        jobId: jobB.id,
      });
      expect(jobBStatus.status).to.equal("pending");
      expectNoSensitiveValues(response.body, tokenA.plaintextToken);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("rejects private-key payloads before persistence", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-security",
    );

    try {
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write", "certops:evidence:write"],
      });
      const app = buildExecutorApp();
      const route = "/api/v1/certops/executor/events";
      const auth = `Bearer ${token.plaintextToken}`;

      const dangerousBodies = [
        eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          privateKey: "not-allowed",
        }),
        eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          message: PRIVATE_KEY_PEM,
        }),
        eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          metadata: [{ name: "privateKeyPem", value: "abc" }],
        }),
        eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          message: "-----BEGIN ENCRYPTED PRIVATE KEY-----\nincomplete",
        }),
        eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          metadata: [
            {
              name: "publicNote",
              value: Buffer.from(PRIVATE_KEY_PEM).toString("base64"),
            },
          ],
        }),
        eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          message: ENCRYPTED_PKCS8_DER.toString("base64"),
        }),
        eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          metadata: [
            {
              name: "publicNote",
              value: ENCRYPTED_PKCS8_DER.toString("hex"),
            },
          ],
        }),
        eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          message: longOidEncryptedPkcs8Der().toString("base64"),
        }),
        eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          evidence: [
            {
              eventType: "certificate.observed",
              summary: longOidEncryptedPkcs8Der().toString("hex"),
            },
          ],
        }),
      ];

      for (const body of dangerousBodies) {
        const beforeArtifacts = await countJobArtifacts({
          workspaceId: workspaceA,
          jobId: job.id,
        });
        const beforeAudits = await auditActionCounts({
          workspaceId: workspaceA,
        });
        const response = await supertest(app)
          .post(route)
          .set("Authorization", auth)
          .send(body);
        const afterArtifacts = await countJobArtifacts({
          workspaceId: workspaceA,
          jobId: job.id,
        });
        const afterAudits = await auditActionCounts({
          workspaceId: workspaceA,
        });

        expect(response.status).to.equal(422);
        expect(response.body.code).to.equal("PRIVATE_KEY_MATERIAL_REJECTED");
        expect(afterArtifacts).to.deep.equal(beforeArtifacts);
        expect(afterAudits.CERTOPS_KEY_MATERIAL_REJECTED || 0).to.equal(
          (beforeAudits.CERTOPS_KEY_MATERIAL_REJECTED || 0) + 1,
        );
        expectNoSensitiveValues(response.body, token.plaintextToken);
      }
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("rejects server-owned metadata collisions before logs, evidence, audits, or idempotency records", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-reserved-metadata",
    );

    try {
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write", "certops:evidence:write"],
      });
      const app = buildExecutorApp();
      const route = "/api/v1/certops/executor/events";
      const auth = `Bearer ${token.plaintextToken}`;
      const bodies = [
        eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          metadata: [{ name: "redactionApplied", value: true }],
        }),
        eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          metadata: [{ name: "redaction_count", value: -100 }],
        }),
        ...[
          "redactedSecretCategories",
          "redacted_secret_categories",
          "REDACTED-SECRET-CATEGORIES",
        ].map((name) =>
          eventPayload({
            workspaceId: workspaceA,
            jobId: job.id,
            metadata: [{ name, value: "forged" }],
          }),
        ),
        eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          eventType: "evidence.attached",
          status: "accepted",
          evidence: [
            {
              eventType: "certificate.observed",
              metadata: [{ name: "source", value: "forged" }],
            },
          ],
        }),
        eventPayload({
          workspaceId: workspaceA,
          jobId: job.id,
          eventType: "evidence.attached",
          status: "accepted",
          evidence: [
            {
              eventType: "certificate.observed",
              metadata: [
                { name: "redacted_secret_categories", value: "forged" },
              ],
            },
          ],
        }),
      ];

      for (const body of bodies) {
        const before = await countJobArtifacts({ workspaceId: workspaceA, jobId: job.id });
        const response = await supertest(app)
          .post(route)
          .set("Authorization", auth)
          .send(body);
        expect(response.status).to.equal(400);
        expect(response.body.code).to.equal("CERTOPS_EXECUTOR_EVENT_INVALID");
        expect(await countJobArtifacts({ workspaceId: workspaceA, jobId: job.id })).to.deep.equal(before);
        expectNoSensitiveValues(response.body, token.plaintextToken);
      }

      const auditCounts = await auditActionCounts({ workspaceId: workspaceA, jobId: job.id });
      expect(auditCounts.CERTOPS_GENERIC_SECRET_REDACTION_APPLIED || 0).to.equal(0);
      expect(await countExecutorEventRecords({ workspaceId: workspaceA, jobId: job.id })).to.equal(0);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("redacts generic secrets in log and evidence metadata before persistence", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-redaction",
    );

    try {
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write", "certops:evidence:write"],
      });
      const app = buildExecutorApp();
      const route = "/api/v1/certops/executor/events";
      const auth = `Bearer ${token.plaintextToken}`;
      const response = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(
          eventPayload({
            workspaceId: workspaceA,
            jobId: job.id,
            eventType: "evidence.attached",
            status: "accepted",
            message: "password=swordfish",
            metadata: [
              {
                name: "executorNote",
                value: "Authorization: Bearer abc123tokenvalue",
              },
              { name: "credential", value: "abc" },
            ],
            evidence: [
              {
                schemaVersion: 1,
                evidenceId: `evidence-${crypto.randomUUID()}`,
                jobId: job.id,
                workspaceId: workspaceA,
                certificateId: "cert-1",
                eventType: "certificate.observed",
                source: "executor",
                observedAt: new Date().toISOString(),
                summary: "credential=abc",
                metadata: [
                  { name: "note", value: "password=swordfish" },
                  { name: "secret", value: "abc" },
                ],
              },
            ],
          }),
        );

      expect(response.status).to.equal(202);
      expectNoSensitiveValues(response.body, token.plaintextToken, [
        "abc123tokenvalue",
        "credential=abc",
      ]);

      const logs = await listCertificateJobLog({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(logs.items).to.have.length(1);
      expect(logs.items[0].message).to.equal("password=[REDACTED]");
      expect(logs.items[0].metadata.executorNote).to.equal(
        "Authorization: [REDACTED]",
      );
      expect(logs.items[0].metadata.redactedMetadata2).to.equal("[REDACTED]");
      expect(logs.items[0].metadata.redactionApplied).to.equal(true);
      expect(logs.items[0].metadata.redactionCount).to.be.greaterThan(0);

      const evidence = await listCertificateEvidence({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(evidence.items).to.have.length(1);
      expect(evidence.items[0].metadata.summary).to.equal(
        "credential=[REDACTED]",
      );
      expect(evidence.items[0].metadata.note).to.equal(
        "password=[REDACTED]",
      );
      expect(evidence.items[0].metadata.redactedMetadata2).to.equal(
        "[REDACTED]",
      );
      expect(evidence.items[0].metadata.redactionApplied).to.equal(true);
      const serialized = JSON.stringify({
        logs: logs.items,
        evidence: evidence.items,
      });
      expect(serialized).to.include("[REDACTED]");
      expect(serialized).to.not.include("password=swordfish");
      expect(serialized).to.not.include("credential=abc");
      expect(serialized).to.not.include("abc123tokenvalue");
      expect(serialized).to.not.include(token.plaintextToken);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("redacts generic-secret field-name aliases without persisting client names or values", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-secret-aliases",
    );

    try {
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write", "certops:evidence:write"],
      });
      const response = await supertest(buildExecutorApp())
        .post("/api/v1/certops/executor/events")
        .set("Authorization", `Bearer ${token.plaintextToken}`)
        .send(
          eventPayload({
            workspaceId: workspaceA,
            jobId: job.id,
            eventType: "evidence.attached",
            status: "accepted",
            metadata: [{ name: "apiToken", value: "event-token-value" }],
            evidence: [
              {
                eventType: "certificate.observed",
                metadata: [
                  { name: "cookie_header", value: "evidence-cookie-value" },
                ],
              },
            ],
          }),
        );
      expect(response.status).to.equal(202);

      const logs = await listCertificateJobLog({ workspaceId: workspaceA, jobId: job.id });
      const evidence = await listCertificateEvidence({ workspaceId: workspaceA, jobId: job.id });
      const audits = await TestUtils.execQuery(
        "SELECT action, metadata FROM audit_events WHERE workspace_id = $1",
        [workspaceA],
      );
      const persisted = JSON.stringify({
        logMetadata: logs.items.map((item) => item.metadata),
        evidenceMetadata: evidence.items.map((item) => item.metadata),
        auditMetadata: audits.rows.map((item) => item.metadata),
      });

      expect(logs.items[0].metadata.redactedMetadata1).to.equal("[REDACTED]");
      expect(evidence.items[0].metadata.redactedMetadata1).to.equal("[REDACTED]");
      for (const raw of [
        "event-token-value",
        "evidence-cookie-value",
        '"apiToken"',
        '"cookie_header"',
      ]) {
        expect(persisted).to.not.include(raw);
      }
      expectNoSensitiveValues(response.body, token.plaintextToken, [
        "event-token-value",
        "evidence-cookie-value",
      ]);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("redacts cookie, header, token, and cloud-secret strings without losing public timeline context", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-content-redaction",
    );

    try {
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write", "certops:evidence:write"],
      });
      const response = await supertest(buildExecutorApp())
        .post("/api/v1/certops/executor/events")
        .set("Authorization", `Bearer ${token.plaintextToken}`)
        .send(
          eventPayload({
            workspaceId: workspaceA,
            jobId: job.id,
            eventType: "evidence.attached",
            status: "accepted",
            message: "executor failed; token=message-value; retrying",
            metadata: [
              { name: "executorNote", value: "X-API-Key: metadata-value" },
            ],
            evidence: [
              {
                schemaVersion: 1,
                evidenceId: `evidence-${crypto.randomUUID()}`,
                jobId: job.id,
                workspaceId: workspaceA,
                certificateId: "cert-1",
                eventType: "certificate.observed",
                source: "executor",
                observedAt: new Date().toISOString(),
                summary: "Cookie: session=summary-value",
                metadata: [
                  {
                    name: "cloudNote",
                    value: "AWS_SECRET_ACCESS_KEY=evidence-value",
                  },
                ],
                artifactRefs: [
                  {
                    type: "log",
                    reference: "Set-Cookie: sid=artifact-value; HttpOnly",
                  },
                ],
                redactionApplied: false,
              },
            ],
          }),
        );
      expect(response.status).to.equal(202);

      const logs = await listCertificateJobLog({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      const evidence = await listCertificateEvidence({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      const audits = await TestUtils.execQuery(
        `SELECT action, metadata
           FROM audit_events
          WHERE workspace_id = $1
            AND metadata->>'jobId' = $2
          ORDER BY action ASC`,
        [workspaceA, job.id],
      );
      const serialized = JSON.stringify({
        response: response.body,
        logs: logs.items,
        evidence: evidence.items,
        audits: audits.rows,
      });

      expect(logs.items[0].message).to.equal(
        "executor failed; token=[REDACTED]; retrying",
      );
      expect(logs.items[0].metadata.executorNote).to.equal(
        "X-API-Key: [REDACTED]",
      );
      expect(evidence.items[0].metadata.summary).to.equal(
        "Cookie: [REDACTED]",
      );
      expect(evidence.items[0].metadata.cloudNote).to.equal(
        "AWS_SECRET_ACCESS_KEY=[REDACTED]",
      );
      expect(evidence.items[0].metadata.artifactRefs[0].reference).to.equal(
        "Set-Cookie: [REDACTED]",
      );
      const redactionAudit = audits.rows.find(
        (row) => row.action === "CERTOPS_GENERIC_SECRET_REDACTION_APPLIED",
      );
      expect(redactionAudit.metadata.redactedFields).to.deep.equal([
        "cookie",
        "generic-secret",
      ]);
      for (const rawValue of [
        "message-value",
        "metadata-value",
        "summary-value",
        "evidence-value",
        "artifact-value",
      ]) {
        expect(serialized).to.not.include(rawValue);
      }
      expect(serialized).to.include("[REDACTED]");
      expectNoSensitiveValues(response.body, token.plaintextToken);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("records safe audit events for accepted, conflicting, and rejected evidence output", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-audit",
    );

    try {
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write", "certops:evidence:write"],
      });
      const app = buildExecutorApp();
      const route = "/api/v1/certops/executor/events";
      const auth = `Bearer ${token.plaintextToken}`;
      const eventId = `event-${crypto.randomUUID()}`;
      const acceptedPayload = eventPayload({
        workspaceId: workspaceA,
        jobId: job.id,
        eventId,
        eventType: "evidence.attached",
        status: "accepted",
        message: "password=first-secret",
        evidence: [
          {
            schemaVersion: 1,
            evidenceId: `evidence-${crypto.randomUUID()}`,
            jobId: job.id,
            workspaceId: workspaceA,
            certificateId: "cert-1",
            eventType: "certificate.observed",
            source: "executor",
            observedAt: new Date().toISOString(),
            output: "executor output credential=audit-secret",
          },
        ],
      });

      const accepted = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(acceptedPayload);
      const conflict = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send({ ...acceptedPayload, message: "changed public message" });
      const privateKeyRejected = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(
          eventPayload({
            workspaceId: workspaceA,
            jobId: job.id,
            eventId: `event-${crypto.randomUUID()}`,
            eventType: "evidence.attached",
            status: "accepted",
            evidence: [
              {
                schemaVersion: 1,
                eventType: "certificate.observed",
                source: "executor",
                observedAt: new Date().toISOString(),
                output: PRIVATE_KEY_PEM,
              },
            ],
          }),
        );

      expect(accepted.status).to.equal(202);
      expect(conflict.status).to.equal(409);
      expect(conflict.body.code).to.equal("CERTOPS_EXECUTOR_EVENT_CONFLICT");
      expect(privateKeyRejected.status).to.equal(422);
      expect(privateKeyRejected.body.code).to.equal(
        "PRIVATE_KEY_MATERIAL_REJECTED",
      );

      const auditEvents = await listCertOpsAuditEvents(workspaceA);
      const actions = auditEvents.map((event) => event.action);
      for (const action of [
        "CERTOPS_EXECUTOR_EVENT_ACCEPTED",
        "CERTOPS_EVIDENCE_ACCEPTED",
        "CERTOPS_GENERIC_SECRET_REDACTION_APPLIED",
        "CERTOPS_KEY_MATERIAL_REJECTED",
      ]) {
        expect(actions).to.include(action);
      }
      expect(actions).to.not.include("CERTOPS_EVIDENCE_REJECTED");

      const serialized = JSON.stringify(auditEvents);
      for (const forbidden of [
        token.plaintextToken,
        `Bearer ${token.plaintextToken}`,
        "first-secret",
        "audit-secret",
        "PRIVATE KEY",
      ]) {
        expect(serialized).to.not.include(forbidden);
      }
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });
});

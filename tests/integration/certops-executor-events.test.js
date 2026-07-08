const crypto = require("crypto");
const { createRequire } = require("module");
const supertest = require("supertest");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();
const { createApiToken } = require("../../apps/api/services/certops/apiTokens");
const {
  createCertificateJob,
  getCertificateJobById,
  listCertificateJobLog,
} = require("../../apps/api/services/certops/jobs");
const {
  listCertificateEvidence,
} = require("../../apps/api/services/certops/evidence");
const {
  createCsrfExemptMiddleware,
} = require("../../apps/api/middleware/csrf-exempt");
const {
  createCertOpsExecutorRouter,
} = require("../../apps/api/routes/certops-executor");

const apiRequire = createRequire(
  require.resolve("../../apps/api/package.json"),
);
const express = apiRequire("express");

const PRIVATE_KEY_PEM =
  "-----BEGIN RSA PRIVATE KEY-----\nRkFLRS1OT1QtQS1SRUFMLUtFWQ==\n-----END RSA PRIVATE KEY-----";

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

function buildExecutorApp({ rateLimitOptions, csrf = false } = {}) {
  const app = express();
  app.use(express.json());

  if (csrf) {
    app.use(
      "/api",
      createCsrfExemptMiddleware((_req, res) =>
        res.status(403).json({
          error: "Invalid CSRF token",
          code: "EBADCSRFTOKEN",
        }),
      ),
    );
  }

  app.use(
    createCertOpsExecutorRouter({
      rateLimitOptions: rateLimitOptions || { windowMs: 60_000, max: 100 },
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

async function createJob({ workspaceId, ownerId }) {
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

  it("requires a valid machine token with certops:executor:events scope", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-auth",
    );

    try {
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const scoped = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:executor:events"],
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
      expect(ok.body.evidenceId).to.equal(undefined);
      expect(ok.body.accepted).to.equal(undefined);
      expect(ok.body.code).to.equal(undefined);
      expect(ok.body.user).to.equal(undefined);
      expect(ok.body.authenticated).to.equal(undefined);
      expectNoSensitiveValues(ok.body, scoped.plaintextToken);
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
        scopes: ["certops:executor:events"],
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
        scopes: ["certops:executor:events"],
      });
      const app = buildExecutorApp({ csrf: true });

      const accepted = await supertest(app)
        .post("/api/v1/certops/executor/events")
        .set("Authorization", `Bearer ${token.plaintextToken}`)
        .send(eventPayload({ workspaceId: workspaceA, jobId: job.id }));
      expect(accepted.status).to.equal(202);

      const unrelated = await supertest(app)
        .post(`/api/v1/workspaces/${workspaceA}/certops/unrelated-write`)
        .send({});
      expect(unrelated.status).to.equal(403);
      expect(unrelated.body.code).to.equal("EBADCSRFTOKEN");
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
        scopes: ["certops:executor:events"],
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

      const completedJob = await createJob({ workspaceId: workspaceA, ownerId });
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

      const failedJob = await createJob({ workspaceId: workspaceA, ownerId });
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
      expect(progress.body.status).to.equal("queued");
      expect(
        (await getCertificateJobById({
          workspaceId: workspaceA,
          jobId: progressJob.id,
        })).status,
      ).to.equal("queued");

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

  it("treats duplicate executor event IDs idempotently without duplicating side effects", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-idempotency",
    );

    try {
      const app = buildExecutorApp();
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:executor:events"],
      });
      const route = "/api/v1/certops/executor/events";
      const auth = `Bearer ${token.plaintextToken}`;
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const payload = eventPayload({
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
            metadata: [{ name: "issuer", value: "TokenTimer Test CA" }],
          },
        ],
      });

      const first = await supertest(app).post(route).set("Authorization", auth).send(payload);
      const second = await supertest(app).post(route).set("Authorization", auth).send(payload);
      const artifacts = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: job.id,
      });

      expect(first.status).to.equal(202);
      expect(second.status).to.equal(202);
      expect(first.body.duplicate).to.equal(false);
      expect(first.body.idempotent).to.equal(false);
      expect(second.body.duplicate).to.equal(true);
      expect(second.body.idempotent).to.equal(true);
      expect(second.body.eventId).to.equal(first.body.eventId);
      expect(second.body.evidenceId).to.equal(first.body.evidenceId);
      expect(artifacts).to.deep.equal({
        logs: 1,
        evidence: 1,
        executorEvents: 1,
      });
      expectNoSensitiveValues(second.body, token.plaintextToken);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("uses the sanitized executor event payload for idempotency hashes", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-sanitized-idempotency",
    );

    try {
      const app = buildExecutorApp();
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:executor:events"],
      });
      const route = "/api/v1/certops/executor/events";
      const auth = `Bearer ${token.plaintextToken}`;
      const job = await createJob({ workspaceId: workspaceA, ownerId });
      const eventId = `event-${crypto.randomUUID()}`;
      const evidenceId = `evidence-${crypto.randomUUID()}`;
      const payload = eventPayload({
        workspaceId: workspaceA,
        jobId: job.id,
        eventId,
        eventType: "evidence.attached",
        status: "accepted",
        message: "password=first-secret",
        evidence: [
          {
            schemaVersion: 1,
            evidenceId,
            jobId: job.id,
            workspaceId: workspaceA,
            certificateId: "cert-1",
            eventType: "certificate.observed",
            source: "executor",
            observedAt: new Date().toISOString(),
            summary: "credential=first-secret",
          },
        ],
      });
      const retriedPayload = {
        ...payload,
        message: "password=second-secret",
        evidence: [
          {
            ...payload.evidence[0],
            summary: "credential=second-secret",
          },
        ],
      };

      const first = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(payload);
      const second = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(retriedPayload);
      const artifacts = await countJobArtifacts({
        workspaceId: workspaceA,
        jobId: job.id,
      });

      expect(first.status).to.equal(202);
      expect(second.status).to.equal(202);
      expect(first.body.duplicate).to.equal(false);
      expect(first.body.idempotent).to.equal(false);
      expect(second.body.duplicate).to.equal(true);
      expect(second.body.idempotent).to.equal(true);
      expect(artifacts).to.deep.equal({
        logs: 1,
        evidence: 1,
        executorEvents: 1,
      });

      const logs = await listCertificateJobLog({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      const evidence = await listCertificateEvidence({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(logs.items[0].message).to.equal("[REDACTED]");
      expect(logs.items[0].metadata.redactionApplied).to.equal(true);
      expect(evidence.items[0].metadata.summary).to.equal("[REDACTED]");
      expect(evidence.items[0].metadata.redactionApplied).to.equal(true);

      const serialized = JSON.stringify({
        first: first.body,
        second: second.body,
        logs: logs.items,
        evidence: evidence.items,
      });
      expect(serialized).to.include("[REDACTED]");
      expect(serialized).to.not.include("first-secret");
      expect(serialized).to.not.include("second-secret");
      expectNoSensitiveValues(second.body, token.plaintextToken, [
        "first-secret",
        "second-secret",
      ]);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("isolates executor event IDs by job and rejects conflicting retries safely", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-executor-events-conflict",
    );

    try {
      const app = buildExecutorApp();
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:executor:events"],
      });
      const tokenB = await createScopedToken({
        workspaceId: workspaceB,
        ownerId,
        scopes: ["certops:executor:events"],
      });
      const route = "/api/v1/certops/executor/events";
      const auth = `Bearer ${token.plaintextToken}`;
      const authB = `Bearer ${tokenB.plaintextToken}`;
      const sharedEventId = `event-${crypto.randomUUID()}`;
      const jobA = await createJob({ workspaceId: workspaceA, ownerId });
      const jobB = await createJob({ workspaceId: workspaceA, ownerId });
      const workspaceBJob = await createJob({ workspaceId: workspaceB, ownerId });

      const firstPayload = eventPayload({
        workspaceId: workspaceA,
        jobId: jobA.id,
        eventId: sharedEventId,
        message: "first accepted event",
      });
      const conflictingPayload = {
        ...firstPayload,
        message: "different accepted event",
      };
      const otherJobPayload = eventPayload({
        workspaceId: workspaceA,
        jobId: jobB.id,
        eventId: sharedEventId,
      });
      const otherWorkspacePayload = eventPayload({
        workspaceId: workspaceB,
        jobId: workspaceBJob.id,
        eventId: sharedEventId,
      });

      const first = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(firstPayload);
      const conflict = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(conflictingPayload);
      const otherJob = await supertest(app)
        .post(route)
        .set("Authorization", auth)
        .send(otherJobPayload);
      const otherWorkspace = await supertest(app)
        .post(route)
        .set("Authorization", authB)
        .send(otherWorkspacePayload);

      expect(first.status).to.equal(202);
      expect(conflict.status).to.equal(409);
      expect(conflict.body.code).to.equal("CERTOPS_EXECUTOR_EVENT_CONFLICT");
      expect(otherJob.status).to.equal(202);
      expect(otherWorkspace.status).to.equal(202);
      expect(await countJobArtifacts({ workspaceId: workspaceA, jobId: jobA.id })).to.deep.equal({
        logs: 1,
        evidence: 0,
        executorEvents: 1,
      });
      expect(await countJobArtifacts({ workspaceId: workspaceA, jobId: jobB.id })).to.deep.equal({
        logs: 1,
        evidence: 0,
        executorEvents: 1,
      });
      expect(
        await countJobArtifacts({
          workspaceId: workspaceB,
          jobId: workspaceBJob.id,
        }),
      ).to.deep.equal({
        logs: 1,
        evidence: 0,
        executorEvents: 1,
      });
      expectNoSensitiveValues(conflict.body, token.plaintextToken);
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
        scopes: ["certops:executor:events"],
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
        scopes: ["certops:executor:events"],
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
        "[REDACTED]",
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
        scopes: ["certops:executor:events"],
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
        scopes: ["certops:executor:events"],
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
        scopes: ["certops:executor:events"],
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
      expect(jobBStatus.status).to.equal("queued");
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
        scopes: ["certops:executor:events"],
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
      ];

      for (const body of dangerousBodies) {
        const beforeLogs = await listCertificateJobLog({
          workspaceId: workspaceA,
          jobId: job.id,
        });
        const response = await supertest(app)
          .post(route)
          .set("Authorization", auth)
          .send(body);
        const afterLogs = await listCertificateJobLog({
          workspaceId: workspaceA,
          jobId: job.id,
        });

        expect(response.status).to.equal(422);
        expect(response.body.code).to.equal("PRIVATE_KEY_MATERIAL_REJECTED");
        expect(afterLogs.items).to.have.length(beforeLogs.items.length);
        expectNoSensitiveValues(response.body, token.plaintextToken);
      }
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
        scopes: ["certops:executor:events"],
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
      expect(logs.items[0].message).to.equal("[REDACTED]");
      expect(logs.items[0].metadata.executorNote).to.equal("[REDACTED]");
      expect(logs.items[0].metadata.redactedMetadata2).to.equal("[REDACTED]");
      expect(logs.items[0].metadata.redactionApplied).to.equal(true);
      expect(logs.items[0].metadata.redactionCount).to.be.greaterThan(0);

      const evidence = await listCertificateEvidence({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(evidence.items).to.have.length(1);
      expect(evidence.items[0].metadata.summary).to.equal("[REDACTED]");
      expect(evidence.items[0].metadata.note).to.equal("[REDACTED]");
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
});

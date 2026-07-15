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
} = require("../../apps/api/services/certops/jobs");
const {
  listCertificateEvidence,
} = require("../../apps/api/services/certops/evidence");
const {
  createCertOpsExecutorRouter,
} = require("../../apps/api/routes/certops-executor");
const {
  jobCompletedEvent,
  evidenceAttachedEnvelope,
} = require("../fixtures/certops-docs-examples");

const apiRequire = createRequire(
  require.resolve("../../apps/api/package.json"),
);
const express = apiRequire("express");

/**
 * Verifies the request/response examples quoted in docs/certops/executor-api.md
 * against the real executor routes. If validation, response shape, or status
 * codes drift, this suite fails before the docs go stale. See the "verified in"
 * comments in the doc for which section each test covers.
 */

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
      "not-used-in-certops-docs-fixtures-test",
    ],
  );
  const ownerId = owner.rows[0].id;
  const workspaceId = crypto.randomUUID();

  await TestUtils.execQuery(
    `INSERT INTO workspaces (id, name, created_by, plan) VALUES ($1, $2, $3, 'oss')`,
    [workspaceId, `${label} workspace`, ownerId],
  );

  return { ownerId, workspaceId };
}

async function cleanupWorkspace(ownerId, workspaceId) {
  await TestUtils.execQuery(
    "DELETE FROM audit_events WHERE workspace_id = $1",
    [workspaceId],
  );
  await TestUtils.execQuery(
    "DELETE FROM certificate_executor_events WHERE workspace_id = $1",
    [workspaceId],
  );
  await TestUtils.execQuery(
    "DELETE FROM certificate_evidence WHERE workspace_id = $1",
    [workspaceId],
  );
  await TestUtils.execQuery(
    "DELETE FROM certificate_job_log WHERE workspace_id = $1",
    [workspaceId],
  );
  await TestUtils.execQuery(
    "DELETE FROM certificate_jobs WHERE workspace_id = $1",
    [workspaceId],
  );
  await TestUtils.execQuery("DELETE FROM api_tokens WHERE workspace_id = $1", [
    workspaceId,
  ]);
  await TestUtils.execQuery("DELETE FROM workspaces WHERE id = $1", [
    workspaceId,
  ]);
  await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
}

function buildExecutorApp() {
  const app = express();
  app.use(express.json());
  app.use(
    createCertOpsExecutorRouter({
      rateLimitOptions: { windowMs: 60_000, max: 100 },
    }),
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
    name: "Docs fixture executor",
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

describe("CertOps executor-api.md documented examples", function () {
  this.timeout(60000);

  before(async () => {
    await runMigrations();
  });

  it("POST /api/v1/certops/jobs/:jobId/events with the doc's job.completed example returns 202 and moves the job to succeeded", async () => {
    const { ownerId, workspaceId } = await createWorkspacePair(
      "docs-fixtures-job-completed",
    );

    try {
      const job = await createJob({ workspaceId, ownerId });
      const token = await createScopedToken({
        workspaceId,
        ownerId,
        scopes: ["certops:events:write"],
      });
      const app = buildExecutorApp();

      const body = jobCompletedEvent({ workspaceId, jobId: job.id });

      const response = await supertest(app)
        .post(`/api/v1/certops/jobs/${job.id}/events`)
        .set("Authorization", `Bearer ${token.plaintextToken}`)
        .send(body);

      // Documented in "## 2. Report events": successful submission is 202,
      // not 200/201.
      expect(response.status).to.equal(202);
      expect(response.body.ok).to.equal(true);
      expect(response.body.jobId).to.equal(job.id);
      expect(response.body.status).to.equal("succeeded");

      const refreshedJob = await TestUtils.execQuery(
        "SELECT status FROM certificate_jobs WHERE id = $1",
        [job.id],
      );
      expect(refreshedJob.rows[0].status).to.equal("succeeded");
    } finally {
      await cleanupWorkspace(ownerId, workspaceId);
    }
  });

  it("POST /api/v1/certops/jobs/:jobId/events with the doc's evidence.attached example returns 202 and stores evidence", async () => {
    const { ownerId, workspaceId } = await createWorkspacePair(
      "docs-fixtures-evidence-attached",
    );

    try {
      const job = await createJob({ workspaceId, ownerId });
      const token = await createScopedToken({
        workspaceId,
        ownerId,
        scopes: ["certops:events:write", "certops:evidence:write"],
      });
      const app = buildExecutorApp();

      const body = evidenceAttachedEnvelope({ workspaceId, jobId: job.id });

      const response = await supertest(app)
        .post(`/api/v1/certops/jobs/${job.id}/events`)
        .set("Authorization", `Bearer ${token.plaintextToken}`)
        .send(body);

      expect(response.status).to.equal(202);
      expect(response.body.ok).to.equal(true);
      expect(response.body.evidenceIds).to.have.lengthOf(1);

      const evidence = await listCertificateEvidence({ workspaceId, jobId: job.id });
      expect(evidence.items).to.have.lengthOf(1);
      expect(evidence.items[0].evidenceType).to.equal("certificate.observed");
    } finally {
      await cleanupWorkspace(ownerId, workspaceId);
    }
  });

  it("posting an unknown jobId returns 404 CERTOPS_JOB_NOT_FOUND, confirming jobs are not auto-created by executors", async () => {
    const { ownerId, workspaceId } = await createWorkspacePair(
      "docs-fixtures-unknown-job",
    );

    try {
      const token = await createScopedToken({
        workspaceId,
        ownerId,
        scopes: ["certops:events:write"],
      });
      const app = buildExecutorApp();
      const unknownJobId = crypto.randomUUID();

      const response = await supertest(app)
        .post(`/api/v1/certops/jobs/${unknownJobId}/events`)
        .set("Authorization", `Bearer ${token.plaintextToken}`)
        .send(jobCompletedEvent({ workspaceId, jobId: unknownJobId }));

      expect(response.status).to.equal(404);
      expect(response.body.code).to.equal("CERTOPS_JOB_NOT_FOUND");
    } finally {
      await cleanupWorkspace(ownerId, workspaceId);
    }
  });

  it("rejects private key material in an evidence payload with 422, never redacting it", async () => {
    const { ownerId, workspaceId } = await createWorkspacePair(
      "docs-fixtures-private-key-rejection",
    );

    try {
      const job = await createJob({ workspaceId, ownerId });
      const token = await createScopedToken({
        workspaceId,
        ownerId,
        scopes: ["certops:events:write", "certops:evidence:write"],
      });
      const app = buildExecutorApp();

      const body = evidenceAttachedEnvelope({ workspaceId, jobId: job.id });
      body.evidence[0].output =
        "-----BEGIN RSA PRIVATE KEY-----\nRkFLRS1OT1QtQS1SRUFMLUtFWQ==\n-----END RSA PRIVATE KEY-----";

      const response = await supertest(app)
        .post(`/api/v1/certops/jobs/${job.id}/events`)
        .set("Authorization", `Bearer ${token.plaintextToken}`)
        .send(body);

      expect(response.status).to.equal(422);
      expect(response.body.code).to.equal("PRIVATE_KEY_MATERIAL_REJECTED");

      const evidence = await listCertificateEvidence({ workspaceId, jobId: job.id });
      expect(evidence.items).to.have.lengthOf(0);
    } finally {
      await cleanupWorkspace(ownerId, workspaceId);
    }
  });
});

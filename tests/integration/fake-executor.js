"use strict";

// Reusable fake-executor simulator for CertOps integration tests (plan B3).
// Not a test itself: it drives the real executor HTTP routes the way an
// external executor binary would (machine token auth, lifecycle events,
// evidence attachment, replays). Setup helpers mirror the conventions in
// tests/integration/certops-executor-events.test.js and
// certops-api-token-auth.test.js.

const crypto = require("crypto");
const { createRequire } = require("module");
const supertest = require("supertest");

const { TestUtils } = require("./setup");
const {
  createApiToken,
  revokeApiToken,
} = require("../../apps/api/services/certops/apiTokens");
const {
  createCertificateJob,
} = require("../../apps/api/services/certops/jobs");
const {
  createCertOpsExecutorRouter,
} = require("../../apps/api/routes/certops-executor");

const apiRequire = createRequire(
  require.resolve("../../apps/api/package.json"),
);
const express = apiRequire("express");

const EXECUTOR_EVENTS_ROUTE = "/api/v1/certops/executor/events";

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
      "not-used-in-certops-fake-executor-harness",
    ],
  );
  const ownerId = owner.rows[0].id;
  const workspaceA = crypto.randomUUID();
  const workspaceB = crypto.randomUUID();

  await TestUtils.execQuery(
    `INSERT INTO workspaces (id, name, created_by, plan)
     VALUES ($1, $2, $3, 'oss'), ($4, $5, $3, 'oss')`,
    [workspaceA, `${label} A`, ownerId, workspaceB, `${label} B`],
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
  await TestUtils.execQuery(
    "DELETE FROM workspaces WHERE id = ANY($1::uuid[])",
    [workspaceIds],
  );
  await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
}

function buildExecutorApp({ rateLimitOptions } = {}) {
  const app = express();
  app.use(express.json());
  app.use(
    createCertOpsExecutorRouter({
      rateLimitOptions: rateLimitOptions || { windowMs: 60_000, max: 1000 },
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

async function createScopedToken({ workspaceId, ownerId, scopes, name }) {
  return createApiToken({
    workspaceId,
    name: name || "Fake executor",
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

function eventPayload({
  workspaceId,
  jobId,
  eventType = "job.started",
  status = "running",
  ...overrides
}) {
  return {
    schemaVersion: 1,
    eventId: `event-${crypto.randomUUID()}`,
    workspaceId,
    jobId,
    eventType,
    status,
    occurredAt: new Date().toISOString(),
    message: "Fake executor event",
    metadata: [{ name: "executor", value: "fake-executor" }],
    ...overrides,
  };
}

// A fake executor bound to one app + workspace + machine token. Each
// lifecycle helper returns the supertest response; the sent payload is kept
// on `lastPayload` so callers can replay it verbatim.
function createFakeExecutor({ app, workspaceId, plaintextToken }) {
  const executor = {
    app,
    workspaceId,
    plaintextToken,
    lastPayload: null,

    async postEvent(payload, { route = EXECUTOR_EVENTS_ROUTE, token } = {}) {
      executor.lastPayload = payload;
      return supertest(app)
        .post(route)
        .set("Authorization", `Bearer ${token || executor.plaintextToken}`)
        .send(payload);
    },

    async sendLifecycleEvent(jobId, eventType, status, overrides = {}) {
      return executor.postEvent(
        eventPayload({ workspaceId, jobId, eventType, status, ...overrides }),
      );
    },

    async started(jobId, overrides = {}) {
      return executor.sendLifecycleEvent(
        jobId,
        "job.started",
        "running",
        overrides,
      );
    },

    async accepted(jobId, overrides = {}) {
      return executor.sendLifecycleEvent(
        jobId,
        "job.accepted",
        "claimed",
        overrides,
      );
    },

    async rejected(jobId, overrides = {}) {
      return executor.sendLifecycleEvent(
        jobId,
        "job.rejected",
        "rejected",
        overrides,
      );
    },

    async progress(jobId, overrides = {}) {
      return executor.sendLifecycleEvent(
        jobId,
        "job.progress",
        "running",
        overrides,
      );
    },

    async completed(jobId, overrides = {}) {
      return executor.sendLifecycleEvent(
        jobId,
        "job.completed",
        "succeeded",
        overrides,
      );
    },

    async failed(jobId, overrides = {}) {
      return executor.sendLifecycleEvent(
        jobId,
        "job.failed",
        "failed",
        overrides,
      );
    },

    async attachEvidence(jobId, evidenceItems, overrides = {}) {
      return executor.postEvent(
        {
          schemaVersion: 1,
          eventId: `event-${crypto.randomUUID()}`,
          occurredAt: new Date().toISOString(),
          evidence: evidenceItems,
          ...overrides,
        },
        { route: `/api/v1/certops/jobs/${jobId}/evidence` },
      );
    },

    // Re-sends the exact same body (same eventId) to exercise idempotency.
    async replayLastEvent() {
      if (!executor.lastPayload) {
        throw new Error("No event sent yet; nothing to replay");
      }
      return executor.postEvent(executor.lastPayload);
    },
  };

  return executor;
}

module.exports = {
  EXECUTOR_EVENTS_ROUTE,
  buildExecutorApp,
  cleanupWorkspacePair,
  createFakeExecutor,
  createJob,
  createScopedToken,
  createWorkspacePair,
  eventPayload,
  revokeApiToken,
};

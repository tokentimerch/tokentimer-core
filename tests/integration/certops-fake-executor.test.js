const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const crypto = require("crypto");
const { expect } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();
const {
  getCertificateJobById,
  listCertificateJobLog,
} = require("../../apps/api/services/certops/jobs");
const {
  listCertificateEvidence,
} = require("../../apps/api/services/certops/evidence");
const {
  buildExecutorApp,
  cleanupWorkspacePair,
  createFakeExecutor,
  createJob,
  createScopedToken,
  createWorkspacePair,
  revokeApiToken,
} = require("./fake-executor");

const PRIVATE_KEY_PEM =
  "-----BEGIN RSA PRIVATE KEY-----\nRkFLRS1OT1QtQS1SRUFMLUtFWQ==\n-----END RSA PRIVATE KEY-----";

function expectNoSensitiveValues(body, rawToken) {
  const serialized = JSON.stringify(body);
  expect(serialized).to.not.include(rawToken);
  expect(serialized).to.not.include("Authorization");
  expect(serialized).to.not.include("token_hash");
  expect(serialized).to.not.include("PRIVATE KEY");
}

describe("CertOps fake executor (B3)", function () {
  this.timeout(60000);

  before(async () => {
    await runMigrations();
  });

  it("does not reopen a succeeded job on a late job.started with a new eventId", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-fake-executor-replay",
    );

    try {
      const app = buildExecutorApp();
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write"],
      });
      const executor = createFakeExecutor({
        app,
        workspaceId: workspaceA,
        plaintextToken: token.plaintextToken,
      });
      const job = await createJob({ workspaceId: workspaceA, ownerId });

      const started = await executor.started(job.id);
      expect(started.status).to.equal(202);
      const completed = await executor.completed(job.id);
      expect(completed.status).to.equal(202);
      expect(completed.body.status).to.equal("succeeded");

      const terminal = await getCertificateJobById({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(terminal.status).to.equal("succeeded");
      const completedAt = terminal.completedAt;

      // Out-of-order replay: a NEW eventId, so idempotency does not dedupe
      // it. The event is accepted and logged, but the job must stay terminal.
      const lateStart = await executor.started(job.id);
      expect(lateStart.status).to.equal(202);
      expect(lateStart.body.status).to.equal("succeeded");

      const afterReplay = await getCertificateJobById({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(afterReplay.status).to.equal("succeeded");
      expect(afterReplay.completedAt).to.equal(completedAt);

      // The late event is still recorded in the job log (ignored, not lost).
      const logs = await listCertificateJobLog({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      const startedEvents = logs.items.filter(
        (item) => item.eventType === "job.started",
      );
      expect(startedEvents.length).to.equal(2);
      expectNoSensitiveValues(lateStart.body, token.plaintextToken);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("keeps error fields on a failed job when a late non-error event arrives", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-fake-executor-error-fields",
    );

    try {
      const app = buildExecutorApp();
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write"],
      });
      const executor = createFakeExecutor({
        app,
        workspaceId: workspaceA,
        plaintextToken: token.plaintextToken,
      });
      const job = await createJob({ workspaceId: workspaceA, ownerId });

      const failed = await executor.failed(job.id, {
        message: "Deployment failed on executor",
      });
      expect(failed.status).to.equal(202);
      expect(failed.body.status).to.equal("failed");

      const terminal = await getCertificateJobById({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(terminal.status).to.equal("failed");

      const lateStart = await executor.started(job.id);
      expect(lateStart.status).to.equal(202);
      expect(lateStart.body.status).to.equal("failed");

      const afterReplay = await getCertificateJobById({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(afterReplay.status).to.equal("failed");
      expect(afterReplay.errorCode).to.equal(terminal.errorCode);
      expect(afterReplay.errorMessage).to.equal(terminal.errorMessage);
      expect(afterReplay.completedAt).to.equal(terminal.completedAt);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("rejects a revoked machine token on executor routes without changing job state", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-fake-executor-revoked",
    );

    try {
      const app = buildExecutorApp();
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write"],
      });
      const executor = createFakeExecutor({
        app,
        workspaceId: workspaceA,
        plaintextToken: token.plaintextToken,
      });
      const job = await createJob({ workspaceId: workspaceA, ownerId });

      const beforeRevoke = await executor.started(job.id);
      expect(beforeRevoke.status).to.equal(202);

      await revokeApiToken({
        workspaceId: workspaceA,
        tokenId: token.token.id,
        revokedBy: ownerId,
      });

      const denied = await executor.completed(job.id);
      expect(denied.status).to.be.oneOf([401, 403]);
      expect(denied.status).to.not.equal(500);
      expectNoSensitiveValues(denied.body, token.plaintextToken);

      const afterDenied = await getCertificateJobById({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(afterDenied.status).to.equal("running");
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("replays a duplicate eventId idempotently through the harness", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-fake-executor-duplicate",
    );

    try {
      const app = buildExecutorApp();
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write"],
      });
      const executor = createFakeExecutor({
        app,
        workspaceId: workspaceA,
        plaintextToken: token.plaintextToken,
      });
      const job = await createJob({ workspaceId: workspaceA, ownerId });

      const first = await executor.started(job.id);
      expect(first.status).to.equal(202);
      expect(first.body.duplicate).to.not.equal(true);

      const replay = await executor.replayLastEvent();
      expect(replay.status).to.equal(202);
      expect(replay.body.duplicate).to.equal(true);

      const logs = await listCertificateJobLog({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(logs.items.length).to.equal(1);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("attaches evidence through the harness and lists it back sanitized", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-fake-executor-evidence",
    );

    try {
      const app = buildExecutorApp();
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write", "certops:evidence:write"],
      });
      const executor = createFakeExecutor({
        app,
        workspaceId: workspaceA,
        plaintextToken: token.plaintextToken,
      });
      const job = await createJob({ workspaceId: workspaceA, ownerId });

      const attached = await executor.attachEvidence(job.id, [
        {
          schemaVersion: 1,
          evidenceId: `evidence-${crypto.randomUUID()}`,
          jobId: job.id,
          workspaceId: workspaceA,
          certificateId: "cert-1",
          eventType: "certificate.observed",
          source: "executor",
          observedAt: new Date().toISOString(),
          summary: "Observed public certificate fingerprint via harness",
          metadata: [{ name: "issuer", value: "TokenTimer Test CA" }],
        },
      ]);

      expect(attached.status).to.equal(202);
      expectNoSensitiveValues(attached.body, token.plaintextToken);

      const evidence = await listCertificateEvidence({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(evidence.items).to.have.length(1);
      expect(evidence.items[0]).to.include({
        evidenceType: "certificate.observed",
        subjectId: "cert-1",
        createdByApiTokenId: token.token.id,
      });
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("redacts secret-looking metadata sent through the harness", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-fake-executor-redaction",
    );

    try {
      const app = buildExecutorApp();
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write"],
      });
      const executor = createFakeExecutor({
        app,
        workspaceId: workspaceA,
        plaintextToken: token.plaintextToken,
      });
      const job = await createJob({ workspaceId: workspaceA, ownerId });

      const started = await executor.started(job.id, {
        message: "password=swordfish",
        metadata: [{ name: "credential", value: "abc" }],
      });

      expect(started.status).to.equal(202);
      expectNoSensitiveValues(started.body, token.plaintextToken);

      const logs = await listCertificateJobLog({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(logs.items[0].message).to.equal("[REDACTED]");
      expect(logs.items[0].metadata.redactionApplied).to.equal(true);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("rejects a private-key upload attempt through the harness before persistence", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-fake-executor-keyupload",
    );

    try {
      const app = buildExecutorApp();
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        scopes: ["certops:events:write"],
      });
      const executor = createFakeExecutor({
        app,
        workspaceId: workspaceA,
        plaintextToken: token.plaintextToken,
      });
      const job = await createJob({ workspaceId: workspaceA, ownerId });

      const beforeLogs = await listCertificateJobLog({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      const rejected = await executor.started(job.id, {
        message: PRIVATE_KEY_PEM,
      });

      expect(rejected.status).to.equal(422);
      expect(rejected.body.code).to.equal("PRIVATE_KEY_MATERIAL_REJECTED");
      expectNoSensitiveValues(rejected.body, token.plaintextToken);

      const afterLogs = await listCertificateJobLog({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(afterLogs.items.length).to.equal(beforeLogs.items.length);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("rejects an evidence attempt through the harness when the token lacks evidence:write scope", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-fake-executor-wrongscope",
    );

    try {
      const app = buildExecutorApp();
      const token = await createScopedToken({
        workspaceId: workspaceA,
        ownerId,
        // Deliberately missing certops:evidence:write.
        scopes: ["certops:events:write"],
      });
      const executor = createFakeExecutor({
        app,
        workspaceId: workspaceA,
        plaintextToken: token.plaintextToken,
      });
      const job = await createJob({ workspaceId: workspaceA, ownerId });

      const denied = await executor.attachEvidence(job.id, [
        {
          schemaVersion: 1,
          evidenceId: `evidence-${crypto.randomUUID()}`,
          jobId: job.id,
          workspaceId: workspaceA,
          certificateId: "cert-1",
          eventType: "certificate.observed",
          source: "executor",
          observedAt: new Date().toISOString(),
          summary: "Should be denied before reaching persistence",
        },
      ]);

      expect(denied.status).to.equal(403);
      expect(denied.body.code).to.equal("CERTOPS_API_TOKEN_SCOPE_DENIED");
      expectNoSensitiveValues(denied.body, token.plaintextToken);

      const evidence = await listCertificateEvidence({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(evidence.items).to.have.length(0);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });
});

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();
const {
  getCertificateJobById,
  listCertificateJobLog,
} = require("../../apps/api/services/certops/jobs");
const {
  buildExecutorApp,
  cleanupWorkspacePair,
  createFakeExecutor,
  createJob,
  createScopedToken,
  createWorkspacePair,
  revokeApiToken,
} = require("./fake-executor");

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
});

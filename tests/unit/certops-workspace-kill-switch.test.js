"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  CERTOPS_WORKSPACE_NOT_FOUND,
  CERTOPS_WORKSPACE_PAUSED,
  CERTOPS_WORKSPACE_PAUSE_REASON_INVALID,
  CERTOPS_WORKSPACE_PAUSE_STATE_INVALID,
  MAX_CERTOPS_PAUSE_REASON_LENGTH,
  assertWorkspaceCertOpsActive,
  createManualCertificateJob,
  getWorkspaceCertOpsActivitySnapshot,
  getWorkspaceCertOpsPauseState,
  lockWorkspaceForCertOpsSideEffect,
  normalizeReason,
  setWorkspaceCertOpsPauseState,
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/workspaceKillSwitch.js",
  ),
);
const {
  PAUSED_RESPONSE,
  createRequireWorkspaceCertOpsActive,
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/middleware/require-workspace-certops-active.js",
  ),
);
const {
  CERTOPS_DISABLED,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/settings.js"),
);

function createStatefulPool(initialPaused = false) {
  let certOpsPaused = initialPaused;
  let transactionStart = null;
  let jobs = [];
  const queries = [];
  const client = {
    released: false,
    async query(sql, params = []) {
      const normalized = String(sql).replace(/\s+/g, " ").trim();
      queries.push({ sql: normalized, params });

      if (normalized === "BEGIN") {
        transactionStart = { certOpsPaused, jobs: [...jobs] };
        return { rows: [] };
      }
      if (normalized === "COMMIT") {
        transactionStart = null;
        return { rows: [] };
      }
      if (normalized === "ROLLBACK") {
        certOpsPaused = transactionStart.certOpsPaused;
        jobs = transactionStart.jobs;
        transactionStart = null;
        return { rows: [] };
      }
      if (normalized.startsWith("SELECT id, certops_paused FROM workspaces")) {
        return {
          rows: [{ id: "workspace-1", certops_paused: certOpsPaused }],
        };
      }
      if (normalized.startsWith("UPDATE workspaces")) {
        certOpsPaused = params[0];
        return { rows: [] };
      }
      throw new Error(`Unexpected query: ${normalized}`);
    },
    release() {
      this.released = true;
    },
  };

  return {
    client,
    queries,
    async connect() {
      return client;
    },
    async query(...args) {
      return client.query(...args);
    },
    get certOpsPaused() {
      return certOpsPaused;
    },
    addJob(job) {
      jobs.push(job);
    },
    get jobs() {
      return jobs;
    },
  };
}

function responseRecorder() {
  return {
    statusCode: null,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
  };
}

describe("CertOps workspace kill-switch service", () => {
  it("keeps stored pause state distinct from each global rollout combination", async () => {
    for (const { enabled, paused, active } of [
      { enabled: false, paused: false, active: false },
      { enabled: false, paused: true, active: false },
      { enabled: true, paused: true, active: false },
      { enabled: true, paused: false, active: true },
    ]) {
      const state = await getWorkspaceCertOpsPauseState({
        workspaceId: "workspace-1",
        dbPool: createStatefulPool(paused),
        certOpsEnabledResolver: async () => enabled,
      });
      assert.deepEqual(state, {
        workspaceId: "workspace-1",
        certOpsPaused: paused,
        certOpsEnabled: enabled,
        certOpsActive: active,
      });
    }
  });

  it("fails closed when the workspace cannot be resolved", async () => {
    const pool = {
      async query() {
        return { rows: [] };
      },
    };
    await assert.rejects(
      () =>
        getWorkspaceCertOpsPauseState({
          workspaceId: "missing-workspace",
          dbPool: pool,
          certOpsEnabledResolver: async () => true,
        }),
      (error) => error?.code === CERTOPS_WORKSPACE_NOT_FOUND,
    );
  });

  it("pauses and resumes transactionally with one accurate transition audit", async () => {
    const pool = createStatefulPool(false);
    const audits = [];

    const paused = await setWorkspaceCertOpsPauseState({
      workspaceId: "workspace-1",
      certOpsPaused: true,
      reason: "  incident containment  ",
      actorUserId: 42,
      dbPool: pool,
      certOpsEnabledResolver: async () => true,
      auditWriter: async (event) => audits.push(event),
    });
    assert.equal(pool.certOpsPaused, true);
    assert.deepEqual(paused, {
      workspaceId: "workspace-1",
      certOpsPaused: true,
      certOpsEnabled: true,
      certOpsActive: false,
      changed: true,
    });
    assert.equal(audits.length, 1);
    assert.equal(audits[0].action, "CERTOPS_WORKSPACE_PAUSED");
    assert.deepEqual(audits[0].metadata, {
      workspaceId: "workspace-1",
      previousCertOpsPaused: false,
      certOpsPaused: true,
      certOpsEnabled: true,
      certOpsActive: false,
      reason: "incident containment",
    });

    const resumed = await setWorkspaceCertOpsPauseState({
      workspaceId: "workspace-1",
      certOpsPaused: false,
      actorUserId: 42,
      dbPool: pool,
      certOpsEnabledResolver: async () => true,
      auditWriter: async (event) => audits.push(event),
    });
    assert.equal(pool.certOpsPaused, false);
    assert.equal(resumed.changed, true);
    assert.equal(resumed.certOpsActive, true);
    assert.equal(audits.length, 2);
    assert.equal(audits[1].action, "CERTOPS_WORKSPACE_RESUMED");
    assert.equal(audits[1].metadata.previousCertOpsPaused, true);
  });

  it("does not write a false transition audit when the requested state already exists", async () => {
    const pool = createStatefulPool(true);
    let auditCount = 0;
    const state = await setWorkspaceCertOpsPauseState({
      workspaceId: "workspace-1",
      certOpsPaused: true,
      dbPool: pool,
      certOpsEnabledResolver: async () => true,
      auditWriter: async () => {
        auditCount += 1;
      },
    });

    assert.equal(state.changed, false);
    assert.equal(auditCount, 0);
    assert.equal(pool.queries.some((query) => query.sql.startsWith("UPDATE")), false);
  });

  it("rolls back the state change when synchronous audit persistence fails", async () => {
    const pool = createStatefulPool(false);
    await assert.rejects(
      () =>
        setWorkspaceCertOpsPauseState({
          workspaceId: "workspace-1",
          certOpsPaused: true,
          dbPool: pool,
          certOpsEnabledResolver: async () => true,
          auditWriter: async () => {
            throw new Error("audit unavailable");
          },
        }),
      /audit unavailable/,
    );
    assert.equal(pool.certOpsPaused, false);
    assert.equal(pool.queries.some((query) => query.sql === "ROLLBACK"), true);
  });

  it("rolls back a manual job when its synchronous creation audit fails", async () => {
    const pool = createStatefulPool(false);
    const job = {
      id: "job-1",
      operation: "deploy",
      subjectType: "managed_certificate",
      subjectId: "certificate-1",
      source: "api",
    };

    await assert.rejects(
      () =>
        createManualCertificateJob({
          workspaceId: "workspace-1",
          dbPool: pool,
          certOpsEnabledResolver: async () => true,
          jobCreator: async () => {
            pool.addJob(job);
            return { job, created: true };
          },
          auditWriter: async () => {
            throw new Error("audit unavailable");
          },
        }),
      /audit unavailable/,
    );

    assert.deepEqual(pool.jobs, []);
    assert.equal(pool.queries.some((query) => query.sql === "ROLLBACK"), true);
    assert.equal(
      pool.queries.some((query) => query.sql.endsWith("FOR SHARE")),
      true,
    );
  });

  it("does not emit a duplicate manual-job audit for an idempotent replay", async () => {
    const pool = createStatefulPool(false);
    let auditCount = 0;
    const result = await createManualCertificateJob({
      workspaceId: "workspace-1",
      dbPool: pool,
      certOpsEnabledResolver: async () => true,
      jobCreator: async () => ({
        job: {
          id: "existing-job",
          operation: "deploy",
          subjectType: "managed_certificate",
          subjectId: "certificate-1",
          source: "api",
        },
        created: false,
      }),
      auditWriter: async () => {
        auditCount += 1;
      },
    });

    assert.equal(result.created, false);
    assert.equal(auditCount, 0);
    assert.equal(pool.queries.some((query) => query.sql === "COMMIT"), true);
  });

  it("validates and redacts the bounded operator reason", async () => {
    assert.equal(normalizeReason("token=abc123"), "token=[REDACTED]");
    assert.throws(
      () => normalizeReason("x".repeat(MAX_CERTOPS_PAUSE_REASON_LENGTH + 1)),
      (error) => error?.code === CERTOPS_WORKSPACE_PAUSE_REASON_INVALID,
    );
    assert.throws(
      () => normalizeReason("line one\nline two"),
      (error) => error?.code === CERTOPS_WORKSPACE_PAUSE_REASON_INVALID,
    );
    await assert.rejects(
      () =>
        setWorkspaceCertOpsPauseState({
          workspaceId: "workspace-1",
          certOpsPaused: "yes",
          dbPool: createStatefulPool(false),
        }),
      (error) => error?.code === CERTOPS_WORKSPACE_PAUSE_STATE_INVALID,
    );
  });

  it("keeps the unlocked activity helper advisory and exposes it by snapshot name", async () => {
    await assert.rejects(
      () =>
        getWorkspaceCertOpsActivitySnapshot({
          workspaceId: "workspace-1",
          dbPool: createStatefulPool(true),
          certOpsEnabledResolver: async () => true,
        }),
      (error) => error?.code === CERTOPS_WORKSPACE_PAUSED,
    );
    await assert.rejects(
      () =>
        assertWorkspaceCertOpsActive({
          workspaceId: "workspace-1",
          dbPool: createStatefulPool(false),
          certOpsEnabledResolver: async () => false,
        }),
      (error) => error?.code === "CERTOPS_DISABLED",
    );
  });

  it("locks and checks workspace activity for an authoritative side effect", async () => {
    const activePool = createStatefulPool(false);
    const workspace = await lockWorkspaceForCertOpsSideEffect({
      client: activePool.client,
      workspaceId: "workspace-1",
      certOpsEnabledResolver: async () => true,
    });
    assert.equal(workspace.id, "workspace-1");
    assert.equal(
      activePool.queries.some((query) => query.sql.endsWith("FOR SHARE")),
      true,
    );

    await assert.rejects(
      () =>
        lockWorkspaceForCertOpsSideEffect({
          client: createStatefulPool(false).client,
          workspaceId: "workspace-1",
          certOpsEnabledResolver: async () => false,
        }),
      (error) => {
        assert.equal(error?.code, CERTOPS_DISABLED);
        assert.deepEqual(error?.state, {
          workspaceId: "workspace-1",
          certOpsPaused: false,
          certOpsEnabled: false,
          certOpsActive: false,
        });
        return true;
      },
    );
    await assert.rejects(
      () =>
        lockWorkspaceForCertOpsSideEffect({
          client: createStatefulPool(true).client,
          workspaceId: "workspace-1",
          certOpsEnabledResolver: async () => true,
        }),
      (error) => error?.code === CERTOPS_WORKSPACE_PAUSED,
    );
    await assert.rejects(
      () => lockWorkspaceForCertOpsSideEffect({ workspaceId: "workspace-1" }),
      (error) => error?.code === CERTOPS_WORKSPACE_NOT_FOUND,
    );
  });

  it("blocks both transactional gates before creating a job or audit", async () => {
    for (const { enabled, paused, code } of [
      { enabled: false, paused: false, code: CERTOPS_DISABLED },
      { enabled: true, paused: true, code: CERTOPS_WORKSPACE_PAUSED },
    ]) {
      const pool = createStatefulPool(paused);
      let jobCreatorCalls = 0;
      let auditCalls = 0;

      await assert.rejects(
        () =>
          createManualCertificateJob({
            workspaceId: "workspace-1",
            dbPool: pool,
            certOpsEnabledResolver: async () => enabled,
            jobCreator: async () => {
              jobCreatorCalls += 1;
              return { job: { id: "must-not-exist" }, created: true };
            },
            auditWriter: async () => {
              auditCalls += 1;
            },
          }),
        (error) => error?.code === code,
      );

      assert.equal(jobCreatorCalls, 0);
      assert.equal(auditCalls, 0);
      assert.deepEqual(pool.jobs, []);
      assert.equal(pool.queries[0].sql, "BEGIN");
      assert.equal(
        pool.queries.some((query) => query.sql.endsWith("FOR SHARE")),
        true,
      );
      assert.equal(pool.queries.at(-1).sql, "ROLLBACK");
    }
  });

  it("keeps the active global check, workspace lock, job, and audit atomic", async () => {
    const pool = createStatefulPool(false);
    const calls = [];
    const job = {
      id: "job-1",
      operation: "deploy",
      subjectType: "managed_certificate",
      subjectId: "certificate-1",
      source: "api",
    };

    const result = await createManualCertificateJob({
      workspaceId: "workspace-1",
      dbPool: pool,
      certOpsEnabledResolver: async ({ dbPool }) => {
        assert.equal(dbPool, pool.client);
        assert.equal(
          pool.queries.some((query) => query.sql.endsWith("FOR SHARE")),
          true,
        );
        return true;
      },
      jobCreator: async ({ client }) => {
        assert.equal(client, pool.client);
        calls.push("job");
        pool.addJob(job);
        return { job, created: true };
      },
      auditWriter: async ({ client }) => {
        assert.equal(client, pool.client);
        calls.push("audit");
      },
    });

    assert.equal(result.job, job);
    assert.equal(result.created, true);
    assert.deepEqual(calls, ["job", "audit"]);
    assert.deepEqual(pool.jobs, [job]);
    assert.equal(pool.queries[0].sql, "BEGIN");
    assert.equal(pool.queries.at(-1).sql, "COMMIT");
  });
});

describe("requireWorkspaceCertOpsActive middleware", () => {
  it("allows an active workspace and attaches the resolved state", async () => {
    const middleware = createRequireWorkspaceCertOpsActive({
      pauseStateResolver: async () => ({ certOpsPaused: false, certOpsActive: true }),
    });
    const req = { workspace: { id: "workspace-1" } };
    const res = responseRecorder();
    let nextCalled = false;

    await middleware(req, res, () => {
      nextCalled = true;
    });
    assert.equal(nextCalled, true);
    assert.equal(res.statusCode, null);
    assert.equal(req.certOpsWorkspaceState.certOpsActive, true);
  });

  it("returns the stable conflict response for a paused workspace", async () => {
    const middleware = createRequireWorkspaceCertOpsActive({
      pauseStateResolver: async () => ({ certOpsPaused: true, certOpsActive: false }),
    });
    const res = responseRecorder();
    await middleware({ workspace: { id: "workspace-1" } }, res, () => {
      throw new Error("next must not be called");
    });

    assert.equal(res.statusCode, 409);
    assert.deepEqual(res.body, PAUSED_RESPONSE);
  });

  it("fails closed when workspace state cannot be loaded", async () => {
    const middleware = createRequireWorkspaceCertOpsActive({
      pauseStateResolver: async () => {
        throw new Error("database unavailable");
      },
    });
    const res = responseRecorder();
    await middleware({ workspace: { id: "workspace-1" } }, res, () => {
      throw new Error("next must not be called");
    });

    assert.equal(res.statusCode, 503);
    assert.equal(res.body.code, "CERTOPS_WORKSPACE_STATE_UNAVAILABLE");
  });
});

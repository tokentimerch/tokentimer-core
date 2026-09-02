"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  CERTOPS_WORKSPACE_NOT_FOUND,
  CERTOPS_WORKSPACE_PAUSED,
  CERTOPS_WORKSPACE_PAUSE_REASON_INVALID,
  CERTOPS_WORKSPACE_PAUSE_STATE_INVALID,
  CERTOPS_WORKSPACE_APPROVAL_POLICY_STATE_INVALID,
  MAX_CERTOPS_PAUSE_REASON_LENGTH,
  assertWorkspaceCertOpsActive,
  createManualCertificateJob,
  getWorkspaceCertOpsActivitySnapshot,
  getWorkspaceCertOpsPauseState,
  lockWorkspaceForCertOpsSideEffect,
  normalizeReason,
  setWorkspaceCertOpsPauseState,
  setWorkspaceCertOpsRequireApprovalAlways,
  setWorkspaceCertOpsSettings,
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

function createStatefulPool(initialPaused = false, initialRequireApprovalAlways = false) {
  let certOpsPaused = initialPaused;
  let certOpsRequireApprovalAlways = initialRequireApprovalAlways;
  let transactionStart = null;
  let jobs = [];
  const queries = [];
  const client = {
    released: false,
    async query(sql, params = []) {
      const normalized = String(sql).replace(/\s+/g, " ").trim();
      queries.push({ sql: normalized, params });

      if (normalized === "BEGIN") {
        transactionStart = {
          certOpsPaused,
          certOpsRequireApprovalAlways,
          jobs: [...jobs],
        };
        return { rows: [] };
      }
      if (normalized === "COMMIT") {
        transactionStart = null;
        return { rows: [] };
      }
      if (normalized === "ROLLBACK") {
        certOpsPaused = transactionStart.certOpsPaused;
        certOpsRequireApprovalAlways =
          transactionStart.certOpsRequireApprovalAlways;
        jobs = transactionStart.jobs;
        transactionStart = null;
        return { rows: [] };
      }
      if (
        normalized.startsWith(
          "SELECT id, certops_paused, certops_require_approval_always FROM workspaces",
        )
      ) {
        return {
          rows: [
            {
              id: "workspace-1",
              certops_paused: certOpsPaused,
              certops_require_approval_always: certOpsRequireApprovalAlways,
            },
          ],
        };
      }
      if (
        normalized.startsWith(
          "UPDATE workspaces SET certops_paused = $1, certops_require_approval_always = $2",
        )
      ) {
        certOpsPaused = params[0];
        certOpsRequireApprovalAlways = params[1];
        return { rows: [] };
      }
      if (normalized.startsWith("UPDATE workspaces SET certops_paused")) {
        certOpsPaused = params[0];
        return { rows: [] };
      }
      if (
        normalized.startsWith(
          "UPDATE workspaces SET certops_require_approval_always",
        )
      ) {
        certOpsRequireApprovalAlways = params[0];
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
    get certOpsRequireApprovalAlways() {
      return certOpsRequireApprovalAlways;
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
        certOpsRequireApprovalAlways: false,
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
      certOpsRequireApprovalAlways: false,
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

  it("names the store/binding for a manually created windows-iis job, not just targetType", async () => {
    const pool = createStatefulPool(false);
    let auditMetadata = null;
    const job = {
      id: "job-windows-1",
      operation: "issue",
      subjectType: "managed_certificate",
      subjectId: "certificate-1",
      source: "api",
      payload: {
        target: {
          type: "windows-iis",
          store: "LocalMachine\\My",
          binding: { site: "Default Web Site", port: 443, sniHost: "e2e.example.com" },
        },
      },
    };

    await createManualCertificateJob({
      workspaceId: "workspace-1",
      dbPool: pool,
      certOpsEnabledResolver: async () => true,
      jobCreator: async () => {
        pool.addJob(job);
        return { job, created: true };
      },
      auditWriter: async ({ action, metadata }) => {
        if (action === "CERTOPS_JOB_CREATED_MANUAL") auditMetadata = metadata;
      },
    });

    assert.ok(auditMetadata);
    assert.equal(auditMetadata.targetType, "windows-iis");
    assert.equal(auditMetadata.windowsStore, "LocalMachine\\My");
    assert.equal(auditMetadata.windowsBindingSite, "Default Web Site");
    assert.equal(auditMetadata.windowsBindingPort, 443);
    assert.equal(auditMetadata.windowsBindingSniHost, "e2e.example.com");
  });

  it("reports only a null targetType (no windows fields) for a non-windows manual job", async () => {
    const pool = createStatefulPool(false);
    let auditMetadata = null;
    const job = {
      id: "job-linux-1",
      operation: "issue",
      subjectType: "managed_certificate",
      subjectId: "certificate-2",
      source: "api",
      payload: { target: { type: "agent-file" } },
    };

    await createManualCertificateJob({
      workspaceId: "workspace-1",
      dbPool: pool,
      certOpsEnabledResolver: async () => true,
      jobCreator: async () => {
        pool.addJob(job);
        return { job, created: true };
      },
      auditWriter: async ({ action, metadata }) => {
        if (action === "CERTOPS_JOB_CREATED_MANUAL") auditMetadata = metadata;
      },
    });

    assert.ok(auditMetadata);
    assert.equal(auditMetadata.targetType, "agent-file");
    assert.equal(auditMetadata.windowsStore, null);
    assert.equal(auditMetadata.windowsBindingSite, null);
    assert.equal(auditMetadata.windowsBindingPort, null);
    assert.equal(auditMetadata.windowsBindingSniHost, null);
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
          certOpsRequireApprovalAlways: false,
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

  it("forwards the workspace's require-approval-always column to the job creator", async () => {
    for (const requireApprovalAlways of [false, true]) {
      const pool = createStatefulPool(false, requireApprovalAlways);
      let receivedFlag = null;

      await createManualCertificateJob({
        workspaceId: "workspace-1",
        dbPool: pool,
        certOpsEnabledResolver: async () => true,
        jobCreator: async (options) => {
          receivedFlag = options.workspaceRequiresApprovalAlways;
          return {
            job: { id: "job-1", operation: "deploy", source: "api" },
            created: true,
          };
        },
        auditWriter: async () => {},
      });

      assert.equal(receivedFlag, requireApprovalAlways);
    }
  });
});

describe("CertOps workspace approval-policy setter", () => {
  it("enables and disables the policy transactionally with one accurate transition audit", async () => {
    const pool = createStatefulPool(false, false);
    const audits = [];

    const enabled = await setWorkspaceCertOpsRequireApprovalAlways({
      workspaceId: "workspace-1",
      requireApprovalAlways: true,
      actorUserId: 42,
      dbPool: pool,
      certOpsEnabledResolver: async () => true,
      auditWriter: async (event) => audits.push(event),
    });
    assert.equal(pool.certOpsRequireApprovalAlways, true);
    assert.deepEqual(enabled, {
      workspaceId: "workspace-1",
      certOpsPaused: false,
      certOpsEnabled: true,
      certOpsActive: true,
      certOpsRequireApprovalAlways: true,
      changed: true,
    });
    assert.equal(audits.length, 1);
    assert.equal(audits[0].action, "CERTOPS_WORKSPACE_APPROVAL_POLICY_ENABLED");
    assert.deepEqual(audits[0].metadata, {
      workspaceId: "workspace-1",
      previousRequireApprovalAlways: false,
      certOpsRequireApprovalAlways: true,
    });

    const disabled = await setWorkspaceCertOpsRequireApprovalAlways({
      workspaceId: "workspace-1",
      requireApprovalAlways: false,
      actorUserId: 42,
      dbPool: pool,
      certOpsEnabledResolver: async () => true,
      auditWriter: async (event) => audits.push(event),
    });
    assert.equal(pool.certOpsRequireApprovalAlways, false);
    assert.equal(disabled.changed, true);
    assert.equal(audits.length, 2);
    assert.equal(
      audits[1].action,
      "CERTOPS_WORKSPACE_APPROVAL_POLICY_DISABLED",
    );
    assert.equal(audits[1].metadata.previousRequireApprovalAlways, true);
  });

  it("does not write a false transition audit when the requested state already exists", async () => {
    const pool = createStatefulPool(false, true);
    let auditCount = 0;
    const state = await setWorkspaceCertOpsRequireApprovalAlways({
      workspaceId: "workspace-1",
      requireApprovalAlways: true,
      dbPool: pool,
      certOpsEnabledResolver: async () => true,
      auditWriter: async () => {
        auditCount += 1;
      },
    });

    assert.equal(state.changed, false);
    assert.equal(auditCount, 0);
    assert.equal(
      pool.queries.some((query) => query.sql.startsWith("UPDATE")),
      false,
    );
  });

  it("rolls back the state change when synchronous audit persistence fails", async () => {
    const pool = createStatefulPool(false, false);
    await assert.rejects(
      () =>
        setWorkspaceCertOpsRequireApprovalAlways({
          workspaceId: "workspace-1",
          requireApprovalAlways: true,
          dbPool: pool,
          certOpsEnabledResolver: async () => true,
          auditWriter: async () => {
            throw new Error("audit unavailable");
          },
        }),
      /audit unavailable/,
    );
    assert.equal(pool.certOpsRequireApprovalAlways, false);
    assert.equal(pool.queries.some((query) => query.sql === "ROLLBACK"), true);
  });

  it("rejects a non-boolean requireApprovalAlways", async () => {
    await assert.rejects(
      () =>
        setWorkspaceCertOpsRequireApprovalAlways({
          workspaceId: "workspace-1",
          requireApprovalAlways: "yes",
          dbPool: createStatefulPool(false, false),
        }),
      (error) => error?.code === CERTOPS_WORKSPACE_APPROVAL_POLICY_STATE_INVALID,
    );
  });
});

describe("CertOps workspace combined settings update", () => {
  it("writes both fields in one transaction with one UPDATE and both audits", async () => {
    const pool = createStatefulPool(false, false);
    const audits = [];

    const state = await setWorkspaceCertOpsSettings({
      workspaceId: "workspace-1",
      certOpsPaused: true,
      requireApprovalAlways: true,
      reason: "incident containment",
      actorUserId: 42,
      dbPool: pool,
      certOpsEnabledResolver: async () => true,
      auditWriter: async (event) => audits.push(event),
    });

    assert.deepEqual(state, {
      workspaceId: "workspace-1",
      certOpsPaused: true,
      certOpsEnabled: true,
      certOpsActive: false,
      certOpsRequireApprovalAlways: true,
      changed: true,
    });
    assert.equal(pool.certOpsPaused, true);
    assert.equal(pool.certOpsRequireApprovalAlways, true);
    assert.equal(
      pool.queries.filter((query) => query.sql.startsWith("UPDATE")).length,
      1,
    );
    assert.equal(audits.length, 2);
    assert.deepEqual(
      audits.map((event) => event.action),
      ["CERTOPS_WORKSPACE_PAUSED", "CERTOPS_WORKSPACE_APPROVAL_POLICY_ENABLED"],
    );
  });

  it("rolls back both fields when the second setting's audit write fails", async () => {
    // This is the review finding: a single request naming both fields must
    // not be able to commit the pause change and then fail the approval
    // change, leaving the workspace half-updated.
    const pool = createStatefulPool(false, false);
    let auditCalls = 0;

    await assert.rejects(
      () =>
        setWorkspaceCertOpsSettings({
          workspaceId: "workspace-1",
          certOpsPaused: true,
          requireApprovalAlways: true,
          dbPool: pool,
          certOpsEnabledResolver: async () => true,
          auditWriter: async ({ action }) => {
            auditCalls += 1;
            if (action === "CERTOPS_WORKSPACE_APPROVAL_POLICY_ENABLED") {
              throw new Error("audit unavailable");
            }
          },
        }),
      /audit unavailable/,
    );

    assert.equal(auditCalls, 2);
    assert.equal(pool.certOpsPaused, false);
    assert.equal(pool.certOpsRequireApprovalAlways, false);
    assert.equal(pool.queries.some((query) => query.sql === "ROLLBACK"), true);
    assert.equal(pool.queries.some((query) => query.sql === "COMMIT"), false);
  });

  it("only writes and audits the field that actually changed", async () => {
    const pool = createStatefulPool(true, false);
    const audits = [];

    const state = await setWorkspaceCertOpsSettings({
      workspaceId: "workspace-1",
      certOpsPaused: true,
      requireApprovalAlways: true,
      dbPool: pool,
      certOpsEnabledResolver: async () => true,
      auditWriter: async (event) => audits.push(event),
    });

    assert.equal(state.changed, true);
    assert.equal(audits.length, 1);
    assert.equal(audits[0].action, "CERTOPS_WORKSPACE_APPROVAL_POLICY_ENABLED");
  });

  it("commits no write and emits no audit when neither field actually changes", async () => {
    const pool = createStatefulPool(true, true);
    let auditCount = 0;

    const state = await setWorkspaceCertOpsSettings({
      workspaceId: "workspace-1",
      certOpsPaused: true,
      requireApprovalAlways: true,
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

  it("rejects a non-boolean field before opening a transaction", async () => {
    const pool = createStatefulPool(false, false);
    await assert.rejects(
      () =>
        setWorkspaceCertOpsSettings({
          workspaceId: "workspace-1",
          certOpsPaused: true,
          requireApprovalAlways: "yes",
          dbPool: pool,
        }),
      (error) => error?.code === CERTOPS_WORKSPACE_APPROVAL_POLICY_STATE_INVALID,
    );
    assert.equal(pool.queries.length, 0);
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

"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  CERTOPS_JOB_LOG_EVENT_TYPE_INVALID,
  CERTOPS_JOB_IDEMPOTENCY_CONFLICT,
  CERTOPS_JOB_NOT_FOUND,
  CERTOPS_JOB_STATUS_INVALID,
  PRIVATE_KEY_MATERIAL_REJECTED,
  appendCertificateJobLog,
  createCertificateJob,
  getCertificateJobById,
  jobCreationRequestFingerprint,
  listCertificateJobLog,
  listCertificateJobs,
  updateCertificateJobStatus,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/jobs.js"),
);

const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";
const WORKSPACE_B = "22222222-2222-4222-8222-222222222222";
const PRIVATE_KEY_PEM =
  "-----BEGIN RSA PRIVATE KEY-----\nRkFLRS1OT1QtQS1SRUFMLUtFWQ==\n-----END RSA PRIVATE KEY-----";
const SUSPICIOUS_ENCRYPTED_PKCS8_DER = Buffer.concat([
  Buffer.from([0x30, 0x81, 0x8b, 0x30, 0x81, 0x85, 0x06, 0x81, 0x82, 0x2a]),
  Buffer.alloc(128, 0x81),
  Buffer.from([0x01, 0x04, 0x01, 0x01]),
]);

function json(value) {
  return typeof value === "string" ? JSON.parse(value) : value;
}

function createMemoryClient() {
  const jobs = [];
  const logs = [];
  let nextJob = 1;
  let nextLog = 1;
  let tick = 0;
  const now = () => new Date(Date.UTC(2026, 5, 30, 0, tick++, 0));

  return {
    jobs,
    logs,
    async query(sql, params = []) {
      const normalizedSql = sql.replace(/\s+/g, " ");

      if (normalizedSql.includes("INSERT INTO certificate_jobs")) {
        const idempotencyKey = params[6];
        if (
          idempotencyKey &&
          jobs.some(
            (row) =>
              row.workspace_id === params[0] &&
              row.idempotency_key === idempotencyKey,
          )
        ) {
          const error = new Error("duplicate idempotency key");
          error.code = "23505";
          error.constraint = "uq_certificate_jobs_workspace_idempotency_key";
          throw error;
        }

        const createdAt = now();
        const row = {
          id: `job-${nextJob++}`,
          workspace_id: params[0],
          operation: params[1],
          status: params[2],
          source: params[3],
          requested_by_user_id: params[4],
          requested_by_api_token_id: params[5],
          idempotency_key: idempotencyKey,
          subject_type: params[7],
          subject_id: params[8],
          payload: json(params[9]),
          result_metadata: json(params[10]),
          error_code: params[11],
          error_message: params[12],
          created_at: createdAt,
          updated_at: createdAt,
          queued_at: params[13],
          started_at: params[14],
          completed_at: params[15],
          canceled_at: params[16],
          creation_request_hash: params[17],
        };
        jobs.push(row);
        return { rows: [row] };
      }

      if (normalizedSql.includes("idempotency_key = $2")) {
        return {
          rows: jobs.filter(
            (row) =>
              row.workspace_id === params[0] && row.idempotency_key === params[1],
          ),
        };
      }

      if (
        normalizedSql.includes("FROM certificate_jobs") &&
        normalizedSql.includes("AND id = $2") &&
        normalizedSql.includes("LIMIT 1")
      ) {
        return {
          rows: jobs.filter(
            (row) => row.workspace_id === params[0] && row.id === params[1],
          ),
        };
      }

      if (
        normalizedSql.includes("FROM certificate_jobs") &&
        normalizedSql.includes("ORDER BY created_at DESC")
      ) {
        let rows = jobs.filter((row) => row.workspace_id === params[0]);
        if (normalizedSql.includes("status = $2")) {
          rows = rows.filter((row) => row.status === params[1]);
        }
        return { rows };
      }

      if (normalizedSql.includes("UPDATE certificate_jobs")) {
        const row = jobs.find(
          (item) => item.workspace_id === params[0] && item.id === params[1],
        );
        if (!row || row.status !== params[9]) return { rows: [] };
        row.status = params[2];
        if (params[3]) row.result_metadata = json(params[4]);
        if (params[5]) row.error_code = params[6];
        if (params[7]) row.error_message = params[8];
        row.updated_at = now();
        if (
          [
            "pending_approval",
            "approved",
            "pending",
            "claimed",
            "running",
          ].includes(params[2])
        ) {
          row.queued_at = row.queued_at || now();
        }
        if (params[2] === "running") row.started_at = row.started_at || now();
        if (
          ["succeeded", "failed", "blocked"].includes(params[2])
        ) {
          row.completed_at = row.completed_at || now();
        }
        if (params[2] === "cancelled") {
          row.canceled_at = row.canceled_at || now();
        }
        return { rows: [row] };
      }

      if (normalizedSql.includes("INSERT INTO certificate_job_log")) {
        const createdAt = now();
        const row = {
          id: `log-${nextLog++}`,
          workspace_id: params[0],
          job_id: params[1],
          event_type: params[2],
          status: params[3],
          message: params[4],
          metadata: json(params[5]),
          created_by_user_id: params[6],
          created_by_api_token_id: params[7],
          created_at: createdAt,
        };
        logs.push(row);
        return { rows: [row] };
      }

      if (
        normalizedSql.includes("FROM certificate_job_log") &&
        normalizedSql.includes("ORDER BY created_at DESC")
      ) {
        return {
          rows: logs.filter(
            (row) => row.workspace_id === params[0] && row.job_id === params[1],
          ),
        };
      }

      throw new Error(`Unexpected query: ${normalizedSql}`);
    },
  };
}

function collectKeys(value, keys = []) {
  if (Array.isArray(value)) {
    for (const item of value) collectKeys(item, keys);
    return keys;
  }
  if (!value || typeof value !== "object") return keys;
  for (const [key, item] of Object.entries(value)) {
    keys.push(key);
    collectKeys(item, keys);
  }
  return keys;
}

function assertNoCustodyKeys(value) {
  const forbidden = [
    "privatekey",
    "privatekeypem",
    "encryptedprivatekey",
    "keymaterial",
    "pfxblob",
    "jksblob",
    "tlskey",
    "caprivatekey",
    "keystorepassword",
    "privatekeypassword",
    "keypassword",
    "password",
    "secret",
    "credential",
    "tokensecret",
    "apisecret",
    "rawsecret",
    "rawprivatekey",
    "rawkey",
    "pemprivatekey",
  ];

  for (const key of collectKeys(value)) {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, "");
    const hit = forbidden.find((fragment) => normalized.includes(fragment));
    assert.equal(hit, undefined, `${key} looks like a custody field`);
  }
  assert.equal(JSON.stringify(value).includes("PRIVATE KEY"), false);
}

describe("CertOps jobs service", () => {
  it("creates a job with safe public payload", async () => {
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "deploy",
      source: "api",
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: {
        target: "kubernetes/default/web-cert",
        fingerprintSha256:
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      },
      requestedByUserId: 123,
    });

    assert.equal(job.workspaceId, WORKSPACE_A);
    assert.equal(job.operation, "deploy");
    assert.equal(job.status, "pending");
    assert.equal(job.payload.target, "kubernetes/default/web-cert");
    assert.match(job.createdAt, /^2026-06-30T/);
    assertNoCustodyKeys(job);
  });

  it("gets and lists jobs scoped by workspace", async () => {
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      payload: { certificateId: "cert-1" },
    });
    await createCertificateJob({
      client,
      workspaceId: WORKSPACE_B,
      operation: "renew",
      payload: { certificateId: "cert-2" },
    });

    assert.equal(
      (await getCertificateJobById({
        client,
        workspaceId: WORKSPACE_A,
        jobId: job.id,
      })).id,
      job.id,
    );
    assert.equal(
      await getCertificateJobById({
        client,
        workspaceId: WORKSPACE_B,
        jobId: job.id,
      }),
      null,
    );

    const listA = await listCertificateJobs({ client, workspaceId: WORKSPACE_A });
    const listB = await listCertificateJobs({ client, workspaceId: WORKSPACE_B });
    assert.deepEqual(listA.items.map((item) => item.id), [job.id]);
    assert.equal(listB.items.some((item) => item.id === job.id), false);
  });

  it("updates status only to bounded lifecycle values", async () => {
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      payload: { certificateId: "cert-1" },
    });

    const running = await updateCertificateJobStatus({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      status: "running",
      resultMetadata: { executor: "executor-a" },
    });
    assert.equal(running.status, "running");
    assert.equal(running.statusTransitionApplied, true);
    assert.equal(running.statusTransitionIgnored, false);
    assert.equal(running.resultMetadata.executor, "executor-a");
    assert.match(running.startedAt, /^2026-06-30T/);

    await assert.rejects(
      () =>
        updateCertificateJobStatus({
          client,
          workspaceId: WORKSPACE_A,
          jobId: job.id,
          status: "accepted",
        }),
      (error) => error?.code === CERTOPS_JOB_STATUS_INVALID,
    );

    for (const staleStatus of ["queued", "canceled"]) {
      await assert.rejects(
        () =>
          createCertificateJob({
            client,
            workspaceId: WORKSPACE_A,
            operation: "renew",
            status: staleStatus,
            payload: { certificateId: "cert-1" },
          }),
        (error) => error?.code === CERTOPS_JOB_STATUS_INVALID,
      );
    }
  });

  it("enforces monotonic transitions and preserves terminal timestamps", async () => {
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      payload: { certificateId: "cert-1" },
      status: "pending_approval",
    });

    const approved = await updateCertificateJobStatus({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      status: "approved",
    });
    const pending = await updateCertificateJobStatus({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      status: "pending",
    });
    const running = await updateCertificateJobStatus({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      status: "running",
    });
    const failed = await updateCertificateJobStatus({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      status: "failed",
      errorCode: "DEPLOY_FAILED",
      errorMessage: "The public deployment check failed",
    });

    assert.equal(approved.status, "approved");
    assert.equal(pending.status, "pending");
    assert.equal(running.status, "running");
    assert.match(running.startedAt, /^2026-06-30T/);
    assert.equal(failed.status, "failed");
    assert.match(failed.completedAt, /^2026-06-30T/);

    const lateRunning = await updateCertificateJobStatus({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      status: "running",
    });
    assert.equal(lateRunning.status, "failed");
    assert.equal(lateRunning.statusTransitionApplied, false);
    assert.equal(lateRunning.statusTransitionIgnored, true);
    assert.equal(
      lateRunning.statusTransitionIgnoredReason,
      "terminal_regression",
    );
    assert.equal(lateRunning.completedAt, failed.completedAt);
    assert.equal(lateRunning.errorCode, "DEPLOY_FAILED");
    assert.equal(
      lateRunning.errorMessage,
      "The public deployment check failed",
    );

    const replay = await updateCertificateJobStatus({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      status: "failed",
    });
    assert.equal(replay.status, "failed");
    assert.equal(replay.statusTransitionApplied, false);
    assert.equal(replay.statusTransitionIgnoredReason, "terminal_replay");
    assert.equal(replay.completedAt, failed.completedAt);
    assert.equal(replay.errorCode, "DEPLOY_FAILED");
    assert.equal(replay.errorMessage, "The public deployment check failed");
  });

  it("ignores active-state regressions from every terminal status", async () => {
    const client = createMemoryClient();

    for (const terminalStatus of [
      "succeeded",
      "failed",
      "rejected",
      "blocked",
      "cancelled",
    ]) {
      const job = await createCertificateJob({
        client,
        workspaceId: WORKSPACE_A,
        operation: "renew",
        payload: { certificateId: `cert-${terminalStatus}` },
        status: terminalStatus,
        errorCode: terminalStatus === "failed" ? "DEPLOY_FAILED" : null,
        errorMessage:
          terminalStatus === "failed" ? "Public deployment failed" : null,
      });

      const lateRunning = await updateCertificateJobStatus({
        client,
        workspaceId: WORKSPACE_A,
        jobId: job.id,
        status: "running",
        errorCode: null,
        errorMessage: null,
      });

      assert.equal(lateRunning.status, terminalStatus);
      assert.equal(lateRunning.statusTransitionApplied, false);
      assert.equal(lateRunning.statusTransitionIgnored, true);
      assert.equal(
        lateRunning.statusTransitionIgnoredReason,
        "terminal_regression",
      );
      assert.equal(lateRunning.completedAt, job.completedAt);
      assert.equal(lateRunning.cancelledAt, job.cancelledAt);
      assert.equal(lateRunning.errorCode, job.errorCode);
      assert.equal(lateRunning.errorMessage, job.errorMessage);
    }
  });

  it("ignores stale active-state regressions and preserves current lifecycle data", async () => {
    const client = createMemoryClient();

    for (const [currentStatus, staleStatus] of [
      ["running", "claimed"],
      ["running", "pending"],
      ["claimed", "pending"],
    ]) {
      const job = await createCertificateJob({
        client,
        workspaceId: WORKSPACE_A,
        operation: "renew",
        payload: { certificateId: `cert-${currentStatus}-${staleStatus}` },
        status: currentStatus,
        errorCode: "EXECUTOR_CONTEXT",
        errorMessage: "Public lifecycle context remains available",
      });

      const stale = await updateCertificateJobStatus({
        client,
        workspaceId: WORKSPACE_A,
        jobId: job.id,
        status: staleStatus,
        errorCode: null,
        errorMessage: "",
      });

      assert.equal(stale.status, currentStatus);
      assert.equal(stale.statusTransitionApplied, false);
      assert.equal(stale.statusTransitionIgnored, true);
      assert.equal(stale.statusTransitionIgnoredReason, "active_regression");
      assert.equal(stale.queuedAt, job.queuedAt);
      assert.equal(stale.startedAt, job.startedAt);
      assert.equal(stale.completedAt, job.completedAt);
      assert.equal(stale.errorCode, "EXECUTOR_CONTEXT");
      assert.equal(
        stale.errorMessage,
        "Public lifecycle context remains available",
      );
    }
  });

  it("treats same active-state reports as observable replays", async () => {
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      payload: { certificateId: "cert-active-replay" },
      status: "running",
    });

    const replay = await updateCertificateJobStatus({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      status: "running",
    });

    assert.equal(replay.status, "running");
    assert.equal(replay.statusTransitionApplied, false);
    assert.equal(replay.statusTransitionIgnored, true);
    assert.equal(replay.statusTransitionIgnoredReason, "active_replay");
  });

  it("allows executor rejection before a job reaches another terminal outcome", async () => {
    const client = createMemoryClient();

    for (const status of [
      "pending_approval",
      "approved",
      "pending",
      "claimed",
      "running",
    ]) {
      const job = await createCertificateJob({
        client,
        workspaceId: WORKSPACE_A,
        operation: "renew",
        payload: { certificateId: `cert-rejected-${status}` },
        status,
      });
      const rejected = await updateCertificateJobStatus({
        client,
        workspaceId: WORKSPACE_A,
        jobId: job.id,
        status: "rejected",
      });

      assert.equal(rejected.status, "rejected");
      assert.equal(rejected.statusTransitionApplied, true);
    }

    const succeeded = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      payload: { certificateId: "cert-rejected-after-success" },
      status: "succeeded",
    });
    const lateRejected = await updateCertificateJobStatus({
      client,
      workspaceId: WORKSPACE_A,
      jobId: succeeded.id,
      status: "rejected",
    });
    assert.equal(lateRejected.status, "succeeded");
    assert.equal(lateRejected.statusTransitionIgnoredReason, "terminal_regression");
  });

  it("sets lifecycle timestamps from the initial canonical status", async () => {
    const client = createMemoryClient();
    const running = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      payload: { certificateId: "cert-running" },
      status: "running",
    });
    const blocked = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      payload: { certificateId: "cert-blocked" },
      status: "blocked",
    });
    const cancelled = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      payload: { certificateId: "cert-cancelled" },
      status: "cancelled",
    });

    assert.match(running.queuedAt, /^20/);
    assert.match(running.startedAt, /^20/);
    assert.match(blocked.completedAt, /^20/);
    assert.match(cancelled.cancelledAt, /^20/);
  });

  it("preserves terminal error fields even when a replay tries to clear them", async () => {
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      payload: { certificateId: "cert-1" },
      status: "running",
    });

    const failed = await updateCertificateJobStatus({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      status: "failed",
      errorCode: "VALIDATION_FAILED",
      errorMessage: "Public certificate validation failed",
    });
    const replay = await updateCertificateJobStatus({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      status: "failed",
    });
    const cleared = await updateCertificateJobStatus({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      status: "failed",
      errorCode: null,
      errorMessage: "",
    });

    assert.equal(replay.errorCode, failed.errorCode);
    assert.equal(replay.errorMessage, failed.errorMessage);
    assert.equal(cleared.errorCode, failed.errorCode);
    assert.equal(cleared.errorMessage, failed.errorMessage);
    assert.equal(cleared.statusTransitionApplied, false);
  });

  it("appends and lists safe job log entries", async () => {
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      payload: { certificateId: "cert-1" },
    });

    const log = await appendCertificateJobLog({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      eventType: "job.progress",
      status: "running",
      message: "Executor started renewal",
      metadata: { step: "renewal", attempt: 1 },
    });
    assert.equal(log.jobId, job.id);
    assert.equal(log.metadata.step, "renewal");

    const logs = await listCertificateJobLog({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
    });
    assert.deepEqual(logs.items.map((item) => item.id), [log.id]);
    assertNoCustodyKeys(logs);

    await assert.rejects(
      () =>
        appendCertificateJobLog({
          client,
          workspaceId: WORKSPACE_A,
          jobId: job.id,
          eventType: "job.deleted",
          metadata: {},
        }),
      (error) => error?.code === CERTOPS_JOB_LOG_EVENT_TYPE_INVALID,
    );
  });

  it("rejects dangerous payload and log metadata recursively", async () => {
    const client = createMemoryClient();
    await assert.rejects(
      () =>
        createCertificateJob({
          client,
          workspaceId: WORKSPACE_A,
          operation: "renew",
          payload: { nested: { privateKeyPem: PRIVATE_KEY_PEM } },
        }),
      (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );

    await assert.rejects(
      () =>
        createCertificateJob({
          client,
          workspaceId: WORKSPACE_A,
          operation: "renew",
          payload: { attachment: SUSPICIOUS_ENCRYPTED_PKCS8_DER.toString("base64") },
        }),
      (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );

    await assert.rejects(
      () =>
        createCertificateJob({
          client,
          workspaceId: WORKSPACE_A,
          operation: "renew",
          payload: { certificateId: "cert-1" },
          resultMetadata: { apiKey: "not-allowed" },
        }),
      (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );

    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      payload: { certificateId: "cert-1" },
    });

    await assert.rejects(
      () =>
        updateCertificateJobStatus({
          client,
          workspaceId: WORKSPACE_A,
          jobId: job.id,
          status: "running",
          resultMetadata: {
            attachment: SUSPICIOUS_ENCRYPTED_PKCS8_DER.toString("hex"),
          },
        }),
      (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );

    await assert.rejects(
      () =>
        appendCertificateJobLog({
          client,
          workspaceId: WORKSPACE_A,
          jobId: job.id,
          eventType: "job.progress",
          message: "password=swordfish",
          metadata: {},
        }),
      (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );

    await assert.rejects(
      () =>
        appendCertificateJobLog({
          client,
          workspaceId: WORKSPACE_A,
          jobId: job.id,
          eventType: "job.progress",
          metadata: { nested: [{ credential: "not-allowed" }] },
        }),
      (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );
  });

  it("canonicalizes the immutable job creation-request fingerprint", () => {
    const first = jobCreationRequestFingerprint({
      operation: "renew",
      status: "pending",
      source: "api",
      requestedByUserId: "user-1",
      requestedByApiTokenId: null,
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: { nested: { alpha: 1, beta: 2 }, labels: ["a", "b"] },
      resultMetadata: { initial: { alpha: 1, beta: 2 } },
      errorCode: null,
      errorMessage: null,
      queuedAt: null,
      startedAt: null,
      completedAt: null,
      cancelledAt: null,
    });
    const reordered = jobCreationRequestFingerprint({
      operation: "renew",
      status: "pending",
      source: "api",
      requestedByUserId: "user-1",
      requestedByApiTokenId: null,
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: { labels: ["a", "b"], nested: { beta: 2, alpha: 1 } },
      resultMetadata: { initial: { beta: 2, alpha: 1 } },
      errorCode: null,
      errorMessage: null,
      queuedAt: null,
      startedAt: null,
      completedAt: null,
      cancelledAt: null,
    });
    const differentArrayOrder = jobCreationRequestFingerprint({
      operation: "renew",
      status: "pending",
      source: "api",
      requestedByUserId: "user-1",
      requestedByApiTokenId: null,
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: { nested: { alpha: 1, beta: 2 }, labels: ["b", "a"] },
      resultMetadata: { initial: { alpha: 1, beta: 2 } },
      errorCode: null,
      errorMessage: null,
      queuedAt: null,
      startedAt: null,
      completedAt: null,
      cancelledAt: null,
    });
    const nullPayload = jobCreationRequestFingerprint({
      operation: "renew",
      status: "pending",
      source: "api",
      requestedByUserId: "user-1",
      requestedByApiTokenId: null,
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: { nested: null },
      resultMetadata: {},
      errorCode: null,
      errorMessage: null,
      queuedAt: null,
      startedAt: null,
      completedAt: null,
      cancelledAt: null,
    });
    const omittedPayload = jobCreationRequestFingerprint({
      operation: "renew",
      status: "pending",
      source: "api",
      requestedByUserId: "user-1",
      requestedByApiTokenId: null,
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: {},
      resultMetadata: {},
      errorCode: null,
      errorMessage: null,
      queuedAt: null,
      startedAt: null,
      completedAt: null,
      cancelledAt: null,
    });

    assert.equal(reordered, first);
    assert.notEqual(differentArrayOrder, first);
    assert.notEqual(nullPayload, omittedPayload);
    assert.match(first, /^[a-f0-9]{64}$/);
  });

  it("applies idempotency per workspace", async () => {
    const client = createMemoryClient();
    const first = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      idempotencyKey: "idem-1",
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: { certificateId: "cert-1" },
    });
    const second = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      idempotencyKey: "idem-1",
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: { certificateId: "cert-1" },
    });
    const otherWorkspace = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_B,
      operation: "renew",
      idempotencyKey: "idem-1",
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: { certificateId: "cert-1" },
    });

    assert.equal(second.id, first.id);
    assert.notEqual(otherWorkspace.id, first.id);

    for (const change of [
      { operation: "deploy" },
      { payload: { certificateId: "cert-2" } },
      { subjectType: "external" },
      { subjectId: "cert-2" },
      { source: "external" },
      { requestedByUserId: "33333333-3333-4333-8333-333333333333" },
      { requestedByApiTokenId: "44444444-4444-4444-8444-444444444444" },
      { status: "approved" },
      { resultMetadata: { initial: "different" } },
      { errorCode: "DIFFERENT_ERROR" },
      { errorMessage: "A different public error" },
    ]) {
      await assert.rejects(
        () =>
          createCertificateJob({
            client,
            workspaceId: WORKSPACE_A,
            operation: "renew",
            idempotencyKey: "idem-1",
            subjectType: "managed_certificate",
            subjectId: "cert-1",
            payload: { certificateId: "cert-1" },
            ...change,
          }),
        (error) => error?.code === CERTOPS_JOB_IDEMPOTENCY_CONFLICT,
      );
    }
  });

  it("keeps idempotent replays valid after lifecycle updates", async () => {
    const client = createMemoryClient();
    const request = {
      workspaceId: WORKSPACE_A,
      operation: "renew",
      source: "api",
      idempotencyKey: "idem-lifecycle",
      subjectType: "managed_certificate",
      subjectId: "cert-lifecycle",
      payload: { certificateId: "cert-lifecycle", labels: { environment: "test" } },
    };
    const created = await createCertificateJob({ client, ...request });
    assert.match(created.creationRequestHash, /^[a-f0-9]{64}$/);
    const running = await updateCertificateJobStatus({
      client,
      workspaceId: WORKSPACE_A,
      jobId: created.id,
      status: "running",
      resultMetadata: { phase: "validated" },
    });
    const replay = await createCertificateJob({ client, ...request });

    assert.equal(replay.id, created.id);
    assert.equal(replay.status, "running");
    assert.deepEqual(replay.resultMetadata, { phase: "validated" });
    assert.equal(running.id, replay.id);
    assert.equal(replay.creationRequestHash, created.creationRequestHash);

    await assert.rejects(
      () =>
        createCertificateJob({
          client,
          ...request,
          payload: { certificateId: "cert-lifecycle", labels: { environment: "prod" } },
        }),
      (error) => error?.code === CERTOPS_JOB_IDEMPOTENCY_CONFLICT,
    );
  });

  it("uses the immutable-subset fallback without backfilling legacy null fingerprints", async () => {
    const client = createMemoryClient();
    const request = {
      workspaceId: WORKSPACE_A,
      operation: "deploy",
      source: "api",
      idempotencyKey: "legacy-null-fingerprint",
      subjectType: "managed_certificate",
      subjectId: "legacy-cert",
      payload: { certificateId: "legacy-cert" },
    };
    const created = await createCertificateJob({ client, ...request });
    client.jobs[0].creation_request_hash = null;
    await updateCertificateJobStatus({
      client,
      workspaceId: WORKSPACE_A,
      jobId: created.id,
      status: "running",
      resultMetadata: { phase: "current" },
    });

    const replay = await createCertificateJob({ client, ...request });
    assert.equal(replay.id, created.id);
    assert.equal(replay.status, "running");
    assert.equal(client.jobs[0].creation_request_hash, null);

    await assert.rejects(
      () =>
        createCertificateJob({
          client,
          ...request,
          payload: { certificateId: "different-legacy-cert" },
        }),
      (error) => error?.code === CERTOPS_JOB_IDEMPOTENCY_CONFLICT,
    );
  });

  it("conflicts on changed explicit original lifecycle timestamps", async () => {
    const cases = [
      {
        name: "queuedAt",
        request: {
          status: "pending",
          queuedAt: "2026-06-30T00:00:00.000Z",
        },
        changed: { queuedAt: "2026-06-30T00:01:00.000Z" },
      },
      {
        name: "startedAt",
        request: {
          status: "running",
          queuedAt: "2026-06-30T00:00:00.000Z",
          startedAt: "2026-06-30T00:01:00.000Z",
        },
        changed: { startedAt: "2026-06-30T00:02:00.000Z" },
      },
      {
        name: "completedAt",
        request: {
          status: "failed",
          queuedAt: "2026-06-30T00:00:00.000Z",
          startedAt: "2026-06-30T00:01:00.000Z",
          completedAt: "2026-06-30T00:02:00.000Z",
        },
        changed: { completedAt: "2026-06-30T00:03:00.000Z" },
      },
      {
        name: "cancelledAt",
        request: {
          status: "cancelled",
          queuedAt: "2026-06-30T00:00:00.000Z",
          cancelledAt: "2026-06-30T00:02:00.000Z",
        },
        changed: { cancelledAt: "2026-06-30T00:03:00.000Z" },
      },
    ];

    for (const testCase of cases) {
      const client = createMemoryClient();
      const request = {
        workspaceId: WORKSPACE_A,
        operation: "deploy",
        source: "api",
        idempotencyKey: `explicit-${testCase.name}`,
        payload: { certificateId: `cert-${testCase.name}` },
        ...testCase.request,
      };
      await createCertificateJob({ client, ...request });
      await assert.rejects(
        () =>
          createCertificateJob({
            client,
            ...request,
            ...testCase.changed,
          }),
        (error) => error?.code === CERTOPS_JOB_IDEMPOTENCY_CONFLICT,
      );
    }
  });

  it("throws not found for missing or wrong-workspace status updates", async () => {
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      payload: { certificateId: "cert-1" },
    });

    for (const options of [
      { workspaceId: WORKSPACE_A, jobId: "missing-job" },
      { workspaceId: WORKSPACE_B, jobId: job.id },
    ]) {
      await assert.rejects(
        () =>
          updateCertificateJobStatus({
            client,
            ...options,
            status: "running",
          }),
        (error) => error?.code === CERTOPS_JOB_NOT_FOUND,
      );
    }
  });

  it("rejects generic secret metadata while allowing public certificate metadata", async () => {
    const client = createMemoryClient();
    const publicMetadata = {
      issuer: "TokenTimer Test CA",
      fingerprintSha256:
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      serialNumber: "01AF",
      subject: "CN=example.com",
      san: ["example.com"],
      status: "valid",
      source: "executor",
      attempt: 1,
    };
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      payload: publicMetadata,
      resultMetadata: publicMetadata,
    });
    assert.equal(job.payload.issuer, "TokenTimer Test CA");

    for (const metadata of [
      { apiKey: "not-allowed" },
      { token: "not-allowed" },
      { apiToken: "not-allowed" },
      { auth_token: "not-allowed" },
      { "bearer-token": "not-allowed" },
      { sessionToken: "not-allowed" },
      { secretToken: "not-allowed" },
      { refreshToken: "not-allowed" },
      { idToken: "not-allowed" },
      { xAuthToken: "not-allowed" },
      { xApiKey: "not-allowed" },
      { cookieHeader: "not-allowed" },
      { setCookie: "not-allowed" },
      { awsSecretAccessKey: "not-allowed" },
      { passphrase: "not-allowed" },
      { authorization: "Bearer not-allowed" },
      { note: "accessToken=not-allowed" },
      { note: "clientSecret=not-allowed" },
      { note: "Cookie: session=not-allowed" },
      { note: "Set-Cookie: session=not-allowed" },
      { note: "X-API-Key: not-allowed" },
      { note: "token=not-allowed" },
    ]) {
      await assert.rejects(
        () =>
          appendCertificateJobLog({
            client,
            workspaceId: WORKSPACE_A,
            jobId: job.id,
            eventType: "job.progress",
            metadata,
          }),
        (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
      );
    }

    for (const message of [
      "Cookie: session=not-allowed",
      "Set-Cookie: session=not-allowed",
      "X-API-Key: not-allowed",
      "token=not-allowed",
    ]) {
      await assert.rejects(
        () =>
          appendCertificateJobLog({
            client,
            workspaceId: WORKSPACE_A,
            jobId: job.id,
            eventType: "job.progress",
            message,
            metadata: {},
          }),
        (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
      );
    }

    await assert.rejects(
      () =>
        createCertificateJob({
          client,
          workspaceId: WORKSPACE_A,
          operation: "renew",
          payload: { note: "Cookie: session=not-allowed" },
        }),
      (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );

    await assert.rejects(
      () =>
        updateCertificateJobStatus({
          client,
          workspaceId: WORKSPACE_A,
          jobId: job.id,
          status: "running",
          errorMessage: "X-API-Key: not-allowed",
        }),
      (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );
    assert.equal(JSON.stringify(client.logs).includes("not-allowed"), false);
    assert.equal(JSON.stringify(client.jobs).includes("not-allowed"), false);

    const redactedLog = await appendCertificateJobLog({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      eventType: "job.progress",
      metadata: {
        note: "password=[REDACTED]",
        redactionApplied: true,
      },
    });
    assert.equal(redactedLog.metadata.note, "password=[REDACTED]");
  });

  it("rejects log writes for missing or wrong-workspace jobs", async () => {
    const client = createMemoryClient();
    await assert.rejects(
      () =>
        appendCertificateJobLog({
          client,
          workspaceId: WORKSPACE_A,
          jobId: "missing-job",
          eventType: "job.progress",
          metadata: {},
        }),
      (error) => error?.code === CERTOPS_JOB_NOT_FOUND,
    );
  });
});

"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  CERTOPS_JOB_LOG_EVENT_TYPE_INVALID,
  CERTOPS_JOB_NOT_FOUND,
  CERTOPS_JOB_STATUS_INVALID,
  PRIVATE_KEY_MATERIAL_REJECTED,
  appendCertificateJobLog,
  createCertificateJob,
  getCertificateJobById,
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
        if (!row) return { rows: [] };
        const terminalStatuses = [
          "succeeded",
          "failed",
          "rejected",
          "blocked",
          "cancelled",
        ];
        if (terminalStatuses.includes(row.status) && row.status !== params[2]) {
          return { rows: [] };
        }
        row.status = params[2];
        if (params[3]) row.result_metadata = json(params[4]);
        row.error_code = params[5] ?? row.error_code;
        row.error_message = params[6] ?? row.error_message;
        row.updated_at = now();
        if (params[2] === "running") row.started_at = row.started_at || now();
        if (params[2] === "succeeded" || params[2] === "failed") {
          row.completed_at = row.completed_at || now();
        }
        if (params[2] === "cancelled") row.canceled_at = row.canceled_at || now();
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
  });

  it("ignores late transitions once a job reaches a terminal status", async () => {
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      payload: { certificateId: "cert-1" },
    });

    const succeeded = await updateCertificateJobStatus({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      status: "succeeded",
    });
    assert.equal(succeeded.status, "succeeded");
    const completedAt = succeeded.completedAt;

    // Late job.started replay with a new eventId must not reopen the job.
    const lateStart = await updateCertificateJobStatus({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      status: "running",
    });
    assert.equal(lateStart.status, "succeeded");
    assert.equal(lateStart.completedAt, completedAt);
    assert.equal(lateStart.startedAt, succeeded.startedAt);

    const lateCancel = await updateCertificateJobStatus({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      status: "cancelled",
    });
    assert.equal(lateCancel.status, "succeeded");
    assert.equal(lateCancel.cancelledAt, null);
  });

  it("keeps error fields when later non-error events arrive", async () => {
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      payload: { certificateId: "cert-1" },
    });

    const failed = await updateCertificateJobStatus({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      status: "failed",
      errorCode: "RENEWAL_TIMEOUT",
      errorMessage: "Executor timed out during renewal",
    });
    assert.equal(failed.status, "failed");
    assert.equal(failed.errorCode, "RENEWAL_TIMEOUT");

    // Late non-error event: terminal status stays, error fields survive.
    const lateStart = await updateCertificateJobStatus({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      status: "running",
    });
    assert.equal(lateStart.status, "failed");
    assert.equal(lateStart.errorCode, "RENEWAL_TIMEOUT");
    assert.equal(lateStart.errorMessage, "Executor timed out during renewal");

    // Same-status replay without error fields must not clear them either.
    const replayFailed = await updateCertificateJobStatus({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      status: "failed",
    });
    assert.equal(replayFailed.status, "failed");
    assert.equal(replayFailed.errorCode, "RENEWAL_TIMEOUT");
    assert.equal(replayFailed.errorMessage, "Executor timed out during renewal");
  });

  it("still returns null for unknown jobs on status update", async () => {
    const client = createMemoryClient();
    const missing = await updateCertificateJobStatus({
      client,
      workspaceId: WORKSPACE_A,
      jobId: "missing-job",
      status: "running",
    });
    assert.equal(missing, null);
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

    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      payload: { certificateId: "cert-1" },
    });

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

  it("applies idempotency per workspace", async () => {
    const client = createMemoryClient();
    const first = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      idempotencyKey: "idem-1",
      payload: { certificateId: "cert-1" },
    });
    const second = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      idempotencyKey: "idem-1",
      payload: { certificateId: "cert-1" },
    });
    const otherWorkspace = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_B,
      operation: "renew",
      idempotencyKey: "idem-1",
      payload: { certificateId: "cert-1" },
    });

    assert.equal(second.id, first.id);
    assert.notEqual(otherWorkspace.id, first.id);
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

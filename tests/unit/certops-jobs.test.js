"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  CERTOPS_JOB_LOG_EVENT_TYPE_INVALID,
  CERTOPS_JOB_IDEMPOTENCY_CONFLICT,
  CERTOPS_JOB_INVALID,
  CERTOPS_JOB_NOT_FOUND,
  CERTOPS_JOB_OPERATION_INVALID,
  CERTOPS_JOB_STATUS_INVALID,
  CERTOPS_JOB_EXECUTION_FIELD_INVALID,
  CERTOPS_JOB_EXECUTION_FIELD_REQUIRED,
  JOB_OPERATIONS,
  PRIVATE_KEY_MATERIAL_REJECTED,
  SUBJECT_TYPES,
  TRUST_ANCHOR_OPERATIONS,
  appendCertificateJobLog,
  createCertificateJob,
  getCertificateJobById,
  isTrustAnchorOperation,
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

function createMemoryClient(options = {}) {
  const jobs = [];
  const logs = [];
  let nextJob = 1;
  let nextLog = 1;
  let tick = 0;
  const now = () => new Date(Date.UTC(2026, 5, 30, 0, tick++, 0));
  const workspaces = new Map([
    [
      WORKSPACE_A,
      {
        certops_require_approval_always:
          options.requireApprovalAlways === true,
      },
    ],
    [WORKSPACE_B, { certops_require_approval_always: false }],
  ]);

  return {
    jobs,
    logs,
    setRequireApprovalAlways(workspaceId, value) {
      const row = workspaces.get(workspaceId) || {};
      row.certops_require_approval_always = value === true;
      workspaces.set(workspaceId, row);
    },
    async query(sql, params = []) {
      const normalizedSql = sql.replace(/\s+/g, " ");

      if (
        normalizedSql.includes("FROM workspaces") &&
        normalizedSql.includes("certops_require_approval_always")
      ) {
        const row = workspaces.get(params[0]);
        return {
          rows: row
            ? [
                {
                  certops_require_approval_always:
                    row.certops_require_approval_always === true,
                },
              ]
            : [],
        };
      }

      if (normalizedSql.includes("pg_advisory_xact_lock")) {
        return { rows: [{ pg_advisory_xact_lock: "" }] };
      }

      if (
        normalizedSql.includes("FROM certificate_jobs") &&
        normalizedSql.includes("operation = ANY($3::text[])") &&
        normalizedSql.includes("FOR UPDATE")
      ) {
        const terminal = new Set(params[1] || []);
        const capOperations = new Set(params[2] || []);
        return {
          rows: jobs
            .filter(
              (row) =>
                row.workspace_id === params[0] &&
                capOperations.has(row.operation) &&
                !terminal.has(row.status),
            )
            .map((row) => ({
              ca_endpoint:
                typeof row.payload?.caEndpoint === "string" &&
                row.payload.caEndpoint.trim() !== ""
                  ? row.payload.caEndpoint.trim()
                  : null,
            })),
        };
      }

      if (normalizedSql.includes("INSERT INTO certificate_jobs")) {
        const idempotencyKey = params[8];
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
          mode: params[3],
          source: params[4],
          executor_kind: params[5],
          requested_by_user_id: params[6],
          requested_by_api_token_id: params[7],
          idempotency_key: idempotencyKey,
          subject_type: params[9],
          subject_id: params[10],
          payload: json(params[11]),
          result_metadata: json(params[12]),
          error_code: params[13],
          error_message: params[14],
          assigned_agent_id: params[15],
          required_target_selector: params[16],
          required_dns_provider: params[17],
          required_command_profile: params[18],
          created_at: createdAt,
          updated_at: createdAt,
          queued_at: params[19],
          started_at: params[20],
          completed_at: params[21],
          canceled_at: params[22],
          creation_request_hash: params[23],
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
        normalizedSql.includes("SELECT COUNT(*)::int AS total") &&
        normalizedSql.includes("FROM certificate_jobs")
      ) {
        let rows = jobs.filter((row) => row.workspace_id === params[0]);
        if (normalizedSql.includes("status = $2")) {
          rows = rows.filter((row) => row.status === params[1]);
        }
        return { rows: [{ total: rows.length }] };
      }

      if (
        normalizedSql.includes("FROM certificate_jobs") &&
        normalizedSql.includes("ORDER BY created_at DESC")
      ) {
        let rows = jobs.filter((row) => row.workspace_id === params[0]);
        if (normalizedSql.includes("status = $2")) {
          rows = rows.filter((row) => row.status === params[1]);
        }
        const limitMatch = /LIMIT \$(\d+) OFFSET \$(\d+)/.exec(normalizedSql);
        if (limitMatch) {
          const limit = Number(params[Number(limitMatch[1]) - 1]);
          const offset = Number(params[Number(limitMatch[2]) - 1]);
          rows = rows.slice(offset, offset + limit);
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
          [
            "succeeded",
            "failed",
            "blocked",
            "dry_run_complete",
            "orphaned_unknown_effect",
          ].includes(params[2])
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
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: { certificateId: "cert-1" },
    });
    await createCertificateJob({
      client,
      workspaceId: WORKSPACE_B,
      operation: "renew",
      subjectType: "managed_certificate",
      subjectId: "cert-2",
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
    assert.equal(listA.pagination.total, 1);
  });

  it("counts the filtered set rather than the page", async () => {
    const client = createMemoryClient();
    for (let index = 0; index < 12; index += 1) {
      await createCertificateJob({
        client,
        workspaceId: WORKSPACE_A,
        operation: "deploy",
        subjectType: "managed_certificate",
        subjectId: `cert-${index}`,
        payload: { certificateId: `cert-${index}` },
      });
    }

    const page = await listCertificateJobs({
      client,
      workspaceId: WORKSPACE_A,
      limit: 5,
    });
    assert.equal(page.items.length, 5);
    assert.deepEqual(page.pagination, { limit: 5, offset: 0, total: 12 });

    const beyond = await listCertificateJobs({
      client,
      workspaceId: WORKSPACE_A,
      limit: 5,
      offset: 90,
    });
    assert.deepEqual(beyond.items, []);
    assert.equal(beyond.pagination.total, 12);
  });

  it("counts through the same predicate as the page when filtering", async () => {
    const client = createMemoryClient();
    for (let index = 0; index < 6; index += 1) {
      const job = await createCertificateJob({
        client,
        workspaceId: WORKSPACE_A,
        operation: "deploy",
        subjectType: "managed_certificate",
        subjectId: `cert-${index}`,
        payload: { certificateId: `cert-${index}` },
      });
      if (index < 2) {
        await updateCertificateJobStatus({
          client,
          workspaceId: WORKSPACE_A,
          jobId: job.id,
          status: "running",
        });
      }
    }

    const filtered = await listCertificateJobs({
      client,
      workspaceId: WORKSPACE_A,
      status: "running",
      limit: 1,
    });

    assert.equal(filtered.items.length, 1);
    assert.equal(filtered.items[0].status, "running");
    assert.equal(filtered.pagination.total, 2);
  });

  it("updates status only to bounded lifecycle values", async () => {
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      subjectType: "managed_certificate",
      subjectId: "cert-1",
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
            subjectType: "managed_certificate",
            subjectId: "cert-1",
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
      subjectType: "managed_certificate",
      subjectId: "cert-1",
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
        subjectType: "managed_certificate",
        subjectId: `cert-${terminalStatus}`,
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
        subjectType: "managed_certificate",
        subjectId: `cert-${currentStatus}-${staleStatus}`,
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
      subjectType: "managed_certificate",
      subjectId: "cert-active-replay",
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
        subjectType: "managed_certificate",
        subjectId: `cert-rejected-${status}`,
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
      subjectType: "managed_certificate",
      subjectId: "cert-rejected-after-success",
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
      subjectType: "managed_certificate",
      subjectId: "cert-running",
      payload: { certificateId: "cert-running" },
      status: "running",
    });
    const blocked = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      subjectType: "managed_certificate",
      subjectId: "cert-blocked",
      payload: { certificateId: "cert-blocked" },
      status: "blocked",
    });
    const cancelled = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      subjectType: "managed_certificate",
      subjectId: "cert-cancelled",
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
      subjectType: "managed_certificate",
      subjectId: "cert-1",
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
      subjectType: "managed_certificate",
      subjectId: "cert-1",
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
          subjectType: "managed_certificate",
          subjectId: "cert-1",
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
          subjectType: "managed_certificate",
          subjectId: "cert-1",
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
          subjectType: "managed_certificate",
          subjectId: "cert-1",
          payload: { certificateId: "cert-1" },
          resultMetadata: { apiKey: "not-allowed" },
        }),
      (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );

    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      subjectType: "managed_certificate",
      subjectId: "cert-1",
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
        subjectType: "managed_certificate",
        subjectId: `cert-${testCase.name}`,
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
      subjectType: "managed_certificate",
      subjectId: "cert-1",
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
      subjectType: "managed_certificate",
      subjectId: "cert-1",
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
          subjectType: "managed_certificate",
          subjectId: "cert-1",
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

  it("accepts a fully loaded executable renew payload", async () => {
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      source: "automation",
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: {
        target: "example.com",
        commandRef: "acme-renew-default",
        caEndpoint: "https://acme-v02.api.letsencrypt.org/directory",
        acmeKind: "certbot",
        keyRotation: true,
        certPath: "/etc/ssl/live/example.com/cert.pem",
        reloadService: "nginx",
        verifyHost: "example.com",
        verifyPort: 443,
        dnsZone: "example.com",
        dnsProvider: "cloudflare",
        renewalProfile: {
          schemaVersion: 1,
          sanPolicy: {
            mode: "exact",
            sans: ["example.com"],
            allowWildcards: false,
          },
          keyAlgorithm: "rsa",
          keySize: 2048,
          keyRotationPolicy: { rotateOnRenew: true },
          preferredChain: null,
          ca: {
            endpoint: "https://acme-v02.api.letsencrypt.org/directory",
            accountRef: null,
            eabRef: null,
          },
          acme: { kind: "certbot", commandRef: "acme-renew-default" },
          dns: { provider: "cloudflare", zone: "example.com" },
          deploymentTargets: [
            {
              type: "endpoint",
              reference: "example.com",
              certPath: "/etc/ssl/live/example.com/cert.pem",
              reloadService: "nginx",
            },
          ],
          target: {
            type: "endpoint",
            reference: "example.com",
            certPath: "/etc/ssl/live/example.com/cert.pem",
          },
          verification: {
            host: "example.com",
            port: 443,
            requireMatch: true,
          },
        },
      },
    });

    assert.equal(job.operation, "renew");
    assert.equal(job.payload.commandRef, "acme-renew-default");
    assert.equal(job.payload.verifyPort, 443);
    assert.ok(job.payload.renewalProfile);
    assertNoCustodyKeys(job);
  });

  it("exposes the execution columns with safe defaults", async () => {
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      source: "api",
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: { target: "example.com" },
    });

    assert.equal(job.claimedByAgentId, null);
    assert.equal(job.claimId, null);
    assert.equal(job.leaseExpiresAt, null);
    assert.equal(job.attemptCount, 0);
    assert.equal(job.maxAttempts, 3);
    assert.equal(job.nextAttemptAt, null);
    assert.equal(job.scheduledFor, null);
  });

  it("rejects malformed execution field values", async () => {
    const client = createMemoryClient();
    const badPayloads = [
      { commandRef: "not valid because of spaces" },
      { caEndpoint: "ftp://example.com/dir" },
      { caEndpoint: "not-a-url" },
      { acmeKind: "lego" },
      { keyRotation: "yes" },
      { certPath: "" },
      { reloadService: "bad service name" },
      { verifyHost: "" },
      { verifyPort: 0 },
      { verifyPort: 70000 },
      { verifyPort: 443.5 },
      { dnsZone: "" },
      { dnsProvider: "spaces are bad" },
    ];

    for (const fields of badPayloads) {
      await assert.rejects(
        () =>
          createCertificateJob({
            client,
            workspaceId: WORKSPACE_A,
            operation: "renew",
            source: "automation",
            subjectType: "managed_certificate",
            subjectId: "cert-1",
            payload: { target: "example.com", ...fields },
          }),
        (error) => error?.code === CERTOPS_JOB_EXECUTION_FIELD_INVALID,
        `expected rejection for ${JSON.stringify(fields)}`,
      );
    }
  });

  it("requires commandRef/caEndpoint/certPath/dnsZone/dnsProvider for an issue job (no renewalProfile to fall back on)", async () => {
    const client = createMemoryClient();
    const fullIssuePayload = {
      target: "example.com",
      commandRef: "certbot-renew",
      caEndpoint: "https://acme.example.com/directory",
      certPath: "/etc/ssl/live/example.com/cert.pem",
      dnsZone: "example.com",
      dnsProvider: "cloudflare",
    };
    const requiredFields = [
      "commandRef",
      "caEndpoint",
      "certPath",
      "dnsZone",
      "dnsProvider",
    ];

    for (const fieldName of requiredFields) {
      const payload = { ...fullIssuePayload };
      delete payload[fieldName];
      await assert.rejects(
        () =>
          createCertificateJob({
            client,
            workspaceId: WORKSPACE_A,
            operation: "issue",
            source: "api",
            subjectType: "managed_certificate",
            subjectId: "cert-1",
            payload,
          }),
        (error) => error?.code === CERTOPS_JOB_EXECUTION_FIELD_REQUIRED,
        `expected ${fieldName} to be required for issue`,
      );
    }

    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "issue",
      source: "api",
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: fullIssuePayload,
    });
    assert.equal(job.operation, "issue");
  });

  // Multi-destination deploy is real, but only via renewalProfile
  // .deploymentTargets on a renew job. Derivation reads deploymentTargets[0]
  // and nothing else, so a multi-target issue used to deploy everywhere and then
  // produce a profile covering one host: the others silently stopped renewing
  // months later. Refusing the request is the recoverable failure.
  it("refuses an issue payload carrying more than one deploymentTargets entry", async () => {
    const client = createMemoryClient();
    const basePayload = {
      target: "example.com",
      commandRef: "certbot-renew",
      caEndpoint: "https://acme.example.com/directory",
      certPath: "/etc/ssl/live/example.com/cert.pem",
      dnsZone: "example.com",
      dnsProvider: "cloudflare",
    };

    await assert.rejects(
      () =>
        createCertificateJob({
          client,
          workspaceId: WORKSPACE_A,
          operation: "issue",
          source: "api",
          subjectType: "managed_certificate",
          subjectId: "cert-multi",
          payload: {
            ...basePayload,
            deploymentTargets: [
              { type: "endpoint", reference: "web-01", certPath: "/a/cert.pem" },
              { type: "endpoint", reference: "web-02", certPath: "/b/cert.pem" },
            ],
          },
        }),
      (error) => error?.code === CERTOPS_JOB_EXECUTION_FIELD_INVALID,
      "expected a multi-target issue payload to be refused",
    );

    await assert.rejects(
      () =>
        createCertificateJob({
          client,
          workspaceId: WORKSPACE_A,
          operation: "issue",
          source: "api",
          subjectType: "managed_certificate",
          subjectId: "cert-multi",
          payload: { ...basePayload, deploymentTargets: "not-an-array" },
        }),
      (error) => error?.code === CERTOPS_JOB_EXECUTION_FIELD_INVALID,
      "expected a non-array deploymentTargets to be refused",
    );

    // Exactly one target is the shape derivation can faithfully reproduce, and
    // omitting the array entirely (fields flat on the payload) stays valid.
    const single = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "issue",
      source: "api",
      subjectType: "managed_certificate",
      subjectId: "cert-single",
      payload: {
        ...basePayload,
        deploymentTargets: [
          { type: "endpoint", reference: "web-01", certPath: "/a/cert.pem" },
        ],
      },
    });
    assert.equal(single.operation, "issue");

    // renew is deliberately NOT constrained: its multi-target support comes
    // from an explicit renewalProfile the operator or derivation authored, so
    // nothing is being inferred from position there.
    const renew = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      source: "api",
      subjectType: "managed_certificate",
      subjectId: "cert-renew",
      payload: {
        target: "example.com",
        deploymentTargets: [
          { type: "endpoint", reference: "web-01", certPath: "/a/cert.pem" },
          { type: "endpoint", reference: "web-02", certPath: "/b/cert.pem" },
        ],
      },
    });
    assert.equal(renew.operation, "renew");
  });

  it("rejects execution fields on operations that never execute them", async () => {
    const client = createMemoryClient();

    // noop and revoke never carry execution intent.
    for (const operation of ["noop", "revoke"]) {
      await assert.rejects(
        () =>
          createCertificateJob({
            client,
            workspaceId: WORKSPACE_A,
            operation,
            source: "api",
            subjectType: "managed_certificate",
            subjectId: "cert-1",
            payload: { caEndpoint: "https://acme.example.com/directory" },
          }),
        (error) => error?.code === CERTOPS_JOB_EXECUTION_FIELD_INVALID,
      );
    }

    // deploy carries deploy fields but not renewal-only fields.
    await assert.rejects(
      () =>
        createCertificateJob({
          client,
          workspaceId: WORKSPACE_A,
          operation: "deploy",
          source: "api",
          subjectType: "managed_certificate",
          subjectId: "cert-1",
          payload: { acmeKind: "certbot" },
        }),
      (error) => error?.code === CERTOPS_JOB_EXECUTION_FIELD_INVALID,
    );

    const deployJob = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "deploy",
      source: "api",
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: {
        certPath: "/etc/ssl/live/example.com/cert.pem",
        reloadService: "nginx",
        verifyHost: "example.com",
        verifyPort: 443,
      },
    });
    assert.equal(deployJob.operation, "deploy");
  });

  it("keeps rejecting pem-named payload fields for stored executable payloads", async () => {
    const client = createMemoryClient();
    // certificatePem is dispatch-time-only: the persistence boundary must
    // reject it even though the wire schema allows it on dispatched jobs.
    await assert.rejects(
      () =>
        createCertificateJob({
          client,
          workspaceId: WORKSPACE_A,
          operation: "deploy",
          source: "api",
          subjectType: "managed_certificate",
          subjectId: "cert-1",
          payload: {
            certificatePem:
              "-----BEGIN CERTIFICATE-----\nRkFLRQ==\n-----END CERTIFICATE-----",
          },
        }),
      (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );
  });

  it("defaults mode to real and persists it on the row and payload", async () => {
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "deploy",
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: { target: "host/web" },
    });
    assert.equal(job.mode, "real");
    assert.equal(job.payload.mode, "real");
    assert.equal(client.jobs[0].mode, "real");
  });

  it("accepts explicit dry_run mode and rejects succeeding it", async () => {
    const { CERTOPS_JOB_MODE_TERMINAL_INVALID } = require(
      path.resolve(__dirname, "../../apps/api/services/certops/jobs.js"),
    );
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "noop",
      mode: "dry_run",
      payload: {},
    });
    assert.equal(job.mode, "dry_run");
    assert.equal(job.payload.mode, "dry_run");

    await assert.rejects(
      () =>
        updateCertificateJobStatus({
          client,
          workspaceId: WORKSPACE_A,
          jobId: job.id,
          status: "succeeded",
        }),
      (error) => error?.code === CERTOPS_JOB_MODE_TERMINAL_INVALID,
    );

    const completed = await updateCertificateJobStatus({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      status: "dry_run_complete",
    });
    assert.equal(completed.status, "dry_run_complete");
  });

  it("sets completed_at when transitioning to orphaned_unknown_effect", async () => {
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "deploy",
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: { target: "host/web" },
    });
    assert.equal(job.completedAt, null);

    const claimed = await updateCertificateJobStatus({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      status: "claimed",
    });
    assert.equal(claimed.completedAt, null);

    const orphaned = await updateCertificateJobStatus({
      client,
      workspaceId: WORKSPACE_A,
      jobId: job.id,
      status: "orphaned_unknown_effect",
    });
    assert.equal(orphaned.status, "orphaned_unknown_effect");
    assert.ok(orphaned.completedAt, "orphaned_unknown_effect must set completed_at");
  });

  it("requires a valid renewalProfile for automation renew jobs", async () => {
    const {
      CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
    } = require(
      path.resolve(__dirname, "../../apps/api/services/certops/jobs.js"),
    );
    const client = createMemoryClient();
    await assert.rejects(
      () =>
        createCertificateJob({
          client,
          workspaceId: WORKSPACE_A,
          operation: "renew",
          source: "automation",
          subjectType: "managed_certificate",
          subjectId: "cert-1",
          payload: { certificateId: "cert-1" },
        }),
      (error) => error?.code === CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
    );
  });

  it("enforces per-CA renew capacity across sequential creators for the same CA", async () => {
    const {
      CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED,
    } = require(
      path.resolve(__dirname, "../../apps/api/services/certops/jobs.js"),
    );
    const client = createMemoryClient();
    const env = { CERTOPS_RENEWAL_PER_CA_CAP: "2" };
    const caEndpoint = "https://acme.example.com/directory";

    const first = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      source: "api",
      subjectType: "managed_certificate",
      subjectId: "cert-a",
      payload: { certificateId: "cert-a", caEndpoint },
      idempotencyKey: "manual-cert-a",
      env,
    });
    const second = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      source: "api",
      subjectType: "managed_certificate",
      subjectId: "cert-b",
      payload: { certificateId: "cert-b", caEndpoint },
      idempotencyKey: "scheduler-cert-b",
      env,
    });
    assert.ok(first.id);
    assert.ok(second.id);
    assert.notEqual(first.id, second.id);

    await assert.rejects(
      () =>
        createCertificateJob({
          client,
          workspaceId: WORKSPACE_A,
          operation: "renew",
          source: "api",
          subjectType: "managed_certificate",
          subjectId: "cert-c",
          payload: { certificateId: "cert-c", caEndpoint },
          idempotencyKey: "manual-cert-c",
          env,
        }),
      (error) => error?.code === CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED,
    );

    // Idempotent replay of an existing job must still succeed at capacity.
    const replay = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      source: "api",
      subjectType: "managed_certificate",
      subjectId: "cert-a",
      payload: { certificateId: "cert-a", caEndpoint },
      idempotencyKey: "manual-cert-a",
      env,
      returnOutcome: true,
    });
    assert.equal(replay.created, false);
    assert.equal(replay.job.id, first.id);

    // A different CA bucket remains independently capped.
    const otherCa = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      source: "api",
      subjectType: "managed_certificate",
      subjectId: "cert-d",
      payload: {
        certificateId: "cert-d",
        caEndpoint: "https://other.example/directory",
      },
      idempotencyKey: "manual-cert-d",
      env,
    });
    assert.ok(otherCa.id);
  });
});

describe("CertOps jobs service - workspace-forced approval policy override", () => {
  it("forces pending_approval when the workspace policy is on and the caller did not request approval", async () => {
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "deploy",
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: { target: "host/web" },
      workspaceRequiresApprovalAlways: true,
    });

    assert.equal(job.status, "pending_approval");
  });

  it("overrides an explicit conflicting status when the workspace forces approval", async () => {
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "deploy",
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: { target: "host/web" },
      status: "pending",
      workspaceRequiresApprovalAlways: true,
    });

    assert.equal(job.status, "pending_approval");
  });

  it("still requires pending_approval, not a bypass, when both the per-job flag and the workspace policy are on", async () => {
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "deploy",
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: { target: "host/web" },
      requiresApproval: true,
      workspaceRequiresApprovalAlways: true,
    });

    assert.equal(job.status, "pending_approval");
  });

  it("leaves the default status alone when the workspace policy is off", async () => {
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "deploy",
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: { target: "host/web" },
      workspaceRequiresApprovalAlways: false,
    });

    assert.equal(job.status, "pending");
  });

  it("does not force approval for protocol_smoke, exempt the same way it is exempt from every other approval-flow concept", async () => {
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "protocol_smoke",
      allowDiagnosticOperation: true,
      mode: "dry_run",
      workspaceRequiresApprovalAlways: true,
    });

    assert.equal(job.status, "pending");
  });

  it("forces pending_approval from the workspace row even when the caller omits workspaceRequiresApprovalAlways", async () => {
    const client = createMemoryClient();
    client.setRequireApprovalAlways(WORKSPACE_A, true);
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "deploy",
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: { target: "host/web" },
    });

    assert.equal(job.status, "pending_approval");
  });

  it("does not let an explicit false override a true workspace policy row", async () => {
    const client = createMemoryClient();
    client.setRequireApprovalAlways(WORKSPACE_A, true);
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "deploy",
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: { target: "host/web" },
      status: "pending",
      workspaceRequiresApprovalAlways: false,
    });

    assert.equal(job.status, "pending_approval");
  });
});

describe("CertOps trust-anchor operation and subject-type wiring (ADR-0012 decisions 4-6, 14)", () => {
  it("adds distribute-trust/revoke-trust to the operation vocabulary and trust_anchor to the subject vocabulary", () => {
    assert.ok(JOB_OPERATIONS.includes("distribute-trust"));
    assert.ok(JOB_OPERATIONS.includes("revoke-trust"));
    assert.ok(SUBJECT_TYPES.includes("trust_anchor"));
    assert.deepEqual(
      [...TRUST_ANCHOR_OPERATIONS].sort(),
      ["distribute-trust", "revoke-trust"],
    );
  });

  it("isTrustAnchorOperation recognizes only the two trust operations", () => {
    assert.equal(isTrustAnchorOperation("distribute-trust"), true);
    assert.equal(isTrustAnchorOperation("revoke-trust"), true);
    for (const operation of ["issue", "renew", "deploy", "reload", "revoke", "noop"]) {
      assert.equal(isTrustAnchorOperation(operation), false);
    }
    assert.equal(isTrustAnchorOperation(null), false);
    assert.equal(isTrustAnchorOperation(undefined), false);
  });

  it("creates a distribute-trust job with a trust_anchor subject", async () => {
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "distribute-trust",
      source: "api",
      subjectType: "trust_anchor",
      subjectId: "anchor-1",
      payload: {},
    });
    assert.equal(job.operation, "distribute-trust");
    assert.equal(job.subjectType, "trust_anchor");
    assert.equal(job.subjectId, "anchor-1");
  });

  it("rejects a pem-named field on a distribute-trust job's stored payload, the same as it would on a certificate job", async () => {
    // The signed pem the agent needs to install lives on the dispatch-time
    // wire payload (trust-job-payload.schema.json), attached only when the
    // job is signed and handed to the agent, never in the row this function
    // persists. Proving that boundary here is what stands in for a
    // logs/evidence redaction test: nothing that reaches storage (and from
    // there, logs or evidence exports) ever carries a pem-named field for a
    // trust job, exactly as for a certificate job's certificatePem.
    const client = createMemoryClient();
    await assert.rejects(
      () =>
        createCertificateJob({
          client,
          workspaceId: WORKSPACE_A,
          operation: "distribute-trust",
          source: "api",
          subjectType: "trust_anchor",
          subjectId: "anchor-1",
          payload: {
            pem: "-----BEGIN CERTIFICATE-----\nRkFLRQ==\n-----END CERTIFICATE-----",
          },
        }),
      (error) => error?.code === PRIVATE_KEY_MATERIAL_REJECTED,
    );
  });

  it("creates a revoke-trust job with a trust_anchor subject", async () => {
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "revoke-trust",
      source: "api",
      subjectType: "trust_anchor",
      subjectId: "anchor-1",
      payload: {},
    });
    assert.equal(job.operation, "revoke-trust");
    assert.equal(job.subjectType, "trust_anchor");
  });

  it("rejects a distribute-trust job with no subject at all", async () => {
    const client = createMemoryClient();
    await assert.rejects(
      () =>
        createCertificateJob({
          client,
          workspaceId: WORKSPACE_A,
          operation: "distribute-trust",
          source: "api",
          payload: {},
        }),
      (error) => error?.code === CERTOPS_JOB_INVALID,
    );
  });

  it("rejects a distribute-trust job whose subjectType is managed_certificate", async () => {
    const client = createMemoryClient();
    await assert.rejects(
      () =>
        createCertificateJob({
          client,
          workspaceId: WORKSPACE_A,
          operation: "distribute-trust",
          source: "api",
          subjectType: "managed_certificate",
          subjectId: "cert-1",
          payload: {},
        }),
      (error) => error?.code === CERTOPS_JOB_INVALID,
    );
  });

  it("rejects an ordinary certificate job (renew) whose subjectType is trust_anchor", async () => {
    const client = createMemoryClient();
    await assert.rejects(
      () =>
        createCertificateJob({
          client,
          workspaceId: WORKSPACE_A,
          operation: "renew",
          source: "api",
          subjectType: "trust_anchor",
          subjectId: "anchor-1",
          payload: { certificateId: "cert-1", caEndpoint: "https://acme.example/directory" },
        }),
      (error) => error?.code === CERTOPS_JOB_INVALID,
    );
  });

  it("by construction: refuses an automation-sourced trust-anchor job, so the renewal scheduler can never create one", async () => {
    const client = createMemoryClient();
    await assert.rejects(
      () =>
        createCertificateJob({
          client,
          workspaceId: WORKSPACE_A,
          operation: "distribute-trust",
          source: "automation",
          subjectType: "trust_anchor",
          subjectId: "anchor-1",
          payload: {},
        }),
      (error) => error?.code === CERTOPS_JOB_OPERATION_INVALID,
    );
  });

  it("still allows automation-sourced renew jobs (the scheduler's own lane is untouched)", async () => {
    const client = createMemoryClient();
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      source: "automation",
      subjectType: "managed_certificate",
      subjectId: "cert-1",
      payload: {
        certificateId: "cert-1",
        caEndpoint: "https://acme.example/directory",
        renewalProfile: {
          schemaVersion: 1,
          target: { type: "domain", reference: "cert-1", certPath: "/etc/ssl/live/cert-1/cert.pem" },
          deploymentTargets: [{ type: "domain", reference: "cert-1", certPath: "/etc/ssl/live/cert-1/cert.pem" }],
          ca: { endpoint: "https://acme.example/directory", accountRef: null, eabRef: null },
          acme: { kind: "certbot", commandRef: "cmd" },
          dns: { provider: "cloudflare", zone: "example.com" },
          sanPolicy: { mode: "exact", sans: ["cert-1"], allowWildcards: false },
          keyAlgorithm: "ecdsa",
          keySize: 256,
          keyRotationPolicy: { rotateOnRenew: true },
          preferredChain: null,
          verification: { host: null, port: null, requireMatch: false },
        },
      },
    });
    assert.equal(job.operation, "renew");
  });
});

describe("CertOps jobs service - managed certificate ownership guard", () => {
  const OBSERVED_CERT_ID = "a1111111-1111-4111-8111-111111111111";
  const AGENT_LOCAL_CERT_ID = "a2222222-2222-4222-8222-222222222222";
  const DISCOVERED_CERT_ID = "a3333333-3333-4333-8333-333333333333";
  const OWNING_AGENT_DB_ID = "b1111111-1111-4111-8111-111111111111";

  function createOwnershipMemoryClient({ certificates = [], agents = [] } = {}) {
    const jobs = [];
    let nextJob = 1;

    return {
      jobs,
      async query(sql, params = []) {
        const normalizedSql = sql.replace(/\s+/g, " ");

        if (
          normalizedSql.includes("FROM workspaces") &&
          normalizedSql.includes("certops_require_approval_always")
        ) {
          return { rows: [{ certops_require_approval_always: false }] };
        }

        if (normalizedSql.includes("pg_advisory_xact_lock")) {
          return { rows: [{ pg_advisory_xact_lock: "" }] };
        }

        if (normalizedSql.includes("FROM managed_certificates")) {
          const [workspaceId, id] = params;
          const row = certificates.find(
            (cert) => cert.workspace_id === workspaceId && cert.id === id,
          );
          return { rows: row ? [row] : [] };
        }

        if (normalizedSql.includes("FROM certops_agents")) {
          const [workspaceId, agentId] = params;
          const row = agents.find(
            (agent) =>
              agent.workspace_id === workspaceId && agent.agent_id === agentId,
          );
          return { rows: row ? [{ id: row.id }] : [] };
        }

        if (
          normalizedSql.includes("FROM certificate_jobs") &&
          normalizedSql.includes("operation = ANY($3::text[])") &&
          normalizedSql.includes("FOR UPDATE")
        ) {
          return { rows: [] };
        }

        if (normalizedSql.includes("idempotency_key = $2")) {
          return { rows: [] };
        }

        if (normalizedSql.includes("INSERT INTO certificate_jobs")) {
          const createdAt = new Date(Date.UTC(2026, 5, 30, 0, 0, 0));
          const row = {
            id: `job-${nextJob++}`,
            workspace_id: params[0],
            operation: params[1],
            status: params[2],
            mode: params[3],
            source: params[4],
            executor_kind: params[5],
            requested_by_user_id: params[6],
            requested_by_api_token_id: params[7],
            idempotency_key: params[8],
            subject_type: params[9],
            subject_id: params[10],
            payload: json(params[11]),
            result_metadata: json(params[12]),
            error_code: params[13],
            error_message: params[14],
            assigned_agent_id: params[15],
            required_target_selector: params[16],
            required_dns_provider: params[17],
            required_command_profile: params[18],
            created_at: createdAt,
            updated_at: createdAt,
            queued_at: params[19],
            started_at: params[20],
            completed_at: params[21],
            canceled_at: params[22],
            creation_request_hash: params[23],
          };
          jobs.push(row);
          return { rows: [row] };
        }

        throw new Error(`Unhandled query in ownership test client: ${normalizedSql}`);
      },
    };
  }

  it("rejects a renew job for a managed_certificate with no agent-manageable key custody", async () => {
    const { CERTOPS_CERTIFICATE_NOT_AGENT_DEPLOYABLE } = require(
      path.resolve(__dirname, "../../apps/api/services/certops/jobs.js"),
    );
    const client = createOwnershipMemoryClient({
      certificates: [
        {
          workspace_id: WORKSPACE_A,
          id: OBSERVED_CERT_ID,
          key_mode: null,
          source: "endpoint_monitor",
          discovery_agent_id: null,
        },
      ],
    });

    await assert.rejects(
      () =>
        createCertificateJob({
          client,
          workspaceId: WORKSPACE_A,
          operation: "renew",
          subjectType: "managed_certificate",
          subjectId: OBSERVED_CERT_ID,
          payload: {},
        }),
      (error) => error?.code === CERTOPS_CERTIFICATE_NOT_AGENT_DEPLOYABLE,
    );
  });

  it("allows a renew job for a managed_certificate with agent-local key custody and no discovery agent", async () => {
    const client = createOwnershipMemoryClient({
      certificates: [
        {
          workspace_id: WORKSPACE_A,
          id: AGENT_LOCAL_CERT_ID,
          key_mode: "agent-local",
          source: "api",
          discovery_agent_id: null,
        },
      ],
    });

    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      subjectType: "managed_certificate",
      subjectId: AGENT_LOCAL_CERT_ID,
      payload: {},
    });
    assert.equal(job.assignedAgentId, null);
  });

  it("auto-assigns the certificate's discovering agent for an agent_filesystem certificate", async () => {
    const client = createOwnershipMemoryClient({
      certificates: [
        {
          workspace_id: WORKSPACE_A,
          id: DISCOVERED_CERT_ID,
          key_mode: "agent-local",
          source: "agent_filesystem",
          discovery_agent_id: "candidate-edge-01-9001",
        },
      ],
      agents: [
        {
          workspace_id: WORKSPACE_A,
          id: OWNING_AGENT_DB_ID,
          agent_id: "candidate-edge-01-9001",
        },
      ],
    });

    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      subjectType: "managed_certificate",
      subjectId: DISCOVERED_CERT_ID,
      payload: {},
    });
    assert.equal(job.assignedAgentId, OWNING_AGENT_DB_ID);
  });

  it("does not override an explicit assignedAgentId with the auto-derived discovery agent", async () => {
    const explicitAgentId = "c4444444-4444-4444-8444-444444444444";
    const client = createOwnershipMemoryClient({
      certificates: [
        {
          workspace_id: WORKSPACE_A,
          id: DISCOVERED_CERT_ID,
          key_mode: "agent-local",
          source: "agent_filesystem",
          discovery_agent_id: "candidate-edge-01-9001",
        },
      ],
      agents: [
        {
          workspace_id: WORKSPACE_A,
          id: OWNING_AGENT_DB_ID,
          agent_id: "candidate-edge-01-9001",
        },
      ],
    });

    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      subjectType: "managed_certificate",
      subjectId: DISCOVERED_CERT_ID,
      assignedAgentId: explicitAgentId,
      payload: {},
    });
    assert.equal(job.assignedAgentId, explicitAgentId);
  });

  it("skips the ownership lookup entirely for non-UUID subject ids (free-text/test fixtures)", async () => {
    const client = createOwnershipMemoryClient({});
    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      subjectType: "managed_certificate",
      subjectId: "not-a-uuid",
      payload: {},
    });
    assert.equal(job.assignedAgentId, null);
  });

  function minimalValidRenewalPayload() {
    return {
      target: "example.com",
      commandRef: "acme-renew-default",
      caEndpoint: "https://acme-v02.api.letsencrypt.org/directory",
      acmeKind: "certbot",
      keyRotation: true,
      certPath: "/etc/ssl/live/example.com/cert.pem",
      reloadService: "nginx",
      verifyHost: "example.com",
      verifyPort: 443,
      dnsZone: "example.com",
      dnsProvider: "cloudflare",
      renewalProfile: {
        schemaVersion: 1,
        sanPolicy: {
          mode: "exact",
          sans: ["example.com"],
          allowWildcards: false,
        },
        keyAlgorithm: "rsa",
        keySize: 2048,
        keyRotationPolicy: { rotateOnRenew: true },
        preferredChain: null,
        ca: {
          endpoint: "https://acme-v02.api.letsencrypt.org/directory",
          accountRef: null,
          eabRef: null,
        },
        acme: { kind: "certbot", commandRef: "acme-renew-default" },
        dns: { provider: "cloudflare", zone: "example.com" },
        deploymentTargets: [
          {
            type: "endpoint",
            reference: "example.com",
            certPath: "/etc/ssl/live/example.com/cert.pem",
            reloadService: "nginx",
          },
        ],
        target: {
          type: "endpoint",
          reference: "example.com",
          certPath: "/etc/ssl/live/example.com/cert.pem",
        },
        verification: {
          host: "example.com",
          port: 443,
          requireMatch: true,
        },
      },
    };
  }

  it("rejects an automation-sourced renew job for a certificate whose profile is disabled", async () => {
    const { CERTOPS_RENEWAL_AUTO_RENEW_DISABLED } = require(
      path.resolve(__dirname, "../../apps/api/services/certops/jobs.js"),
    );
    const client = createOwnershipMemoryClient({
      certificates: [
        {
          workspace_id: WORKSPACE_A,
          id: AGENT_LOCAL_CERT_ID,
          key_mode: "agent-local",
          source: "api",
          discovery_agent_id: null,
          profile_status: "disabled",
        },
      ],
    });

    await assert.rejects(
      () =>
        createCertificateJob({
          client,
          workspaceId: WORKSPACE_A,
          operation: "renew",
          source: "automation",
          subjectType: "managed_certificate",
          subjectId: AGENT_LOCAL_CERT_ID,
          payload: minimalValidRenewalPayload(),
        }),
      (error) => error?.code === CERTOPS_RENEWAL_AUTO_RENEW_DISABLED,
    );
  });

  it("rejects an automation-sourced renew job for a certificate whose profile is archived", async () => {
    const { CERTOPS_RENEWAL_AUTO_RENEW_DISABLED } = require(
      path.resolve(__dirname, "../../apps/api/services/certops/jobs.js"),
    );
    const client = createOwnershipMemoryClient({
      certificates: [
        {
          workspace_id: WORKSPACE_A,
          id: AGENT_LOCAL_CERT_ID,
          key_mode: "agent-local",
          source: "api",
          discovery_agent_id: null,
          profile_status: "archived",
        },
      ],
    });

    await assert.rejects(
      () =>
        createCertificateJob({
          client,
          workspaceId: WORKSPACE_A,
          operation: "renew",
          source: "automation",
          subjectType: "managed_certificate",
          subjectId: AGENT_LOCAL_CERT_ID,
          payload: minimalValidRenewalPayload(),
        }),
      (error) => error?.code === CERTOPS_RENEWAL_AUTO_RENEW_DISABLED,
    );
  });

  it("allows a manually-sourced renew job for a certificate whose profile is disabled (manual renew is the documented override)", async () => {
    const client = createOwnershipMemoryClient({
      certificates: [
        {
          workspace_id: WORKSPACE_A,
          id: AGENT_LOCAL_CERT_ID,
          key_mode: "agent-local",
          source: "api",
          discovery_agent_id: null,
          profile_status: "disabled",
        },
      ],
    });

    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      source: "api",
      subjectType: "managed_certificate",
      subjectId: AGENT_LOCAL_CERT_ID,
      payload: {},
    });
    assert.equal(job.status, "pending");
  });

  it("allows an automation-sourced renew job for a certificate whose profile is active", async () => {
    const client = createOwnershipMemoryClient({
      certificates: [
        {
          workspace_id: WORKSPACE_A,
          id: AGENT_LOCAL_CERT_ID,
          key_mode: "agent-local",
          source: "api",
          discovery_agent_id: null,
          profile_status: "active",
        },
      ],
    });

    const job = await createCertificateJob({
      client,
      workspaceId: WORKSPACE_A,
      operation: "renew",
      source: "automation",
      subjectType: "managed_certificate",
      subjectId: AGENT_LOCAL_CERT_ID,
      payload: minimalValidRenewalPayload(),
    });
    assert.equal(job.status, "pending");
  });
});

describe("CertOps jobs service - manualRenewalJobCreator (canonical manual/bulk renewal materializer)", () => {
  const MANUAL_RENEWAL_CERT_ID = "c1111111-1111-4111-8111-111111111111";

  function validRenewalProfileSource() {
    return {
      schemaVersion: 1,
      profileId: "profile-1",
      profileName: "web-tls",
      sanPolicy: {
        mode: "exact",
        sans: ["app.example.com"],
        allowWildcards: false,
      },
      keyAlgorithm: "rsa",
      keySize: 2048,
      keyRotationPolicy: { rotateOnRenew: true },
      preferredChain: null,
      ca: {
        endpoint: "https://acme-v02.api.letsencrypt.org/directory",
        accountRef: null,
        eabRef: null,
      },
      acme: { kind: "certbot", commandRef: "acme-renew-default" },
      dns: { provider: "cloudflare", zone: "example.com" },
      deploymentTargets: [
        {
          type: "endpoint",
          reference: "host/web",
          certPath: "/etc/ssl/certs/app.pem",
          reloadService: "nginx",
        },
      ],
      target: {
        type: "endpoint",
        reference: "host/web",
        certPath: "/etc/ssl/certs/app.pem",
      },
      verification: { host: "app.example.com", port: 443, requireMatch: true },
    };
  }

  function certificateRow(overrides = {}) {
    return {
      id: MANUAL_RENEWAL_CERT_ID,
      workspace_id: WORKSPACE_A,
      common_name: "app.example.com",
      subject_alt_names: ["app.example.com"],
      not_after: new Date("2026-08-01T00:00:00.000Z"),
      key_mode: "agent-local",
      profile_id: "profile-1",
      profile_name: "web-tls",
      profile_key_mode: "agent-local",
      profile_public_metadata: { renewalProfile: validRenewalProfileSource() },
      ...overrides,
    };
  }

  function createManualRenewalMemoryClient({ certificates = [] } = {}) {
    const jobs = [];
    let nextJob = 1;

    return {
      jobs,
      async query(sql, params = []) {
        const normalizedSql = sql.replace(/\s+/g, " ");

        if (
          normalizedSql.includes("FROM workspaces") &&
          normalizedSql.includes("certops_require_approval_always")
        ) {
          return { rows: [{ certops_require_approval_always: false }] };
        }

        if (normalizedSql.includes("pg_advisory_xact_lock")) {
          return { rows: [{ pg_advisory_xact_lock: "" }] };
        }

        if (normalizedSql.includes("FROM managed_certificates")) {
          const [workspaceId, id] = params;
          const row = certificates.find(
            (cert) => cert.workspace_id === workspaceId && cert.id === id,
          );
          return { rows: row ? [row] : [] };
        }

        if (
          normalizedSql.includes("FROM certificate_jobs") &&
          normalizedSql.includes("operation = ANY($3::text[])") &&
          normalizedSql.includes("FOR UPDATE")
        ) {
          return { rows: [] };
        }

        if (normalizedSql.includes("idempotency_key = $2")) {
          return { rows: [] };
        }

        if (normalizedSql.includes("INSERT INTO certificate_jobs")) {
          const createdAt = new Date(Date.UTC(2026, 5, 30, 0, 0, 0));
          const row = {
            id: `job-${nextJob++}`,
            workspace_id: params[0],
            operation: params[1],
            status: params[2],
            mode: params[3],
            source: params[4],
            executor_kind: params[5],
            requested_by_user_id: params[6],
            requested_by_api_token_id: params[7],
            idempotency_key: params[8],
            subject_type: params[9],
            subject_id: params[10],
            payload: json(params[11]),
            result_metadata: json(params[12]),
            error_code: params[13],
            error_message: params[14],
            assigned_agent_id: params[15],
            required_target_selector: params[16],
            required_dns_provider: params[17],
            required_command_profile: params[18],
            created_at: createdAt,
            updated_at: createdAt,
            queued_at: params[19],
            started_at: params[20],
            completed_at: params[21],
            canceled_at: params[22],
            creation_request_hash: params[23],
          };
          jobs.push(row);
          return { rows: [row] };
        }

        throw new Error(
          `Unhandled query in manual renewal test client: ${normalizedSql}`,
        );
      },
    };
  }

  it("materializes the exact same payload the scheduler would build, when the manual request supplies no override", async () => {
    const { buildRenewalJobPayload } = require(
      path.resolve(
        __dirname,
        "../../apps/api/services/certops/renewalProfile.js",
      ),
    );
    const { manualRenewalJobCreator } = require(
      path.resolve(__dirname, "../../apps/api/services/certops/jobs.js"),
    );
    const certificate = certificateRow();
    const client = createManualRenewalMemoryClient({
      certificates: [certificate],
    });

    const job = await manualRenewalJobCreator({
      certificateId: MANUAL_RENEWAL_CERT_ID,
    })({
      client,
      workspaceId: WORKSPACE_A,
      source: "api",
    });

    const schedulerPayload = buildRenewalJobPayload({ certificate });
    const { mode, ...persistedPayloadWithoutMode } = job.payload;
    assert.equal(mode, "real");
    assert.deepEqual(
      { ...persistedPayloadWithoutMode, reason: schedulerPayload.reason },
      schedulerPayload,
    );
    assert.equal(job.operation, "renew");
    assert.equal(job.subjectType, "managed_certificate");
    assert.equal(job.subjectId, MANUAL_RENEWAL_CERT_ID);
  });

  it("fails at creation time, before any row is inserted, when the certificate has no stored renewal profile", async () => {
    const { CERTOPS_RENEWAL_PROFILE_INCOMPLETE } = require(
      path.resolve(
        __dirname,
        "../../apps/api/services/certops/renewalProfile.js",
      ),
    );
    const { manualRenewalJobCreator } = require(
      path.resolve(__dirname, "../../apps/api/services/certops/jobs.js"),
    );
    const client = createManualRenewalMemoryClient({
      certificates: [certificateRow({ profile_id: null })],
    });

    await assert.rejects(
      () =>
        manualRenewalJobCreator({ certificateId: MANUAL_RENEWAL_CERT_ID })({
          client,
          workspaceId: WORKSPACE_A,
          source: "api",
        }),
      (error) => error?.code === CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
    );
    assert.equal(client.jobs.length, 0);
  });

  it("fails at creation time with a certificate-not-found error for an unknown certificateId", async () => {
    const { CERTOPS_CERTIFICATE_NOT_FOUND, manualRenewalJobCreator } = require(
      path.resolve(__dirname, "../../apps/api/services/certops/jobs.js"),
    );
    const client = createManualRenewalMemoryClient({ certificates: [] });

    await assert.rejects(
      () =>
        manualRenewalJobCreator({ certificateId: MANUAL_RENEWAL_CERT_ID })({
          client,
          workspaceId: WORKSPACE_A,
          source: "api",
        }),
      (error) => error?.code === CERTOPS_CERTIFICATE_NOT_FOUND,
    );
    assert.equal(client.jobs.length, 0);
  });

  it("applies an allowlisted reason override on top of the materialized profile", async () => {
    const { manualRenewalJobCreator } = require(
      path.resolve(__dirname, "../../apps/api/services/certops/jobs.js"),
    );
    const certificate = certificateRow();
    const client = createManualRenewalMemoryClient({
      certificates: [certificate],
    });

    const job = await manualRenewalJobCreator({
      certificateId: MANUAL_RENEWAL_CERT_ID,
    })({
      client,
      workspaceId: WORKSPACE_A,
      source: "api",
      payload: { reason: "customer requested" },
    });

    assert.equal(job.payload.reason, "customer requested");
    assert.equal(job.payload.commandRef, "acme-renew-default");
    assert.equal(job.payload.caEndpoint, certificate.profile_public_metadata.renewalProfile.ca.endpoint);
  });

  it("rejects an override of a field outside the allowlist before touching the certificate row", async () => {
    const { CERTOPS_RENEWAL_OVERRIDE_INVALID } = require(
      path.resolve(
        __dirname,
        "../../apps/api/services/certops/renewalProfile.js",
      ),
    );
    const { manualRenewalJobCreator } = require(
      path.resolve(__dirname, "../../apps/api/services/certops/jobs.js"),
    );
    const client = createManualRenewalMemoryClient({
      certificates: [certificateRow()],
    });

    await assert.rejects(
      () =>
        manualRenewalJobCreator({ certificateId: MANUAL_RENEWAL_CERT_ID })({
          client,
          workspaceId: WORKSPACE_A,
          source: "api",
          payload: { caEndpoint: "https://operator-supplied.example/acme" },
        }),
      (error) => error?.code === CERTOPS_RENEWAL_OVERRIDE_INVALID,
    );
    assert.equal(client.jobs.length, 0);
  });

  it("preflight returns the payload the real creation path would insert, without writing anything", async () => {
    const { preflightManualRenewalJob } = require(
      path.resolve(__dirname, "../../apps/api/services/certops/jobs.js"),
    );
    const certificate = certificateRow();
    const client = createManualRenewalMemoryClient({
      certificates: [certificate],
    });

    const payload = await preflightManualRenewalJob({
      client,
      workspaceId: WORKSPACE_A,
      certificateId: MANUAL_RENEWAL_CERT_ID,
      payload: { reason: "pre-audit" },
    });

    assert.equal(payload.reason, "pre-audit");
    assert.equal(payload.certificateId, MANUAL_RENEWAL_CERT_ID);
    assert.equal(payload.commandRef, "acme-renew-default");
    assert.ok(payload.renewalProfile);
    assert.equal(client.jobs.length, 0);
  });

  it("preflight surfaces an incomplete stored renewal profile with the same code the real run raises", async () => {
    const { CERTOPS_RENEWAL_PROFILE_INCOMPLETE } = require(
      path.resolve(
        __dirname,
        "../../apps/api/services/certops/renewalProfile.js",
      ),
    );
    const { preflightManualRenewalJob } = require(
      path.resolve(__dirname, "../../apps/api/services/certops/jobs.js"),
    );
    const client = createManualRenewalMemoryClient({
      certificates: [certificateRow({ profile_id: null })],
    });

    await assert.rejects(
      () =>
        preflightManualRenewalJob({
          client,
          workspaceId: WORKSPACE_A,
          certificateId: MANUAL_RENEWAL_CERT_ID,
        }),
      (error) => error?.code === CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
    );
    assert.equal(client.jobs.length, 0);
  });

  it("preflight rejects an unknown certificate the same way the real run does", async () => {
    const { CERTOPS_CERTIFICATE_NOT_FOUND, preflightManualRenewalJob } =
      require(
        path.resolve(__dirname, "../../apps/api/services/certops/jobs.js"),
      );
    const client = createManualRenewalMemoryClient({ certificates: [] });

    await assert.rejects(
      () =>
        preflightManualRenewalJob({
          client,
          workspaceId: WORKSPACE_A,
          certificateId: MANUAL_RENEWAL_CERT_ID,
        }),
      (error) => error?.code === CERTOPS_CERTIFICATE_NOT_FOUND,
    );
  });
});

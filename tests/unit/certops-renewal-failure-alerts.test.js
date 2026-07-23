"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  certRenewalFailedAlertKey,
  queueCertRenewalFailedAlert,
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/renewalFailureAlerts.js",
  ),
);
const { ingestResult } = require(
  path.resolve(__dirname, "../../apps/api/services/certops/agentDispatch.js"),
);

const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";

function createMockClient(handler) {
  const state = { queries: [] };
  const client = {
    query: async (text, params) => {
      const sql = typeof text === "string" ? text : text?.text || "";
      state.queries.push({ text: sql, params });
      const trimmed = sql.trim().toUpperCase();
      if (
        trimmed === "BEGIN" ||
        trimmed === "COMMIT" ||
        trimmed === "ROLLBACK" ||
        trimmed.startsWith("SAVEPOINT") ||
        trimmed.startsWith("RELEASE SAVEPOINT") ||
        trimmed.startsWith("ROLLBACK TO SAVEPOINT")
      ) {
        return { rows: [] };
      }
      return handler(sql, params, state);
    },
  };
  return { state, client };
}

// Default happy-path handler: renew job with a managed_certificate subject
// linked to token 77, no existing alert, one admin, email-eligible group.
function happyPathHandler(overrides = {}) {
  return (sql, params) => {
    if (sql.includes("FROM managed_certificates")) {
      return overrides.managedCert !== undefined
        ? overrides.managedCert
        : { rows: [{ id: "cert-1", token_id: 77 }] };
    }
    if (sql.includes("FROM alert_queue WHERE alert_key")) {
      return overrides.existingAlert !== undefined
        ? overrides.existingAlert
        : { rows: [] };
    }
    if (sql.includes("FROM workspace_memberships")) {
      return overrides.membership !== undefined
        ? overrides.membership
        : { rows: [{ user_id: 5 }] };
    }
    if (sql.includes("FROM workspace_settings")) {
      return overrides.settings !== undefined
        ? overrides.settings
        : {
            rows: [
              {
                email_alerts_enabled: true,
                contact_groups: [
                  { id: "g1", email_contact_ids: ["c1"] },
                ],
                default_contact_group_id: "g1",
                webhook_urls: [],
              },
            ],
          };
    }
    if (sql.includes("FROM tokens")) {
      return overrides.token !== undefined
        ? overrides.token
        : { rows: [{ contact_group_id: null }] };
    }
    if (sql.includes("INSERT INTO alert_queue")) {
      return { rows: [], rowCount: 1 };
    }
    if (sql.includes("FROM certificate_jobs")) {
      return overrides.jobFetch !== undefined
        ? overrides.jobFetch
        : { rows: [] };
    }
    throw new Error(`unexpected query: ${sql}`);
  };
}

function renewJob(overrides = {}) {
  return {
    id: 42,
    workspace_id: WORKSPACE_A,
    operation: "renew",
    subject_type: "managed_certificate",
    subject_id: "cert-1",
    ...overrides,
  };
}

describe("renewalFailureAlerts.queueCertRenewalFailedAlert", () => {
  it("queues an alert with the correct alert_key and token anchor", async () => {
    const { state, client } = createMockClient(happyPathHandler());
    const outcome = await queueCertRenewalFailedAlert({
      client,
      job: renewJob(),
      workspaceId: WORKSPACE_A,
      errorCode: "AGENT_RESULT_FAILED",
    });

    assert.equal(outcome.queued, true);
    assert.equal(outcome.alertKey, "cert_renewal_failed:42");
    assert.equal(outcome.tokenId, 77);

    const insert = state.queries.find((q) =>
      q.text.includes("INSERT INTO alert_queue"),
    );
    assert.ok(insert, "alert_queue insert expected");
    // [userId, tokenId, alertKey, thresholdDays, channels]
    assert.equal(insert.params[0], 5);
    assert.equal(insert.params[1], 77);
    assert.equal(insert.params[2], "cert_renewal_failed:42");
    assert.equal(insert.params[3], 0);
    assert.deepEqual(JSON.parse(insert.params[4]), ["email"]);
    assert.match(insert.text, /'pending'/);
    assert.match(insert.text, /CURRENT_DATE/);
  });

  it("dedupes on an existing alert_key", async () => {
    const { state, client } = createMockClient(
      happyPathHandler({ existingAlert: { rows: [{ id: 9 }] } }),
    );
    const outcome = await queueCertRenewalFailedAlert({
      client,
      job: renewJob(),
      workspaceId: WORKSPACE_A,
    });

    assert.equal(outcome.queued, false);
    assert.equal(outcome.reason, "already_queued");
    assert.equal(
      state.queries.some((q) => q.text.includes("INSERT INTO alert_queue")),
      false,
    );
  });

  it("skips cleanly with a reason when the cert has no linked token", async () => {
    const { state, client } = createMockClient(
      happyPathHandler({
        managedCert: { rows: [{ id: "cert-1", token_id: null }] },
      }),
    );
    const outcome = await queueCertRenewalFailedAlert({
      client,
      job: renewJob(),
      workspaceId: WORKSPACE_A,
    });

    assert.equal(outcome.queued, false);
    assert.equal(outcome.reason, "no_linked_token");
    assert.equal(
      state.queries.some((q) => q.text.includes("INSERT INTO alert_queue")),
      false,
    );
  });

  it("skips non-renew operations", async () => {
    const { client } = createMockClient(happyPathHandler());
    const outcome = await queueCertRenewalFailedAlert({
      client,
      job: renewJob({ operation: "deploy" }),
      workspaceId: WORKSPACE_A,
    });
    assert.equal(outcome.queued, false);
    assert.equal(outcome.reason, "not_renew_operation");
  });

  it("skips jobs without a managed_certificate subject", async () => {
    const { client } = createMockClient(happyPathHandler());
    const outcome = await queueCertRenewalFailedAlert({
      client,
      job: renewJob({ subject_type: null, subject_id: null }),
      workspaceId: WORKSPACE_A,
    });
    assert.equal(outcome.queued, false);
    assert.equal(outcome.reason, "no_managed_certificate_subject");
  });

  it("skips when no admin recipient exists", async () => {
    const { client } = createMockClient(
      happyPathHandler({ membership: { rows: [] } }),
    );
    const outcome = await queueCertRenewalFailedAlert({
      client,
      job: renewJob(),
      workspaceId: WORKSPACE_A,
    });
    assert.equal(outcome.queued, false);
    assert.equal(outcome.reason, "no_recipient");
  });

  it("skips when no channels are eligible", async () => {
    const { client } = createMockClient(
      happyPathHandler({
        settings: {
          rows: [
            {
              email_alerts_enabled: false,
              contact_groups: [],
              default_contact_group_id: null,
              webhook_urls: [],
            },
          ],
        },
      }),
    );
    const outcome = await queueCertRenewalFailedAlert({
      client,
      job: renewJob(),
      workspaceId: WORKSPACE_A,
    });
    assert.equal(outcome.queued, false);
    assert.equal(outcome.reason, "no_channels");
  });

  it("builds a stable alert key from the job id", () => {
    assert.equal(certRenewalFailedAlertKey(42), "cert_renewal_failed:42");
  });
});

// --- Emission point 1: agentDispatch.ingestResult ---

function createMockPool(handler) {
  const state = { queries: [], released: false, transaction: [] };
  const client = {
    query: async (text, params) => {
      const sql = typeof text === "string" ? text : text?.text || "";
      state.queries.push({ text: sql, params });
      const trimmed = sql.trim().toUpperCase();
      if (
        trimmed === "BEGIN" ||
        trimmed === "COMMIT" ||
        trimmed === "ROLLBACK"
      ) {
        state.transaction.push(trimmed);
        return { rows: [] };
      }
      if (
        trimmed.startsWith("SAVEPOINT") ||
        trimmed.startsWith("RELEASE SAVEPOINT") ||
        trimmed.startsWith("ROLLBACK TO SAVEPOINT")
      ) {
        return { rows: [] };
      }
      return handler(sql, params, state);
    },
    release: () => {
      state.released = true;
    },
  };
  return { state, client, connect: async () => client, query: client.query };
}

function agentFixture(overrides = {}) {
  return {
    id: "agent-row-1",
    workspaceId: WORKSPACE_A,
    agentId: "agent-01",
    status: "active",
    ...overrides,
  };
}

function lockedJobRow(overrides = {}) {
  return {
    id: 42,
    status: "claimed",
    claimed_by_agent_id: "agent-row-1",
    claim_id: "claim-uuid-1",
    operation: "renew",
    subject_type: "managed_certificate",
    subject_id: "cert-1",
    ...overrides,
  };
}

function resultBody(overrides = {}) {
  return {
    jobId: "42",
    attemptId: "claim-uuid-1",
    claimId: "claim-uuid-1",
    nonce: "n-1",
    status: "failed",
    errorMessage: "renewal timed out",
    ...overrides,
  };
}

function ingestHandler({ jobRow }) {
  return (sql) => {
    if (sql.includes("FOR UPDATE")) return { rows: [jobRow] };
    if (sql.includes("UPDATE certificate_jobs")) {
      return {
        rows: [
          {
            id: jobRow.id,
            status: "failed",
            error_code: "AGENT_RESULT_FAILED",
            completed_at: new Date("2026-07-22T10:00:00Z"),
          },
        ],
      };
    }
    throw new Error(`unexpected query: ${sql}`);
  };
}

describe("agentDispatch.ingestResult renewal-failure emission", () => {
  const silentLogger = { warn() {}, error() {}, info() {}, debug() {} };

  it("emits on terminal renew failure inside the transaction", async () => {
    const jobRow = lockedJobRow();
    const dbPool = createMockPool(ingestHandler({ jobRow }));
    const calls = [];

    const result = await ingestResult({
      dbPool,
      agent: agentFixture(),
      body: resultBody(),
      deps: {
        consumeNonce: async () => ({ consumed: true }),
        queueCertRenewalFailedAlert: async (options) => {
          calls.push(options);
          return { queued: true, alertKey: "cert_renewal_failed:42" };
        },
        logger: silentLogger,
      },
    });

    assert.equal(result.ok, true);
    assert.equal(result.status, "failed");
    assert.equal(calls.length, 1);
    assert.equal(calls[0].workspaceId, WORKSPACE_A);
    assert.equal(calls[0].job.id, 42);
    assert.equal(calls[0].job.operation, "renew");
    assert.equal(calls[0].errorCode, "AGENT_RESULT_FAILED");
    // Same transaction: the injected client is the pool's tx client.
    assert.ok(calls[0].client, "transaction client expected");
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "COMMIT"]);
  });

  it("does not emit on success", async () => {
    const jobRow = lockedJobRow();
    const dbPool = createMockPool((sql) => {
      if (sql.includes("FOR UPDATE")) return { rows: [jobRow] };
      if (sql.includes("UPDATE certificate_jobs")) {
        return {
          rows: [
            {
              id: 42,
              status: "succeeded",
              error_code: null,
              completed_at: new Date(),
            },
          ],
        };
      }
      throw new Error(`unexpected query: ${sql}`);
    });
    const calls = [];

    const result = await ingestResult({
      dbPool,
      agent: agentFixture(),
      body: resultBody({ status: "succeeded", errorMessage: undefined }),
      deps: {
        consumeNonce: async () => ({ consumed: true }),
        queueCertRenewalFailedAlert: async (options) => {
          calls.push(options);
          return { queued: true };
        },
        logger: silentLogger,
      },
    });

    assert.equal(result.status, "succeeded");
    assert.equal(calls.length, 0);
  });

  it("does not emit for deploy jobs", async () => {
    const jobRow = lockedJobRow({ operation: "deploy" });
    const dbPool = createMockPool(ingestHandler({ jobRow }));
    const calls = [];

    const result = await ingestResult({
      dbPool,
      agent: agentFixture(),
      body: resultBody(),
      deps: {
        consumeNonce: async () => ({ consumed: true }),
        queueCertRenewalFailedAlert: async (options) => {
          calls.push(options);
          return { queued: true };
        },
        logger: silentLogger,
      },
    });

    assert.equal(result.status, "failed");
    assert.equal(calls.length, 0);
  });

  it("a throwing alert dep does not break ingestion", async () => {
    const jobRow = lockedJobRow();
    const dbPool = createMockPool(ingestHandler({ jobRow }));
    const warnings = [];

    const result = await ingestResult({
      dbPool,
      agent: agentFixture(),
      body: resultBody(),
      deps: {
        consumeNonce: async () => ({ consumed: true }),
        queueCertRenewalFailedAlert: async () => {
          throw new Error("alert pipeline down");
        },
        logger: {
          ...silentLogger,
          warn: (msg, meta) => warnings.push({ msg, meta }),
        },
      },
    });

    assert.equal(result.ok, true);
    assert.equal(result.status, "failed");
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "COMMIT"]);
    assert.ok(
      warnings.some((w) => w.msg === "certops-renewal-failed-alert-error"),
    );
    // The savepoint protected the transaction.
    const savepointRollback = dbPool.state.queries.find((q) =>
      q.text.trim().toUpperCase().startsWith("ROLLBACK TO SAVEPOINT"),
    );
    assert.ok(savepointRollback, "savepoint rollback expected");
  });
});

// --- Emission point 2: certops-worker lease reaper ---

const { pathToFileURL } = require("node:url");
const workerUrl = pathToFileURL(
  path.join(__dirname, "..", "..", "apps", "worker", "src", "certops-worker.js"),
).href;

function normalizeSql(sql) {
  return String(sql).replace(/\s+/g, " ").trim();
}

function createReaperClient(rows) {
  const queries = [];
  return {
    queries,
    async query(sql, params = []) {
      const normalized = normalizeSql(sql);
      queries.push({ sql: normalized, params });
      if (
        normalized === "BEGIN" ||
        normalized === "COMMIT" ||
        normalized === "ROLLBACK"
      ) {
        return { rows: [] };
      }
      if (normalized.startsWith("SELECT cj.id, cj.workspace_id")) {
        return { rows };
      }
      return { rows: [] };
    },
  };
}

describe("certops-worker lease reaper renewal-failure emission", () => {
  const silentLogger = { info() {}, warn() {}, error() {}, debug() {} };

  it("emits for terminal agent_offline renew failures only", async () => {
    const worker = await import(workerUrl);
    const client = createReaperClient([
      {
        id: "job-renew",
        workspace_id: "ws-1",
        status: "running",
        attempt_count: 3,
        max_attempts: 3,
        operation: "renew",
        subject_type: "managed_certificate",
        subject_id: "cert-1",
        agent_alive: false,
        past_hard_grace: false,
      },
      {
        id: "job-deploy",
        workspace_id: "ws-1",
        status: "running",
        attempt_count: 3,
        max_attempts: 3,
        operation: "deploy",
        subject_type: "managed_certificate",
        subject_id: "cert-2",
        agent_alive: false,
        past_hard_grace: false,
      },
      {
        id: "job-requeue",
        workspace_id: "ws-1",
        status: "claimed",
        attempt_count: 0,
        max_attempts: 3,
        operation: "renew",
        subject_type: "managed_certificate",
        subject_id: "cert-3",
        agent_alive: false,
        past_hard_grace: false,
      },
    ]);
    const calls = [];

    const summary = await worker.reapExpiredLeases({
      client,
      log: silentLogger,
      queueRenewalFailedAlert: async (options) => {
        calls.push(options);
        return { queued: true, alertKey: `cert_renewal_failed:${options.job.id}` };
      },
    });

    assert.deepStrictEqual(summary, {
      scanned: 3,
      requeued: 1,
      failed: 2,
      deferred: 0,
    });
    // Only the terminally failed renew job emits; deploy and requeued do not.
    assert.equal(calls.length, 1);
    assert.equal(calls[0].job.id, "job-renew");
    assert.equal(calls[0].workspaceId, "ws-1");
    assert.equal(calls[0].errorCode, "agent_offline");
    assert.strictEqual(client.queries.at(-1).sql, "COMMIT");
  });

  it("a throwing alert dep does not break the reaper", async () => {
    const worker = await import(workerUrl);
    const client = createReaperClient([
      {
        id: "job-renew",
        workspace_id: "ws-1",
        status: "running",
        attempt_count: 3,
        max_attempts: 3,
        operation: "renew",
        subject_type: "managed_certificate",
        subject_id: "cert-1",
        agent_alive: false,
        past_hard_grace: false,
      },
    ]);
    const warnings = [];

    const summary = await worker.reapExpiredLeases({
      client,
      log: {
        ...silentLogger,
        warn: (msg, meta) => warnings.push({ msg, meta }),
      },
      queueRenewalFailedAlert: async () => {
        throw new Error("alert pipeline down");
      },
    });

    assert.deepStrictEqual(summary, {
      scanned: 1,
      requeued: 0,
      failed: 1,
      deferred: 0,
    });
    assert.strictEqual(client.queries.at(-1).sql, "COMMIT");
    assert.ok(
      warnings.some((w) => w.msg === "certops-renewal-failed-alert-error"),
    );
    const savepointRollback = client.queries.find((q) =>
      q.sql.startsWith("ROLLBACK TO SAVEPOINT"),
    );
    assert.ok(savepointRollback, "savepoint rollback expected");
  });

  it("logs a skip warning when the alert is not queued", async () => {
    const worker = await import(workerUrl);
    const client = createReaperClient([
      {
        id: "job-renew",
        workspace_id: "ws-1",
        status: "running",
        attempt_count: 3,
        max_attempts: 3,
        operation: "renew",
        subject_type: "managed_certificate",
        subject_id: "cert-1",
        agent_alive: false,
        past_hard_grace: false,
      },
    ]);
    const warnings = [];

    await worker.reapExpiredLeases({
      client,
      log: {
        ...silentLogger,
        warn: (msg, meta) => warnings.push({ msg, meta }),
      },
      queueRenewalFailedAlert: async () => ({
        queued: false,
        reason: "no_linked_token",
      }),
    });

    const skip = warnings.find(
      (w) => w.msg === "certops-renewal-failed-alert-skipped",
    );
    assert.ok(skip, "skip warning expected");
    assert.equal(skip.meta.reason, "no_linked_token");
  });
});

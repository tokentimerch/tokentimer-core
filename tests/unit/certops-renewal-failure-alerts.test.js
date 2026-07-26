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

  it("skips operations that do not alert", async () => {
    const { client } = createMockClient(happyPathHandler());
    const outcome = await queueCertRenewalFailedAlert({
      client,
      job: renewJob({ operation: "deploy" }),
      workspaceId: WORKSPACE_A,
    });
    assert.equal(outcome.queued, false);
    assert.equal(outcome.reason, "operation_not_alerting");
  });

  it("skips issue jobs: an issuance failure has no certificate to alert on", async () => {
    const { client } = createMockClient(happyPathHandler());
    const outcome = await queueCertRenewalFailedAlert({
      client,
      job: renewJob({ operation: "issue" }),
      workspaceId: WORKSPACE_A,
    });
    assert.equal(outcome.queued, false);
    assert.equal(outcome.reason, "operation_not_alerting");
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

// Shared branch for the provisioning reconciliation lookup ingestResult now
// performs on success. Returns "nothing to reconcile" so these tests stay
// focused on alert emission; the reconciliation behaviour itself is covered
// in certops-issuance.test.js.
function reconciliationNoopBranch(sql) {
  if (sql.includes("FROM managed_certificates") && sql.includes("FOR UPDATE")) {
    return { rows: [] };
  }
  if (sql.includes("FROM certificate_evidence")) return { rows: [] };
  if (sql.includes("UPDATE managed_certificates")) return { rows: [] };
  return null;
}

function ingestHandler({ jobRow }) {
  return (sql) => {
    const reconciliation = reconciliationNoopBranch(sql);
    if (reconciliation) return reconciliation;
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

describe("agentDispatch.ingestResult outbox enqueue", () => {
  const silentLogger = { warn() {}, error() {}, info() {}, debug() {} };

  it("records the alert intent in the outbox inside the transaction", async () => {
    const jobRow = lockedJobRow();
    const dbPool = createMockPool(ingestHandler({ jobRow }));
    const events = [];

    const result = await ingestResult({
      dbPool,
      agent: agentFixture(),
      body: resultBody(),
      deps: {
        consumeNonce: async () => ({ consumed: true }),
        enqueueOutboxEvent: async (options) => {
          events.push(options);
          return { enqueued: true, id: "outbox-1" };
        },
        logger: silentLogger,
      },
    });

    assert.equal(result.ok, true);
    assert.equal(result.status, "failed");
    assert.equal(events.length, 1);
    assert.equal(events[0].eventType, "renewal_alert_requested");
    assert.equal(events[0].workspaceId, WORKSPACE_A);
    assert.equal(events[0].dedupeKey, "42");
    assert.equal(events[0].payload.operation, "renew");
    assert.equal(events[0].payload.jobStatus, "failed");
    assert.equal(events[0].payload.origin, "agent_result");
    assert.equal(events[0].payload.errorCode, "AGENT_RESULT_FAILED");
    // Same transaction: the enqueue gets the pool's tx client, so the terminal
    // status and the intent commit together.
    assert.ok(events[0].client, "transaction client expected");
    assert.deepEqual(dbPool.state.transaction, ["BEGIN", "COMMIT"]);
  });

  it("does not enqueue on success", async () => {
    const jobRow = lockedJobRow();
    const dbPool = createMockPool((sql) => {
      const reconciliation = reconciliationNoopBranch(sql);
      if (reconciliation) return reconciliation;
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
    const events = [];

    const result = await ingestResult({
      dbPool,
      agent: agentFixture(),
      body: resultBody({ status: "succeeded", errorMessage: undefined }),
      deps: {
        consumeNonce: async () => ({ consumed: true }),
        enqueueOutboxEvent: async (options) => {
          events.push(options);
          return { enqueued: true };
        },
        logger: silentLogger,
      },
    });

    assert.equal(result.status, "succeeded");
    assert.equal(events.length, 0);
  });

  it("does not enqueue for deploy jobs", async () => {
    const jobRow = lockedJobRow({ operation: "deploy" });
    const dbPool = createMockPool(ingestHandler({ jobRow }));
    const events = [];

    const result = await ingestResult({
      dbPool,
      agent: agentFixture(),
      body: resultBody(),
      deps: {
        consumeNonce: async () => ({ consumed: true }),
        enqueueOutboxEvent: async (options) => {
          events.push(options);
          return { enqueued: true };
        },
        logger: silentLogger,
      },
    });

    assert.equal(result.status, "failed");
    assert.equal(events.length, 0);
  });

  it("does not enqueue for a failed issue job", async () => {
    const jobRow = lockedJobRow({ operation: "issue" });
    const dbPool = createMockPool(ingestHandler({ jobRow }));
    const events = [];

    await ingestResult({
      dbPool,
      agent: agentFixture(),
      body: resultBody(),
      deps: {
        consumeNonce: async () => ({ consumed: true }),
        enqueueOutboxEvent: async (options) => {
          events.push(options);
          return { enqueued: true };
        },
        logger: silentLogger,
      },
    });

    assert.equal(events.length, 0);
  });

  it("fails ingestion when the outbox enqueue fails, rather than losing the intent", async () => {
    const jobRow = lockedJobRow();
    const dbPool = createMockPool(ingestHandler({ jobRow }));

    await assert.rejects(
      ingestResult({
        dbPool,
        agent: agentFixture(),
        body: resultBody(),
        deps: {
          consumeNonce: async () => ({ consumed: true }),
          enqueueOutboxEvent: async () => {
            throw new Error("outbox insert failed");
          },
          logger: silentLogger,
        },
      }),
      /outbox insert failed/,
    );

    // The whole terminal transition rolls back. "Ingestion never fails" and
    // "the intent is durable" cannot both hold, and durability is the one that
    // an operator depends on.
    assert.ok(dbPool.state.transaction.includes("ROLLBACK"));
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

describe("certops-worker lease reaper outbox enqueue", () => {
  const silentLogger = { info() {}, warn() {}, error() {}, debug() {} };

  it("enqueues for terminal renew failures only", async () => {
    const worker = await import(workerUrl);
    const client = createReaperClient([
      {
        id: "job-renew",
        workspace_id: "ws-1",
        // status 'claimed' with lease_renewed_at unset means no side effects
        // were ever possible; with retries exhausted and the agent gone,
        // this is the only path that terminally fails as agent_offline
        // (a 'running' job is always effects_unknown; see reapExpiredLeases).
        status: "claimed",
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
    const events = [];

    const summary = await worker.reapExpiredLeases({
      client,
      log: silentLogger,
      recordOutboxEvent: async (options) => {
        events.push(options);
        return { enqueued: true };
      },
    });

    assert.deepStrictEqual(summary, {
      scanned: 3,
      requeued: 1,
      failed: 2,
      deferred: 0,
    });
    // Only the terminally failed renew job enqueues; deploy and requeued do not.
    assert.equal(events.length, 1);
    assert.equal(events[0].dedupeKey, "job-renew");
    assert.equal(events[0].workspaceId, "ws-1");
    assert.equal(events[0].payload.errorCode, "agent_offline");
    assert.equal(events[0].payload.origin, "lease_reaper");
    assert.strictEqual(client.queries.at(-1).sql, "COMMIT");
  });

  it("marks an orphaned renew high priority", async () => {
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
    const events = [];

    await worker.reapExpiredLeases({
      client,
      log: silentLogger,
      recordOutboxEvent: async (options) => {
        events.push(options);
        return { enqueued: true };
      },
    });

    assert.equal(events.length, 1);
    assert.equal(events[0].payload.jobStatus, "orphaned_unknown_effect");
    assert.equal(events[0].payload.priority, "high");
  });
});

// --- Classification: origin, not status alone ---

const {
  classifyTerminalTransition,
  TRANSITION_ORIGINS,
  RENEWAL_ALERTING_OPERATIONS,
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/renewalAlertPolicy.js",
  ),
);

describe("renewalAlertPolicy.classifyTerminalTransition", () => {
  it("excludes issue from the alerting set so caller and resolver agree", () => {
    assert.equal(RENEWAL_ALERTING_OPERATIONS.has("renew"), true);
    assert.equal(RENEWAL_ALERTING_OPERATIONS.has("issue"), false);
  });

  const cases = [
    // [description, operation, status, origin, expectedAlertWorthy]
    ["agent execution failure", "renew", "failed", TRANSITION_ORIGINS.AGENT_RESULT, true],
    ["agent policy rejection", "renew", "rejected", TRANSITION_ORIGINS.AGENT_RESULT, true],
    ["human approval rejection", "renew", "rejected", TRANSITION_ORIGINS.APPROVAL_REJECTION, false],
    ["human cancellation", "renew", "cancelled", TRANSITION_ORIGINS.OPERATOR_CANCEL, false],
    ["agent blocked", "renew", "blocked", TRANSITION_ORIGINS.AGENT_RESULT, true],
    ["lease expiry orphan", "renew", "orphaned_unknown_effect", TRANSITION_ORIGINS.LEASE_REAPER, true],
    ["stale agent fencing", "renew", "orphaned_unknown_effect", TRANSITION_ORIGINS.STALE_AGENT, true],
    ["forced retirement", "renew", "cancelled", TRANSITION_ORIGINS.FORCED_RETIREMENT, true],
    ["dry run", "renew", "dry_run_complete", TRANSITION_ORIGINS.AGENT_RESULT, false],
    ["success", "renew", "succeeded", TRANSITION_ORIGINS.AGENT_RESULT, false],
    ["issue failure", "issue", "failed", TRANSITION_ORIGINS.AGENT_RESULT, false],
    ["deploy failure", "deploy", "failed", TRANSITION_ORIGINS.AGENT_RESULT, false],
  ];

  for (const [label, operation, status, origin, expected] of cases) {
    it(`${label}: alertWorthy=${expected}`, () => {
      const outcome = classifyTerminalTransition({ operation, status, origin });
      assert.equal(outcome.alertWorthy, expected, label);
      // Every decision explains itself; a silent skip is the bug this replaced.
      assert.ok(
        typeof outcome.reason === "string" && outcome.reason.length > 0,
        "reason expected",
      );
    });
  }

  it("distinguishes the same status by origin", () => {
    const byAgent = classifyTerminalTransition({
      operation: "renew",
      status: "rejected",
      origin: TRANSITION_ORIGINS.AGENT_RESULT,
    });
    const byHuman = classifyTerminalTransition({
      operation: "renew",
      status: "rejected",
      origin: TRANSITION_ORIGINS.APPROVAL_REJECTION,
    });
    assert.equal(byAgent.alertWorthy, true);
    assert.equal(byHuman.alertWorthy, false);
    assert.notEqual(byAgent.reason, byHuman.reason);
  });
});

// --- Outbox drain ---

function createDrainPool(rows, { alertThrows = false, alertOutcome = null } = {}) {
  const queries = [];
  return {
    queries,
    async query(sql, params = []) {
      const normalized = normalizeSql(sql);
      queries.push({ sql: normalized, params });
      if (normalized.startsWith("WITH due AS")) return { rows };
      return { rows: [], rowCount: 1 };
    },
    alertThrows,
    alertOutcome,
  };
}

function outboxRow(overrides = {}) {
  return {
    id: "outbox-1",
    workspace_id: "ws-1",
    event_type: "renewal_alert_requested",
    dedupe_key: "job-1",
    payload: { jobId: "job-1", errorCode: "AGENT_RESULT_FAILED" },
    attempt_count: 1,
    max_attempts: 5,
    ...overrides,
  };
}

describe("certops-worker outbox drain", () => {
  const silentLogger = { info() {}, warn() {}, error() {}, debug() {} };

  it("resolves a queued alert and marks the event succeeded", async () => {
    const worker = await import(workerUrl);
    const dbPool = createDrainPool([outboxRow()]);

    const summary = await worker.drainCertOpsOutbox({
      dbPool,
      log: silentLogger,
      alertResolver: async () => ({ queued: true, alertKey: "k" }),
    });

    assert.equal(summary.scanned, 1);
    assert.equal(summary.succeeded, 1);
    const update = dbPool.queries.find(
      (q) => q.sql.includes("UPDATE certops_outbox") && q.params[0] === "succeeded",
    );
    assert.ok(update, "terminal succeeded update expected");
    // Owner-scoped: the terminal write is conditional on this run's claim id.
    assert.match(update.sql, /claim_id = \$4::uuid/);
  });

  it("marks a structural skip terminal, preserving the reason", async () => {
    const worker = await import(workerUrl);
    const dbPool = createDrainPool([outboxRow()]);

    const summary = await worker.drainCertOpsOutbox({
      dbPool,
      log: silentLogger,
      alertResolver: async () => ({ queued: false, reason: "no_linked_token" }),
    });

    assert.equal(summary.skipped, 1);
    const update = dbPool.queries.find(
      (q) => q.sql.includes("UPDATE certops_outbox") && q.params[0] === "skipped",
    );
    assert.ok(update, "terminal skipped update expected");
    assert.equal(update.params[1], "no_linked_token");
  });

  it("retries a thrown error with backoff and keeps the row pending", async () => {
    const worker = await import(workerUrl);
    const dbPool = createDrainPool([outboxRow({ attempt_count: 1 })]);

    const summary = await worker.drainCertOpsOutbox({
      dbPool,
      log: silentLogger,
      alertResolver: async () => {
        throw new Error("alert pipeline down");
      },
    });

    assert.equal(summary.retried, 1);
    assert.equal(summary.failed, 0);
    const update = dbPool.queries.find((q) =>
      q.sql.includes("SET status = CASE WHEN"),
    );
    assert.ok(update, "retry update expected");
    assert.equal(update.params[0], false, "not exhausted yet");
    assert.match(String(update.params[1]), /alert pipeline down/);
  });

  it("parks the row as failed once attempts are exhausted", async () => {
    const worker = await import(workerUrl);
    const dbPool = createDrainPool([
      outboxRow({ attempt_count: 5, max_attempts: 5 }),
    ]);

    const summary = await worker.drainCertOpsOutbox({
      dbPool,
      log: silentLogger,
      alertResolver: async () => {
        throw new Error("still down");
      },
    });

    assert.equal(summary.failed, 1);
    const update = dbPool.queries.find((q) =>
      q.sql.includes("SET status = CASE WHEN"),
    );
    assert.equal(update.params[0], true, "exhausted");
  });

  it("defers an event type whose handler is not implemented yet", async () => {
    const worker = await import(workerUrl);
    const dbPool = createDrainPool([
      outboxRow({ event_type: "profile_derivation_requested" }),
    ]);

    const summary = await worker.drainCertOpsOutbox({
      dbPool,
      log: silentLogger,
      alertResolver: async () => ({ queued: true }),
    });

    // Deferred, not dropped: recording the intent is pointless if the drain
    // silently discards the event types it cannot handle yet.
    assert.equal(summary.retried, 1);
    assert.equal(summary.skipped, 0);
    assert.equal(summary.succeeded, 0);
  });
});

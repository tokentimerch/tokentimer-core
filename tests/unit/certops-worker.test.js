"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

const workerUrl = pathToFileURL(
  path.join(
    __dirname,
    "..",
    "..",
    "apps",
    "worker",
    "src",
    "certops-worker.js",
  ),
).href;

const silentLogger = {
  info() {},
  warn() {},
  error() {},
  debug() {},
};

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
      if (normalized === "BEGIN" || normalized === "COMMIT" || normalized === "ROLLBACK") {
        return { rows: [] };
      }
      if (normalized.startsWith("SELECT cj.id, cj.workspace_id")) {
        return { rows };
      }
      return { rows: [] };
    },
  };
}

describe("certops maintenance worker", () => {
  it("resolves the agent offline threshold from env with a 10 minute default", async () => {
    const worker = await import(workerUrl);

    assert.strictEqual(worker.resolveAgentOfflineAfterMs({}), 600000);
    assert.strictEqual(
      worker.resolveAgentOfflineAfterMs({ CERTOPS_AGENT_OFFLINE_AFTER_MS: "" }),
      600000,
    );
    assert.strictEqual(
      worker.resolveAgentOfflineAfterMs({
        CERTOPS_AGENT_OFFLINE_AFTER_MS: "30000",
      }),
      30000,
    );
    assert.strictEqual(
      worker.resolveAgentOfflineAfterMs({
        CERTOPS_AGENT_OFFLINE_AFTER_MS: "-5",
      }),
      600000,
    );
    assert.strictEqual(
      worker.resolveAgentOfflineAfterMs({
        CERTOPS_AGENT_OFFLINE_AFTER_MS: "abc",
      }),
      600000,
    );
  });

  it("computes exponential backoff capped at 30 minutes", async () => {
    const worker = await import(workerUrl);

    assert.strictEqual(worker.computeBackoffMs(1), 60000);
    assert.strictEqual(worker.computeBackoffMs(2), 120000);
    assert.strictEqual(worker.computeBackoffMs(3), 240000);
    assert.strictEqual(worker.computeBackoffMs(20), 1800000);
    assert.strictEqual(worker.computeBackoffMs(0), 60000);
  });

  it("selects expired leases with FOR UPDATE SKIP LOCKED inside a transaction", async () => {
    const worker = await import(workerUrl);
    const client = createReaperClient([]);

    const summary = await worker.reapExpiredLeases({
      client,
      log: silentLogger,
    });

    assert.deepStrictEqual(summary, {
      scanned: 0,
      requeued: 0,
      failed: 0,
      deferred: 0,
    });
    assert.strictEqual(client.queries[0].sql, "BEGIN");
    const select = client.queries[1].sql;
    assert.match(select, /cj\.status IN \('claimed', 'running'\)/);
    assert.match(select, /cj\.executor_kind = 'agent'/);
    assert.match(select, /cj\.lease_expires_at < NOW\(\)/);
    assert.match(select, /LEFT JOIN certops_agents ca/);
    assert.match(select, /AS agent_alive/);
    assert.match(select, /AS past_hard_grace/);
    assert.match(select, /FOR UPDATE OF cj SKIP LOCKED/);
    assert.strictEqual(client.queries.at(-1).sql, "COMMIT");
  });

  it("requeues claimed jobs with retry budget when the agent is gone", async () => {
    const worker = await import(workerUrl);
    const client = createReaperClient([
      {
        id: "job-1",
        workspace_id: "ws-1",
        status: "claimed",
        attempt_count: 1,
        max_attempts: 3,
        lease_renewed_at: null,
        agent_alive: false,
        past_hard_grace: false,
      },
    ]);

    const summary = await worker.reapExpiredLeases({
      client,
      log: silentLogger,
    });

    assert.deepStrictEqual(summary, {
      scanned: 1,
      requeued: 1,
      failed: 0,
      deferred: 0,
    });

    const update = client.queries.find((q) =>
      q.sql.startsWith("UPDATE certificate_jobs SET status = 'pending'"),
    );
    assert.ok(update, "expected a requeue UPDATE");
    assert.match(update.sql, /claimed_by_agent_id = NULL/);
    assert.match(update.sql, /claim_id = NULL/);
    assert.match(update.sql, /lease_expires_at = NULL/);
    // attempt_count is NOT incremented here: the claim path already
    // counted this dispatch attempt.
    assert.doesNotMatch(update.sql, /attempt_count = attempt_count \+ 1/);
    assert.match(update.sql, /next_attempt_at = NOW\(\)/);
    assert.deepStrictEqual(update.params, ["job-1", "60000"]);

    const logInsert = client.queries.find((q) =>
      q.sql.startsWith("INSERT INTO certificate_job_log"),
    );
    assert.ok(logInsert, "expected a job log insert");
    assert.strictEqual(logInsert.params[2], "job.status_updated");
    assert.strictEqual(logInsert.params[3], "pending");
    const metadata = JSON.parse(logInsert.params[5]);
    assert.strictEqual(metadata.outcome, "requeued");
    assert.strictEqual(metadata.attemptCount, 1);
    assert.strictEqual(metadata.backoffMs, 60000);
  });

  it("defers claimed jobs whose agent is still alive within the hard grace", async () => {
    const worker = await import(workerUrl);
    const client = createReaperClient([
      {
        id: "job-alive",
        workspace_id: "ws-1",
        status: "claimed",
        attempt_count: 1,
        max_attempts: 3,
        lease_renewed_at: null,
        agent_alive: true,
        past_hard_grace: false,
      },
    ]);

    const summary = await worker.reapExpiredLeases({
      client,
      log: silentLogger,
    });

    assert.deepStrictEqual(summary, {
      scanned: 1,
      requeued: 0,
      failed: 0,
      deferred: 1,
    });
    // Deferred rows are left completely untouched this sweep.
    assert.ok(
      !client.queries.some((q) => q.sql.startsWith("UPDATE certificate_jobs")),
      "a deferred job must not be updated",
    );
  });

  it("requeues never-renewed claimed jobs past hard grace even if agent is alive (B6)", async () => {
    const worker = await import(workerUrl);
    const client = createReaperClient([
      {
        id: "job-hung-never-renewed",
        workspace_id: "ws-1",
        status: "claimed",
        attempt_count: 1,
        max_attempts: 3,
        lease_renewed_at: null,
        agent_alive: true,
        past_hard_grace: true,
      },
    ]);

    const summary = await worker.reapExpiredLeases({
      client,
      log: silentLogger,
    });

    assert.deepStrictEqual(summary, {
      scanned: 1,
      requeued: 1,
      failed: 0,
      deferred: 0,
    });
    const update = client.queries.find((q) =>
      q.sql.startsWith("UPDATE certificate_jobs SET status = 'pending'"),
    );
    assert.ok(update, "never-renewed past grace must requeue safely");
  });

  it("marks renewed expired leases as orphaned_unknown_effect with reconciliation fields", async () => {
    const worker = await import(workerUrl);
    const client = createReaperClient([
      {
        id: "job-renewed",
        workspace_id: "ws-1",
        status: "running",
        attempt_count: 1,
        max_attempts: 3,
        lease_renewed_at: new Date("2026-07-22T10:00:00.000Z"),
        agent_alive: false,
        past_hard_grace: false,
      },
    ]);
    const auditEvents = [];
    const auditWriter = async (event) => {
      auditEvents.push(event);
    };

    const summary = await worker.reapExpiredLeases({
      client,
      log: silentLogger,
      auditWriter,
    });

    assert.deepStrictEqual(summary, {
      scanned: 1,
      requeued: 0,
      failed: 1,
      deferred: 0,
    });
    const update = client.queries.find((q) =>
      q.sql.startsWith(
        "UPDATE certificate_jobs SET status = 'orphaned_unknown_effect'",
      ),
    );
    assert.ok(update, "expected an orphaned_unknown_effect UPDATE");
    assert.match(update.sql, /needs_operator_reconciliation = TRUE/);
    assert.match(update.sql, /reconciliation_reason = \$3/);
    assert.deepStrictEqual(update.params, [
      "job-renewed",
      "effects_unknown",
      "lease_expired_after_side_effect_window_agent_unresponsive",
    ]);

    const logInsert = client.queries.find((q) =>
      q.sql.startsWith("INSERT INTO certificate_job_log"),
    );
    assert.strictEqual(logInsert.params[3], "orphaned_unknown_effect");
    const metadata = JSON.parse(logInsert.params[5]);
    assert.strictEqual(metadata.outcome, "orphaned_unknown_effect");
    assert.strictEqual(
      metadata.reconciliationReason,
      "lease_expired_after_side_effect_window_agent_unresponsive",
    );

    // The reconciliation runbook's Step 1 relies on this: without it, a
    // lease-reaped job is invisible to an audit-log-based search even though
    // the runbook claims "every terminal non-success writes one of these".
    assert.strictEqual(auditEvents.length, 1, "expected one CERTOPS_JOB_FAILED audit event");
    assert.strictEqual(auditEvents[0].action, "CERTOPS_JOB_FAILED");
    assert.strictEqual(auditEvents[0].workspaceId, "ws-1");
    assert.strictEqual(auditEvents[0].metadata.jobId, "job-renewed");
    assert.strictEqual(auditEvents[0].metadata.jobStatus, "orphaned_unknown_effect");
    assert.strictEqual(auditEvents[0].metadata.source, "lease-reaper");
    assert.strictEqual(auditEvents[0].metadata.needsOperatorReconciliation, true);
    assert.strictEqual(
      auditEvents[0].metadata.reconciliationReason,
      "lease_expired_after_side_effect_window_agent_unresponsive",
    );
  });

  it("fails claimed jobs without retry budget as agent_offline", async () => {
    const worker = await import(workerUrl);
    const client = createReaperClient([
      {
        id: "job-2",
        workspace_id: "ws-1",
        status: "claimed",
        attempt_count: 3,
        max_attempts: 3,
        lease_renewed_at: null,
        agent_alive: false,
        past_hard_grace: false,
      },
    ]);
    const auditEvents = [];
    const auditWriter = async (event) => {
      auditEvents.push(event);
    };

    const summary = await worker.reapExpiredLeases({
      client,
      log: silentLogger,
      auditWriter,
    });

    assert.deepStrictEqual(summary, {
      scanned: 1,
      requeued: 0,
      failed: 1,
      deferred: 0,
    });

    const update = client.queries.find((q) =>
      q.sql.startsWith("UPDATE certificate_jobs SET status = 'failed'"),
    );
    assert.ok(update, "expected a fail UPDATE");
    assert.match(update.sql, /error_code = \$2/);
    assert.deepStrictEqual(update.params, ["job-2", "agent_offline"]);

    const logInsert = client.queries.find((q) =>
      q.sql.startsWith("INSERT INTO certificate_job_log"),
    );
    assert.strictEqual(logInsert.params[2], "job.failed");
    assert.strictEqual(logInsert.params[3], "failed");
    const metadata = JSON.parse(logInsert.params[5]);
    assert.strictEqual(metadata.errorCode, "agent_offline");

    assert.strictEqual(auditEvents.length, 1, "expected one CERTOPS_JOB_FAILED audit event");
    assert.strictEqual(auditEvents[0].action, "CERTOPS_JOB_FAILED");
    assert.strictEqual(auditEvents[0].metadata.jobStatus, "failed");
    assert.strictEqual(auditEvents[0].metadata.errorCode, "agent_offline");
    assert.strictEqual(auditEvents[0].metadata.needsOperatorReconciliation, false);
  });

  it("never requeues running jobs; marks them orphaned_unknown_effect instead", async () => {
    const worker = await import(workerUrl);
    const client = createReaperClient([
      {
        id: "job-3",
        workspace_id: "ws-1",
        status: "running",
        attempt_count: 0,
        max_attempts: 3,
        lease_renewed_at: null,
        agent_alive: false,
        past_hard_grace: false,
      },
    ]);

    const summary = await worker.reapExpiredLeases({
      client,
      log: silentLogger,
    });

    assert.deepStrictEqual(summary, {
      scanned: 1,
      requeued: 0,
      failed: 1,
      deferred: 0,
    });
    const update = client.queries.find((q) =>
      q.sql.startsWith(
        "UPDATE certificate_jobs SET status = 'orphaned_unknown_effect'",
      ),
    );
    assert.ok(update, "running job must orphan, not requeue");
    assert.deepStrictEqual(update.params, [
      "job-3",
      "effects_unknown",
      "lease_expired_after_side_effect_window_agent_unresponsive",
    ]);
  });

  it("regression: still defers alive agents within hard grace unchanged", async () => {
    const worker = await import(workerUrl);
    const client = createReaperClient([
      {
        id: "job-alive-regression",
        workspace_id: "ws-1",
        status: "running",
        attempt_count: 1,
        max_attempts: 3,
        lease_renewed_at: new Date("2026-07-22T10:00:00.000Z"),
        agent_alive: true,
        past_hard_grace: false,
      },
    ]);

    const summary = await worker.reapExpiredLeases({
      client,
      log: silentLogger,
    });

    assert.deepStrictEqual(summary, {
      scanned: 1,
      requeued: 0,
      failed: 0,
      deferred: 1,
    });
    assert.ok(
      !client.queries.some((q) => q.sql.startsWith("UPDATE certificate_jobs")),
      "grace-deferred renewed jobs must remain untouched",
    );
  });

  it("regression: still fails exhausted never-renewed claims as agent_offline", async () => {
    const worker = await import(workerUrl);
    const client = createReaperClient([
      {
        id: "job-offline-regression",
        workspace_id: "ws-1",
        status: "claimed",
        attempt_count: 3,
        max_attempts: 3,
        lease_renewed_at: null,
        agent_alive: false,
        past_hard_grace: false,
      },
    ]);

    const summary = await worker.reapExpiredLeases({
      client,
      log: silentLogger,
    });

    assert.deepStrictEqual(summary, {
      scanned: 1,
      requeued: 0,
      failed: 1,
      deferred: 0,
    });
    const update = client.queries.find((q) =>
      q.sql.startsWith("UPDATE certificate_jobs SET status = 'failed'"),
    );
    assert.ok(update);
    assert.deepStrictEqual(update.params, [
      "job-offline-regression",
      "agent_offline",
    ]);
  });

  it("rolls back when a reaper update fails", async () => {
    const worker = await import(workerUrl);
    const queries = [];
    const client = {
      async query(sql, params = []) {
        const normalized = normalizeSql(sql);
        queries.push(normalized);
        if (normalized.startsWith("SELECT cj.id, cj.workspace_id")) {
          return {
            rows: [
              {
                id: "job-4",
                workspace_id: "ws-1",
                status: "claimed",
                attempt_count: 0,
                max_attempts: 3,
                lease_renewed_at: null,
                agent_alive: false,
                past_hard_grace: false,
              },
            ],
          };
        }
        if (normalized.startsWith("UPDATE certificate_jobs")) {
          throw new Error("update exploded");
        }
        return { rows: [] };
      },
    };

    await assert.rejects(
      () => worker.reapExpiredLeases({ client, log: silentLogger }),
      /update exploded/,
    );
    assert.ok(queries.includes("ROLLBACK"));
    assert.ok(!queries.includes("COMMIT"));
  });

  it("marks stale active agents offline and reports them", async () => {
    const worker = await import(workerUrl);
    const queries = [];
    const warned = [];
    const client = {
      async query(sql, params = []) {
        queries.push({ sql: normalizeSql(sql), params });
        return {
          rows: [
            {
              id: "row-1",
              agent_id: "agent-a",
              workspace_id: "ws-1",
              last_seen_at: new Date("2026-01-01T00:00:00Z"),
            },
          ],
        };
      },
    };

    const result = await worker.sweepStaleAgents({
      client,
      offlineAfterMs: 600000,
      log: {
        ...silentLogger,
        warn: (msg, meta) => warned.push({ msg, meta }),
      },
    });

    assert.strictEqual(result.staleCount, 1);
    assert.deepStrictEqual(result.staleAgents[0].agentId, "agent-a");

    const update = queries[0];
    assert.match(update.sql, /SET status = 'offline'/);
    assert.match(update.sql, /WHERE status = 'active'/);
    assert.match(
      update.sql,
      /COALESCE\(last_seen_at, created_at\) < NOW\(\)/,
    );
    assert.deepStrictEqual(update.params, ["600000"]);

    assert.strictEqual(warned.length, 1);
    assert.deepStrictEqual(warned[0].meta.agentIds, ["agent-a"]);
  });

  it("queues one down alert per newly-stale agent via the injected alert queuer", async () => {
    const worker = await import(workerUrl);
    const client = {
      async query() {
        return {
          rows: [
            {
              id: "row-1",
              agent_id: "agent-a",
              workspace_id: "ws-1",
              name: "agent-a-name",
              hostname: "host-a",
              platform: "linux",
              last_seen_at: new Date("2026-01-01T00:00:00Z"),
              downtime_alerts_enabled: true,
              contact_group_id: "cg-1",
            },
          ],
        };
      },
    };

    const queuedCalls = [];
    const result = await worker.sweepStaleAgents({
      client,
      offlineAfterMs: 600000,
      log: silentLogger,
      resolveImpactedCertificates: async () => [
        { id: "cert-1", commonName: "api.example.com", renewalPathState: "unavailable" },
      ],
      alertQueuer: async (args) => {
        queuedCalls.push(args);
        return { queued: true, alertKey: "agent_health:row-1:down", channels: ["email"] };
      },
    });

    assert.strictEqual(result.staleCount, 1);
    assert.strictEqual(result.alertsQueued, 1);
    assert.strictEqual(queuedCalls.length, 1);
    assert.strictEqual(queuedCalls[0].transitionType, "down");
    assert.strictEqual(queuedCalls[0].agent.id, "row-1");
    assert.strictEqual(queuedCalls[0].agent.contactGroupId, "cg-1");
    assert.strictEqual(queuedCalls[0].offlineAfterMs, 600000);
    assert.deepStrictEqual(queuedCalls[0].impactedCertificates, [
      { id: "cert-1", commonName: "api.example.com", renewalPathState: "unavailable" },
    ]);
  });

  it("the default resolveImpactedCertificates wires the real renewal-path dependency resolver", async () => {
    const worker = await import(workerUrl);
    const client = {
      async query(sql, params = []) {
        const normalized = normalizeSql(sql);
        if (/^UPDATE certops_agents/.test(normalized)) {
          return {
            rows: [
              {
                id: "row-1",
                agent_id: "agent-a",
                workspace_id: "ws-1",
                name: "agent-a-name",
                hostname: "host-a",
                platform: "linux",
                last_seen_at: new Date("2026-01-01T00:00:00Z"),
                downtime_alerts_enabled: true,
                contact_group_id: "cg-1",
              },
            ],
          };
        }
        if (/FROM managed_certificates mc/.test(normalized)) {
          return {
            rows: [
              {
                id: "cert-dependent",
                workspace_id: "ws-1",
                status: "active",
                key_mode: "agent-local",
                source: "agent_filesystem",
                common_name: "api.example.com",
                profile_id: "profile-1",
                deployed_agent_id: null,
                discovery_agent_id: "agent-a",
                certificate_public_metadata: {},
                profile_status: "active",
                profile_public_metadata: {},
              },
            ],
          };
        }
        if (/FROM certops_agents/.test(normalized)) {
          return {
            rows: [
              {
                id: "row-1",
                agent_id: "agent-a",
                name: "agent-a-name",
                hostname: "host-a",
                platform: "linux",
                status: "offline",
                last_seen_at: new Date("2026-01-01T00:00:00Z"),
                created_at: new Date("2025-12-01T00:00:00Z"),
                declared_target_selectors: [],
              },
            ],
          };
        }
        throw new Error(`Unexpected query: ${normalized}`);
      },
    };

    const queuedCalls = [];
    const result = await worker.sweepStaleAgents({
      client,
      offlineAfterMs: 600000,
      log: silentLogger,
      alertQueuer: async (args) => {
        queuedCalls.push(args);
        return { queued: true, alertKey: "agent_health:row-1:down", channels: ["email"] };
      },
    });

    assert.strictEqual(result.staleCount, 1);
    assert.strictEqual(queuedCalls.length, 1);
    // The pinned certificate (agent_filesystem discovery-agent string ==
    // agent-a, now offline with no redundant executor) shows up without any
    // test-supplied stub -- this is the real renewalPathHealth.js resolver,
    // not a fake.
    assert.deepStrictEqual(queuedCalls[0].impactedCertificates, [
      {
        id: "cert-dependent",
        commonName: "api.example.com",
        renewalPathState: "unavailable",
      },
    ]);
  });

  it("the default resolveImpactedCertificates resolves each workspace's renewal-path projection at most once per sweep tick, even with multiple stale agents", async () => {
    const worker = await import(workerUrl);
    let managedCertificatesQueryCount = 0;
    const client = {
      async query(sql, params = []) {
        const normalized = normalizeSql(sql);
        if (/^UPDATE certops_agents/.test(normalized)) {
          return {
            rows: [
              {
                id: "row-1",
                agent_id: "agent-a",
                workspace_id: "ws-1",
                name: "agent-a-name",
                hostname: "host-a",
                platform: "linux",
                last_seen_at: new Date("2026-01-01T00:00:00Z"),
                downtime_alerts_enabled: true,
                contact_group_id: "cg-1",
              },
              {
                id: "row-2",
                agent_id: "agent-b",
                workspace_id: "ws-1",
                name: "agent-b-name",
                hostname: "host-b",
                platform: "linux",
                last_seen_at: new Date("2026-01-01T00:00:00Z"),
                downtime_alerts_enabled: true,
                contact_group_id: "cg-1",
              },
            ],
          };
        }
        if (/FROM managed_certificates mc/.test(normalized)) {
          managedCertificatesQueryCount += 1;
          return { rows: [] };
        }
        if (/FROM certops_agents/.test(normalized)) {
          return {
            rows: [
              {
                id: "row-1",
                agent_id: "agent-a",
                name: "agent-a-name",
                hostname: "host-a",
                platform: "linux",
                status: "offline",
                last_seen_at: new Date("2026-01-01T00:00:00Z"),
                created_at: new Date("2025-12-01T00:00:00Z"),
                declared_target_selectors: [],
              },
              {
                id: "row-2",
                agent_id: "agent-b",
                name: "agent-b-name",
                hostname: "host-b",
                platform: "linux",
                status: "offline",
                last_seen_at: new Date("2026-01-01T00:00:00Z"),
                created_at: new Date("2025-12-01T00:00:00Z"),
                declared_target_selectors: [],
              },
            ],
          };
        }
        throw new Error(`Unexpected query: ${normalized}`);
      },
    };

    const queuedCalls = [];
    const result = await worker.sweepStaleAgents({
      client,
      offlineAfterMs: 600000,
      log: silentLogger,
      alertQueuer: async (args) => {
        queuedCalls.push(args);
        return { queued: true, alertKey: `agent_health:${args.agent.id}:down`, channels: ["email"] };
      },
    });

    assert.strictEqual(result.staleCount, 2);
    assert.strictEqual(queuedCalls.length, 2);
    // Both agents belong to workspace ws-1: the workspace-wide certificate
    // projection must be resolved once and shared, not once per agent.
    assert.strictEqual(
      managedCertificatesQueryCount,
      1,
      "resolveRenewalPathsForWorkspace must be shared across agents in the same workspace within one sweep tick",
    );
  });

  it("does not queue an alert or throw when no agent crosses the stale threshold", async () => {
    const worker = await import(workerUrl);
    const client = { async query() { return { rows: [] }; } };
    let calls = 0;

    const result = await worker.sweepStaleAgents({
      client,
      offlineAfterMs: 600000,
      log: silentLogger,
      alertQueuer: async () => {
        calls += 1;
        return { queued: true };
      },
    });

    assert.strictEqual(result.staleCount, 0);
    assert.strictEqual(result.alertsQueued, 0);
    assert.strictEqual(calls, 0);
  });

  it("a failing alert queuer does not stop the sweep from reporting the stale agent", async () => {
    const worker = await import(workerUrl);
    const client = {
      async query() {
        return {
          rows: [
            {
              id: "row-1",
              agent_id: "agent-a",
              workspace_id: "ws-1",
              last_seen_at: new Date("2026-01-01T00:00:00Z"),
            },
          ],
        };
      },
    };

    const result = await worker.sweepStaleAgents({
      client,
      offlineAfterMs: 600000,
      log: silentLogger,
      alertQueuer: async () => {
        throw new Error("delivery boom");
      },
    });

    assert.strictEqual(result.staleCount, 1);
    assert.strictEqual(result.alertsQueued, 0);
  });

  it("finds active agents with a still-open down alert and queues recovery", async () => {
    const worker = await import(workerUrl);
    const queries = [];
    const client = {
      async query(sql, params = []) {
        queries.push({ sql: normalizeSql(sql), params });
        return {
          rows: [
            {
              id: "row-1",
              agent_id: "agent-a",
              workspace_id: "ws-1",
              name: "agent-a-name",
              hostname: "host-a",
              platform: "linux",
              last_seen_at: new Date("2026-01-02T00:00:00Z"),
              downtime_alerts_enabled: true,
              contact_group_id: null,
            },
          ],
        };
      },
    };

    const queuedCalls = [];
    const result = await worker.sweepAgentRecoveries({
      client,
      log: silentLogger,
      alertQueuer: async (args) => {
        queuedCalls.push(args);
        return { queued: true, alertKey: "agent_health:row-1:recovered", channels: ["email"] };
      },
    });

    assert.strictEqual(result.candidateCount, 1);
    assert.strictEqual(result.alertsQueued, 1);
    assert.strictEqual(queuedCalls[0].transitionType, "recovered");
    assert.strictEqual(queuedCalls[0].agent.agentId, "agent-a");
    assert.match(queries[0].sql, /JOIN alert_queue/);
    assert.match(queries[0].sql, /WHERE a\.status = 'active'/);
  });

  it("queues nothing when no active agent has an open down alert", async () => {
    const worker = await import(workerUrl);
    const client = { async query() { return { rows: [] }; } };
    let calls = 0;

    const result = await worker.sweepAgentRecoveries({
      client,
      log: silentLogger,
      alertQueuer: async () => {
        calls += 1;
        return { queued: true };
      },
    });

    assert.strictEqual(result.candidateCount, 0);
    assert.strictEqual(result.alertsQueued, 0);
    assert.strictEqual(calls, 0);
  });

  it("runs all sweeps in isolation so one failure does not stop the others", async () => {
    const worker = await import(workerUrl);
    let nonceCalls = 0;
    let renewalCalls = 0;

    const results = await worker.runCertOpsMaintenance({
      env: {},
      log: silentLogger,
      // Lease reaper and stale-agent sweep both explode.
      withClientFn: async () => {
        throw new Error("db down");
      },
      dbPool: { marker: "pool" },
      nonceSweeper: async ({ client }) => {
        nonceCalls += 1;
        assert.strictEqual(client.marker, "pool");
        return 7;
      },
      registrationReplaySweeper: async ({ client }) => {
        assert.strictEqual(client.marker, "pool");
        return 0;
      },
      renewalSweeper: async ({ dbPool }) => {
        renewalCalls += 1;
        assert.strictEqual(dbPool.marker, "pool");
        return { scanned: 0, created: 0, replayed: 0, skippedPaused: 0, errors: [] };
      },
      pushMetricsFn: async () => {},
    });

    assert.strictEqual(results.leaseReaper.status, "failed");
    assert.strictEqual(results.staleAgents.status, "failed");
    assert.strictEqual(results.nonceSweep.status, "success");
    assert.strictEqual(results.nonceSweep.result.deleted, 7);
    assert.strictEqual(results.registrationReplaySweep.status, "success");
    assert.strictEqual(results.renewalScheduler.status, "success");
    assert.strictEqual(nonceCalls, 1);
    assert.strictEqual(renewalCalls, 1);
  });

  it("honors per-sweep enable flags independently", async () => {
    const worker = await import(workerUrl);
    let nonceCalls = 0;
    let renewalCalls = 0;
    let clientCalls = 0;

    const results = await worker.runCertOpsMaintenance({
      env: {
      CERTOPS_SWEEP_LEASE_REAPER_ENABLED: "false",
      CERTOPS_SWEEP_STALE_AGENTS_ENABLED: "0",
      CERTOPS_SWEEP_AGENT_RECOVERY_ALERTS_ENABLED: "0",
      CERTOPS_SWEEP_NONCE_ENABLED: "true",
        CERTOPS_SWEEP_REGISTRATION_REPLAY_ENABLED: "false",
        CERTOPS_SWEEP_RENEWAL_SCHEDULER_ENABLED: "off",
      },
      log: silentLogger,
      withClientFn: async (fn) => {
        clientCalls += 1;
        return fn({ async query() { return { rows: [] }; } });
      },
      dbPool: { marker: "pool" },
      nonceSweeper: async () => {
        nonceCalls += 1;
        return 1;
      },
      renewalSweeper: async () => {
        renewalCalls += 1;
        return { scanned: 0, created: 0 };
      },
      pushMetricsFn: async () => {},
    });

    assert.strictEqual(results.leaseReaper.status, "skipped");
    assert.strictEqual(results.staleAgents.status, "skipped");
    assert.strictEqual(results.agentRecoveryAlerts.status, "skipped");
    assert.strictEqual(results.nonceSweep.status, "success");
    assert.strictEqual(results.registrationReplaySweep.status, "skipped");
    assert.strictEqual(results.renewalScheduler.status, "skipped");
    assert.strictEqual(nonceCalls, 1);
    assert.strictEqual(renewalCalls, 0);
    assert.strictEqual(clientCalls, 0);
  });

  it("isolates a timed-out sweep without blocking later sweeps", async () => {
    const worker = await import(workerUrl);
    let renewalCalls = 0;

    const results = await worker.runCertOpsMaintenance({
      env: {
        CERTOPS_SWEEP_LEASE_REAPER_TIMEOUT_MS: "20",
        CERTOPS_SWEEP_STALE_AGENTS_ENABLED: "false",
        CERTOPS_SWEEP_NONCE_ENABLED: "false",
        CERTOPS_SWEEP_REGISTRATION_REPLAY_ENABLED: "false",
      },
      log: silentLogger,
      withClientFn: async () => {
        await new Promise((resolve) => setTimeout(resolve, 200));
        return { scanned: 0 };
      },
      renewalSweeper: async () => {
        renewalCalls += 1;
        return { scanned: 0, created: 0 };
      },
      pushMetricsFn: async () => {},
    });

    assert.strictEqual(results.leaseReaper.status, "failed");
    assert.match(results.leaseReaper.error.message, /timed out/);
    assert.strictEqual(results.renewalScheduler.status, "success");
    assert.strictEqual(renewalCalls, 1);
  });

  it("resolves sweep enable and timeout helpers from env", async () => {
    const worker = await import(workerUrl);
    assert.strictEqual(worker.isSweepEnabled("lease-reaper", {}), true);
    assert.strictEqual(
      worker.isSweepEnabled("lease-reaper", {
        CERTOPS_SWEEP_LEASE_REAPER_ENABLED: "false",
      }),
      false,
    );
    assert.strictEqual(worker.resolveSweepTimeoutMs("nonce-sweep", {}), 120000);
    assert.strictEqual(
      worker.resolveSweepTimeoutMs("nonce-sweep", {
        CERTOPS_SWEEP_NONCE_TIMEOUT_MS: "5000",
      }),
      5000,
    );
  });

  it("invokes the nonce sweeper against the worker pool", async () => {
    const worker = await import(workerUrl);
    const seenClients = [];

    const results = await worker.runCertOpsMaintenance({
      env: {},
      log: silentLogger,
      withClientFn: async (fn) =>
        fn({
          async query(sql) {
            return { rows: [] };
          },
        }),
      dbPool: { marker: "the-pool" },
      nonceSweeper: async ({ client }) => {
        seenClients.push(client);
        return 3;
      },
      registrationReplaySweeper: async () => 0,
      renewalSweeper: async () => ({
        scanned: 0,
        created: 0,
        replayed: 0,
        skippedPaused: 0,
        errors: [],
      }),
      pushMetricsFn: async () => {},
    });

    assert.strictEqual(results.nonceSweep.status, "success");
    assert.strictEqual(results.nonceSweep.result.deleted, 3);
    assert.strictEqual(seenClients.length, 1);
    assert.strictEqual(seenClients[0].marker, "the-pool");
  });

  it("invokes the registration-replay sweeper against the worker pool", async () => {
    const worker = await import(workerUrl);
    const seenClients = [];

    const results = await worker.runCertOpsMaintenance({
      env: {
        CERTOPS_SWEEP_LEASE_REAPER_ENABLED: "false",
        CERTOPS_SWEEP_STALE_AGENTS_ENABLED: "false",
        CERTOPS_SWEEP_NONCE_ENABLED: "false",
        CERTOPS_SWEEP_RENEWAL_SCHEDULER_ENABLED: "false",
      },
      log: silentLogger,
      withClientFn: async (fn) => fn({ async query() { return { rows: [] }; } }),
      dbPool: { marker: "replay-pool" },
      registrationReplaySweeper: async ({ client }) => {
        seenClients.push(client);
        return 4;
      },
      pushMetricsFn: async () => {},
    });

    assert.strictEqual(results.registrationReplaySweep.status, "success");
    assert.strictEqual(results.registrationReplaySweep.result.deleted, 4);
    assert.strictEqual(seenClients.length, 1);
    assert.strictEqual(seenClients[0].marker, "replay-pool");
  });

  it("honors the registration-replay sweep enable flag", async () => {
    const worker = await import(workerUrl);
    let replayCalls = 0;

    const results = await worker.runCertOpsMaintenance({
      env: {
        CERTOPS_SWEEP_LEASE_REAPER_ENABLED: "false",
        CERTOPS_SWEEP_STALE_AGENTS_ENABLED: "false",
        CERTOPS_SWEEP_NONCE_ENABLED: "false",
        CERTOPS_SWEEP_REGISTRATION_REPLAY_ENABLED: "false",
        CERTOPS_SWEEP_RENEWAL_SCHEDULER_ENABLED: "false",
      },
      log: silentLogger,
      withClientFn: async (fn) => fn({ async query() { return { rows: [] }; } }),
      registrationReplaySweeper: async () => {
        replayCalls += 1;
        return 1;
      },
      pushMetricsFn: async () => {},
    });

    assert.strictEqual(results.registrationReplaySweep.status, "skipped");
    assert.strictEqual(replayCalls, 0);
  });
});

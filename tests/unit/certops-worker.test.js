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

const metricsUrl = pathToFileURL(
  path.join(
    __dirname,
    "..",
    "..",
    "apps",
    "worker",
    "src",
    "certops-metrics.js",
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

function executableProfile(reference = "host/web") {
  return {
    schemaVersion: 1,
    profileId: "profile-1",
    profileName: "web",
    sanPolicy: { mode: "exact", sans: ["api.example.com"], allowWildcards: false },
    keyAlgorithm: "rsa",
    keySize: 2048,
    keyRotationPolicy: { rotateOnRenew: true },
    preferredChain: null,
    ca: { endpoint: "https://acme.example.test/directory", accountRef: null, eabRef: null },
    acme: { kind: "certbot", commandRef: "renew.web" },
    dns: { provider: "cloudflare", zone: "example.com" },
    deploymentTargets: [{ type: "endpoint", reference, certPath: "/etc/ssl/api.pem" }],
    target: { type: "endpoint", reference, certPath: "/etc/ssl/api.pem" },
    verification: { host: null, port: null, requireMatch: false },
  };
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

// runCertOpsMaintenance rejects when any sweep failed, so a failing run exits
// non-zero. Tests that assert on per-sweep outcomes rather than on that exit
// signal read the results off the rejection.
async function runMaintenanceResults(worker, options) {
  try {
    return await worker.runCertOpsMaintenance(options);
  } catch (error) {
    if (error?.code !== "CERTOPS_MAINTENANCE_SWEEP_FAILED") throw error;
    return error.results;
  }
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

  it("unwinds a lease-reaped trust job in the reaper's own transaction", async () => {
    const worker = await import(workerUrl);
    const client = createReaperClient([
      {
        id: "job-trust",
        workspace_id: "ws-1",
        status: "claimed",
        attempt_count: 3,
        max_attempts: 3,
        operation: "distribute-trust",
        subject_type: "trust_anchor",
        subject_id: "anchor-1",
        lease_renewed_at: null,
        agent_alive: false,
        past_hard_grace: false,
      },
    ]);
    const unwinds = [];

    const summary = await worker.reapExpiredLeases({
      client,
      log: silentLogger,
      auditWriter: async () => {},
      trustTerminalHook: async (args) => {
        unwinds.push(args);
        return { action: "deleted" };
      },
    });

    assert.strictEqual(summary.failed, 1);
    assert.strictEqual(unwinds.length, 1, "expected one trust unwind");
    assert.strictEqual(unwinds[0].client, client);
    assert.strictEqual(unwinds[0].job.id, "job-trust");
    assert.strictEqual(unwinds[0].job.status, "failed");
    assert.strictEqual(unwinds[0].job.operation, "distribute-trust");
    assert.strictEqual(unwinds[0].job.workspace_id, "ws-1");

    // The unwind must land between the failed UPDATE and the COMMIT, so the
    // job status and the installation state cannot be observed apart.
    const updateIndex = client.queries.findIndex((q) =>
      q.sql.startsWith("UPDATE certificate_jobs SET status = 'failed'"),
    );
    const commitIndex = client.queries.findIndex((q) => q.sql === "COMMIT");
    assert.ok(updateIndex >= 0 && commitIndex > updateIndex);
  });

  it("does not unwind non-trust jobs the reaper fails", async () => {
    const worker = await import(workerUrl);
    const client = createReaperClient([
      {
        id: "job-renew",
        workspace_id: "ws-1",
        status: "claimed",
        attempt_count: 3,
        max_attempts: 3,
        operation: "renew",
        lease_renewed_at: null,
        agent_alive: false,
        past_hard_grace: false,
      },
    ]);
    let unwindCalls = 0;

    await worker.reapExpiredLeases({
      client,
      log: silentLogger,
      auditWriter: async () => {},
      trustTerminalHook: async () => {
        unwindCalls += 1;
      },
    });

    assert.strictEqual(unwindCalls, 0);
  });

  it("rolls the whole reaper transaction back when a trust unwind fails", async () => {
    const worker = await import(workerUrl);
    const client = createReaperClient([
      {
        id: "job-trust-broken",
        workspace_id: "ws-1",
        status: "claimed",
        attempt_count: 3,
        max_attempts: 3,
        operation: "revoke-trust",
        lease_renewed_at: null,
        agent_alive: false,
        past_hard_grace: false,
      },
    ]);

    await assert.rejects(
      () =>
        worker.reapExpiredLeases({
          client,
          log: silentLogger,
          auditWriter: async () => {},
          trustTerminalHook: async () => {
            throw new Error("installation row locked");
          },
        }),
      /installation row locked/,
    );

    assert.strictEqual(client.queries.at(-1).sql, "ROLLBACK");
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

    const update = queries.find((entry) => /UPDATE certops_agents/.test(entry.sql));
    assert.match(update.sql, /SET status = 'offline'/);
    assert.match(update.sql, /AND status = 'active'/);
    assert.match(
      update.sql,
      /COALESCE\(last_seen_at, created_at\) < NOW\(\)/,
    );
    assert.deepStrictEqual(update.params, ["600000", "row-1", "ws-1"]);
    assert.ok(
      queries.some((entry) => /INSERT INTO certops_agent_health_incidents/.test(entry.sql)),
      "the durable incident must be written in the offline transaction",
    );

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
        if (["BEGIN", "COMMIT", "ROLLBACK"].includes(normalized)) return { rows: [] };
        if (/INSERT INTO certops_agent_health_incidents/.test(normalized)) return { rows: [], rowCount: 1 };
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
                profile_public_metadata: { renewalProfile: executableProfile() },
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
                declared_target_selectors: ["host/web"],
                supported_operations: ["renew"],
                supported_dns_providers: ["cloudflare"],
                declared_command_profile_names: ["renew.web"],
                declared_capabilities: [],
                capabilities_updated_at: new Date().toISOString(),
                agent_kind: "normal",
                agent_version: "0.1.0",
                protocol_version: "1.0.0",
                clock_offset_ms: 0,
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

  it("refreshes the workspace renewal-path projection after each per-agent offline transition", async () => {
    const worker = await import(workerUrl);
    let managedCertificatesQueryCount = 0;
    const client = {
      async query(sql, params = []) {
        const normalized = normalizeSql(sql);
        if (["BEGIN", "COMMIT", "ROLLBACK"].includes(normalized)) return { rows: [] };
        if (/INSERT INTO certops_agent_health_incidents/.test(normalized)) return { rows: [], rowCount: 1 };
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
    // Each per-agent transaction changes liveness before resolving impact.
    // The next agent must see that newly committed state instead of reusing
    // a projection from before the previous transition.
    assert.strictEqual(
      managedCertificatesQueryCount,
      2,
      "each committed status transition must invalidate the workspace projection",
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

  it("rolls the offline transition back when alert persistence fails", async () => {
    const worker = await import(workerUrl);
    const queries = [];
    const client = {
      async query(sql) {
        const normalized = normalizeSql(sql);
        queries.push(normalized);
        if (["BEGIN", "COMMIT", "ROLLBACK"].includes(normalized)) return { rows: [] };
        if (/INSERT INTO certops_agent_health_incidents/.test(normalized)) return { rows: [], rowCount: 1 };
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

    await assert.rejects(
      () => worker.sweepStaleAgents({
        client,
        offlineAfterMs: 600000,
        log: silentLogger,
        alertQueuer: async () => {
          throw new Error("delivery boom");
        },
      }),
      /delivery boom/,
    );
    assert.ok(queries.includes("ROLLBACK"));
    assert.ok(!queries.includes("COMMIT"));

    const retried = await worker.sweepStaleAgents({
      client,
      offlineAfterMs: 600000,
      log: silentLogger,
      alertQueuer: async () => ({ queued: true }),
    });
    assert.deepStrictEqual(
      { staleCount: retried.staleCount, alertsQueued: retried.alertsQueued },
      { staleCount: 1, alertsQueued: 1 },
    );
    assert.ok(queries.includes("COMMIT"));
  });

  it("keeps unrelated DOWN transitions committed when one agent fails mid-sweep", async () => {
    const worker = await import(workerUrl);
    const rows = [
      {
        id: "row-1",
        agent_id: "agent-a",
        workspace_id: "ws-1",
        downtime_alerts_enabled: true,
      },
      {
        id: "row-2",
        agent_id: "agent-b",
        workspace_id: "ws-1",
        downtime_alerts_enabled: true,
      },
    ];
    let currentAgentId = null;
    const committed = [];
    const rolledBack = [];
    const alertCalls = [];
    const client = {
      async query(sql, params = []) {
        const normalized = normalizeSql(sql);
        if (/^SELECT id, agent_id, workspace_id/.test(normalized)) {
          return { rows };
        }
        if (normalized === "BEGIN") return { rows: [] };
        if (/^UPDATE certops_agents/.test(normalized)) {
          currentAgentId = params[1];
          return { rows: [rows.find((row) => row.id === currentAgentId)] };
        }
        if (/INSERT INTO certops_agent_health_incidents/.test(normalized)) {
          return { rows: [], rowCount: 1 };
        }
        if (normalized === "COMMIT") {
          committed.push(currentAgentId);
          currentAgentId = null;
          return { rows: [] };
        }
        if (normalized === "ROLLBACK") {
          rolledBack.push(currentAgentId);
          currentAgentId = null;
          return { rows: [] };
        }
        throw new Error(`Unexpected query: ${normalized}`);
      },
    };

    await assert.rejects(
      () =>
        worker.sweepStaleAgents({
          client,
          offlineAfterMs: 600000,
          log: silentLogger,
          resolveImpactedCertificates: async () => [],
          alertQueuer: async ({ agent }) => {
            alertCalls.push(agent.id);
            if (agent.id === "row-1") {
              throw new Error("down persistence failed");
            }
            return { queued: true };
          },
        }),
      /down persistence failed/,
    );

    assert.deepStrictEqual(alertCalls, ["row-1", "row-2"]);
    assert.deepStrictEqual(rolledBack, ["row-1"]);
    assert.deepStrictEqual(committed, ["row-2"]);
  });

  it("finds active agents with a still-open down alert and queues recovery", async () => {
    const worker = await import(workerUrl);
    const queries = [];
    const client = {
      async query(sql, params = []) {
        const normalized = normalizeSql(sql);
        queries.push({ sql: normalized, params });
        if (["BEGIN", "COMMIT", "ROLLBACK"].includes(normalized)) return { rows: [] };
        if (/DELETE FROM certops_agent_health_incidents/.test(normalized)) return { rows: [], rowCount: 1 };
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
    const select = queries.find((entry) => /FROM certops_agents a/.test(entry.sql));
    assert.match(select.sql, /JOIN certops_agent_health_incidents/);
    assert.match(select.sql, /WHERE a\.status = 'active'/);
    assert.ok(
      queries.some((entry) => /DELETE FROM certops_agent_health_incidents/.test(entry.sql)),
    );
  });

  it("keeps the recovery incident open when recovery alert persistence fails", async () => {
    const worker = await import(workerUrl);
    const queries = [];
    const client = {
      async query(sql) {
        const normalized = normalizeSql(sql);
        queries.push(normalized);
        if (["BEGIN", "COMMIT", "ROLLBACK"].includes(normalized)) return { rows: [] };
        if (/FROM certops_agents a/.test(normalized)) {
          return {
            rows: [{
              id: "row-1",
              agent_id: "agent-a",
              workspace_id: "ws-1",
              downtime_alerts_enabled: true,
            }],
          };
        }
        if (/DELETE FROM certops_agent_health_incidents/.test(normalized)) {
          return { rows: [], rowCount: 1 };
        }
        throw new Error(`Unexpected query: ${normalized}`);
      },
    };

    await assert.rejects(
      () => worker.sweepAgentRecoveries({
        client,
        log: silentLogger,
        resolveImpactedCertificates: async () => [],
        alertQueuer: async () => {
          throw new Error("recovery insert failed");
        },
      }),
      /recovery insert failed/,
    );
    assert.ok(queries.includes("ROLLBACK"));
    assert.ok(!queries.includes("COMMIT"));
    assert.ok(!queries.some((sql) => /DELETE FROM certops_agent_health_incidents/.test(sql)));

    const retried = await worker.sweepAgentRecoveries({
      client,
      log: silentLogger,
      resolveImpactedCertificates: async () => [],
      alertQueuer: async () => ({ queued: true }),
    });
    assert.deepStrictEqual(retried, { candidateCount: 1, alertsQueued: 1 });
    assert.ok(
      queries.some((sql) =>
        /DELETE FROM certops_agent_health_incidents/.test(sql),
      ),
    );
  });

  it("keeps unrelated RECOVERY transitions committed when one agent fails mid-sweep", async () => {
    const worker = await import(workerUrl);
    const rows = [
      {
        id: "row-1",
        agent_id: "agent-a",
        workspace_id: "ws-1",
        downtime_alerts_enabled: true,
      },
      {
        id: "row-2",
        agent_id: "agent-b",
        workspace_id: "ws-1",
        downtime_alerts_enabled: true,
      },
    ];
    let currentAgentId = null;
    const committed = [];
    const rolledBack = [];
    const deletedIncidents = [];
    const alertCalls = [];
    const client = {
      async query(sql, params = []) {
        const normalized = normalizeSql(sql);
        if (/FROM certops_agents a/.test(normalized)) {
          if (params.length === 0) return { rows };
          currentAgentId = params[0];
          return { rows: [rows.find((row) => row.id === currentAgentId)] };
        }
        if (normalized === "BEGIN") return { rows: [] };
        if (/DELETE FROM certops_agent_health_incidents/.test(normalized)) {
          deletedIncidents.push(params[0]);
          return { rows: [], rowCount: 1 };
        }
        if (normalized === "COMMIT") {
          committed.push(currentAgentId);
          currentAgentId = null;
          return { rows: [] };
        }
        if (normalized === "ROLLBACK") {
          rolledBack.push(currentAgentId);
          currentAgentId = null;
          return { rows: [] };
        }
        throw new Error(`Unexpected query: ${normalized}`);
      },
    };

    await assert.rejects(
      () =>
        worker.sweepAgentRecoveries({
          client,
          log: silentLogger,
          resolveImpactedCertificates: async () => [],
          alertQueuer: async ({ agent }) => {
            alertCalls.push(agent.id);
            if (agent.id === "row-1") {
              throw new Error("recovery persistence failed");
            }
            return { queued: true };
          },
        }),
      /recovery persistence failed/,
    );

    assert.deepStrictEqual(alertCalls, ["row-1", "row-2"]);
    assert.deepStrictEqual(rolledBack, ["row-1"]);
    assert.deepStrictEqual(deletedIncidents, ["row-2"]);
    assert.deepStrictEqual(committed, ["row-2"]);
  });

  it("keeps the recovery incident open while DOWN delivery is in flight", async () => {
    const worker = await import(workerUrl);
    const queries = [];
    const client = {
      async query(sql) {
        const normalized = normalizeSql(sql);
        queries.push(normalized);
        if (["BEGIN", "COMMIT", "ROLLBACK"].includes(normalized)) {
          return { rows: [] };
        }
        if (/FROM certops_agents a/.test(normalized)) {
          return {
            rows: [
              {
                id: "row-1",
                agent_id: "agent-a",
                workspace_id: "ws-1",
                downtime_alerts_enabled: true,
              },
            ],
          };
        }
        throw new Error(`Unexpected query: ${normalized}`);
      },
    };

    const result = await worker.sweepAgentRecoveries({
      client,
      log: silentLogger,
      resolveImpactedCertificates: async () => [],
      alertQueuer: async () => ({
        queued: false,
        retry: true,
        reason: "down_delivery_in_progress",
      }),
    });

    assert.deepStrictEqual(result, { candidateCount: 1, alertsQueued: 0 });
    assert.ok(queries.includes("COMMIT"));
    assert.ok(
      !queries.some((sql) =>
        /DELETE FROM certops_agent_health_incidents/.test(sql),
      ),
    );
  });

  it("closes a delivered outage while alerts are disabled and does not recover it later", async () => {
    const worker = await import(workerUrl);
    let incidentOpen = true;
    let alertsEnabled = false;
    const transitions = [];
    const client = {
      async query(sql) {
        const normalized = normalizeSql(sql);
        if (["BEGIN", "COMMIT", "ROLLBACK"].includes(normalized)) {
          return { rows: [] };
        }
        if (/FROM certops_agents a/.test(normalized)) {
          return {
            rows: incidentOpen
              ? [{
                  id: "row-1",
                  agent_id: "agent-a",
                  workspace_id: "ws-1",
                  downtime_alerts_enabled: alertsEnabled,
                }]
              : [],
          };
        }
        if (/DELETE FROM certops_agent_health_incidents/.test(normalized)) {
          incidentOpen = false;
          return { rows: [], rowCount: 1 };
        }
        throw new Error(`Unexpected query: ${normalized}`);
      },
    };
    const alertQueuer = async ({ transitionType, agent }) => {
      transitions.push({ transitionType, enabled: agent.downtimeAlertsEnabled });
      return {
        queued: false,
        reason: "alerts_disabled_incident_closed",
      };
    };

    const disabledRecovery = await worker.sweepAgentRecoveries({
      client,
      log: silentLogger,
      resolveImpactedCertificates: async () => [],
      alertQueuer,
    });
    alertsEnabled = true;
    const afterReenable = await worker.sweepAgentRecoveries({
      client,
      log: silentLogger,
      resolveImpactedCertificates: async () => [],
      alertQueuer,
    });

    assert.deepStrictEqual(disabledRecovery, {
      candidateCount: 1,
      alertsQueued: 0,
    });
    assert.deepStrictEqual(afterReenable, {
      candidateCount: 0,
      alertsQueued: 0,
    });
    assert.deepStrictEqual(transitions, [
      { transitionType: "recovered", enabled: false },
    ]);
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

    const results = await runMaintenanceResults(worker, {
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

    const results = await runMaintenanceResults(worker, {
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

    const results = await runMaintenanceResults(worker, {
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

    const results = await runMaintenanceResults(worker, {
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

    const results = await runMaintenanceResults(worker, {
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

    const results = await runMaintenanceResults(worker, {
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

  it("rejects with a sweep-failure code so a failing run exits non-zero", async () => {
    const worker = await import(workerUrl);
    let metricsPushed = 0;

    await assert.rejects(
      () =>
        worker.runCertOpsMaintenance({
          env: {
            CERTOPS_SWEEP_STALE_AGENTS_ENABLED: "false",
            CERTOPS_SWEEP_AGENT_RECOVERY_ALERTS_ENABLED: "false",
            CERTOPS_SWEEP_NONCE_ENABLED: "false",
            CERTOPS_SWEEP_REGISTRATION_REPLAY_ENABLED: "false",
            CERTOPS_SWEEP_RENEWAL_SCHEDULER_ENABLED: "false",
            CERTOPS_SWEEP_OUTBOX_DRAIN_ENABLED: "false",
            CERTOPS_SWEEP_DIAGNOSTIC_AGENT_INACTIVITY_ENABLED: "false",
            CERTOPS_SWEEP_TRUST_ANCHOR_RECONCILIATION_ENABLED: "false",
          },
          log: silentLogger,
          withClientFn: async () => {
            throw new Error("db down");
          },
          pushMetricsFn: async () => {
            metricsPushed += 1;
          },
        }),
      (err) => {
        assert.strictEqual(err.code, "CERTOPS_MAINTENANCE_SWEEP_FAILED");
        assert.match(err.message, /1 sweep\(s\) failed: leaseReaper/);
        assert.strictEqual(err.results.leaseReaper.status, "failed");
        return true;
      },
    );

    // Metrics must still ship for a failing run, otherwise the failure is
    // invisible in the series that would explain it.
    assert.strictEqual(metricsPushed, 1);
  });

  it("does not fail the run when sweeps are only skipped", async () => {
    const worker = await import(workerUrl);

    const results = await worker.runCertOpsMaintenance({
      env: {
        CERTOPS_SWEEP_LEASE_REAPER_ENABLED: "false",
        CERTOPS_SWEEP_STALE_AGENTS_ENABLED: "false",
        CERTOPS_SWEEP_AGENT_RECOVERY_ALERTS_ENABLED: "false",
        CERTOPS_SWEEP_REGISTRATION_REPLAY_ENABLED: "false",
        CERTOPS_SWEEP_RENEWAL_SCHEDULER_ENABLED: "false",
        CERTOPS_SWEEP_OUTBOX_DRAIN_ENABLED: "false",
        CERTOPS_SWEEP_DIAGNOSTIC_AGENT_INACTIVITY_ENABLED: "false",
        CERTOPS_SWEEP_TRUST_ANCHOR_RECONCILIATION_ENABLED: "false",
      },
      log: silentLogger,
      dbPool: { marker: "pool" },
      nonceSweeper: async () => 2,
      pushMetricsFn: async () => {},
    });

    assert.strictEqual(results.leaseReaper.status, "skipped");
    assert.strictEqual(results.trustAnchorReconciliation.status, "skipped");
    assert.strictEqual(results.nonceSweep.status, "success");
  });

  it("treats only failed sweeps as a failed run", async () => {
    const metrics = await import(metricsUrl);

    assert.deepStrictEqual(metrics.identifyFailedSweeps({}), []);
    assert.deepStrictEqual(metrics.identifyFailedSweeps(undefined), []);
    assert.deepStrictEqual(
      metrics.identifyFailedSweeps({
        a: { status: "success" },
        b: { status: "skipped" },
        c: { status: "failed" },
        d: { status: "failed" },
      }),
      ["c", "d"],
    );
  });
});

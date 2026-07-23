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

  it("fails alive-but-silent agents past the hard grace without requeue", async () => {
    const worker = await import(workerUrl);
    const client = createReaperClient([
      {
        id: "job-hung",
        workspace_id: "ws-1",
        status: "claimed",
        attempt_count: 1,
        max_attempts: 3,
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
      requeued: 0,
      failed: 1,
      deferred: 0,
    });
    const update = client.queries.find((q) =>
      q.sql.startsWith("UPDATE certificate_jobs SET status = 'failed'"),
    );
    assert.ok(update, "expected a fail UPDATE");
    // The agent may have executed side effects: never requeue, and record
    // lease_expired (not agent_offline) because the agent is still alive.
    assert.deepStrictEqual(update.params, ["job-hung", "lease_expired"]);
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
  });

  it("never requeues running jobs because pending is not a legal transition", async () => {
    const worker = await import(workerUrl);
    const client = createReaperClient([
      {
        id: "job-3",
        workspace_id: "ws-1",
        status: "running",
        attempt_count: 0,
        max_attempts: 3,
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
    assert.ok(update, "running job must fail, not requeue");
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
    assert.strictEqual(results.renewalScheduler.status, "success");
    assert.strictEqual(nonceCalls, 1);
    assert.strictEqual(renewalCalls, 1);
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
});

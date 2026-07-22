"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  DEFAULT_RENEWAL_THRESHOLD_DAYS,
  findCertificatesDueForRenewal,
  renewalIdempotencyKey,
  resolveRenewalThresholdDays,
  runRenewalSchedulerSweep,
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/renewalScheduler.js",
  ),
);
const {
  CERTOPS_WORKSPACE_PAUSED,
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/services/certops/workspaceKillSwitch.js",
  ),
);
const {
  CERTOPS_DISABLED,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/settings.js"),
);

function normalizeSql(sql) {
  return String(sql).replace(/\s+/g, " ").trim();
}

const NOT_AFTER = new Date("2026-08-01T00:00:00.000Z");

function dueCertificate(overrides = {}) {
  return {
    id: "cert-1",
    workspace_id: "ws-1",
    common_name: "app.example.com",
    not_after: NOT_AFTER,
    key_mode: null,
    profile_renew_before_days: null,
    ...overrides,
  };
}

/**
 * Fake pool whose connect() yields transaction-recording clients. The scan
 * query result is injectable; workspace pause state controls the FOR SHARE
 * gate inside lockWorkspaceForCertOpsSideEffect.
 */
function createSchedulerPool({
  dueRows = [],
  pausedWorkspaces = new Set(),
} = {}) {
  const clients = [];
  const scanQueries = [];
  const pool = {
    clients,
    scanQueries,
    async query(sql, params) {
      scanQueries.push({ sql: normalizeSql(sql), params });
      return { rows: dueRows };
    },
    async connect() {
      const client = {
        released: false,
        queries: [],
        async query(sql, params = []) {
          const normalized = normalizeSql(sql);
          this.queries.push({ sql: normalized, params });
          if (
            normalized === "BEGIN" ||
            normalized === "COMMIT" ||
            normalized === "ROLLBACK"
          ) {
            return { rows: [] };
          }
          if (normalized.startsWith("SELECT id, certops_paused FROM workspaces")) {
            return {
              rows: [
                {
                  id: params[0],
                  certops_paused: pausedWorkspaces.has(params[0]),
                },
              ],
            };
          }
          if (normalized.includes("system_settings")) {
            return { rows: [{ certops_settings: { enabled: true } }] };
          }
          return { rows: [] };
        },
        release() {
          this.released = true;
        },
      };
      clients.push(client);
      return client;
    },
  };
  return pool;
}

describe("certops renewal scheduler", () => {
  it("resolves the renewal threshold from env with a 30 day default", () => {
    assert.strictEqual(resolveRenewalThresholdDays({}), 30);
    assert.strictEqual(DEFAULT_RENEWAL_THRESHOLD_DAYS, 30);
    assert.strictEqual(
      resolveRenewalThresholdDays({ CERTOPS_RENEWAL_THRESHOLD_DAYS: "14" }),
      14,
    );
    assert.strictEqual(
      resolveRenewalThresholdDays({ CERTOPS_RENEWAL_THRESHOLD_DAYS: "0" }),
      30,
    );
    assert.strictEqual(
      resolveRenewalThresholdDays({ CERTOPS_RENEWAL_THRESHOLD_DAYS: "junk" }),
      30,
    );
  });

  it("derives a stable idempotency key from cert id and not_after", () => {
    const first = renewalIdempotencyKey("cert-1", NOT_AFTER);
    const second = renewalIdempotencyKey("cert-1", NOT_AFTER.toISOString());
    assert.strictEqual(first, second);
    assert.strictEqual(first, `certops-renewal:cert-1:${NOT_AFTER.getTime()}`);

    const nextWindow = renewalIdempotencyKey(
      "cert-1",
      new Date("2026-11-01T00:00:00.000Z"),
    );
    assert.notStrictEqual(first, nextWindow);
  });

  it("dedupes against open renew jobs via NOT EXISTS on non-terminal statuses", async () => {
    const pool = createSchedulerPool({ dueRows: [] });

    await findCertificatesDueForRenewal({
      db: pool,
      thresholdDays: 30,
      terminalStatuses: ["succeeded", "failed"],
    });

    assert.strictEqual(pool.scanQueries.length, 1);
    const { sql, params } = pool.scanQueries[0];
    assert.match(sql, /FROM managed_certificates mc/);
    assert.match(sql, /NOT EXISTS/);
    assert.match(sql, /cj\.operation = 'renew'/);
    assert.match(sql, /cj\.subject_type = 'managed_certificate'/);
    assert.match(sql, /NOT \(cj\.status = ANY\(\$2::text\[\]\)\)/);
    assert.match(sql, /mc\.status NOT IN \('revoked', 'decommissioned'\)/);
    assert.strictEqual(params[0], "30");
    assert.deepStrictEqual(params[1], ["succeeded", "failed"]);
  });

  it("creates an automation renew job for a due certificate inside a gated transaction", async () => {
    const pool = createSchedulerPool({ dueRows: [dueCertificate()] });
    const createdJobs = [];

    const summary = await runRenewalSchedulerSweep({
      dbPool: pool,
      env: {},
      jobCreator: async (options) => {
        createdJobs.push(options);
        return { job: { id: "job-1" }, created: true };
      },
    });

    assert.strictEqual(summary.scanned, 1);
    assert.strictEqual(summary.created, 1);
    assert.strictEqual(summary.replayed, 0);
    assert.strictEqual(summary.skippedPaused, 0);
    assert.deepStrictEqual(summary.errors, []);

    assert.strictEqual(createdJobs.length, 1);
    const job = createdJobs[0];
    assert.strictEqual(job.operation, "renew");
    assert.strictEqual(job.source, "automation");
    assert.strictEqual(job.subjectType, "managed_certificate");
    assert.strictEqual(job.subjectId, "cert-1");
    assert.strictEqual(
      job.idempotencyKey,
      `certops-renewal:cert-1:${NOT_AFTER.getTime()}`,
    );
    assert.strictEqual(job.payload.certificateId, "cert-1");
    assert.strictEqual(job.payload.notAfter, NOT_AFTER.toISOString());
    // No key_mode policy data: keyRotation must be omitted entirely.
    assert.ok(!("keyRotation" in job.payload));

    // The job creation transaction acquires the workspace kill-switch lock
    // (FOR SHARE) before the insert and commits afterwards.
    const client = pool.clients[0];
    const sqls = client.queries.map((q) => q.sql);
    assert.strictEqual(sqls[0], "BEGIN");
    assert.ok(
      sqls.some((sql) =>
        sql.startsWith("SELECT id, certops_paused FROM workspaces"),
      ),
    );
    assert.strictEqual(sqls.at(-1), "COMMIT");
    assert.strictEqual(client.released, true);
  });

  it("sets keyRotation only for agent-local key modes", async () => {
    const pool = createSchedulerPool({
      dueRows: [dueCertificate({ key_mode: "agent-local" })],
    });
    const createdJobs = [];

    await runRenewalSchedulerSweep({
      dbPool: pool,
      env: {},
      jobCreator: async (options) => {
        createdJobs.push(options);
        return { job: { id: "job-1" }, created: true };
      },
    });

    assert.strictEqual(createdJobs[0].payload.keyRotation, false);
  });

  it("counts idempotent replays without creating duplicates", async () => {
    const pool = createSchedulerPool({ dueRows: [dueCertificate()] });

    const summary = await runRenewalSchedulerSweep({
      dbPool: pool,
      env: {},
      jobCreator: async () => ({ job: { id: "job-1" }, created: false }),
    });

    assert.strictEqual(summary.created, 0);
    assert.strictEqual(summary.replayed, 1);
    assert.deepStrictEqual(summary.errors, []);
  });

  it("skips paused workspaces without erroring and rolls the transaction back", async () => {
    const pool = createSchedulerPool({
      dueRows: [
        dueCertificate({ id: "cert-paused", workspace_id: "ws-paused" }),
        dueCertificate({ id: "cert-ok", workspace_id: "ws-ok" }),
      ],
      pausedWorkspaces: new Set(["ws-paused"]),
    });
    const createdJobs = [];

    const summary = await runRenewalSchedulerSweep({
      dbPool: pool,
      env: {},
      jobCreator: async (options) => {
        createdJobs.push(options);
        return { job: { id: "job-1" }, created: true };
      },
    });

    assert.strictEqual(summary.scanned, 2);
    assert.strictEqual(summary.skippedPaused, 1);
    assert.strictEqual(summary.created, 1);
    assert.deepStrictEqual(summary.errors, []);
    assert.deepStrictEqual(
      createdJobs.map((job) => job.subjectId),
      ["cert-ok"],
    );

    const pausedClient = pool.clients[0];
    const pausedSqls = pausedClient.queries.map((q) => q.sql);
    assert.ok(pausedSqls.includes("ROLLBACK"));
    assert.ok(!pausedSqls.includes("COMMIT"));
    assert.strictEqual(pausedClient.released, true);
  });

  it("skips globally disabled deployments without erroring", async () => {
    const pool = createSchedulerPool({ dueRows: [dueCertificate()] });

    const summary = await runRenewalSchedulerSweep({
      dbPool: pool,
      // Global kill switch off: lockWorkspaceForCertOpsSideEffect throws
      // CERTOPS_DISABLED before any job insert.
      env: { CERTOPS_ENABLED: "false" },
      jobCreator: async () => {
        throw new Error("job creation must not run when CertOps is disabled");
      },
    });

    assert.strictEqual(summary.skippedPaused, 1);
    assert.strictEqual(summary.created, 0);
    assert.deepStrictEqual(summary.errors, []);
  });

  it("records per-certificate failures without aborting the sweep", async () => {
    const pool = createSchedulerPool({
      dueRows: [
        dueCertificate({ id: "cert-bad" }),
        dueCertificate({ id: "cert-good" }),
      ],
    });
    const createdJobs = [];

    const summary = await runRenewalSchedulerSweep({
      dbPool: pool,
      env: {},
      jobCreator: async (options) => {
        if (options.subjectId === "cert-bad") {
          throw new Error("insert exploded");
        }
        createdJobs.push(options);
        return { job: { id: "job-2" }, created: true };
      },
    });

    assert.strictEqual(summary.created, 1);
    assert.strictEqual(summary.errors.length, 1);
    assert.strictEqual(summary.errors[0].certificateId, "cert-bad");
    assert.match(summary.errors[0].error, /insert exploded/);
    assert.deepStrictEqual(
      createdJobs.map((job) => job.subjectId),
      ["cert-good"],
    );
  });

  it("exposes the pause and disabled error codes it relies on", () => {
    assert.strictEqual(CERTOPS_WORKSPACE_PAUSED, "CERTOPS_WORKSPACE_PAUSED");
    assert.strictEqual(CERTOPS_DISABLED, "CERTOPS_DISABLED");
  });
});

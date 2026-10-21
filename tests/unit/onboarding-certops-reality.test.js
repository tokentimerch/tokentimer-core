const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  summarizeAgents,
  loadCertopsReality,
  loadAdcsReality,
  loadControllerReality,
  loadDistributionReality,
  loadOutboxBacklog,
  loadOverdueEnrollments,
} = require("../../apps/api/services/onboarding/certopsReality");

const agent = (over = {}) => ({
  id: "row-1",
  agentId: "wire-1",
  name: "web-01",
  hostname: "web-01",
  platform: "linux",
  status: "active",
  agentKind: "normal",
  livenessState: "live",
  createdAt: "2026-10-19T10:00:00.000Z",
  supportedOperations: [],
  declaredCapabilities: [],
  ...over,
});

describe("summarizeAgents", () => {
  it("ignores retired and diagnostic agents", () => {
    const summary = summarizeAgents([
      agent(),
      agent({ id: "r", status: "retired" }),
      agent({ id: "d", agentKind: "diagnostic" }),
    ]);
    assert.equal(summary.total, 1);
    assert.equal(summary.live, 1);
  });

  it("counts only live agents and never claims execution from a stale one", () => {
    const summary = summarizeAgents([
      agent({ livenessState: "stale", supportedOperations: ["issue"] }),
    ]);
    assert.equal(summary.total, 1);
    assert.equal(summary.live, 0);
    assert.equal(summary.executionEnabled, false);
  });

  it("detects execution only from executable operations", () => {
    assert.equal(
      summarizeAgents([agent({ supportedOperations: ["noop"] })]).executionEnabled,
      false,
    );
    assert.equal(
      summarizeAgents([agent({ supportedOperations: ["noop", "renew"] })])
        .executionEnabled,
      true,
    );
  });

  it("flags agents registered since the wizard started", () => {
    const summary = summarizeAgents(
      [
        agent({ id: "a", createdAt: "2026-10-19T09:00:00.000Z" }),
        agent({ id: "b", createdAt: "2026-10-19T11:00:00.000Z" }),
      ],
      { since: "2026-10-19T10:00:00.000Z" },
    );
    assert.equal(summary.registeredSinceToken, 1);
  });

  it("exposes only safe fields", () => {
    const [item] = summarizeAgents([
      agent({ pinnedSigningKeyId: "secret-ish", credential: "x" }),
    ]).items;
    assert.equal(item.pinnedSigningKeyId, undefined);
    assert.equal(item.credential, undefined);
    assert.equal(item.hostname, "web-01");
  });
});

describe("loadAdcsReality", () => {
  it("counts only enrollments that reached the install step", async () => {
    const answers = [
      { rows: [] },
      { rows: [{ n: 1 }] },
      { rows: [{ installed: 2 }] },
      { rows: [] },
    ];
    const pool = { query: async () => answers.shift() };
    const adcs = await loadAdcsReality(pool, "w");
    assert.equal(adcs.profiles, 1);
    assert.equal(adcs.installedEnrollments, 2);
    assert.deepEqual(adcs.enrollments, {
      overdue: { count: 0, oldestDueAt: null },
    });
  });
});

const NOW = Date.parse("2026-10-21T12:00:00.000Z");
const minutesAgo = (m) => new Date(NOW - m * 60 * 1000).toISOString();
const snapshotBytes = (pollInterval) =>
  Buffer.from(JSON.stringify(pollInterval === undefined ? {} : { pollInterval }));

describe("loadOverdueEnrollments", () => {
  it("returns zero for an empty workspace", async () => {
    const pool = { query: async () => ({ rows: [] }) };
    assert.deepEqual(await loadOverdueEnrollments(pool, "w", { now: NOW }), {
      count: 0,
      oldestDueAt: null,
    });
  });

  it("scopes by workspace and excludes active jobs, human waits and future polls", async () => {
    let seen;
    const pool = {
      query: async (sql, params) => {
        seen = { sql, params };
        return { rows: [] };
      },
    };
    await loadOverdueEnrollments(pool, "w1", { now: NOW });
    assert.equal(seen.params[0], "w1");
    assert.ok(seen.params[1].includes("pending_issuance"));
    assert.ok(!seen.params[1].includes("installed"));
    assert.equal(seen.params[2].toISOString(), minutesAgo(5));
    assert.ok(seen.params[3].includes("pending_approval"));
    assert.match(seen.sql, /e\.workspace_id = \$1/);
    assert.match(seen.sql, /next_poll_at <= \$3/);
    assert.match(seen.sql, /operator_request_id IS NOT NULL/);
  });

  it("applies twice the snapshot poll interval with a five minute floor", async () => {
    const pool = {
      query: async () => ({
        rows: [
          // Default 900 s interval: grace is 30 min. 20 min late is not overdue.
          { next_poll_at: minutesAgo(20), snapshot_bytes: snapshotBytes() },
          // 60 s interval: grace is the 5 min floor. 6 min late is overdue.
          { next_poll_at: minutesAgo(6), snapshot_bytes: snapshotBytes(60) },
          // Default interval, 45 min late is overdue and the oldest.
          { next_poll_at: minutesAgo(45), snapshot_bytes: snapshotBytes(900) },
          // Unreadable snapshot falls back to the default interval.
          { next_poll_at: minutesAgo(31), snapshot_bytes: Buffer.from("nope") },
        ],
      }),
    };
    assert.deepEqual(await loadOverdueEnrollments(pool, "w", { now: NOW }), {
      count: 3,
      oldestDueAt: minutesAgo(45),
    });
  });
});

describe("loadOutboxBacklog", () => {
  it("returns zero and no timestamp when nothing is waiting", async () => {
    const pool = { query: async () => ({ rows: [{ n: 0, oldest: null }] }) };
    assert.deepEqual(await loadOutboxBacklog(pool, "w", { now: NOW }), {
      count: 0,
      oldestAt: null,
    });
  });

  it("reports the count and oldest due time, scoped and with a five minute cutoff", async () => {
    let seen;
    const pool = {
      query: async (sql, params) => {
        seen = { sql, params };
        return { rows: [{ n: 3, oldest: new Date(NOW - 3600000) }] };
      },
    };
    assert.deepEqual(await loadOutboxBacklog(pool, "w1", { now: NOW }), {
      count: 3,
      oldestAt: minutesAgo(60),
    });
    assert.equal(seen.params[0], "w1");
    assert.equal(seen.params[1].toISOString(), minutesAgo(5));
    assert.match(seen.sql, /status = 'pending'/);
    assert.match(seen.sql, /next_retry_at <= \$2/);
    assert.match(seen.sql, /claimed_until IS NULL OR claimed_until < \$3/);
  });

  it("is attached to the distribution reality", async () => {
    const answers = [
      { rows: [{ groups: 1, bindings: 0, verified_rollouts: 0 }] },
      { rows: [{ n: 2, oldest: minutesAgo(10) }] },
    ];
    const pool = { query: async () => answers.shift() };
    const distribution = await loadDistributionReality(pool, "w", { now: NOW });
    assert.equal(distribution.groups, 1);
    assert.equal(distribution.verified, false);
    assert.deepEqual(distribution.outboxBacklog, {
      count: 2,
      oldestAt: minutesAgo(10),
    });
  });
});

describe("loadCertopsReality", () => {
  it("lists the clusters whose controller has reported", async () => {
    const pool = {
      query: async () => ({
        rows: [
          {
            cluster_id: "prod-eu",
            last_reported_at: "2026-10-19T10:00:00.000Z",
          },
        ],
      }),
    };
    assert.deepEqual(await loadControllerReality(pool, "w"), {
      clusters: [
        { clusterId: "prod-eu", lastReportedAt: "2026-10-19T10:00:00.000Z" },
      ],
    });
  });
  it("returns null (unknown) when CertOps is not enabled", async () => {
    assert.equal(
      await loadCertopsReality(null, {
        workspaceId: "w",
        role: "admin",
        enabled: false,
      }),
      null,
    );
    assert.equal(
      await loadCertopsReality(null, {
        workspaceId: "w",
        role: "admin",
        enabled: "unknown",
      }),
      null,
    );
  });

  it("does not expose agent topology to viewers", async () => {
    assert.equal(
      await loadCertopsReality(null, {
        workspaceId: "w",
        role: "viewer",
        enabled: true,
      }),
      null,
    );
  });
});

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
  loadSessionCertificates,
  loadJobStatus,
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

  it("marks agents that existed before the session so the guide can offer reuse", () => {
    const { items } = summarizeAgents(
      [
        agent({ id: "old", createdAt: "2026-10-19T09:00:00.000Z" }),
        agent({ id: "new", createdAt: "2026-10-19T11:00:00.000Z" }),
      ],
      { since: "2026-10-19T10:00:00.000Z" },
    );
    assert.equal(items.find((i) => i.id === "old").existedBeforeSession, true);
    assert.equal(items.find((i) => i.id === "new").existedBeforeSession, false);
    assert.equal(
      items.find((i) => i.id === "old").createdAt,
      "2026-10-19T09:00:00.000Z",
    );
  });

  it("never claims an agent pre-dates a session it cannot date", () => {
    const [item] = summarizeAgents([
      agent({ createdAt: "2026-10-19T09:00:00.000Z" }),
    ]).items;
    assert.equal(item.existedBeforeSession, false);
  });

  it("reports platform and capabilities per agent so a pick can be scoped", () => {
    const { items } = summarizeAgents([
      agent({
        id: "win",
        platform: "win32",
        declaredCapabilities: ["windows-cert-store-v1", "adcs-enroll-v1"],
      }),
      agent({ id: "lin", platform: "linux" }),
    ]);
    const win = items.find((i) => i.id === "win");
    assert.equal(win.platform, "win32");
    assert.deepEqual(win.declaredCapabilities, [
      "windows-cert-store-v1",
      "adcs-enroll-v1",
    ]);
    assert.equal(items.find((i) => i.id === "lin").platform, "linux");
    assert.deepEqual(items.find((i) => i.id === "lin").declaredCapabilities, []);
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

describe("loadAdcsReality issuer facts", () => {
  it("reports why a check failed without exposing the raw preflight", async () => {
    const issuerRow = {
      id: "i1",
      name: "Corp CA",
      confirmed: false,
      current_version: 0,
      last_preflight: {
        caConfig: "ca01.corp.example.com\\Corp CA",
        template: "WebServer",
        templateCheck: { verdict: "unsafe", reasons: ["template_not_found"] },
        caCheck: { verdict: "safe", reasons: [] },
        caCertificates: [{ keySha256: "secret-ish" }],
      },
    };
    const answers = [
      { rows: [issuerRow, { id: "i2", name: "Draft", current_version: 0, last_preflight: null }] },
      { rows: [{ n: 0 }] },
      { rows: [{ installed: 0 }] },
      { rows: [] },
    ];
    const pool = { query: async () => answers.shift() };
    const { issuers } = await loadAdcsReality(pool, "w");
    assert.deepEqual(issuers[0], {
      id: "i1",
      name: "Corp CA",
      confirmed: false,
      safe: false,
      configured: false,
      checked: true,
      caConfig: "ca01.corp.example.com\\Corp CA",
      template: "WebServer",
      reasons: ["template_not_found"],
      createdAt: null,
      existedBeforeSession: false,
      profileCount: 0,
      attachedCertificates: 0,
      revalidationRequired: false,
      checkedAfterPin: null,
    });
    assert.equal(issuers[1].checked, false);
    assert.deepEqual(issuers[1].reasons, []);
    assert.equal(issuers[1].caConfig, null);
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

describe("session certificates", () => {
  const JOB = "11111111-1111-1111-1111-111111111111";

  it("reads the managed certificate and token of a job", async () => {
    let sql = "";
    const pool = {
      query: async (text) => {
        sql = text;
        return {
          rows: [
            {
              id: JOB,
              operation: "issue",
              status: "succeeded",
              mode: "real",
              certificate_status: "active",
              certificate_id: "22222222-2222-2222-2222-222222222222",
              certificate_token_id: 97,
            },
          ],
        };
      },
    };
    const job = await loadJobStatus(pool, "w", JOB);
    assert.equal(job.certificateId, "22222222-2222-2222-2222-222222222222");
    assert.equal(job.tokenId, 97);
    assert.match(sql, /mc\.token_id/);
  });

  it("reports no token while the certificate has none", async () => {
    const pool = {
      query: async () => ({
        rows: [{ id: JOB, certificate_id: "c1", certificate_token_id: null }],
      }),
    };
    assert.equal((await loadJobStatus(pool, "w", JOB)).tokenId, null);
  });

  it("collects job certificates once and tags their source", async () => {
    const pool = { query: async () => ({ rows: [] }) };
    const out = await loadSessionCertificates(pool, "w", {
      jobs: [
        { job: { certificateId: "c1", tokenId: 5 }, source: "issue" },
        { job: { certificateId: "c1", tokenId: 5 }, source: "publish" },
        { job: { certificateId: "c2", tokenId: null }, source: "publish" },
        { job: null, source: "issue" },
      ],
    });
    assert.deepEqual(out, [
      { certificateId: "c1", tokenId: 5, source: "issue" },
      { certificateId: "c2", tokenId: null, source: "publish" },
    ]);
  });

  it("adds enrollments started since the session began, scoped to the workspace", async () => {
    const seen = [];
    const pool = {
      query: async (sql, params) => {
        seen.push({ sql, params });
        return { rows: [{ certificate_id: "c9", token_id: 41 }] };
      },
    };
    const since = "2026-10-22T10:00:00.000Z";
    const out = await loadSessionCertificates(pool, "w", { since });
    assert.deepEqual(out, [
      { certificateId: "c9", tokenId: 41, source: "enrollment" },
    ]);
    assert.deepEqual(seen[0].params, ["w", since]);
    assert.match(seen[0].sql, /e\.workspace_id = \$1/);
  });

  it("does not query enrollments without a session start", async () => {
    let asked = false;
    const pool = {
      query: async () => {
        asked = true;
        return { rows: [] };
      },
    };
    assert.deepEqual(await loadSessionCertificates(pool, "w", {}), []);
    assert.equal(asked, false);
  });
});

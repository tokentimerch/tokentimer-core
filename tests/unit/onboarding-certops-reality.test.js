const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  summarizeAgents,
  loadCertopsReality,
  loadControllerReality,
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

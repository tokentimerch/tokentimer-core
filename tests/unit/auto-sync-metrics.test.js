"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { Registry } = require("../../apps/api/node_modules/prom-client");
const { pool } = require("../../apps/api/db/database");
const { registerAutoSyncMetrics } = require("../../apps/api/services/autoSyncMetrics");

function mockCreation(t, query) { return t.mock.method(pool, "query", sql => sql.includes("auto_sync_provider_stats") ? query(sql) : Promise.resolve({ rows: [] })); }

const metricName = "auto_sync_items_created_total";

describe("durable run outcome and freshness collectors", () => {
  it("preserves stored providers, zeros all outcomes, and reads fresh values after restart", async (t) => {
    let total = "4";
    t.mock.method(pool, "query", async sql => ({ rows: sql.includes("outcome_stats")
      ? [{ provider: "vault", status: "partial", value: total }]
      : sql.includes("run_freshness") ? [{ provider: "vault", value: "1793000000.5" }] : [] }));
    for (const expected of [4, 5]) {
      const registry = new Registry();
      registerAutoSyncMetrics(registry);
      registerAutoSyncMetrics(registry);
      const metrics = await registry.getMetricsAsJSON();
      const outcomes = metrics.find(m => m.name === "auto_sync_run_outcomes_total");
      assert.equal(outcomes.values.length, 9);
      assert.equal(outcomes.values.find(s => s.labels.provider === "vault").value, expected);
      assert.ok(outcomes.values.filter(s => s.labels.provider === "github").every(s => s.value === 0));
      assert.equal(metrics.find(m => m.name === "auto_sync_last_success_timestamp_seconds").values.find(s => s.labels.provider === "vault").value, 1793000000.5);
      total = "5";
    }
  });

  for (const invalid of [null, "", "-1", "NaN", "9007199254740992", "1.5"]) {
    it(`rejects invalid outcome total ${JSON.stringify(invalid)}`, async (t) => {
      t.mock.method(pool, "query", async sql => ({ rows: sql.includes("outcome_stats")
        ? [{ provider: "github", status: "success", value: invalid }] : [] }));
      const registry = new Registry();
      registerAutoSyncMetrics(registry);
      await assert.rejects(registry.metrics(), /Invalid auto-sync run metric/);
    });
  }

  it("rejects freshness database failures rather than publishing stale success", async (t) => {
    t.mock.method(pool, "query", async sql => {
      if (sql.includes("run_freshness")) throw new Error("freshness unavailable");
      return { rows: [] };
    });
    const registry = new Registry();
    registerAutoSyncMetrics(registry);
    await assert.rejects(registry.metrics(), /freshness unavailable/);
  });
});

async function values(registry) {
  const metric = (await registry.getMetricsAsJSON()).find(
    (entry) => entry.name === metricName,
  );
  assert.ok(metric, "creation counter is registered");
  assert.equal(metric.type, "counter");
  return Object.fromEntries(
    metric.values.map((sample) => [sample.labels.provider, sample.value]),
  );
}

describe("durable auto-sync creation metric collector", { concurrency: false }, () => {
  it("exposes zero before any sync or provider statistics exist", async (t) => {
    const query = mockCreation(t, async () => ({ rows: [] }));
    const registry = new Registry();
    registerAutoSyncMetrics(registry);

    assert.deepEqual(await values(registry), { github: 0, gitlab: 0 });
    assert.equal(query.mock.callCount(), 4);
    assert.match(await registry.metrics(), new RegExp(`# TYPE ${metricName} counter`));
  });

  it("adds configured Enterprise zero labels and preserves stored provider totals", async (t) => {
    mockCreation(t, async () => ({
      rows: [{ provider: "aws", items_created_total: "7" }],
    }));
    const registry = new Registry();
    registerAutoSyncMetrics(registry, {
      providers: ["github", "gitlab", "vault", "azure", "gcp"],
    });

    assert.deepEqual(await values(registry), {
      github: 0,
      gitlab: 0,
      vault: 0,
      azure: 0,
      gcp: 0,
      aws: 7,
    });
  });

  it("exposes the counter under OpenMetrics without a doubled total suffix", async (t) => {
    mockCreation(t, async () => ({
      rows: [{ provider: "gitlab", items_created_total: "23" }],
    }));
    const registry = new Registry(Registry.OPENMETRICS_CONTENT_TYPE);
    registerAutoSyncMetrics(registry);

    for (let i = 0; i < 2; i++) {
      const body = await registry.metrics();
      assert.match(body, /^# TYPE auto_sync_items_created counter$/m);
      assert.match(body, /^auto_sync_items_created_total\{provider="gitlab"\} 23$/m);
      assert.doesNotMatch(body, /auto_sync_items_created_total_total/);
      assert.match(body, /# EOF\n$/);
    }
  });

  it("reads cumulative snapshots without adding them again, including after restart", async (t) => {
    let total = "11";
    mockCreation(t, async () => ({
      rows: [{ provider: "gitlab", items_created_total: total }],
    }));
    const registry = new Registry();
    registerAutoSyncMetrics(registry);

    assert.equal((await values(registry)).gitlab, 11);
    assert.equal((await values(registry)).gitlab, 11);
    total = "13";
    assert.equal((await values(registry)).gitlab, 13);

    const restartedRegistry = new Registry();
    registerAutoSyncMetrics(restartedRegistry);
    assert.equal((await values(restartedRegistry)).gitlab, 13);
  });

  it("keeps concurrent scrape snapshots independent when DB replies arrive out of order", async (t) => {
    const replies = [];
    mockCreation(t, () => new Promise((resolve) => replies.push(resolve)));
    const registry = new Registry();
    registerAutoSyncMetrics(registry);

    const earlier = values(registry);
    const later = values(registry);
    assert.equal(replies.length, 2);
    replies[1]({ rows: [{ provider: "gitlab", items_created_total: "15" }] });
    assert.equal((await later).gitlab, 15);
    replies[0]({ rows: [{ provider: "gitlab", items_created_total: "14" }] });
    assert.equal((await earlier).gitlab, 14);
  });

  it("rejects a failed DB read instead of exposing zero or a cached successful value", async (t) => {
    let failed = false;
    mockCreation(t, async () => {
      if (failed) throw new Error("statistics database unavailable");
      return { rows: [{ provider: "gitlab", items_created_total: "19" }] };
    });
    const registry = new Registry();
    registerAutoSyncMetrics(registry);

    assert.equal((await values(registry)).gitlab, 19);
    failed = true;
    await assert.rejects(registry.metrics(), /statistics database unavailable/);
    failed = false;
    assert.equal((await values(registry)).gitlab, 19);
  });

  for (const invalid of ["-1", "invalid", "Infinity"]) {
    it(`rejects invalid persisted counter value ${invalid}`, async (t) => {
      mockCreation(t, async () => ({
        rows: [{ provider: "gitlab", items_created_total: invalid }],
      }));
      const registry = new Registry();
      registerAutoSyncMetrics(registry);

      await assert.rejects(registry.metrics());
    });
  }
});

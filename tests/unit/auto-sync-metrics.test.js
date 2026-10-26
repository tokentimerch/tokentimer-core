"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { Registry } = require("../../apps/api/node_modules/prom-client");
const { pool } = require("../../apps/api/db/database");
const { registerAutoSyncMetrics } = require("../../apps/api/services/autoSyncMetrics");

const metricName = "auto_sync_items_created_total";

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
    const query = t.mock.method(pool, "query", async () => ({ rows: [] }));
    const registry = new Registry();
    registerAutoSyncMetrics(registry);

    assert.deepEqual(await values(registry), { github: 0, gitlab: 0 });
    assert.equal(query.mock.callCount(), 1);
    assert.match(await registry.metrics(), new RegExp(`# TYPE ${metricName} counter`));
  });

  it("adds configured Enterprise zero labels and preserves stored provider totals", async (t) => {
    t.mock.method(pool, "query", async () => ({
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
    t.mock.method(pool, "query", async () => ({
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
    t.mock.method(pool, "query", async () => ({
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
    t.mock.method(pool, "query", () => new Promise((resolve) => replies.push(resolve)));
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
    t.mock.method(pool, "query", async () => {
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
      t.mock.method(pool, "query", async () => ({
        rows: [{ provider: "gitlab", items_created_total: invalid }],
      }));
      const registry = new Registry();
      registerAutoSyncMetrics(registry);

      await assert.rejects(registry.metrics());
    });
  }
});

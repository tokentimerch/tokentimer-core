"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const metrics = require("../../apps/api/services/autoSyncMetricLabels");
const migration = fs.readFileSync(path.join(__dirname, "../../apps/api/migrations/082-auto-sync-system-metrics.sql"), "utf8");
const defaults = JSON.parse(migration.match(/SET DEFAULT\s*'([^']+)'::jsonb/)[1]);

test("the runtime accepts and retains the metric defaults installed by migration 82", () => {
  assert.equal(metrics.metricSettingsError(defaults), null);
  assert.deepEqual(metrics.normalizeMetricSettings(defaults), defaults);
  assert.ok(metrics.metricSettingsError({ ...defaults, inherit_system: "true" }));
  assert.ok(metrics.metricSettingsError({ ...defaults, unknown: true }));
});

test("creation accounting accepts migrated defaults and honors the stored operator policy", async () => {
  const writes = [];
  const client = { query: async (sql, values) => { writes.push({ sql, values }); return { rows: [] }; } };
  const policy = { override_metrics: true, enabled: true, labels: ["kind"], override_monitoring_group: false };
  await metrics.recordCreationMetrics(client, { provider: "vault", configId: "configuration" },
    { source_kind: "vault-kv", name: "private-asset", source_dimensions: { project: "private-project" } }, defaults, policy);
  assert.equal(writes.length, 2);
  assert.deepEqual(writes[0].values, ["vault", "vault-kv"]);
  assert.deepEqual(writes[1].values.slice(0, 5), ["configuration", "vault-kv", "", "", ""]);
  assert.deepEqual(metrics.effectiveMetricSettings(defaults, {}, policy), { ...defaults, enabled: true, labels: ["kind"] });
});

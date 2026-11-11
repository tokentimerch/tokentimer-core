"use strict";
const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const { normalizeMetricSettings, metricSettingsError, creationDimensions, metricSourceDimensions, permittedExtraLabels } = require("../../apps/api/services/autoSyncMetricLabels");
describe("selectable auto-sync metric metadata", () => {
  it("defaults to no detailed exposure and validates an explicit label allowlist", () => {
    assert.deepEqual(normalizeMetricSettings(), { enabled: false, labels: [], monitoring_group: "" });
    assert.equal(metricSettingsError({ enabled: true, labels: ["asset_name", "project", "kind"], monitoring_group: "critical" }), null);
    for (const invalid of [null, [], { enabled: "true" }, { labels: ["token"] }, { labels: ["kind", "kind"] }, { credentials: "secret" }, { monitoring_group: "x\nsecret" }, { monitoring_group: "x".repeat(65) }]) assert.ok(metricSettingsError(invalid));
  });
  it("captures names/project/group only when their exposure was explicitly enabled", () => {
    const payload = { name: "deploy", source_kind: "gitlab-project-token", source_dimensions: { project: "platform/backend", group: "platform", token: "must-not-appear" } };
    assert.deepEqual(creationDimensions(payload), { kind: "gitlab-project-token", asset_name: "", project: "", group: "" });
    const settings = { enabled: true, labels: ["asset_name", "project"] };
    assert.deepEqual(creationDimensions(payload, settings, { AUTO_SYNC_METRICS_EXTRA_LABELS: "asset_name,project,group" }), { kind: "gitlab-project-token", asset_name: "deploy", project: "platform/backend", group: "" });
    assert.equal(creationDimensions({ ...payload, source_kind: "user-controlled-kind" }, settings, { AUTO_SYNC_METRICS_EXTRA_LABELS: "asset_name,project,group" }).kind, "other");
    assert.equal(JSON.stringify(creationDimensions(payload, settings, { AUTO_SYNC_METRICS_EXTRA_LABELS: "asset_name,project,group" })).includes("must-not-appear"), false);
  });
  it("selects only non-secret scanner scope metadata and preserves full repository paths", () => {
    assert.deepEqual(metricSourceDimensions({ project_path: "platform/backend", project_name: "backend", group_path: "platform", token: "secret" }), { project: "platform/backend", group: "platform" });
    assert.deepEqual(metricSourceDimensions({ repository: "org/repo" }), { project: "org/repo", group: "" });
  });
});

const { Registry } = require("../../apps/api/node_modules/prom-client");
const { pool } = require("../../apps/api/db/database");
const { registerAutoSyncMetrics } = require("../../apps/api/services/autoSyncMetrics");
describe("optional detailed metric collection", () => {
  let previousPolicy;
  beforeEach(() => { previousPolicy = process.env.AUTO_SYNC_METRICS_EXTRA_LABELS; process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "asset_name,project,group"; });
  afterEach(() => { if (previousPolicy === undefined) delete process.env.AUTO_SYNC_METRICS_EXTRA_LABELS; else process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = previousPolicy; });

  const row = { provider: "gitlab", configuration_id: "critical-config", configuration_name: "Critical GitLab",
    kind: "gitlab-project-token", asset_name: "deploy-token", project: "platform/backend", group_name: "platform",
    items_created_total: "2", last_created: "1793000000", metrics_settings: { enabled: true,
      labels: ["configuration_name", "kind", "monitoring_group"], monitoring_group: "critical" } };
  it("aggregates unselected dimensions without leaking asset names and deduplicates registration", async t => {
    t.mock.method(pool, "query", async sql => ({ rows: sql.includes("auto_sync_creation_stats")
      ? [row, { ...row, asset_name: "another-token", items_created_total: "3", last_created: "1793000001" }] : [] }));
    const registry = new Registry(); registerAutoSyncMetrics(registry); registerAutoSyncMetrics(registry);
    const samples = (await registry.getSingleMetric("auto_sync_items_created_detailed_total").get()).values;
    assert.equal(samples.length, 1); assert.equal(samples[0].value, 5);
    assert.equal(samples[0].labels.configuration_id, "critical-config");
    assert.equal(samples[0].labels.monitoring_group, "critical");
    assert.equal(samples[0].labels.asset_name, ""); assert.equal(samples[0].labels.project, "");
    assert.equal((await registry.getSingleMetric("auto_sync_last_creation_timestamp_seconds").get()).values[0].value, 1793000001);
  });
  it("exposes only explicitly selected metadata and removes it on the next scrape after opt-out", async t => {
    let settings = { enabled: true, labels: ["asset_name", "project", "group"] };
    t.mock.method(pool, "query", async () => ({ rows: [{ ...row, metrics_settings: settings }] }));
    const registry = new Registry(); registerAutoSyncMetrics(registry);
    const collector = registry.getSingleMetric("auto_sync_items_created_detailed_total");
    const labels = (await collector.get()).values[0].labels;
    assert.equal(labels.asset_name, "deploy-token"); assert.equal(labels.project, "platform/backend"); assert.equal(labels.group, "platform");
    assert.equal(labels.configuration_name, "");
    settings = { enabled: false, labels: ["asset_name", "project"] };
    assert.deepEqual((await collector.get()).values, []);
  });
  it("keeps configurations separate even with identical names and gives label selection a new series", async t => {
    t.mock.method(pool, "query", async () => ({ rows: [row, { ...row, configuration_id: "other-config" }] }));
    const registry = new Registry(); registerAutoSyncMetrics(registry);
    const values = (await registry.getSingleMetric("auto_sync_items_created_detailed_total").get()).values;
    assert.equal(values.length, 2); assert.notEqual(values[0].labels.configuration_id, values[1].labels.configuration_id);
    assert.ok(values[0].labels.label_set.includes("kind"));
  });
  it("rejects invalid counter/timestamp reads instead of serving a cached value", async t => {
    let invalid = { ...row, items_created_total: "-1" };
    t.mock.method(pool, "query", async () => ({ rows: [invalid] }));
    const registry = new Registry(); registerAutoSyncMetrics(registry);
    await assert.rejects(registry.getSingleMetric("auto_sync_items_created_detailed_total").get(), /counter/);
    invalid = { ...row, last_created: "invalid" };
    await assert.rejects(registry.getSingleMetric("auto_sync_last_creation_timestamp_seconds").get(), /timestamp/);
  });
  it("defaults high-cardinality labels off and suppresses saved names even if a client opted in", async t => {
    assert.deepEqual(permittedExtraLabels({ AUTO_SYNC_METRICS_EXTRA_LABELS: "project,unknown,project" }), ["project"]);
    const partial = creationDimensions({ name: "secret-name", source_kind: "gitlab-pat", source_dimensions: { project: "allowed", group: "hidden" } }, { enabled: true, labels: ["asset_name", "project", "group"] }, { AUTO_SYNC_METRICS_EXTRA_LABELS: "project" });
    assert.deepEqual(partial, { kind: "gitlab-pat", asset_name: "", project: "allowed", group: "" });
    assert.deepEqual(permittedExtraLabels({}), []);
    assert.deepEqual(permittedExtraLabels({ AUTO_SYNC_METRICS_EXTRA_LABELS: "TRUE" }), []);
    assert.deepEqual(permittedExtraLabels({ AUTO_SYNC_METRICS_EXTRA_LABELS: "asset_name,project,group" }), ["asset_name", "project", "group"]);
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "false";
    const selected = { enabled: true, labels: ["asset_name", "project", "group", "kind", "monitoring_group"], monitoring_group: "critical" };
    t.mock.method(pool, "query", async () => ({ rows: [{ ...row, metrics_settings: selected }] }));
    const registry = new Registry(); registerAutoSyncMetrics(registry);
    const collector = registry.getSingleMetric("auto_sync_items_created_detailed_total");
    const labels = (await collector.get()).values[0].labels;
    assert.equal(labels.asset_name, ""); assert.equal(labels.project, ""); assert.equal(labels.group, "");
    assert.equal(labels.kind, "gitlab-project-token"); assert.equal(labels.monitoring_group, "critical");
    assert.equal(labels.label_set, "kind,monitoring_group");
    assert.deepEqual(creationDimensions({ name: "private-name", source_kind: "gitlab-project-token", source_dimensions: { project: "private-project", group: "private-group" } }, selected),
      { kind: "gitlab-project-token", asset_name: "", project: "", group: "" });
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "asset_name,project,group";
    assert.equal((await collector.get()).values[0].labels.asset_name, "deploy-token");
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "false";
    assert.equal((await collector.get()).values[0].labels.asset_name, "");
  });

});

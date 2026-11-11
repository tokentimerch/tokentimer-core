"use strict";

const { test, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const labels = require("../../apps/api/services/autoSyncMetricLabels");
const { pool } = require("../../apps/api/db/database");
const { persistScan } = require("../../apps/api/services/integrationScans");
const { bindImportItemsToScan } = require("../../apps/api/services/scanBinding");
const { registerAutoSyncDetailMetrics } = require("../../apps/api/services/autoSyncDetailMetrics");

const previous = Object.fromEntries(
  ["AUTO_SYNC_METRICS_ENABLED", "AUTO_SYNC_METRICS_LABELS", "AUTO_SYNC_METRICS_EXTRA_LABELS"]
    .map(key => [key, process.env[key]]),
);
beforeEach(() => {
  for (const key of Object.keys(previous)) delete process.env[key];
});
afterEach(() => {
  for (const [key, value] of Object.entries(previous)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});
const selected = { enabled: true, labels: ["kind", "owner_username"] };
const allowed = { AUTO_SYNC_METRICS_EXTRA_LABELS: "owner_username" };
const payload = {
  source_provider: "gitlab", source_kind: "gitlab-pat",
  source_dimensions: { owner_username: "alice" },
};
const legacy = { kind: "gitlab-pat", asset_name: "", project: "", group: "" };
const hash = value => createHash("sha256").update(JSON.stringify(value)).digest("hex");

test("owner is a validated optional high-cardinality label requiring effective opt-in", () => {
  assert.ok(labels.OPTIONAL_LABELS.includes("owner_username"));
  assert.ok(labels.HIGH_CARDINALITY_LABELS.includes("owner_username"));
  assert.equal(labels.metricSettingsError(selected), null);
  assert.ok(labels.metricSettingsError({ ...selected, labels: ["owner_username", "owner_username"] }));
  assert.deepEqual(labels.permittedExtraLabels({}), []);
  assert.deepEqual(labels.permittedExtraLabels(allowed), ["owner_username"]);
  assert.deepEqual(labels.creationDimensions(payload, selected, allowed), {
    ...legacy, owner_username: "alice",
  });
  for (const [settings, env, policy] of [
    [undefined, allowed],
    [{ ...selected, enabled: false }, allowed],
    [{ enabled: true, labels: ["kind"] }, allowed],
    [selected, {}],
    [selected, { AUTO_SYNC_METRICS_EXTRA_LABELS: "none" }],
    [selected, allowed, { override_metrics: true, enabled: false, labels: ["owner_username"] }],
    [selected, { ...allowed, AUTO_SYNC_METRICS_ENABLED: "true", AUTO_SYNC_METRICS_LABELS: "kind" }],
  ]) {
    const dimensions = labels.creationDimensions(payload, settings, env, policy);
    assert.deepEqual(dimensions, legacy);
    assert.equal(hash(dimensions), hash(legacy));
  }
  assert.equal(labels.creationDimensions(payload, { enabled: false, labels: [] }, allowed, {
    override_metrics: true, enabled: true, labels: ["owner_username"],
  }).owner_username, "alice");
});

test("owner permission never selects owners for a saved global kind-only override", () => {
  const stored = { override_metrics: true, enabled: true, labels: ["kind"] };
  for (const env of [allowed, { AUTO_SYNC_METRICS_EXTRA_LABELS: "project,owner_username" }]) {
    const policy = labels.systemMetricPolicy(stored, env);
    assert.ok(!policy.labels.includes("owner_username"));
    assert.deepEqual(labels.creationDimensions(payload, selected, env, stored), legacy);
    assert.equal(policy.labels.includes("project"), env.AUTO_SYNC_METRICS_EXTRA_LABELS.includes("project"));
  }
  const globalOwner = { ...stored, labels: ["kind", "owner_username"] };
  assert.equal(labels.creationDimensions(payload, { enabled: false }, {}, globalOwner).owner_username, "alice");
  assert.deepEqual(labels.creationDimensions(payload, selected, {}, stored), legacy);
  assert.deepEqual(labels.creationDimensions(payload, selected, {}), legacy);
});

test("only structured PAT owners survive source selection and creation dimensions", () => {
  for (const kind of ["gitlab-project-token", "gitlab-group-token", "gitlab-deploy-token", "gitlab-trigger-token", "gitlab-ssh-key", "github-secret", undefined]) {
    const dimensions = labels.metricSourceDimensions({
      sourceKind: kind, owner_username: "alice", gitlab_owner: "other",
    });
    assert.equal(Object.hasOwn(dimensions, "owner_username"), false);
    assert.equal(Object.hasOwn(labels.creationDimensions({
      ...payload, source_kind: kind,
    }, selected, allowed), "owner_username"), false);
  }
  assert.equal(labels.creationDimensions({
    ...payload, source_provider: "github",
  }, selected, allowed).owner_username, undefined);
  for (const owner of [undefined, null, "", 42, {}, "x".repeat(513)]) {
    assert.equal(Object.hasOwn(labels.metricSourceDimensions({
      sourceKind: "gitlab-pat", owner_username: owner, used_by: "alice",
      location: "gitlab:users/alice/personal_access_tokens/1", name: "alice (Admin)",
    }), "owner_username"), false);
    assert.deepEqual(labels.creationDimensions({
      ...payload, source_dimensions: { owner_username: owner },
    }, selected, allowed), legacy);
  }
  const owner = '界"\\\n'.repeat(100);
  assert.equal(labels.metricSourceDimensions({
    sourceKind: "gitlab-pat", owner_username: owner,
  }).owner_username, owner);
});

test("statistics bind owner as the seventh parameter and preserve legacy hashes when absent", async () => {
  process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "owner_username";
  const calls = [];
  const client = { query: async (sql, params) => { calls.push({ sql, params }); } };
  for (const [settings, expected] of [[selected, "alice"], [{ enabled: false }, ""]]) {
    await labels.recordCreationMetrics(client, { provider: "gitlab", configId: "config" }, payload, settings);
    const insert = calls.at(-1);
    assert.match(insert.sql, /dimension_key, owner_username/);
    assert.equal(insert.params[6], expected);
    assert.equal(insert.params[5], hash(expected ? { ...legacy, owner_username: expected } : legacy));
  }
});

test("collectors hide unknown, non-PAT, non-GitLab and unselected owners on every scrape", async t => {
  process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "owner_username";
  let settings = selected;
  const originalRows = [
    { provider: "gitlab", kind: "gitlab-pat", owner_username: "alice" },
    { provider: "gitlab", kind: "gitlab-pat", owner_username: "" },
    { provider: "gitlab", kind: "gitlab-project-token", owner_username: "spoof" },
    { provider: "github", kind: "gitlab-pat", owner_username: "spoof" },
  ];
  let rows = originalRows;
  t.mock.method(pool, "query", async () => ({ rows: rows.map((row, i) => ({
    configuration_id: `config-${i}`, configuration_name: "same",
    asset_name: "", project: "", group_name: "", items_created_total: "2",
    last_created: "1793000000", ...row, metrics_settings: settings,
  })) }));
  const registry = new Map();
  registerAutoSyncDetailMetrics({
    getSingleMetric: name => registry.get(name),
    registerMetric: metric => registry.set(metric.name, metric),
  }, ["gitlab"]);
  for (const name of ["auto_sync_items_created_detailed_total", "auto_sync_last_creation_timestamp_seconds"]) {
    rows = originalRows;
    const collector = registry.get(name);
    let samples = (await collector.get()).values;
    assert.deepEqual(samples.map(sample => sample.labels.owner_username), ["alice", "", "", ""]);
    settings = { ...selected, labels: ["kind"] };
    assert.ok((await collector.get()).values.every(sample => sample.labels.owner_username === ""));
    settings = selected;
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "none";
    assert.ok((await collector.get()).values.every(sample => sample.labels.owner_username === ""));
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "owner_username";
    settings = { ...selected, enabled: false };
    assert.deepEqual((await collector.get()).values, []);
    settings = selected;
    rows = [rows[0], { ...rows[0] }];
    samples = (await collector.get()).values;
    assert.equal(samples.length, 2, "configuration IDs keep identical owners separate");
  }
});

test("scan persistence captures owners only within a current opted-in GitLab fence", async t => {
  process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = "owner_username";
  const id = "11111111-1111-4111-8111-111111111111";
  let configSettings = selected, policy = {}, stale = false;
  const writes = [];
  const client = {
    release() {},
    async query(sql, params) {
      if (sql.includes("FROM auto_sync_configs c")) {
        return { rows: stale ? [] : [{ metrics_settings: configSettings, system_metric_policy: policy }] };
      }
      if (sql.includes("INSERT INTO integration_scans")) {
        return { rows: [{ id, started_at: new Date("2026-11-11") }] };
      }
      if (sql.includes("INSERT INTO integration_scan_items")) writes.push(params);
      return { rows: [], rowCount: 0 };
    },
  };
  t.mock.method(pool, "connect", async () => client);
  const options = {
    workspaceId: id, provider: "gitlab", identityContext: { host: "gitlab.example", ownerKey: "17" },
    items: [
      { sourceKind: "gitlab-pat", sourceObjectId: "1", dimensions: { project: "p", owner_username: "alice" } },
      { sourceKind: "gitlab-project-token", sourceObjectId: "2", dimensions: { owner_username: "spoof" } },
    ],
    subScopes: [],
    request: { isWorkerCall: true, body: { auto_sync_run: {
      config_id: id, run_id: id, lease_owner: id, generation: 1, scan_version: 1,
    } } },
  };
  await persistScan(options);
  assert.deepEqual(writes.at(-1)[3], { project: "p", owner_username: "alice" });
  assert.deepEqual(writes.at(-1)[7], {});
  for (const scenario of ["disabled", "unselected", "disallowed", "global-disable", "manual"]) {
    configSettings = scenario === "disabled" ? { ...selected, enabled: false }
      : scenario === "unselected" ? { enabled: true, labels: ["kind"] } : selected;
    policy = scenario === "global-disable"
      ? { override_metrics: true, enabled: false, labels: ["owner_username"] } : {};
    process.env.AUTO_SYNC_METRICS_EXTRA_LABELS = scenario === "disallowed" ? "none" : "owner_username";
    await persistScan({ ...options, request: scenario === "manual" ? null : options.request });
    assert.deepEqual(writes.at(-1)[3], { project: "p" }, scenario);
  }
  stale = true;
  const count = writes.length;
  await assert.rejects(persistScan(options), { code: "AUTO_SYNC_RUN_STALE" });
  assert.equal(writes.length, count);
});

test("import binding ignores spoofed owner dimensions and rejects unknown scan items", async t => {
  t.mock.method(pool, "query", async sql => ({
    rows: sql.includes("FROM integration_scans")
      ? [{ id: "scan", source_instance: "gitlab.example", source_owner_key: "17", started_at: new Date() }]
      : [{ source_kind: "gitlab-pat", source_object_id: "1", source_dimensions: { owner_username: "authoritative" } }],
  }));
  const binding = await bindImportItemsToScan({
    scanId: "scan", workspaceId: "workspace", provider: "gitlab",
    pairs: [
      { sourceKind: "gitlab-pat", sourceObjectId: "1", owner_username: "spoof", dimensions: { owner_username: "spoof" } },
      { sourceKind: "gitlab-pat", sourceObjectId: "2", owner_username: "spoof" },
    ],
  });
  assert.deepEqual(binding.resolveForItem(0).source_dimensions, { owner_username: "authoritative" });
  assert.equal(binding.resolveForItem(1), null);
  assert.equal((await bindImportItemsToScan({
    workspaceId: "workspace", provider: "gitlab", pairs: [],
  })).resolveForItem(0), null);
});

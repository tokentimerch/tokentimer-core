"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");
const yaml = createRequire(require.resolve("mocha/package.json"))("js-yaml");

test("Core auto-sync Helm examples match the canonical tested Prometheus rules", () => {
  const root = path.resolve(__dirname, "../..");
  const canonical = yaml.load(fs.readFileSync(path.join(root, "deploy/helm/examples/values-auto-sync-alerts.yaml"), "utf8"));
  const rules = canonical.monitoring.prometheusRules;
  for (const file of ["values-full-test.yaml", "values-auto-sync-alerts.yaml"]) {
    const example = yaml.load(fs.readFileSync(path.join(root, "deploy/helm/examples", file), "utf8"));
    assert.equal(example.monitoring.metrics.enabled, true);
    assert.equal(example.monitoring.prometheusRules.enabled, true);
    assert.deepEqual(example.monitoring.prometheusRules.groups.find(group => group.name === "tokentimer.auto-sync"), rules.groups.find(group => group.name === "tokentimer.auto-sync"));
  }
  const standalone = yaml.load(fs.readFileSync(path.join(root, "deploy/prometheus/auto-sync.rules.yaml"), "utf8"));
  assert.deepEqual(standalone.groups, rules.groups);
});

test("critical asset alerts preserve owner identity on both sides without scrape labels", () => {
  const root = path.resolve(__dirname, "../..");
  const example = yaml.load(fs.readFileSync(path.join(root, "deploy/helm/examples/values-auto-sync-alerts.yaml"), "utf8"));
  const rule = example.monitoring.prometheusRules.groups
    .flatMap(group => group.rules).find(rule => rule.alert === "AutoSyncCriticalAssetsCreated");
  const groupings = [...rule.expr.matchAll(/max by \(([^)]+)\)/g)]
    .map(match => match[1].split(",").map(label => label.trim()));
  const expected = ["installation", "namespace", "job", "provider", "configuration_id",
    "configuration_name", "monitoring_group", "kind", "asset_name", "owner_username",
    "project", "group", "label_set"];
  assert.deepEqual(groupings, [expected, expected]);
  assert.match(rule.annotations.description, /\{\{ with \$labels\.owner_username \}\} Owner: \{\{ \. \}\}\.\{\{ end \}\}/);
});

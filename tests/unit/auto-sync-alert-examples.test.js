"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");
const yaml = createRequire(require.resolve("mocha/package.json"))("js-yaml");

test("Core auto-sync Helm examples match the canonical tested Prometheus rules", () => {
  const root = path.resolve(__dirname, "../..");
  const rules = yaml.load(fs.readFileSync(path.join(root, "deploy/prometheus/auto-sync.rules.yaml"), "utf8"));
  for (const file of ["values-full-test.yaml", "values-auto-sync-alerts.yaml"]) {
    const example = yaml.load(fs.readFileSync(path.join(root, "deploy/helm/examples", file), "utf8"));
    assert.equal(example.monitoring.metrics.enabled, true);
    assert.equal(example.monitoring.prometheusRules.enabled, true);
    assert.deepEqual(example.monitoring.prometheusRules.groups.find(group => group.name === "tokentimer.auto-sync"), rules.groups[0]);
  }
});

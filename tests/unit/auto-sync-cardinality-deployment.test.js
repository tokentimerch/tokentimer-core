"use strict";
const { it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");
const yaml = createRequire(require.resolve("mocha/package.json"))("js-yaml");
const root = path.resolve(__dirname, "../..");
const read = name => fs.readFileSync(path.join(root, name), "utf8");
const key = "AUTO_SYNC_METRICS_ALLOW_HIGH_CARDINALITY_LABELS";
it("production and development Compose explicitly default API high-cardinality labels off", () => {
  const production = yaml.load(read("deploy/compose/docker-compose.yml"));
  assert.equal(production.services.api.environment[key], "${" + key + ":-false}");
  const development = yaml.load(read("deploy/compose/docker-compose.dev.yml"));
  assert.ok(development.services.api.environment.includes(key + "=${" + key + ":-false}"));
});
it("Helm defaults the operator gate off and types the setting as a boolean", () => {
  assert.equal(yaml.load(read("deploy/helm/values.yaml")).monitoring.metrics.allowHighCardinalityLabels, false);
  const schema = JSON.parse(read("deploy/helm/values.schema.json")).properties.monitoring.properties.metrics.properties.allowHighCardinalityLabels;
  assert.equal(schema.type, "boolean"); assert.equal(schema.default, false);
  assert.match(read("deploy/helm/templates/_helpers.tpl"), /AUTO_SYNC_METRICS_ALLOW_HIGH_CARDINALITY_LABELS:.*allowHighCardinalityLabels/);
});
it("operator switches carry an adjacent warning about series growth and metadata", () => {
  for (const file of ["deploy/helm/values.yaml", "deploy/compose/docker-compose.yml", "deploy/compose/docker-compose.dev.yml", "deploy/compose/.env.example", ".env.example"]) {
    assert.match(read(file), /# Warning:.*(?:time series|series).*metadata\.\n\s*(?:- )?(?:AUTO_SYNC_METRICS_ALLOW_HIGH_CARDINALITY_LABELS|allowHighCardinalityLabels)/, file);
  }
});

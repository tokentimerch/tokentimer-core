"use strict";
const { it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");
const yaml = createRequire(require.resolve("mocha/package.json"))("js-yaml");
const root = path.resolve(__dirname, "../..");
const read = name => fs.readFileSync(path.join(root, name), "utf8");
const key = "AUTO_SYNC_METRICS_EXTRA_LABELS";
it("production and development Compose default the extra-label allowlist empty", () => {
  const production = yaml.load(read("deploy/compose/docker-compose.yml"));
  assert.equal(production.services.api.environment[key], "${" + key + ":-}");
  const development = yaml.load(read("deploy/compose/docker-compose.dev.yml"));
  assert.ok(development.services.api.environment.includes(key + "=${" + key + ":-}"));
});
it("Helm defaults the extra-label allowlist empty and restricts supported values", () => {
  assert.deepEqual(yaml.load(read("deploy/helm/values.yaml")).monitoring.metrics.extraLabels, []);
  const schema = JSON.parse(read("deploy/helm/values.schema.json")).properties.monitoring.properties.metrics.properties.extraLabels;
  assert.equal(schema.type, "array"); assert.deepEqual(schema.default, []);
  assert.match(read("deploy/helm/templates/_helpers.tpl"), /AUTO_SYNC_METRICS_EXTRA_LABELS:.*extraLabels/);
});
it("operator switches carry an adjacent warning about series growth and metadata", () => {
  for (const file of ["deploy/helm/values.yaml", "deploy/compose/docker-compose.yml", "deploy/compose/docker-compose.dev.yml", "deploy/compose/.env.example", ".env.example"]) {
    assert.match(read(file), /# Extra labels: asset_name, project, group; none disables them\.[^\n]*\n(?:\s*#[^\n]*\n){3}\s*# Each distinct label combination creates a series in both metrics; combining labels can greatly increase cardinality and expose asset metadata\.\n\s*(?:- )?(?:AUTO_SYNC_METRICS_EXTRA_LABELS|extraLabels)/, file);
  }
});

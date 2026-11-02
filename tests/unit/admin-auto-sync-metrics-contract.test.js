"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const Ajv = require("ajv");
const yaml = require(require.resolve("js-yaml", {
  paths: [path.resolve(__dirname, "../../apps/dashboard")],
}));
const { systemMetricSettingsError } = require("../../apps/api/services/autoSyncMetricLabels");
const spec = yaml.load(fs.readFileSync(path.resolve(__dirname, "../../packages/contracts/openapi/openapi.yaml"), "utf8"));
const endpoint = spec.paths["/api/v1/admin/auto-sync/metrics"];
test("admin metric read and write operations retain authenticated response contracts", () => {
  for (const method of ["get", "put"]) {
    const operation = endpoint[method];
    assert.deepEqual(operation.security, [{ cookieAuth: [] }]);
    for (const status of ["200", "401", "403", "500"]) assert.ok(operation.responses[status]);
    const schema = spec.components.schemas.AutoSyncMetricPolicy;
    assert.ok(schema.properties.enabled);
    assert.ok(schema.properties.labels);
  }
  assert.ok(endpoint.put.responses["400"]);
  assert.ok(endpoint.put.parameters.some(row => row.$ref === "#/components/parameters/CsrfTokenHeader"));
});
test("published admin metric request validation matches the route's real settings validator", () => {
  const validate = new Ajv({ strict: false }).compile(endpoint.put.requestBody.content["application/json"].schema);
  const valid = { enabled: true, labels: ["configuration_name", "kind"], override_metrics: false };
  for (const value of [valid, { ...valid, monitoring_group: "Production" },
    { ...valid, enabled: "true" }, { ...valid, labels: ["unknown"] },
    { ...valid, labels: ["kind", "kind"] }, { ...valid, labels: "kind" },
    { ...valid, override_metrics: "false" }, { ...valid, unknown: true },
    { ...valid, monitoring_group: "a".repeat(65) }, { ...valid, monitoring_group: "a\nb" },
    { labels: [] }, { enabled: false }]) {
    const accepted = typeof value.enabled === "boolean" && Array.isArray(value.labels) && !systemMetricSettingsError(value);
    assert.equal(validate(value), accepted, JSON.stringify(value));
  }
});

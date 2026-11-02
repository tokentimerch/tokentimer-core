"use strict";
const { it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const yaml = require("../../apps/dashboard/node_modules/js-yaml");

it("PagerDuty conflict responses are valid OpenAPI Response Objects", () => {
  const spec = yaml.load(fs.readFileSync(path.join(__dirname, "../../packages/contracts/openapi/openapi.yaml"), "utf8"));
  for (const name of ["/api/v1/workspaces/{id}/webhooks/rename", "/api/v1/workspaces/{id}/pagerduty-incidents/{incidentId}/actions"]) {
    const response = spec.paths[name].post.responses["409"];
    assert.deepEqual(Object.keys(response), ["description"], "commas in flow-style descriptions must stay inside the string");
    assert.equal(typeof response.description, "string");
  }
});

"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const yaml = require(require.resolve("js-yaml", { paths: [path.resolve(__dirname, "../../apps/dashboard")] }));

test("recovery endpoints document their authorization, strict inputs and outcomes", () => {
  const spec = yaml.load(fs.readFileSync(path.join(__dirname, "../../packages/contracts/openapi/openapi.yaml"), "utf8"));
  const base = "/api/v1/workspaces/{id}/certops";
  const proof = spec.paths[`${base}/enrollments/{enrollmentId}/recover-installation-proof`].post;
  const acme = spec.paths[`${base}/acme-store-enrollments/{enrollmentId}/recover`].post;
  const lookup = spec.paths[`${base}/acme-store-enrollments/by-job/{jobId}`].get;
  for (const operation of [proof, acme, lookup]) {
    assert.match(operation.description, /human session/i);
    assert.match(operation.description, /certops\.issuer\.manage/);
    assert.ok(operation.responses["200"]);
  }
  for (const operation of [proof, acme]) {
    assert.ok(operation.parameters.some(parameter => parameter.$ref?.includes("CsrfTokenHeader")));
    assert.equal(operation.requestBody.content["application/json"].schema.additionalProperties, false);
    assert.ok(operation.responses["201"]);
  }
  assert.deepEqual(acme.requestBody.content["application/json"].schema.properties.acknowledgeUnknownEffect.enum, [true]);
  assert.deepEqual(spec.components.schemas.CertOpsAdcsProofRecovery.properties.state.enum,
    ["expected_identity_unavailable", "transport_unavailable", "queued"]);
  assert.deepEqual(lookup.responses["200"].content["application/json"].schema.properties.state.enum,
    ["keygen_intent", "prepared", "submitting", "issued", "installing", "installed", "uncertain"]);
});

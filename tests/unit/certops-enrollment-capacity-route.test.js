"use strict";
// Exercise the actual mounted public enrollment handler's status mapping.
// Only its service result is controlled; no server/database/native action runs.
const { test, mock } = require("node:test"), assert = require("node:assert/strict");
const service = require("../../apps/api/services/certops/certificateEnrollments");
const routePath = require.resolve("../../apps/api/routes/certops-enrollments");
test("public enrollment preserves capacity conflict and existing error status contracts", async () => {
  const previous = require.cache[routePath];
  let controlledError;
  const stub = mock.method(service, "createEnrollment", () => Promise.reject(controlledError));
  try {
    delete require.cache[routePath];
    const router = require(routePath);
    const route = router.stack.find(layer => layer.route?.path === "/api/v1/workspaces/:id/certops/enrollments" && layer.route.methods.post).route;
    const handler = route.stack.at(-1).handle;
    for (const [code, expected] of [["CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED", 409], ["CERTOPS_SNAPSHOT_INVALID", 400], ["CERTOPS_ISSUER_REVALIDATION_REQUIRED", 400], ["CERTOPS_ISSUER_NOT_FOUND", 404], ["CERTOPS_PREFLIGHT_RATE_LIMITED", 429], ["UNEXPECTED_SERVICE_FAILURE", 500]]) {
      controlledError = Object.assign(new Error("controlled internal diagnostic"), { code });
      const response = { statusCode: 200, status(value) { this.statusCode = value; return this; }, json(value) { this.body = value; return this; } };
      await handler({ workspace: { id: "11111111-1111-1111-1111-111111111111" }, user: { id: "22222222-2222-2222-2222-222222222222" }, body: {} }, response);
      assert.equal(response.statusCode, expected, code);
      assert.equal(response.body.code, expected === 500 ? "INTERNAL_ERROR" : code);
      assert.equal(response.body.error, expected === 500 ? "CertOps enrollment request failed" : controlledError.message);
    }
    assert.equal(stub.mock.calls.length, 6);
  } finally { stub.mock.restore(); delete require.cache[routePath]; if (previous) require.cache[routePath] = previous; }
});

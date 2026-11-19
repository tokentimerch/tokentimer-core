const assert = require("node:assert/strict");
const { test } = require("node:test");
const express = require("../../apps/api/node_modules/express");
const request = require("supertest");
const { logger } = require("../../apps/api/utils/logger");
const {
  attachRequestContext,
  requestCorrelation,
} = require("../../apps/api/utils/request-context");
const router = require("../../apps/api/routes/dashboardDiagnostics");

test("dashboard reporting requires a session and logs only fixed categories with the server reference", async (t) => {
  const app = express();
  app.use(requestCorrelation, express.json(), (req, _res, next) => {
    req.isAuthenticated = () => req.get("X-Test-Session") === "signed-in";
    next();
  });
  app.use(router);

  const events = [];
  t.mock.method(logger, "warn", (message, fields) => {
    events.push(attachRequestContext({ message, ...fields }));
  });
  const path = "/api/diagnostics/dashboard";
  const report = { kind: "render", area: "account" };
  await request(app).post(path).send(report).expect(401);
  for (const invalid of [
    { ...report, stack: "synthetic-secret" },
    { ...report, kind: "synthetic-secret" },
    { ...report, area: "/reset-password/synthetic-secret" },
  ]) {
    await request(app).post(path).set("X-Test-Session", "signed-in")
      .send(invalid).expect(400);
  }
  assert.deepEqual(events, []);

  const response = await request(app).post(path)
    .set("X-Test-Session", "signed-in")
    .set("X-Request-Id", "forged-request-id")
    .send(report)
    .expect(204);
  assert.match(response.headers["x-request-id"], /^[0-9a-f-]{36}$/);
  assert.deepEqual(events, [{
    message: "Dashboard error boundary reported",
    correlationId: response.headers["x-request-id"],
    ...report,
  }]);
});

"use strict";
const { test, afterEach } = require("node:test");
const http = require("node:http");
const assert = require("node:assert/strict");
process.env.NODE_ENV = "production";
process.env.GLOBAL_RATE_LIMIT_MAX = "5";
process.env.GLOBAL_SLOWDOWN_DELAY_AFTER = "2";
process.env.GLOBAL_SLOWDOWN_DELAY_MS = "1";
process.env.CERTOPS_MACHINE_IP_RATE_LIMIT_MAX = "3000";
process.env.CERTOPS_MACHINE_IP_SLOWDOWN_DELAY_AFTER = "30000";
process.env.CERTOPS_MACHINE_IP_SLOWDOWN_DELAY_MS = "1";
process.env.LOGIN_EMAIL_RATE_LIMIT_MAX = "1";
const { createRequire } = require("node:module");
const express = createRequire(require.resolve("../../apps/api/package.json"))("express");
const request = require("supertest");
const { createCertOpsMachineWritePreParserBoundary } = require("../../apps/api/middleware/certops-executor-body-parser");
const { applyGlobalRateLimit, speedLimiter, loginEmailLimiter, getDomainCheckerLookupLimiter } = require("../../apps/api/middleware/rateLimit");
function appWith(...middleware) {
  const app = express();
  app.set("trust proxy", 1);
  app.use(...middleware);
  return app;
}
const servers = [];
const httpAgent = new http.Agent({ keepAlive: true });
afterEach(async () => { httpAgent.destroy(); await Promise.all(servers.splice(0).map(server => new Promise(resolve => server.close(resolve)))); });
function endpoint(app) { if (!app.testServer) { app.testServer = app.listen(0); servers.push(app.testServer); } return `http://127.0.0.1:${app.testServer.address().port}`; }
function ip(req, address) { return req.agent(httpAgent).set("X-Forwarded-For", address); }
test("100 agents behind a NAT retain capacity for idle traffic and job bursts", async () => {
  const app = appWith(createCertOpsMachineWritePreParserBoundary(), express.json(), applyGlobalRateLimit, speedLimiter);
  const paths = ["/api/v1/certops/agent/heartbeat", "/api/v1/certops/agent/jobs/claim", "/api/v1/certops/agent/jobs/job-1/lease", "/api/v1/certops/agent/jobs/results"];
  app.post(paths, (req, res) => res.json({ delay: req.slowDown?.delay ?? 0 }));
  for (let agent = 0; agent < 100; agent++) {
    const token = `ttagent_${agent.toString(16).padStart(16, "0")}_${"a".repeat(64)}`;
    for (let call = 0; call < 16; call++) {
      // Two heartbeats, four claims, then five lease and five result writes.
      const path = paths[call < 2 ? 0 : call < 6 ? 1 : call < 11 ? 2 : 3];
      const r = await ip(request(endpoint(app)).post(path), "203.0.113.10").set("Authorization", `Bearer ${token}`).send({});
      assert.equal(r.status, 200, `agent ${agent}, call ${call}`);
      assert.equal(r.body.delay, 0);
    }
  }
});
test("aggregate IP guard blocks forged prefix flood before allocating another prefix bucket", async () => {
  let reachedPrefixLimiter = 0, parsed = 0;
  const boundary = createCertOpsMachineWritePreParserBoundary({ preAuthRateLimitMiddleware: (_req, _res, next) => { reachedPrefixLimiter++; next(); }, parser: (_req, _res, next) => { parsed++; next(); } });
  const app = appWith(boundary, express.json(), applyGlobalRateLimit);
  app.post("/api/v1/certops/agent/heartbeat", (_req, res) => res.sendStatus(204));
  let r;
  for (let i = 0; i <= 3000; i++) {
    const token = `ttagent_${i.toString(16).padStart(16, "0")}_${"a".repeat(64)}`;
    r = await ip(request(endpoint(app)).post("/api/v1/certops/agent/heartbeat"), "203.0.113.12").set("Authorization", `Bearer ${token}`).send({});
    if (i < 3000) assert.equal(r.status, 204);
  }
  assert.equal(r.status, 429);
  assert.equal(reachedPrefixLimiter, 3000);
  assert.equal(parsed, 3000);
  assert.ok(Number(r.headers["retry-after"]) > 0);
});
test("lookalike machine paths remain under the ordinary IP limit", async () => {
  const app = appWith(createCertOpsMachineWritePreParserBoundary(), express.json(), applyGlobalRateLimit);
  app.post("/api/v1/certops/agent/heartbeat/extra", (_req, res) => res.sendStatus(204));
  for (let i = 0; i < 5; i++) assert.equal((await ip(request(endpoint(app)).post("/api/v1/certops/agent/heartbeat/extra"), "203.0.113.13").send({})).status, 204);
  assert.equal((await ip(request(endpoint(app)).post("/api/v1/certops/agent/heartbeat/extra"), "203.0.113.13").send({})).status, 429);
});
test("machine IPv6 /56 shares an aggregate bucket and isolates another subnet", async () => {
  process.env.CERTOPS_MACHINE_IP_RATE_LIMIT_MAX = "5";
  const boundary = createCertOpsMachineWritePreParserBoundary({ preAuthRateLimitMiddleware: (_req, _res, next) => next() });
  process.env.CERTOPS_MACHINE_IP_RATE_LIMIT_MAX = "3000";
  const app = appWith(boundary, applyGlobalRateLimit);
  app.post("/api/v1/certops/agent/heartbeat", (_req, res) => res.sendStatus(204));
  for (let i = 0; i < 5; i++) assert.equal((await ip(request(endpoint(app)).post("/api/v1/certops/agent/heartbeat"), "2001:db8:1234:5600::1").send({})).status, 204);
  assert.equal((await ip(request(endpoint(app)).post("/api/v1/certops/agent/heartbeat"), "2001:db8:1234:56ff::2").send({})).status, 429);
  assert.equal((await ip(request(endpoint(app)).post("/api/v1/certops/agent/heartbeat"), "2001:db8:1234:5700::1").send({})).status, 204);
});
test("wrong methods and forged marker headers cannot select machine limits", async () => {
  const app = appWith(createCertOpsMachineWritePreParserBoundary(), applyGlobalRateLimit);
  app.get("/api/v1/certops/agent/heartbeat", (_req, res) => res.sendStatus(204));
  for (let i = 0; i < 5; i++) assert.equal((await ip(request(endpoint(app)).get("/api/v1/certops/agent/heartbeat"), "203.0.113.14").set("X-Certops-Preauth", "true")).status, 204);
  assert.equal((await ip(request(endpoint(app)).get("/api/v1/certops/agent/heartbeat"), "203.0.113.14").set("X-Certops-Preauth", "true")).status, 429);
});
test("global limit groups an IPv6 /56 while isolating other subnets", async () => {
  const app = appWith(applyGlobalRateLimit);
  app.get("/", (_req, res) => res.sendStatus(204));
  for (let i = 0; i < 5; i++) assert.equal((await ip(request(endpoint(app)).get("/"), "2001:db8:1234:5600::1")).status, 204);
  assert.equal((await ip(request(endpoint(app)).get("/"), "2001:db8:1234:56ff::2")).status, 429);
  assert.equal((await ip(request(endpoint(app)).get("/"), "2001:db8:1234:5700::1")).status, 204);
});
test("global slowdown counts requests from the same IP", async () => {
  const app = appWith(speedLimiter);
  app.get("/", (req, res) => res.json({ delay: req.slowDown.delay }));
  const delays = [];
  for (let i = 0; i < 3; i++) delays.push((await ip(request(endpoint(app)).get("/"), "203.0.113.20")).body.delay);
  assert.deepEqual(delays, [0, 0, 1]);
  assert.equal((await ip(request(endpoint(app)).get("/"), "203.0.113.21")).body.delay, 0);
});
test("email-less login limits are isolated by IP", async () => {
  const app = appWith(express.json(), loginEmailLimiter);
  app.post("/login", (_req, res) => res.sendStatus(401));
  assert.equal((await ip(request(endpoint(app)).post("/login"), "203.0.113.30").send({})).status, 401);
  assert.equal((await ip(request(endpoint(app)).post("/login"), "203.0.113.30").send({})).status, 429);
  assert.equal((await ip(request(endpoint(app)).post("/login"), "203.0.113.31").send({})).status, 401);
});
test("domain lookup fallback isolates IPs in the same workspace", async () => {
  const app = appWith(express.json(), (req, _res, next) => { req.workspace = { id: "workspace-a" }; next(); }, getDomainCheckerLookupLimiter());
  app.post("/lookup", (_req, res) => res.sendStatus(204));
  assert.equal((await ip(request(endpoint(app)).post("/lookup"), "203.0.113.40").send({ domain: "example.com" })).status, 204);
  assert.equal((await ip(request(endpoint(app)).post("/lookup"), "203.0.113.40").send({ domain: "example.com" })).status, 429);
  assert.equal((await ip(request(endpoint(app)).post("/lookup"), "203.0.113.41").send({ domain: "example.com" })).status, 204);
});

test("machine IP windows reject Node timer overflow and accept its maximum", () => {
  const { createCertOpsMachineIpRateLimit } = require("../../apps/api/middleware/machine-ip-rate-limit");
  for (const name of ["CERTOPS_MACHINE_IP_RATE_LIMIT_WINDOW_MS", "CERTOPS_MACHINE_IP_SLOWDOWN_WINDOW_MS"]) {
    const previous = process.env[name];
    try {
      process.env[name] = "2147483648";
      assert.throws(() => createCertOpsMachineIpRateLimit(), new RegExp(name));
      process.env[name] = "2147483647";
      assert.doesNotThrow(() => createCertOpsMachineIpRateLimit());
    } finally {
      if (previous === undefined) delete process.env[name];
      else process.env[name] = previous;
    }
  }
});

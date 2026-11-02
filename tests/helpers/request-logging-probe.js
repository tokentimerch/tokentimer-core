"use strict";

// Exercise the real bootstrap middleware without starting migrations or workers.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const { createRequire } = require("node:module");

async function main() {
  const bootstrap = process.argv[2];
  const apiRequire = createRequire(bootstrap);
  const express = apiRequire("express");
  const cors = apiRequire("cors");
  const { logger } = apiRequire("./utils/logger");
  const { requestCorrelation } = apiRequire("./utils/request-context");
  const records = [];
  logger.on("data", (record) => records.push(record));

  // Pausing the output forces Winston to defer formatting some records until
  // after their request context has ended, as a slow transport can do.
  logger.pause();
  for (let request = 0; request < 3; request++) {
    const req = {};
    requestCorrelation(req, { setHeader() {} }, () => {
      for (let entry = 0; entry < 30; entry++) {
        logger.info("buffered correlation probe", {
          expected: req.correlationId,
          correlationId: "forged-metadata",
          password: "raw-body-marker",
        });
      }
    });
  }
  logger.resume();
  await new Promise((resolve) => setImmediate(resolve));
  const buffered = records.filter((record) => record.message === "buffered correlation probe");
  assert.equal(buffered.length, 90);
  for (const record of buffered) {
    assert.equal(record.correlationId, record.expected);
    assert.equal(record.password, "[REDACTED]");
    if (process.env.PROBE_EXPECT_SERVICE) assert.equal(record.service, process.env.PROBE_EXPECT_SERVICE);
  }
  logger.info("background correlation probe");
  assert.equal(records.at(-1).correlationId, undefined);
  const methodRequest = {};
  requestCorrelation(methodRequest, { setHeader() {} }, () => {
    logger.warn("method correlation probe");
    logger.error(new Error("error correlation probe"));
    logger.log("info", "method correlation probe");
    logger.log({ level: "info", message: "method correlation probe" });
    logger.child({ component: "probe", correlationId: "forged-child-id" }).info("method correlation probe");
  });
  const methods = records.filter((record) => /^(method|error) correlation probe$/.test(record.message));
  assert.equal(methods.length, 5);
  for (const record of methods) assert.equal(record.correlationId, methodRequest.correlationId);

  const source = fs.readFileSync(bootstrap, "utf8");
  const start = source.indexOf("app.use(requestCorrelation);");
  const end = source.indexOf("\n});", start) + "\n});".length;
  assert.ok(start >= 0 && end > start, "missing request middleware in bootstrap");
  const app = express();
  const evaluate = (code, bindings) => Function(...Object.keys(bindings), code)(...Object.values(bindings));
  evaluate(source.slice(start, end), { app, requestCorrelation, logger });
  const origin = "https://dashboard.example.test";
  const corsStart = source.indexOf("const corsOptions = {");
  const corsEndMarker = "app.options(/.*/, cors(corsOptions));";
  const corsEnd = source.indexOf(corsEndMarker, corsStart) + corsEndMarker.length;
  assert.ok(corsStart >= 0 && corsEnd > corsStart, "missing CORS setup in bootstrap");
  const buildCorsOrigins = source.includes("origin: buildCorsOrigins")
    ? apiRequire("./session-cookie-options").buildCorsOrigins
    : undefined;
  evaluate(source.slice(corsStart, corsEnd), {
    app, cors, buildCorsOrigins, FRONTEND_URL: origin,
    process: { env: { NODE_ENV: "production", APP_URL: origin } },
  });
  app.use(express.json());
  const routeLog = (req) => logger.info("HTTP route probe", {
    expected: req.correlationId,
    password: "raw-body-marker",
  });
  app.get("/health", (req, res) => { routeLog(req); res.sendStatus(200); });
  app.get("/api/denied/:id", (req, res) => { routeLog(req); res.sendStatus(401); });
  app.get("/api/fail/:id", (req, _res, next) => { routeLog(req); next(new Error("probe")); });
  app.post("/api/items/:id", async (req, res) => {
    await new Promise((resolve) => setImmediate(resolve));
    routeLog(req);
    res.json({ id: req.correlationId });
  });
  app.get("/auth/oidc/:slug/callback", (req, res) => { routeLog(req); res.sendStatus(200); });
  app.use((error, _req, res, _next) => res.sendStatus(error.status || 500));
  app.use((_req, res) => res.sendStatus(404));
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const request = (path, method = "GET", chunks = [], extraHeaders = {}) => new Promise((resolve, reject) => {
    const req = http.request({
      host: "127.0.0.1", port: server.address().port, path, method,
      headers: { Origin: origin, "X-Request-Id": "forged-client-id", ...extraHeaders },
    }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on("error", reject);
    req.setTimeout(3000, () => req.destroy(new Error("probe request timeout")));
    if (chunks.length) {
      req.write(chunks[0]);
      setTimeout(() => req.end(chunks.slice(1).join("")), 10);
    } else req.end();
  });
  try {
    const responses = await Promise.all([
      request("/health"),
      request("/missing-raw-path-marker?token=raw-body-marker"),
      request("/api/denied/raw-path-marker"),
      request("/api/fail/raw-path-marker?token=raw-body-marker"),
      request("/api/items/raw-path-marker", "POST", ["{bad", "}"], { "Content-Type": "application/json" }),
      request("/api/items/raw-path-marker", "POST", ['{"password":', '"raw-body-marker"}'], { "Content-Type": "application/json" }),
      request("/api/items/raw-path-marker", "OPTIONS", [], {
        "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "Content-Type",
      }),
      request("/auth/oidc/raw-path-marker/callback"),
    ]);
    assert.deepEqual(responses.map((response) => response.status), [200, 404, 401, 500, 400, 200, 204, 200]);
    const ids = responses.map((response) => response.headers["x-request-id"]);
    assert.equal(new Set(ids).size, responses.length);
    for (const response of responses) {
      assert.match(response.headers["x-request-id"], /^[0-9a-f-]{36}$/);
      assert.equal(response.headers["access-control-allow-origin"], origin);
      assert.match(response.headers["access-control-expose-headers"], /X-Request-Id/i);
      const completion = records.filter((record) => record.message === "HTTP request completed" && record.correlationId === response.headers["x-request-id"]);
      assert.equal(completion.length, 1);
      assert.equal(completion[0].statusCode, response.status);
      assert.doesNotMatch(JSON.stringify(completion[0]), /raw-path-marker|raw-body-marker|forged-client-id/);
    }
    assert.equal(JSON.parse(responses[5].body).id, ids[5]);
    for (const record of records.filter((record) => record.message === "HTTP route probe")) {
      assert.equal(record.correlationId, record.expected);
      assert.equal(record.password, "[REDACTED]");
    }
    process.stdout.write(`PROBE_RESULT ${JSON.stringify({ buffered: buffered.length, http: responses.length })}\n`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });

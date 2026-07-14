"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { createRequire } = require("node:module");
const supertest = require("supertest");
const apiRequire = createRequire(
  require.resolve("../../apps/api/package.json"),
);
const express = apiRequire("express");
const {
  createCertOpsExecutorRouter,
} = require("../../apps/api/routes/certops-executor");

const {
  CERTOPS_EXECUTOR_EVENTS_PATH,
  CERTOPS_EXECUTOR_EVENT_BODY_LIMIT_BYTES,
  CERTOPS_EXECUTOR_EVENT_BODY_TOO_LARGE,
  CERTOPS_EXECUTOR_EVENT_INVALID,
  createCertOpsExecutorEventJsonParser,
  createCertOpsExecutorEventPreParserBoundary,
  handleCertOpsExecutorEventBodyParserError,
} = require("../../apps/api/middleware/certops-executor-body-parser");

function buildApp({ onAuth = () => {} } = {}) {
  const app = express();
  app.use(CERTOPS_EXECUTOR_EVENTS_PATH, createCertOpsExecutorEventJsonParser());
  app.use(
    CERTOPS_EXECUTOR_EVENTS_PATH,
    handleCertOpsExecutorEventBodyParserError,
  );
  app.use(express.json({ limit: "10mb" }));
  app.post(CERTOPS_EXECUTOR_EVENTS_PATH, (_req, _res, next) => {
    onAuth();
    next();
  });
  app.post(CERTOPS_EXECUTOR_EVENTS_PATH, (req, res) =>
    res.status(202).json({ bytes: JSON.stringify(req.body).length }),
  );
  app.post("/unrelated", (req, res) =>
    res.status(200).json({ bytes: JSON.stringify(req.body).length }),
  );
  app.use((error, _req, res, _next) =>
    res.status(500).json({ error: error?.message || "unexpected" }),
  );
  return app;
}

function buildBoundaryApp({ rateLimitOptions, onParser = () => {}, onAuth = () => {} } = {}) {
  const app = express();
  const parser = createCertOpsExecutorEventJsonParser();
  app.use(
    createCertOpsExecutorEventPreParserBoundary({
      rateLimitOptions,
      parser: (req, res, next) => {
        onParser();
        return parser(req, res, next);
      },
    }),
  );
  app.use(express.json({ limit: "10mb" }));
  app.post(CERTOPS_EXECUTOR_EVENTS_PATH, (_req, _res, next) => {
    onAuth();
    next();
  });
  app.post(CERTOPS_EXECUTOR_EVENTS_PATH, (_req, res) => res.status(202).json({ ok: true }));
  app.all("/unrelated", (_req, res) => res.status(200).json({ ok: true }));
  return app;
}

describe("CertOps executor body parser", () => {
  it("accepts valid JSON close to the executor-specific limit", async () => {
    const app = buildApp();
    const fillerLength = CERTOPS_EXECUTOR_EVENT_BODY_LIMIT_BYTES - 1024;
    const response = await supertest(app)
      .post(CERTOPS_EXECUTOR_EVENTS_PATH)
      .send({ filler: "a".repeat(fillerLength) })
      .expect(202);

    assert.ok(response.body.bytes > fillerLength);
  });

  it("rejects an oversized executor request before auth or handler work", async () => {
    let authCalls = 0;
    const app = buildApp({ onAuth: () => { authCalls += 1; } });
    const response = await supertest(app)
      .post(CERTOPS_EXECUTOR_EVENTS_PATH)
      .set("Content-Type", "application/json")
      .send(`{"filler":"${"a".repeat(CERTOPS_EXECUTOR_EVENT_BODY_LIMIT_BYTES)}"}`)
      .expect(413);

    assert.equal(authCalls, 0);
    assert.deepEqual(response.body, {
      error: "Executor event payload is too large",
      code: CERTOPS_EXECUTOR_EVENT_BODY_TOO_LARGE,
    });
  });

  it("returns a safe 400 for malformed executor JSON before auth", async () => {
    let authCalls = 0;
    const app = buildApp({ onAuth: () => { authCalls += 1; } });
    const response = await supertest(app)
      .post(CERTOPS_EXECUTOR_EVENTS_PATH)
      .set("Content-Type", "application/json")
      .send('{"filler":')
      .expect(400);

    assert.equal(authCalls, 0);
    assert.deepEqual(response.body, {
      error: "Executor event payload is invalid",
      code: CERTOPS_EXECUTOR_EVENT_INVALID,
    });
  });

  it("leaves the general ten MiB parser available to unrelated routes", async () => {
    const app = buildApp();
    const response = await supertest(app)
      .post("/unrelated")
      .send({ filler: "a".repeat(CERTOPS_EXECUTOR_EVENT_BODY_LIMIT_BYTES + 1024) })
      .expect(200);

    assert.ok(response.body.bytes > CERTOPS_EXECUTOR_EVENT_BODY_LIMIT_BYTES);
  });

  it("charges malformed, oversized, and valid exact-path POSTs before parsing or auth", async () => {
    let parserCalls = 0;
    let authCalls = 0;
    const app = buildBoundaryApp({
      rateLimitOptions: { windowMs: 60_000, max: 2 },
      onParser: () => { parserCalls += 1; },
      onAuth: () => { authCalls += 1; },
    });

    await supertest(app)
      .post(CERTOPS_EXECUTOR_EVENTS_PATH)
      .set("Content-Type", "application/json")
      .send('{"filler":')
      .expect(400);
    await supertest(app)
      .post(CERTOPS_EXECUTOR_EVENTS_PATH)
      .set("Content-Type", "application/json")
      .send(`{"filler":"${"a".repeat(CERTOPS_EXECUTOR_EVENT_BODY_LIMIT_BYTES)}"}`)
      .expect(413);
    const blocked = await supertest(app)
      .post(CERTOPS_EXECUTOR_EVENTS_PATH)
      .send({ public: true })
      .expect(429);

    assert.equal(parserCalls, 2);
    assert.equal(authCalls, 0);
    assert.equal(blocked.body.code, "CERTOPS_MACHINE_RATE_LIMITED");
    assert.equal(blocked.body.retryAfterSeconds > 0, true);
    assert.equal(JSON.stringify(blocked.body).includes("filler"), false);
  });

  it("does not parse, authenticate, or intercept non-exact executor requests", async () => {
    let parserCalls = 0;
    let authCalls = 0;
    const app = buildBoundaryApp({
      rateLimitOptions: { windowMs: 60_000, max: 0 },
      onParser: () => { parserCalls += 1; },
      onAuth: () => { authCalls += 1; },
    });

    await supertest(app).get(CERTOPS_EXECUTOR_EVENTS_PATH).expect(404);
    await supertest(app).post(`${CERTOPS_EXECUTOR_EVENTS_PATH}/extra`).send({ ok: true }).expect(404);
    await supertest(app).post("/unrelated").send({ ok: true }).expect(200);
    const blocked = await supertest(app)
      .post(CERTOPS_EXECUTOR_EVENTS_PATH)
      .send({ ok: true })
      .expect(429);

    assert.equal(parserCalls, 0);
    assert.equal(authCalls, 0);
    assert.equal(blocked.body.code, "CERTOPS_MACHINE_RATE_LIMITED");
  });

  it("marks production-boundary requests so the router does not double-charge pre-auth", async () => {
    let limiterCalls = 0;
    const preAuthRateLimitMiddleware = (_req, _res, next) => {
      limiterCalls += 1;
      return next();
    };
    const app = express();
    app.use(
      createCertOpsExecutorEventPreParserBoundary({
        preAuthRateLimitMiddleware,
      }),
    );
    app.use(express.json());
    app.use(
      createCertOpsExecutorRouter({
        preAuthRateLimitMiddleware,
        certOpsEnabledMiddleware: (_req, res) =>
          res.status(404).json({ code: "NOT_FOUND" }),
      }),
    );

    await supertest(app)
      .post(CERTOPS_EXECUTOR_EVENTS_PATH)
      .send({ schemaVersion: 1 })
      .expect(404);
    assert.equal(limiterCalls, 1);
  });
});

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
  CERTOPS_CONTROLLER_OBSERVATIONS_PATH,
  CERTOPS_CONTROLLER_PROVISIONING_AUTHORIZATION_PATH,
  CERTOPS_CONTROLLER_PROVISIONING_COMMANDS_PATH,
  CERTOPS_JOB_EVENTS_PATH,
  CERTOPS_JOB_EVIDENCE_PATH,
  CERTOPS_EXECUTOR_EVENT_BODY_LIMIT_BYTES,
  CERTOPS_EXECUTOR_EVENT_BODY_TOO_LARGE,
  CERTOPS_EXECUTOR_EVENT_INVALID,
  createCertOpsMachineWriteJsonParser,
  createCertOpsMachineWritePreParserBoundary,
  certOpsMachineWriteRouteFamily,
  handleCertOpsMachineWriteBodyParserError,
} = require("../../apps/api/middleware/certops-executor-body-parser");

const JOB_ID = "11111111-1111-4111-8111-111111111111";
const MACHINE_WRITE_ROUTES = [
  CERTOPS_EXECUTOR_EVENTS_PATH,
  CERTOPS_CONTROLLER_OBSERVATIONS_PATH,
  CERTOPS_CONTROLLER_PROVISIONING_COMMANDS_PATH,
  CERTOPS_CONTROLLER_PROVISIONING_AUTHORIZATION_PATH.replace(":jobId", JOB_ID),
  `/api/v1/certops/jobs/${JOB_ID}/events`,
  `/api/v1/certops/jobs/${JOB_ID}/evidence`,
];

function buildApp({ onAuth = () => {} } = {}) {
  const app = express();
  app.use(CERTOPS_EXECUTOR_EVENTS_PATH, createCertOpsMachineWriteJsonParser());
  app.use(
    CERTOPS_EXECUTOR_EVENTS_PATH,
    handleCertOpsMachineWriteBodyParserError,
  );
  app.use(express.json({ limit: "10mb" }));
  for (const route of [
    CERTOPS_EXECUTOR_EVENTS_PATH,
    CERTOPS_CONTROLLER_OBSERVATIONS_PATH,
    CERTOPS_CONTROLLER_PROVISIONING_COMMANDS_PATH,
    CERTOPS_CONTROLLER_PROVISIONING_AUTHORIZATION_PATH,
    CERTOPS_JOB_EVENTS_PATH,
    CERTOPS_JOB_EVIDENCE_PATH,
  ]) {
    app.post(route, (_req, _res, next) => {
      onAuth();
      next();
    });
    app.post(route, (req, res) =>
      res.status(202).json({ bytes: JSON.stringify(req.body).length }),
    );
  }
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
  const parser = createCertOpsMachineWriteJsonParser();
  app.use(
    createCertOpsMachineWritePreParserBoundary({
      rateLimitOptions,
      parser: (req, res, next) => {
        onParser();
        return parser(req, res, next);
      },
    }),
  );
  app.use(express.json({ limit: "10mb" }));
  for (const route of [
    CERTOPS_EXECUTOR_EVENTS_PATH,
    CERTOPS_CONTROLLER_OBSERVATIONS_PATH,
    CERTOPS_JOB_EVENTS_PATH,
    CERTOPS_JOB_EVIDENCE_PATH,
  ]) {
    app.post(route, (_req, _res, next) => {
      onAuth();
      next();
    });
    app.post(route, (_req, res) => res.status(202).json({ ok: true }));
  }
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

  it("applies the pre-parser boundary once to mixed-case machine-write path variants", async () => {
    for (const executorRoute of [
      "/API/v1/CertOps/Executor/Events",
      "/API/v1/CertOps/Executor/Events/",
      "/API/v1/CertOps/Executor/Observations/",
    ]) {
      let parserCalls = 0;
      let authCalls = 0;
      const app = buildBoundaryApp({
        rateLimitOptions: { windowMs: 60_000, max: 3 },
        onParser: () => { parserCalls += 1; },
        onAuth: () => { authCalls += 1; },
      });

      await supertest(app)
        .post(executorRoute)
        .set("Content-Type", "application/json")
        .send('{"filler":')
        .expect(400);
      assert.equal(parserCalls, 1);
      assert.equal(authCalls, 0);

      await supertest(app)
        .post(executorRoute)
        .set("Content-Type", "application/json")
        .send(`{"filler":"${"a".repeat(CERTOPS_EXECUTOR_EVENT_BODY_LIMIT_BYTES)}"}`)
        .expect(413);
      assert.equal(parserCalls, 2);
      assert.equal(authCalls, 0);

      await supertest(app)
        .post(executorRoute)
        .send({ public: true })
        .expect(202);

      const blocked = await supertest(app)
        .post(executorRoute)
        .send({ public: true })
        .expect(429);

      // A valid body larger than four MiB returns the dedicated 413, proving it
      // did not reach the later general ten MiB parser first.
      assert.equal(parserCalls, 3);
      assert.equal(authCalls, 1);
      assert.equal(blocked.body.code, "CERTOPS_MACHINE_RATE_LIMITED");
      assert.equal(blocked.body.retryAfterSeconds > 0, true);
      assert.equal(JSON.stringify(blocked.body).includes("filler"), false);
    }
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
    await supertest(app).post(`${CERTOPS_EXECUTOR_EVENTS_PATH}//`).send({ ok: true }).expect(404);
    await supertest(app).post("/API/v1/CertOps/Executor/Events/extra").send({ ok: true }).expect(404);
    await supertest(app).post("/API/v1/CertOps/Executor/Events//").send({ ok: true }).expect(404);
    await supertest(app).post("/unrelated").send({ ok: true }).expect(200);
    const blocked = await supertest(app)
      .post(CERTOPS_EXECUTOR_EVENTS_PATH)
      .send({ ok: true })
      .expect(429);

    assert.equal(parserCalls, 0);
    assert.equal(authCalls, 0);
    assert.equal(blocked.body.code, "CERTOPS_MACHINE_RATE_LIMITED");
  });

  it("protects every exact machine write route before the global parser", async () => {
    for (const route of [
      ...MACHINE_WRITE_ROUTES,
      "/API/v1/CertOps/Jobs/11111111-1111-4111-8111-111111111111/Events/",
      "/API/v1/CertOps/Jobs/11111111-1111-4111-8111-111111111111/Evidence/",
      "/API/v1/CertOps/Executor/Provisioning-Commands/11111111-1111-4111-8111-111111111111/Authorize-Mutation/",
    ]) {
      let parserCalls = 0;
      let authCalls = 0;
      const app = buildBoundaryApp({
        rateLimitOptions: { windowMs: 60_000, max: 2 },
        onParser: () => { parserCalls += 1; },
        onAuth: () => { authCalls += 1; },
      });

      await supertest(app)
        .post(route)
        .set("Content-Type", "application/json")
        .send('{"broken":')
        .expect(400);
      const blocked = await supertest(app)
        .post(route)
        .set("Content-Type", "application/json")
        .send(`{"filler":"${"a".repeat(CERTOPS_EXECUTOR_EVENT_BODY_LIMIT_BYTES)}"}`)
        .expect(413);
      assert.equal(parserCalls, 2);
      assert.equal(authCalls, 0);
      assert.equal(blocked.body.code, CERTOPS_EXECUTOR_EVENT_BODY_TOO_LARGE);

      const rateLimited = await supertest(app).post(route).send({ public: true }).expect(429);
      assert.equal(rateLimited.body.code, "CERTOPS_MACHINE_RATE_LIMITED");
      assert.equal(authCalls, 0);
    }
  });

  it("matches only exact case-insensitive executor machine write paths", () => {
    assert.equal(
      certOpsMachineWriteRouteFamily(
        "/API/v1/CertOps/Jobs/11111111-1111-4111-8111-111111111111/Events/",
      ),
      "per-job-events",
    );
    for (const path of [
      "/api/v1/certops/jobs//events",
      "/api/v1/certops/jobs/1/events/extra",
      "/api/v1/certops/jobs/1/evidence//",
      "/api/v1/certops/executor/provisioning-commands//authorize-mutation",
      "/api/v1/certops/executor/provisioning-commands/1/authorize-mutation/extra",
      // /agent/register is now a machine-write family path; only its
      // malformed neighbors must stay unrecognized.
      "/api/v1/certops/agent/register/extra",
      "/api/v1/certops/agent//register",
    ]) {
      assert.equal(certOpsMachineWriteRouteFamily(path), null);
    }
  });

  it("marks production-boundary requests so the router does not double-charge pre-auth", async () => {
    let limiterCalls = 0;
    const preAuthRateLimitMiddleware = (_req, _res, next) => {
      limiterCalls += 1;
      return next();
    };
    const app = express();
    app.use(
      createCertOpsMachineWritePreParserBoundary({
        preAuthRateLimitMiddleware,
      }),
    );
    app.use(express.json());
    app.use(
      createCertOpsExecutorRouter({
        preAuthRateLimitMiddleware,
        controllerObservationAuthMiddleware: (req, _res, next) => {
          req.apiToken = {
            id: "11111111-1111-4111-8111-111111111111",
            workspaceId: "11111111-1111-4111-8111-111111111111",
            controllerClusterId: "controller-a",
            scopes: ["certops:observations:write"],
          };
          return next();
        },
        certOpsEnabledMiddleware: (_req, res) =>
          res.status(404).json({ code: "NOT_FOUND" }),
      }),
    );

    for (const executorRoute of [
      "/API/v1/CertOps/Executor/Events",
      "/API/v1/CertOps/Executor/Events/",
      "/API/v1/CertOps/Executor/Observations",
      "/API/v1/CertOps/Jobs/11111111-1111-4111-8111-111111111111/Events",
      "/API/v1/CertOps/Jobs/11111111-1111-4111-8111-111111111111/Evidence/",
    ]) {
      const expectedStatus = /Observations/i.test(executorRoute) ? 401 : 404;
      await supertest(app)
        .post(executorRoute)
        .send({ schemaVersion: 1 })
        .expect(expectedStatus);
    }
    // Every request crosses the production pre-parser once; the router sees
    // the marker and never invokes its standalone fallback limiter.
    assert.equal(limiterCalls, 5);
  });
});

"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { createRequire } = require("node:module");
const path = require("node:path");

const { CERTOPS_API_TOKEN_UNAUTHORIZED } = require(
  path.resolve(__dirname, "../../apps/api/middleware/api-token-auth.js"),
);
const {
  CERTOPS_MACHINE_RATE_LIMITED,
  CERTOPS_MACHINE_RATE_LIMIT_CONFIG_INVALID,
  CERTOPS_MACHINE_RATE_LIMIT_STORE_REQUIRED,
  createCertOpsMachineTokenPreAuthRateLimit,
  createCertOpsMachineTokenRateLimit,
  machineTokenPreAuthRateLimitKey,
  machineTokenRateLimitKey,
  tokenPrefixFromAuthorization,
  _test,
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/middleware/machine-token-rate-limit.js",
  ),
);

const apiRequire = createRequire(
  require.resolve("../../apps/api/package.json"),
);
const { MemoryStore } = apiRequire("express-rate-limit");

const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";
const WORKSPACE_B = "22222222-2222-4222-8222-222222222222";
const TOKEN_ID = "0123456789abcdef";
const TOKEN_SECRET = "a".repeat(64);
const RAW_TOKEN = `ttx_${TOKEN_ID}_${TOKEN_SECRET}`;
const TOKEN_PREFIX = `ttx_${TOKEN_ID}`;

function createRequest({
  workspaceId = WORKSPACE_A,
  tokenPrefix = TOKEN_PREFIX,
  agentId,
  executorId,
  params = {},
  route = { path: "/events" },
  baseUrl = "/api/v1/certops/executor",
  path: requestPath = "/api/v1/certops/executor/events",
  originalUrl = requestPath,
  ip = "203.0.113.7",
  user,
  authorization = `Bearer ${RAW_TOKEN}`,
} = {}) {
  const headers = {};
  if (authorization !== undefined) headers.authorization = authorization;

  return {
    method: "POST",
    path: requestPath,
    originalUrl,
    baseUrl,
    route,
    ip,
    params,
    headers,
    user,
    apiToken:
      workspaceId || tokenPrefix
        ? {
            id: "token-1",
            workspaceId,
            tokenPrefix,
            scopes: ["certops:events:write"],
            name: "Executor",
            createdBy: 42,
            lastUsedAt: null,
            agentId,
            executorId,
          }
        : undefined,
    get(name) {
      return headers[name.toLowerCase()];
    },
  };
}

function createResponse() {
  return {
    statusCode: null,
    body: null,
    headers: {},
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
    set(name, value) {
      this.headers[name] = value;
      return this;
    },
    setHeader(name, value) {
      this.headers[name] = value;
    },
    getHeader(name) {
      return this.headers[name];
    },
    end(payload) {
      this.ended = true;
      this.endPayload = payload;
      return this;
    },
  };
}

async function runMiddleware(middleware, req) {
  const res = createResponse();
  const result = {
    req,
    res,
    nextCalled: false,
    nextError: null,
  };

  await middleware(req, res, (error) => {
    result.nextCalled = !error;
    result.nextError = error || null;
  });

  return result;
}

function assertNoSensitiveResponseData(body) {
  const text = JSON.stringify(body);
  assert.equal(text.includes(RAW_TOKEN), false);
  assert.equal(text.includes(`Bearer ${RAW_TOKEN}`), false);
  assert.equal(text.includes("token_hash"), false);
  assert.equal(text.includes("privateKey"), false);
  assert.equal(text.includes("credential"), false);
  assert.equal(text.includes("apiSecret"), false);
}

function assertRateLimited(result) {
  assert.equal(result.nextCalled, false);
  assert.equal(result.res.statusCode, 429);
  assert.equal(result.res.body.code, CERTOPS_MACHINE_RATE_LIMITED);
  assert.match(result.res.headers["Retry-After"], /^[1-9][0-9]*$/);
  assert.equal(typeof result.res.body.retryAfterSeconds, "number");
  assert.equal(result.res.body.retry_after_seconds, undefined);
  assertNoSensitiveResponseData(result.res.body);
}

describe("CertOps machine-token rate limiter", () => {
  it("keys post-auth requests by workspace and public prefix, without a route segment", () => {
    const key = machineTokenRateLimitKey(createRequest());
    assert.equal(key, `certops-machine:${WORKSPACE_A}:${TOKEN_PREFIX}`);
    assert.equal(key.includes(RAW_TOKEN), false);
    assert.equal(key.includes("Bearer"), false);
    assert.equal(key.includes("token_hash"), false);
    assert.equal(key.includes("executor_events"), false);
    assert.equal(key.includes("evidence"), false);

    assert.equal(
      machineTokenRateLimitKey(createRequest({ agentId: "agent:one" })),
      `${key}:agent:one`,
    );
    assert.equal(
      machineTokenRateLimitKey(createRequest({ executorId: "executor:one" })),
      `${key}:executor:one`,
    );
    assert.equal(
      machineTokenRateLimitKey(createRequest({ workspaceId: null })),
      null,
    );
    assert.equal(
      machineTokenRateLimitKey(createRequest({ tokenPrefix: null })),
      null,
    );
  });

  it("uses a safe route family without query strings and normalizes dynamic path segments", () => {
    const req = createRequest({
      route: null,
      path: null,
      originalUrl: `/api/v1/certops/executor/events/123e4567-e89b-12d3-a456-426614174000?authorization=Bearer%20${RAW_TOKEN}`,
    });
    const routeFamily = _test.routeFamilyFromRequest(req);
    const key = machineTokenRateLimitKey(req);

    assert.equal(routeFamily, "api_v1_certops_executor_events_id");
    // routeFamily is for log metadata only; the rate-limit key has no route segment
    assert.equal(key, `certops-machine:${WORKSPACE_A}:${TOKEN_PREFIX}`);
    assert.equal(key.includes(RAW_TOKEN), false);
    assert.equal(key.includes("authorization"), false);
    assert.equal(
      _test.routeFamilyFromRequest(createRequest({
        routeFamilyResolver: undefined,
      })),
      "api_v1_certops_executor_events",
    );
    assert.equal(
      _test.routeFamilyFromRequest(createRequest(), {
        routeFamilyResolver: () => "evidence uploads?token=never-used",
      }),
      "evidence_uploads",
    );
  });

  it("ignores route-param machine IDs unless a route explicitly opts in", () => {
    const request = createRequest({
      params: {
        agentId: "attacker-agent",
        executorId: "attacker-executor",
      },
    });
    const defaultKey = machineTokenRateLimitKey(request);
    assert.equal(defaultKey.endsWith(":attacker-agent"), false);
    assert.equal(defaultKey.endsWith(":attacker-executor"), false);

    assert.equal(
      machineTokenRateLimitKey(request, {
        machineIdResolver: (req) => req.params.agentId,
      }),
      `${defaultKey}:attacker-agent`,
    );
  });

  it("shares one post-auth bucket across executor route families for the same token", async () => {
    const middleware = createCertOpsMachineTokenRateLimit({ max: 1 });
    const aggregateEvents = createRequest({
      route: { path: "/events" },
      baseUrl: "/api/v1/certops/executor",
      path: "/api/v1/certops/executor/events",
    });
    const jobEvents = createRequest({
      route: { path: "/:jobId/events" },
      baseUrl: "/api/v1/certops/jobs",
      path: `/api/v1/certops/jobs/${WORKSPACE_A}/events`,
    });
    const evidence = createRequest({
      route: { path: "/:jobId/evidence" },
      baseUrl: "/api/v1/certops/jobs",
      path: `/api/v1/certops/jobs/${WORKSPACE_A}/evidence`,
    });

    assert.equal(
      machineTokenRateLimitKey(aggregateEvents),
      machineTokenRateLimitKey(jobEvents),
    );
    assert.equal(
      machineTokenRateLimitKey(aggregateEvents),
      machineTokenRateLimitKey(evidence),
    );

    assert.equal((await runMiddleware(middleware, aggregateEvents)).nextCalled, true);
    assertRateLimited(await runMiddleware(middleware, jobEvents));
    assertRateLimited(await runMiddleware(middleware, evidence));
  });

  it("shares a bucket within one family and still limits repeat hits on that family", async () => {
    const middleware = createCertOpsMachineTokenRateLimit({ max: 1 });
    const events = createRequest({ route: { path: "/events" } });
    const secondEvents = createRequest({ route: { path: "/events" } });

    assert.equal((await runMiddleware(middleware, events)).nextCalled, true);
    assertRateLimited(await runMiddleware(middleware, secondEvents));
  });
  it("keeps different token prefixes, workspaces, and authenticated machine IDs separate", async () => {
    const middleware = createCertOpsMachineTokenRateLimit({ max: 1 });

    assert.equal((await runMiddleware(middleware, createRequest())).nextCalled, true);
    assert.equal(
      (
        await runMiddleware(
          middleware,
          createRequest({ tokenPrefix: "ttx_fedcba9876543210" }),
        )
      ).nextCalled,
      true,
    );
    assert.equal(
      (
        await runMiddleware(
          middleware,
          createRequest({ workspaceId: WORKSPACE_B }),
        )
      ).nextCalled,
      true,
    );
    assert.equal(
      (
        await runMiddleware(
          middleware,
          createRequest({ agentId: "agent-a" }),
        )
      ).nextCalled,
      true,
    );
    assert.equal(
      (
        await runMiddleware(
          middleware,
          createRequest({ agentId: "agent-b" }),
        )
      ).nextCalled,
      true,
    );
  });

  it("fails closed when post-auth identity is missing", async () => {
    const result = await runMiddleware(
      createCertOpsMachineTokenRateLimit(),
      createRequest({ workspaceId: null, tokenPrefix: null }),
    );

    assert.equal(result.nextCalled, false);
    assert.equal(result.res.statusCode, 401);
    assert.equal(result.res.body.code, CERTOPS_API_TOKEN_UNAUTHORIZED);
  });

  it("is independent from req.user and session state", async () => {
    const middleware = createCertOpsMachineTokenRateLimit({ max: 1 });

    assert.equal(
      (
        await runMiddleware(
          middleware,
          createRequest({ user: { id: 1, role: "admin" } }),
        )
      ).nextCalled,
      true,
    );
    assertRateLimited(
      await runMiddleware(
        middleware,
        createRequest({ user: { id: 2, role: "viewer" } }),
      ),
    );
  });

  it("treats max: 0 and limit: 0 as block-all while limit takes precedence", async () => {
    assertRateLimited(
      await runMiddleware(
        createCertOpsMachineTokenRateLimit({ max: 0 }),
        createRequest(),
      ),
    );
    assertRateLimited(
      await runMiddleware(
        createCertOpsMachineTokenRateLimit({ limit: 0 }),
        createRequest(),
      ),
    );

    const limitWins = createCertOpsMachineTokenRateLimit({ max: 0, limit: 1 });
    assert.equal((await runMiddleware(limitWins, createRequest())).nextCalled, true);
    assertRateLimited(await runMiddleware(limitWins, createRequest()));
  });

  it("rejects invalid max, limit, and window configuration instead of falling back", () => {
    for (const options of [
      { max: -1 },
      { max: "not-a-number" },
      { max: true },
      { limit: -1 },
      { limit: "not-a-number" },
      { limit: false },
      { windowMs: 0 },
      { windowMs: -1 },
      { windowMs: "not-a-number" },
      { windowMs: true },
    ]) {
      assert.throws(
        () => createCertOpsMachineTokenRateLimit(options),
        (error) => error.code === CERTOPS_MACHINE_RATE_LIMIT_CONFIG_INVALID,
      );
    }

    assert.doesNotThrow(() => createCertOpsMachineTokenRateLimit());
    assert.deepEqual(_test.rateLimitOptions({}), {
      limit: 120,
      windowMs: 60_000,
    });
  });

  it("requires a shared store only when explicitly configured", () => {
    for (const factory of [
      createCertOpsMachineTokenRateLimit,
      createCertOpsMachineTokenPreAuthRateLimit,
    ]) {
      assert.throws(
        () => factory({ requireSharedStore: true }),
        (error) => error.code === CERTOPS_MACHINE_RATE_LIMIT_STORE_REQUIRED,
      );
      assert.equal(typeof factory(), "function");
      assert.equal(
        typeof factory({
          requireSharedStore: true,
          store: new MemoryStore(),
        }),
        "function",
      );
    }
  });

  it("extracts only the public prefix from an exact lower-case M2 token", () => {
    assert.equal(
      tokenPrefixFromAuthorization(createRequest()),
      TOKEN_PREFIX,
    );
    for (const authorization of [
      `Bearer ttx__${TOKEN_SECRET}`,
      `Bearer ttx_${TOKEN_ID}_`,
      `Bearer TTX_${TOKEN_ID}_${TOKEN_SECRET}`,
      `Bearer ttx_${TOKEN_ID}_${"A".repeat(64)}`,
      `Basic ${RAW_TOKEN}`,
    ]) {
      assert.equal(
        tokenPrefixFromAuthorization(createRequest({ authorization })),
        null,
      );
    }
  });

  it("uses public prefix or IP fallback for pre-auth keys without retaining raw authorization", () => {
    const validKey = machineTokenPreAuthRateLimitKey(
      createRequest({
        params: { workspaceId: WORKSPACE_A },
        authorization: `Bearer ${RAW_TOKEN}`,
      }),
    );
    const malformedAuthorization = `Bearer ttx__${TOKEN_SECRET}`;
    const fallbackKey = machineTokenPreAuthRateLimitKey(
      createRequest({
        params: { workspaceId: WORKSPACE_A },
        authorization: malformedAuthorization,
        ip: "198.51.100.9",
      }),
    );

    assert.equal(
      validKey,
      `certops-machine-preauth:${WORKSPACE_A}:prefix:${TOKEN_PREFIX}`,
    );
    assert.equal(fallbackKey.endsWith(":ip:198.51.100.9"), true);
    assert.equal(validKey.includes(RAW_TOKEN), false);
    assert.equal(fallbackKey.includes(malformedAuthorization), false);
  });

  it("allows under-limit pre-auth requests and blocks them before authentication when over limit", async () => {
    const middleware = createCertOpsMachineTokenPreAuthRateLimit({ max: 1 });
    assert.equal((await runMiddleware(middleware, createRequest())).nextCalled, true);
    assertRateLimited(await runMiddleware(middleware, createRequest()));
    assert.equal(
      (
        await runMiddleware(
          middleware,
          createRequest({ authorization: "Bearer ttx__malformed" }),
        )
      ).nextCalled,
      true,
    );
  });

  it("allows requests again once the rate-limit window elapses", async () => {
    // Every other test here uses a fixed 60s window and never advances past
    // it, so window-reset behavior itself was never exercised (audit gap).
    // Uses a short real window (100ms) rather than a fake clock since
    // express-rate-limit's underlying store schedules its own timers.
    const middleware = createCertOpsMachineTokenRateLimit({
      windowMs: 100,
      max: 1,
    });

    const first = await runMiddleware(middleware, createRequest());
    assert.equal(first.nextCalled, true);

    const blocked = await runMiddleware(middleware, createRequest());
    assertRateLimited(blocked);

    await new Promise((resolve) => setTimeout(resolve, 150));

    const afterWindow = await runMiddleware(middleware, createRequest());
    assert.equal(afterWindow.nextCalled, true);
  });
});

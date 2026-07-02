"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { CERTOPS_API_TOKEN_UNAUTHORIZED } = require(
  path.resolve(__dirname, "../../apps/api/middleware/api-token-auth.js"),
);
const {
  CERTOPS_MACHINE_RATE_LIMITED,
  createCertOpsMachineTokenRateLimit,
  machineTokenRateLimitKey,
} = require(
  path.resolve(
    __dirname,
    "../../apps/api/middleware/machine-token-rate-limit.js",
  ),
);

const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";
const WORKSPACE_B = "22222222-2222-4222-8222-222222222222";
const RAW_TOKEN = "ttx_abc123_secret456";

function createRequest({
  workspaceId = WORKSPACE_A,
  tokenPrefix = "ttx_abc123",
  agentId,
  executorId,
  params = {},
  user,
  authorization = `Bearer ${RAW_TOKEN}`,
} = {}) {
  const headers = {};
  if (authorization !== undefined) headers.authorization = authorization;

  return {
    method: "POST",
    path: "/v1/certops/executor/events",
    baseUrl: "/api",
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

describe("CertOps machine-token rate limiter", () => {
  it("builds machine-specific workspace-bound keys", () => {
    assert.equal(
      machineTokenRateLimitKey(createRequest()),
      `certops-machine:${WORKSPACE_A}:ttx_abc123`,
    );
    assert.equal(
      machineTokenRateLimitKey(
        createRequest({ agentId: "agent:one" }),
      ),
      `certops-machine:${WORKSPACE_A}:ttx_abc123:agent:one`,
    );
    assert.equal(
      machineTokenRateLimitKey(
        createRequest({ executorId: "executor:one" }),
      ),
      `certops-machine:${WORKSPACE_A}:ttx_abc123:executor:one`,
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

  it("ignores route-param machine IDs by default", () => {
    assert.equal(
      machineTokenRateLimitKey(
        createRequest({
          params: {
            agentId: "attacker-agent",
            executorId: "attacker-executor",
          },
        }),
      ),
      `certops-machine:${WORKSPACE_A}:ttx_abc123`,
    );
  });

  it("allows explicit opt-in route-param machine IDs through a custom resolver", () => {
    assert.equal(
      machineTokenRateLimitKey(
        createRequest({
          params: { agentId: "agent-from-route" },
        }),
        {
          machineIdResolver: (req) => req.params.agentId,
        },
      ),
      `certops-machine:${WORKSPACE_A}:ttx_abc123:agent-from-route`,
    );
  });

  it("allows requests under limit and rejects repeated requests over limit", async () => {
    const middleware = createCertOpsMachineTokenRateLimit({
      windowMs: 60_000,
      max: 2,
    });

    const first = await runMiddleware(middleware, createRequest());
    const second = await runMiddleware(middleware, createRequest());
    const third = await runMiddleware(middleware, createRequest());

    assert.equal(first.nextCalled, true);
    assert.equal(second.nextCalled, true);
    assert.equal(third.nextCalled, false);
    assert.equal(third.res.statusCode, 429);
    assert.equal(third.res.body.code, CERTOPS_MACHINE_RATE_LIMITED);
    assert.match(third.res.headers["Retry-After"], /^[1-9][0-9]*$/);
    assertNoSensitiveResponseData(third.res.body);
  });

  it("keeps different token prefixes in separate buckets", async () => {
    const middleware = createCertOpsMachineTokenRateLimit({
      windowMs: 60_000,
      max: 1,
    });

    assert.equal((await runMiddleware(middleware, createRequest())).nextCalled, true);
    assert.equal(
      (
        await runMiddleware(
          middleware,
          createRequest({ tokenPrefix: "ttx_def456" }),
        )
      ).nextCalled,
      true,
    );
    const blocked = await runMiddleware(middleware, createRequest());
    assert.equal(blocked.res.statusCode, 429);
  });

  it("keeps different workspaces in separate buckets", async () => {
    const middleware = createCertOpsMachineTokenRateLimit({
      windowMs: 60_000,
      max: 1,
    });

    assert.equal((await runMiddleware(middleware, createRequest())).nextCalled, true);
    assert.equal(
      (
        await runMiddleware(
          middleware,
          createRequest({ workspaceId: WORKSPACE_B }),
        )
      ).nextCalled,
      true,
    );
    const blocked = await runMiddleware(middleware, createRequest());
    assert.equal(blocked.res.statusCode, 429);
  });

  it("uses authenticated apiToken agent IDs for separate buckets", async () => {
    const middleware = createCertOpsMachineTokenRateLimit({
      windowMs: 60_000,
      max: 1,
    });

    assert.equal(
      (await runMiddleware(middleware, createRequest({ agentId: "agent-a" })))
        .nextCalled,
      true,
    );
    assert.equal(
      (await runMiddleware(middleware, createRequest({ agentId: "agent-b" })))
        .nextCalled,
      true,
    );
    const blocked = await runMiddleware(
      middleware,
      createRequest({ agentId: "agent-a" }),
    );
    assert.equal(blocked.res.statusCode, 429);
  });

  it("ignores varying route params for bucket identity unless explicitly configured", async () => {
    const middleware = createCertOpsMachineTokenRateLimit({
      windowMs: 60_000,
      max: 1,
    });

    const first = await runMiddleware(
      middleware,
      createRequest({ params: { agentId: "agent-a" } }),
    );
    const second = await runMiddleware(
      middleware,
      createRequest({ params: { agentId: "agent-b" } }),
    );

    assert.equal(first.nextCalled, true);
    assert.equal(second.res.statusCode, 429);

    const optInMiddleware = createCertOpsMachineTokenRateLimit({
      windowMs: 60_000,
      max: 1,
      machineIdResolver: (req) => req.params.agentId,
    });
    const optInFirst = await runMiddleware(
      optInMiddleware,
      createRequest({ params: { agentId: "agent-a" } }),
    );
    const optInSecond = await runMiddleware(
      optInMiddleware,
      createRequest({ params: { agentId: "agent-b" } }),
    );

    assert.equal(optInFirst.nextCalled, true);
    assert.equal(optInSecond.nextCalled, true);
  });

  it("fails closed when req.apiToken is missing", async () => {
    const middleware = createCertOpsMachineTokenRateLimit({
      windowMs: 60_000,
      max: 1,
    });
    const result = await runMiddleware(
      middleware,
      createRequest({ workspaceId: null, tokenPrefix: null }),
    );

    assert.equal(result.nextCalled, false);
    assert.equal(result.res.statusCode, 401);
    assert.equal(result.res.body.code, CERTOPS_API_TOKEN_UNAUTHORIZED);
  });

  it("is independent from req.user and session state", async () => {
    const middleware = createCertOpsMachineTokenRateLimit({
      windowMs: 60_000,
      max: 1,
    });

    const first = await runMiddleware(
      middleware,
      createRequest({ user: { id: 1, role: "admin" } }),
    );
    const second = await runMiddleware(
      middleware,
      createRequest({ user: { id: 2, role: "viewer" } }),
    );

    assert.equal(first.nextCalled, true);
    assert.equal(second.res.statusCode, 429);
  });
});

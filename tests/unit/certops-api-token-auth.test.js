"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  CERTOPS_API_TOKEN_SCOPE_DENIED,
  CERTOPS_API_TOKEN_SCOPE_INVALID,
  CERTOPS_API_TOKEN_WORKSPACE_REQUIRED,
} = require(
  path.resolve(__dirname, "../../apps/api/services/certops/apiTokens.js"),
);
const {
  CERTOPS_API_TOKEN_UNAUTHORIZED,
  bearerTokenFromRequest,
  createCertOpsApiTokenAuth,
  safeApiTokenIdentity,
  workspaceIdFromRequest,
} = require(
  path.resolve(__dirname, "../../apps/api/middleware/api-token-auth.js"),
);
const {
  createCsrfExemptMiddleware,
  isCertOpsMachineTokenCsrfExemptPath,
} = require(
  path.resolve(__dirname, "../../apps/api/middleware/csrf-exempt.js"),
);

const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";
const WORKSPACE_B = "22222222-2222-4222-8222-222222222222";
const RAW_TOKEN = "ttx_abc123_secret456";

function createRequest({
  authorization,
  params = { id: WORKSPACE_A },
  body,
  method = "POST",
  path: requestPath = "/v1/workspaces/111/certops/test",
} = {}) {
  const headers = {};
  if (authorization !== undefined) headers.authorization = authorization;

  return {
    method,
    path: requestPath,
    params,
    body,
    headers,
    get(name) {
      return headers[name.toLowerCase()];
    },
  };
}

function createResponse() {
  return {
    statusCode: null,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
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

function successfulValidation(overrides = {}) {
  return {
    valid: true,
    token: {
      id: "token-1",
      workspaceId: WORKSPACE_A,
      tokenPrefix: "ttx_abc123",
      scopes: ["certops:events:write", "certops:jobs:read"],
      name: "Executor",
      createdBy: 42,
      lastUsedAt: "2026-07-02T00:00:00.000Z",
      token_hash: "must-not-attach",
      plaintextToken: "must-not-attach",
      ...overrides,
    },
  };
}

function collectKeys(value, keys = []) {
  if (Array.isArray(value)) {
    for (const item of value) collectKeys(item, keys);
    return keys;
  }
  if (!value || typeof value !== "object") return keys;
  for (const [key, child] of Object.entries(value)) {
    keys.push(key);
    collectKeys(child, keys);
  }
  return keys;
}

function assertNoCustodyKeys(value) {
  const forbidden = [
    "privatekey",
    "privatekeypem",
    "encryptedprivatekey",
    "keymaterial",
    "pfxblob",
    "jksblob",
    "tlskey",
    "caprivatekey",
    "keystorepassword",
    "privatekeypassword",
    "keypassword",
    "password",
    "secret",
    "credential",
    "tokensecret",
    "apisecret",
    "rawsecret",
    "rawprivatekey",
    "rawkey",
    "pemprivatekey",
  ];

  for (const key of collectKeys(value)) {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, "");
    const hit = forbidden.find((fragment) => normalized.includes(fragment));
    assert.equal(hit, undefined, `${key} looks like a custody field`);
  }
}

describe("CertOps API token auth middleware", () => {
  it("authenticates valid Bearer tokens and attaches safe machine identity", async () => {
    const calls = [];
    const middleware = createCertOpsApiTokenAuth({
      scopes: ["certops:events:write"],
      validateApiToken: async (options) => {
        calls.push(options);
        return successfulValidation();
      },
    });

    const req = createRequest({
      authorization: `Bearer ${RAW_TOKEN}`,
      params: { id: WORKSPACE_A },
    });
    const result = await runMiddleware(middleware, req);

    assert.equal(result.nextCalled, true);
    assert.equal(result.res.statusCode, null);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].rawToken, RAW_TOKEN);
    assert.equal(calls[0].workspaceId, WORKSPACE_A);
    assert.deepEqual(calls[0].requiredScopes, ["certops:events:write"]);
    assert.deepEqual(req.apiToken, {
      id: "token-1",
      workspaceId: WORKSPACE_A,
      tokenPrefix: "ttx_abc123",
      scopes: ["certops:events:write", "certops:jobs:read"],
      name: "Executor",
      createdBy: 42,
      lastUsedAt: "2026-07-02T00:00:00.000Z",
    });
    assert.equal(req.apiToken.token_hash, undefined);
    assert.equal(req.apiToken.plaintextToken, undefined);
    assert.equal(req.user, undefined);
    assert.equal(req.isAdmin, undefined);
    assert.equal(req.authenticated, undefined);
  });

  it("prefers URL workspace params over body workspaceId", async () => {
    let workspaceId;
    const middleware = createCertOpsApiTokenAuth({
      scopes: ["certops:events:write"],
      validateApiToken: async (options) => {
        workspaceId = options.workspaceId;
        return successfulValidation();
      },
    });

    const req = createRequest({
      authorization: `Bearer ${RAW_TOKEN}`,
      params: { workspaceId: WORKSPACE_A },
      body: { workspaceId: WORKSPACE_B },
    });
    await runMiddleware(middleware, req);

    assert.equal(workspaceId, WORKSPACE_A);
  });

  it("can use an explicit workspace resolver for future machine routes", async () => {
    const middleware = createCertOpsApiTokenAuth({
      scopes: ["certops:events:write"],
      resolveWorkspaceId: (req) => req.body.workspaceId,
      validateApiToken: async (options) =>
        successfulValidation({ workspaceId: options.workspaceId }),
    });

    const req = createRequest({
      authorization: `Bearer ${RAW_TOKEN}`,
      params: {},
      body: { workspaceId: WORKSPACE_A },
    });
    const result = await runMiddleware(middleware, req);

    assert.equal(result.nextCalled, true);
    assert.equal(req.apiToken.workspaceId, WORKSPACE_A);
  });

  it("can derive workspace from a validated token for path-job machine routes", async () => {
    const calls = [];
    const middleware = createCertOpsApiTokenAuth({
      scopes: ["certops:evidence:write"],
      allowTokenWorkspace: true,
      validateApiToken: async (options) => {
        calls.push(options);
        return successfulValidation({
          workspaceId: WORKSPACE_A,
          scopes: ["certops:evidence:write"],
        });
      },
    });

    const req = createRequest({
      authorization: `Bearer ${RAW_TOKEN}`,
      params: { jobId: "job-1" },
      body: {},
    });
    const result = await runMiddleware(middleware, req);

    assert.equal(result.nextCalled, true);
    assert.equal(calls[0].workspaceId, null);
    assert.equal(calls[0].allowTokenWorkspace, true);
    assert.equal(req.apiToken.workspaceId, WORKSPACE_A);
  });

  it("does not let certops:read satisfy write scopes", async () => {
    const middleware = createCertOpsApiTokenAuth({
      scopes: ["certops:events:write"],
      validateApiToken: async () => ({
        valid: false,
        code: CERTOPS_API_TOKEN_SCOPE_DENIED,
      }),
    });

    const result = await runMiddleware(
      middleware,
      createRequest({
        authorization: `Bearer ${RAW_TOKEN}`,
        params: { id: WORKSPACE_A },
      }),
    );

    assert.equal(result.res.statusCode, 403);
    assert.equal(result.res.body.code, CERTOPS_API_TOKEN_SCOPE_DENIED);
  });

  it("rejects missing, non-Bearer, and empty Authorization headers with 401", async () => {
    const middleware = createCertOpsApiTokenAuth({
      scopes: ["certops:events:write"],
      validateApiToken: async () => {
        throw new Error("validator must not be called");
      },
    });

    for (const authorization of [undefined, "", "Basic abc", "Bearer"]) {
      const result = await runMiddleware(
        middleware,
        createRequest({ authorization }),
      );

      assert.equal(result.nextCalled, false);
      assert.equal(result.res.statusCode, 401);
      assert.equal(result.res.body.code, CERTOPS_API_TOKEN_UNAUTHORIZED);
    }
  });

  it("rejects malformed, revoked, expired, and wrong-workspace tokens with generic 401", async () => {
    const middleware = createCertOpsApiTokenAuth({
      scopes: ["certops:events:write"],
      validateApiToken: async () => ({ valid: false, code: "ANY_REASON" }),
    });
    const result = await runMiddleware(
      middleware,
      createRequest({ authorization: `Bearer ${RAW_TOKEN}` }),
    );

    assert.equal(result.res.statusCode, 401);
    assert.deepEqual(result.res.body, {
      error: "CertOps API token authentication required",
      code: CERTOPS_API_TOKEN_UNAUTHORIZED,
    });
    assert.equal(JSON.stringify(result.res.body).includes(RAW_TOKEN), false);
    assert.equal(
      JSON.stringify(result.res.body).includes(`Bearer ${RAW_TOKEN}`),
      false,
    );
  });

  it("rejects valid tokens missing a required scope with 403", async () => {
    const middleware = createCertOpsApiTokenAuth({
      scopes: ["certops:evidence:write"],
      validateApiToken: async () => ({
        valid: false,
        code: CERTOPS_API_TOKEN_SCOPE_DENIED,
      }),
    });
    const result = await runMiddleware(
      middleware,
      createRequest({ authorization: `Bearer ${RAW_TOKEN}` }),
    );

    assert.equal(result.res.statusCode, 403);
    assert.equal(result.res.body.code, CERTOPS_API_TOKEN_SCOPE_DENIED);
  });

  it("fails safely when workspace context is missing", async () => {
    const middleware = createCertOpsApiTokenAuth({
      scopes: ["certops:events:write"],
      validateApiToken: async () => {
        throw new Error("validator must not be called without workspace");
      },
    });
    const result = await runMiddleware(
      middleware,
      createRequest({ authorization: `Bearer ${RAW_TOKEN}`, params: {} }),
    );

    assert.equal(result.res.statusCode, 401);
    assert.equal(result.res.body.code, CERTOPS_API_TOKEN_WORKSPACE_REQUIRED);
  });

  it("rejects unknown configured required scopes at setup time", () => {
    assert.throws(
      () =>
        createCertOpsApiTokenAuth({
          scopes: ["certops:admin"],
        }),
      (error) => error.code === CERTOPS_API_TOKEN_SCOPE_INVALID,
    );
  });

  it("rejects an empty/missing required-scopes configuration at setup time (plan A2: config error, not a wildcard)", () => {
    // Array#every() on an empty requiredScopes array is vacuously true, so a
    // route wired with no scopes option would otherwise accept ANY valid
    // token regardless of what it's scoped for. This must fail at middleware
    // construction time, before a single request is served.
    for (const scopes of [undefined, [], null]) {
      assert.throws(
        () => createCertOpsApiTokenAuth({ scopes }),
        (error) => error.code === CERTOPS_API_TOKEN_SCOPE_INVALID,
      );
    }
  });

  it("does not expose custody-looking fields in req.apiToken or responses", async () => {
    const middleware = createCertOpsApiTokenAuth({
      scopes: ["certops:events:write"],
      validateApiToken: async () => successfulValidation(),
    });
    const result = await runMiddleware(
      middleware,
      createRequest({ authorization: `Bearer ${RAW_TOKEN}` }),
    );

    assertNoCustodyKeys(result.req.apiToken);
    assertNoCustodyKeys({
      error: "CertOps API token authentication required",
      code: CERTOPS_API_TOKEN_UNAUTHORIZED,
    });
  });

  it("exports safe request parsing helpers", () => {
    const req = createRequest({
      authorization: `Bearer ${RAW_TOKEN}`,
      params: { id: WORKSPACE_A },
    });

    assert.deepEqual(bearerTokenFromRequest(req), {
      ok: true,
      rawToken: RAW_TOKEN,
    });
    assert.equal(workspaceIdFromRequest(req), WORKSPACE_A);
    assert.deepEqual(
      safeApiTokenIdentity(successfulValidation().token),
      {
        id: "token-1",
        workspaceId: WORKSPACE_A,
        tokenPrefix: "ttx_abc123",
        scopes: ["certops:events:write", "certops:jobs:read"],
        name: "Executor",
        createdBy: 42,
        lastUsedAt: "2026-07-02T00:00:00.000Z",
      },
    );
  });
});

describe("CertOps machine-token CSRF exemption", () => {
  it("exempts only the future executor machine-token namespaces", () => {
    assert.equal(
      isCertOpsMachineTokenCsrfExemptPath("/v1/certops/executor/events"),
      true,
    );
    assert.equal(
      isCertOpsMachineTokenCsrfExemptPath("/v1/certops/executor/jobs/1/events"),
      true,
    );
    assert.equal(
      isCertOpsMachineTokenCsrfExemptPath("/v1/certops/jobs/1/events"),
      true,
    );
    assert.equal(
      isCertOpsMachineTokenCsrfExemptPath("/api/v1/certops/jobs/1/evidence"),
      true,
    );
    assert.equal(
      isCertOpsMachineTokenCsrfExemptPath(
        "/v1/workspaces/111/certops/certificates",
      ),
      false,
    );
    assert.equal(
      isCertOpsMachineTokenCsrfExemptPath("/v1/certops/agent/register"),
      false,
    );
    assert.equal(isCertOpsMachineTokenCsrfExemptPath("/v1/tokens"), false);
  });

  it("keeps unrelated state-changing API routes behind CSRF protection", async () => {
    let protectedCalls = 0;
    let nextCalls = 0;
    const middleware = createCsrfExemptMiddleware((_req, res) => {
      protectedCalls += 1;
      return res.status(403).json({ code: "EBADCSRFTOKEN" });
    });

    await middleware(
      createRequest({
        path: "/v1/workspaces/111/certops/certificates",
        method: "POST",
      }),
      createResponse(),
      () => {
        nextCalls += 1;
      },
    );

    await middleware(
      createRequest({
        path: "/v1/certops/executor/events",
        method: "POST",
      }),
      createResponse(),
      () => {
        nextCalls += 1;
      },
    );

    assert.equal(protectedCalls, 1);
    assert.equal(nextCalls, 1);
  });
});

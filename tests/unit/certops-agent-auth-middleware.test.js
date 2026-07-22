"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  CERTOPS_AGENT_BOOTSTRAP_UNAUTHORIZED,
  CERTOPS_AGENT_SESSION_IDENTITY_FORBIDDEN,
  CERTOPS_AGENT_UNAUTHORIZED,
  createAgentBootstrapTokenAuth,
  createAgentCredentialAuth,
  _test,
} = require(
  path.resolve(__dirname, "../../apps/api/middleware/agent-auth.js"),
);

const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";
const RAW_BOOTSTRAP_TOKEN = `ttboot_${"0123456789abcdef"}_${"a".repeat(64)}`;
const RAW_AGENT_CREDENTIAL = `ttagent_${"0123456789abcdef"}_${"b".repeat(64)}`;

function createRequest({ authorization, params = {}, body } = {}) {
  const headers = {};
  if (authorization !== undefined) headers.authorization = authorization;

  return {
    method: "POST",
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

function safeBootstrapToken(overrides = {}) {
  return {
    id: "boot-1",
    workspaceId: WORKSPACE_A,
    name: "Rack 12 bootstrap",
    tokenPrefix: "ttboot_0123456789abcdef",
    status: "active",
    expiresAt: "2026-08-01T00:00:00.000Z",
    usedAt: null,
    usedByAgentId: null,
    revokedAt: null,
    revokedBy: null,
    createdBy: 7,
    createdAt: "2026-07-01T00:00:00.000Z",
    updatedAt: "2026-07-01T00:00:00.000Z",
    ...overrides,
  };
}

function safeAgent(overrides = {}) {
  return {
    id: "agent-row-1",
    workspaceId: WORKSPACE_A,
    agentId: "agent-01",
    name: "Edge agent",
    status: "active",
    protocolVersion: "1.0.0",
    agentVersion: "0.1.0",
    pinnedSigningKeyId: null,
    lastSeenAt: null,
    retiredAt: null,
    ...overrides,
  };
}

const SESSION_IDENTITIES = [
  { user: { id: 1 } },
  { session: { userId: 1 } },
  { session: { passport: { user: 1 } } },
  { isAdmin: true },
  { authenticated: true },
  { isAuthenticated: () => true },
];

describe("CertOps agent bootstrap token auth middleware", () => {
  it("authenticates a valid bootstrap token without consuming it", async () => {
    const calls = [];
    const middleware = createAgentBootstrapTokenAuth({
      validateBootstrapToken: async (options) => {
        calls.push(options);
        return { valid: true, bootstrapToken: safeBootstrapToken() };
      },
    });

    const req = createRequest({
      authorization: `Bearer ${RAW_BOOTSTRAP_TOKEN}`,
    });
    const result = await runMiddleware(middleware, req);

    assert.equal(result.nextCalled, true);
    assert.equal(result.res.statusCode, null);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].rawToken, RAW_BOOTSTRAP_TOKEN);
    assert.equal(req.agentBootstrapToken.id, "boot-1");
    assert.equal(req.agentBootstrapToken.token_hash, undefined);
    // No consume call: validation is injectable and the middleware only
    // ever calls it once; consumption belongs to the register transaction.
    assert.equal(calls.length, 1);
  });

  it("rejects session identity with 401 before validation", async () => {
    for (const sessionIdentity of SESSION_IDENTITIES) {
      let validationCalled = false;
      const middleware = createAgentBootstrapTokenAuth({
        validateBootstrapToken: async () => {
          validationCalled = true;
          return { valid: true, bootstrapToken: safeBootstrapToken() };
        },
      });
      const req = Object.assign(
        createRequest({ authorization: `Bearer ${RAW_BOOTSTRAP_TOKEN}` }),
        sessionIdentity,
      );
      const result = await runMiddleware(middleware, req);

      assert.equal(result.res.statusCode, 401);
      assert.equal(
        result.res.body.code,
        CERTOPS_AGENT_SESSION_IDENTITY_FORBIDDEN,
      );
      assert.equal(validationCalled, false);
      assert.equal(req.agentBootstrapToken, undefined);
    }
  });

  it("rejects missing and garbled bearer headers with 401", async () => {
    const middleware = createAgentBootstrapTokenAuth({
      validateBootstrapToken: async () => {
        throw new Error("validator must not be called");
      },
    });

    for (const authorization of [undefined, "", "Basic abc", "Bearer", "Bearer "]) {
      const result = await runMiddleware(
        middleware,
        createRequest({ authorization }),
      );
      assert.equal(result.nextCalled, false);
      assert.equal(result.res.statusCode, 401);
      assert.equal(result.res.body.code, CERTOPS_AGENT_BOOTSTRAP_UNAUTHORIZED);
    }
  });

  it("returns the same generic 401 body for every failure reason", async () => {
    const bodies = [];
    for (const code of [
      "CERTOPS_AGENT_BOOTSTRAP_TOKEN_INVALID",
      "CERTOPS_AGENT_BOOTSTRAP_TOKEN_MALFORMED",
      "CERTOPS_AGENT_BOOTSTRAP_TOKEN_EXPIRED",
      "CERTOPS_AGENT_BOOTSTRAP_TOKEN_USED",
      "CERTOPS_AGENT_BOOTSTRAP_TOKEN_REVOKED",
    ]) {
      const middleware = createAgentBootstrapTokenAuth({
        validateBootstrapToken: async () => ({ valid: false, code }),
      });
      const result = await runMiddleware(
        middleware,
        createRequest({ authorization: `Bearer ${RAW_BOOTSTRAP_TOKEN}` }),
      );
      assert.equal(result.res.statusCode, 401);
      bodies.push(result.res.body);
    }

    for (const body of bodies) {
      assert.deepEqual(body, {
        error: "CertOps agent bootstrap authentication required",
        code: CERTOPS_AGENT_BOOTSTRAP_UNAUTHORIZED,
      });
      assert.equal(JSON.stringify(body).includes(RAW_BOOTSTRAP_TOKEN), false);
    }
  });

  it("forwards unexpected validator errors to next", async () => {
    const boom = new Error("db down");
    const middleware = createAgentBootstrapTokenAuth({
      validateBootstrapToken: async () => {
        throw boom;
      },
    });
    const result = await runMiddleware(
      middleware,
      createRequest({ authorization: `Bearer ${RAW_BOOTSTRAP_TOKEN}` }),
    );

    assert.equal(result.nextCalled, false);
    assert.equal(result.nextError, boom);
    assert.equal(result.res.statusCode, null);
  });
});

describe("CertOps agent credential auth middleware", () => {
  it("authenticates a valid agent credential and attaches safe metadata", async () => {
    const calls = [];
    const middleware = createAgentCredentialAuth({
      validateAgentCredential: async (options) => {
        calls.push(options);
        return { valid: true, agent: safeAgent() };
      },
    });

    const req = createRequest({
      authorization: `Bearer ${RAW_AGENT_CREDENTIAL}`,
    });
    const result = await runMiddleware(middleware, req);

    assert.equal(result.nextCalled, true);
    assert.equal(result.res.statusCode, null);
    assert.equal(calls[0].rawCredential, RAW_AGENT_CREDENTIAL);
    assert.equal(req.certopsAgent.id, "agent-row-1");
    assert.equal(req.certopsAgent.status, "active");
    assert.equal(req.certopsAgent.credential_hash, undefined);
    assert.equal(req.certopsAgent.credentialHash, undefined);
  });

  it("still authenticates retired agents so routes can answer 410", async () => {
    const middleware = createAgentCredentialAuth({
      validateAgentCredential: async () => ({
        valid: true,
        agent: safeAgent({
          status: "retired",
          retiredAt: "2026-07-10T00:00:00.000Z",
        }),
      }),
    });

    const req = createRequest({
      authorization: `Bearer ${RAW_AGENT_CREDENTIAL}`,
    });
    const result = await runMiddleware(middleware, req);

    assert.equal(result.nextCalled, true);
    assert.equal(result.res.statusCode, null);
    assert.equal(req.certopsAgent.status, "retired");
    assert.equal(req.certopsAgent.retiredAt, "2026-07-10T00:00:00.000Z");
  });

  it("rejects session identity with 401 before validation", async () => {
    for (const sessionIdentity of SESSION_IDENTITIES) {
      let validationCalled = false;
      const middleware = createAgentCredentialAuth({
        validateAgentCredential: async () => {
          validationCalled = true;
          return { valid: true, agent: safeAgent() };
        },
      });
      const req = Object.assign(
        createRequest({ authorization: `Bearer ${RAW_AGENT_CREDENTIAL}` }),
        sessionIdentity,
      );
      const result = await runMiddleware(middleware, req);

      assert.equal(result.res.statusCode, 401);
      assert.equal(
        result.res.body.code,
        CERTOPS_AGENT_SESSION_IDENTITY_FORBIDDEN,
      );
      assert.equal(validationCalled, false);
      assert.equal(req.certopsAgent, undefined);
    }
  });

  it("allows a bearer credential when Express provides an empty session container", async () => {
    const middleware = createAgentCredentialAuth({
      validateAgentCredential: async () => ({ valid: true, agent: safeAgent() }),
    });
    const req = Object.assign(
      createRequest({ authorization: `Bearer ${RAW_AGENT_CREDENTIAL}` }),
      { session: {} },
    );
    const result = await runMiddleware(middleware, req);

    assert.equal(result.nextCalled, true);
    assert.equal(result.res.statusCode, null);
  });

  it("rejects missing and garbled bearer headers with 401", async () => {
    const middleware = createAgentCredentialAuth({
      validateAgentCredential: async () => {
        throw new Error("validator must not be called");
      },
    });

    for (const authorization of [undefined, "", "Basic abc", "Bearer", "Bearer "]) {
      const result = await runMiddleware(
        middleware,
        createRequest({ authorization }),
      );
      assert.equal(result.nextCalled, false);
      assert.equal(result.res.statusCode, 401);
      assert.equal(result.res.body.code, CERTOPS_AGENT_UNAUTHORIZED);
    }
  });

  it("returns the same generic 401 body for unknown and malformed credentials", async () => {
    const bodies = [];
    for (const code of [
      "CERTOPS_AGENT_CREDENTIAL_INVALID",
      "CERTOPS_AGENT_CREDENTIAL_MALFORMED",
    ]) {
      const middleware = createAgentCredentialAuth({
        validateAgentCredential: async () => ({ valid: false, code }),
      });
      const result = await runMiddleware(
        middleware,
        createRequest({ authorization: `Bearer ${RAW_AGENT_CREDENTIAL}` }),
      );
      assert.equal(result.res.statusCode, 401);
      bodies.push(result.res.body);
    }

    for (const body of bodies) {
      assert.deepEqual(body, {
        error: "CertOps agent authentication required",
        code: CERTOPS_AGENT_UNAUTHORIZED,
      });
      assert.equal(JSON.stringify(body).includes(RAW_AGENT_CREDENTIAL), false);
    }
  });

  it("forwards unexpected validator errors to next", async () => {
    const boom = new Error("db down");
    const middleware = createAgentCredentialAuth({
      validateAgentCredential: async () => {
        throw boom;
      },
    });
    const result = await runMiddleware(
      middleware,
      createRequest({ authorization: `Bearer ${RAW_AGENT_CREDENTIAL}` }),
    );

    assert.equal(result.nextCalled, false);
    assert.equal(result.nextError, boom);
  });

  it("shares hasSessionIdentity semantics with the API token middleware", () => {
    assert.equal(typeof _test.hasSessionIdentity, "function");
    assert.equal(_test.hasSessionIdentity({ session: {} }), false);
    assert.equal(_test.hasSessionIdentity({ user: { id: 1 } }), true);
    assert.equal(_test.hasSessionIdentity({ isAdmin: true }), true);
  });
});

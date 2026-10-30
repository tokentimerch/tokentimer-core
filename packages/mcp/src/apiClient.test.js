"use strict";

const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { createApiClient, buildUrl, pathIsConfined, ToolError } = require("./apiClient");
const { loadConfig } = require("./config");

const CREDENTIAL = `ttopc_${"0123456789abcdef"}_${"a".repeat(64)}`;
const SENTINEL = "UPSTREAM_BODY_SENTINEL_DO_NOT_FORWARD";

let api;
let origin;
let trap;
let trapOrigin;
let seen;
let respond;

function listen(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

const config = (overrides = {}) => ({
  origin,
  basePath: "",
  requestTimeoutMs: 1500,
  maxResponseBytes: 4096,
  authorizationHeader: () => `Bearer ${CREDENTIAL}`,
  ...overrides,
});

const rejection = (promise, code) =>
  assert.rejects(promise, (error) => error instanceof ToolError && error.code === code);

describe("API client", () => {
  before(async () => {
    seen = [];
    trapHits = 0;
    trap = await listen((req, res) => {
      trapHits += 1;
      res.end("{}");
    });
    trapOrigin = `http://127.0.0.1:${trap.address().port}`;
    api = await listen((req, res) => {
      seen.push({ method: req.method, url: req.url, headers: req.headers });
      respond(req, res);
    });
    origin = `http://127.0.0.1:${api.address().port}`;
  });

  after(async () => {
    await new Promise((resolve) => api.close(resolve));
    await new Promise((resolve) => trap.close(resolve));
  });

  let trapHits = 0;
  const json = (status, body, headers = {}) => (req, res) => {
    res.writeHead(status, { "content-type": "application/json", ...headers });
    res.end(typeof body === "string" ? body : JSON.stringify(body));
  };

  it("sends one GET with the bearer credential, a request id and the query", async () => {
    respond = json(200, { ok: true });
    seen.length = 0;
    const client = createApiClient(config());
    const result = await client.get("/api/v1/operator/certificates", { status: "active", limit: 5, skip: undefined, none: null });
    assert.deepEqual(result.body, { ok: true });
    assert.match(result.correlationId, /^[0-9a-f-]{36}$/);
    assert.equal(seen.length, 1);
    assert.equal(seen[0].method, "GET");
    assert.equal(seen[0].url, "/api/v1/operator/certificates?status=active&limit=5");
    assert.equal(seen[0].headers.authorization, `Bearer ${CREDENTIAL}`);
    assert.equal(seen[0].headers.accept, "application/json");
    assert.equal(seen[0].headers["x-request-id"], result.correlationId);
  });

  it("only ever reaches the operator namespace", () => {
    for (const bad of [
      "/api/v1/workspaces/abc/certops/jobs",
      "/api/v1/operator/../workspaces/abc",
      "/api/v1/operator/%2e%2e/workspaces",
      "/api/v1/operator//whoami",
      "/api/v1/operator/",
      "/api/v1/operator",
      "/auth/login",
      "/api/csrf-token",
      "//evil.example.com/api/v1/operator/whoami",
      "/api/v1/operator/whoami?x=1",
      "/api/v1/operator/who ami",
    ]) {
      assert.equal(pathIsConfined(bad), false, bad);
      assert.throws(() => buildUrl(config(), bad), (e) => e instanceof ToolError && e.code === "MCP_VALIDATION_ERROR", bad);
    }
    assert.equal(pathIsConfined("/api/v1/operator/certificates/abc-123/observations"), true);
  });

  it("cannot be steered to another host by a crafted path", () => {
    const url = buildUrl(config(), "/api/v1/operator/whoami", { redirect: "https://evil.example.com" });
    assert.equal(url.origin, origin);
    assert.equal(url.pathname, "/api/v1/operator/whoami");
  });

  it("honors a deployment path prefix", () => {
    const url = buildUrl(config({ basePath: "/tokentimer" }), "/api/v1/operator/whoami");
    assert.equal(url.pathname, "/tokentimer/api/v1/operator/whoami");
  });

  it("refuses a redirect, so the credential cannot be forwarded elsewhere", async () => {
    trapHits = 0;
    respond = (req, res) => {
      res.writeHead(302, { location: `${trapOrigin}/steal` });
      res.end();
    };
    const client = createApiClient(config());
    await rejection(client.get("/api/v1/operator/whoami"), "MCP_UPSTREAM_ERROR");
    assert.equal(trapHits, 0, "the redirect target must never be contacted");
  });

  it("maps statuses to fixed codes and never forwards the upstream body", async () => {
    const expected = {
      400: "MCP_VALIDATION_ERROR",
      401: "MCP_UNAUTHENTICATED",
      403: "MCP_SCOPE_DENIED",
      404: "MCP_NOT_FOUND",
      429: "MCP_RATE_LIMITED",
      500: "MCP_UPSTREAM_ERROR",
      502: "MCP_UPSTREAM_ERROR",
    };
    const client = createApiClient(config());
    for (const [status, code] of Object.entries(expected)) {
      respond = json(Number(status), { error: SENTINEL, code: "INTERNAL", stack: SENTINEL });
      try {
        await client.get("/api/v1/operator/whoami");
        assert.fail(`status ${status} should have thrown`);
      } catch (error) {
        assert.ok(error instanceof ToolError, status);
        assert.equal(error.code, code, status);
        const rendered = JSON.stringify(error.toJSON()) + error.message + error.stack;
        assert.ok(!rendered.includes(SENTINEL), `status ${status} leaked the upstream body`);
        assert.ok(!rendered.includes(CREDENTIAL), "credential leaked");
        assert.ok(!rendered.includes(origin), "upstream address leaked");
      }
    }
  });

  it("reports hosted policy and monthly quota refusals without encouraging immediate retries", async () => {
    const client = createApiClient(config());
    for (const [status, upstreamCode, code, reason] of [
      [402, "PLAN_FEATURE_REQUIRED", "MCP_SCOPE_DENIED", "plan_required"],
      [403, "WORKSPACE_FROZEN", "MCP_SCOPE_DENIED", "workspace_frozen"],
      [429, "CERTOPS_RENEWAL_QUOTA_EXCEEDED", "MCP_CONFLICT", "renewal_quota"],
    ]) {
      respond = json(status, { code: upstreamCode, error: SENTINEL });
      await assert.rejects(client.post("/api/v1/operator/renewals/requests", {}), error => {
        assert.equal(error.code, code);
        assert.equal(error.reason, reason);
        assert.equal(error.retryable, false);
        assert.equal(JSON.stringify(error.toJSON()).includes(SENTINEL), false);
        return true;
      });
    }
  });

  it("marks only transient failures as retryable", async () => {
    const client = createApiClient(config());
    const retryable = async (status) => {
      respond = json(status, {});
      try {
        await client.get("/api/v1/operator/whoami");
      } catch (error) {
        return error.retryable;
      }
      return null;
    };
    assert.equal(await retryable(429), true);
    assert.equal(await retryable(503), true);
    assert.equal(await retryable(401), false);
    assert.equal(await retryable(404), false);
  });

  it("stops reading a response that grows past the cap, whether declared or streamed", async () => {
    const client = createApiClient(config({ maxResponseBytes: 1024 }));
    respond = json(200, { pad: "x".repeat(5000) });
    await rejection(client.get("/api/v1/operator/whoami"), "MCP_RESPONSE_TOO_LARGE");

    respond = (req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.write('{"pad":"');
      const timer = setInterval(() => res.write("y".repeat(512)), 5);
      res.on("close", () => clearInterval(timer));
    };
    await rejection(client.get("/api/v1/operator/whoami"), "MCP_RESPONSE_TOO_LARGE");
  });

  it("refuses early when the server declares a body larger than the cap", async () => {
    const client = createApiClient(config({ maxResponseBytes: 1024, requestTimeoutMs: 2000 }));
    // The server declares a huge body and then goes silent. Only the declared
    // length can reject this quickly; reading would run into the timeout.
    respond = (req, res) => {
      res.writeHead(200, { "content-type": "application/json", "content-length": 500000 });
      res.write("{");
    };
    const started = Date.now();
    await rejection(client.get("/api/v1/operator/whoami"), "MCP_RESPONSE_TOO_LARGE");
    assert.ok(Date.now() - started < 1500, "rejected from the declared length, not after a timeout");
  });

  it("reports a body that stalls or is cut off as an upstream failure, never a raw error", async () => {
    const client = createApiClient(config({ requestTimeoutMs: 400 }));
    respond = (req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.write('{"partial":');
    };
    try {
      await client.get("/api/v1/operator/whoami");
      assert.fail("expected a failure");
    } catch (error) {
      assert.ok(error instanceof ToolError, `got ${error?.constructor?.name}: ${error?.message}`);
      assert.equal(error.code, "MCP_UPSTREAM_ERROR");
      assert.equal(error.retryable, true);
    }
    respond = (req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.write('{"partial":');
      setTimeout(() => req.socket.destroy(), 30);
    };
    try {
      await createApiClient(config()).get("/api/v1/operator/whoami");
      assert.fail("expected a failure");
    } catch (error) {
      assert.ok(error instanceof ToolError, `got ${error?.constructor?.name}: ${error?.message}`);
      assert.equal(error.code, "MCP_UPSTREAM_ERROR");
    }
  });

  it("times out a silent server and reports it as retryable", async () => {
    respond = () => {};
    const client = createApiClient(config({ requestTimeoutMs: 300 }));
    try {
      await client.get("/api/v1/operator/whoami");
      assert.fail("expected a timeout");
    } catch (error) {
      assert.equal(error.code, "MCP_UPSTREAM_ERROR");
      assert.equal(error.retryable, true);
      assert.match(error.message, /in time/);
    }
  });

  it("reports an unreachable API without exposing the address", async () => {
    const dead = await listen(() => {});
    const deadOrigin = `http://127.0.0.1:${dead.address().port}`;
    await new Promise((resolve) => dead.close(resolve));
    const client = createApiClient(config({ origin: deadOrigin }));
    try {
      await client.get("/api/v1/operator/whoami");
      assert.fail("expected a failure");
    } catch (error) {
      assert.equal(error.code, "MCP_UPSTREAM_ERROR");
      assert.ok(!JSON.stringify(error.toJSON()).includes(deadOrigin));
    }
  });

  it("rejects a 200 that is not JSON", async () => {
    respond = (req, res) => {
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<html>login</html>");
    };
    await rejection(createApiClient(config()).get("/api/v1/operator/whoami"), "MCP_UPSTREAM_ERROR");
  });

  it("works with a configuration produced by loadConfig", async () => {
    respond = json(200, { ok: 1 });
    const real = loadConfig({ TOKENTIMER_API_URL: origin, TOKENTIMER_MCP_CREDENTIAL: CREDENTIAL });
    const result = await createApiClient(real).get("/api/v1/operator/whoami");
    assert.deepEqual(result.body, { ok: 1 });
  });
});

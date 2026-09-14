"use strict";

const { describe, it, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

const {
  logger: apiLogger,
  buildOrderedLogRecord,
} = require(path.resolve(__dirname, "../../apps/api/utils/logger.js"));
const webhookSafety = require(path.resolve(
  __dirname,
  "../../apps/api/utils/webhookSafety.js",
));
const {
  CERTOPS_MACHINE_RATE_LIMITED,
  createCertOpsMachineTokenRateLimit,
} = require(path.resolve(
  __dirname,
  "../../apps/api/middleware/machine-token-rate-limit.js",
));

const ORIGINAL_NODE_ENV = process.env.NODE_ENV;

const SENTINEL_SECRET = "tt-sentinel-SECRET-9f3c1a7b-not-a-real-credential";
const SENTINEL_BEARER = `Bearer ttx_0123456789abcdef_${SENTINEL_SECRET}`;
const SENTINEL_COOKIE = "sid=tt-sentinel-COOKIE-VALUE-7e2d";
const SENTINEL_PAYLOAD = "tt-sentinel-WEBHOOK-BODY-4c91";

const TOKEN_ID = "0123456789abcdef";
const WORKSPACE_A = "11111111-1111-4111-8111-111111111111";

afterEach(() => {
  process.env.NODE_ENV = ORIGINAL_NODE_ENV;
  delete process.env.WEBHOOK_ALLOW_PRIVATE_IPS;
  delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;
});

function dumpLogs(entries) {
  return JSON.stringify(entries);
}

function assertKeepsSafeDiagnostics(haystack, { message, code } = {}) {
  if (message) assert.equal(haystack.includes(message), true);
  if (code) assert.equal(haystack.includes(code), true);
}

function assertNoSentinels(haystack) {
  for (const sentinel of [
    SENTINEL_SECRET,
    SENTINEL_BEARER,
    SENTINEL_COOKIE,
    SENTINEL_PAYLOAD,
  ]) {
    assert.equal(
      haystack.includes(sentinel),
      false,
      `log leaked ${sentinel}`,
    );
  }
}

function captureWarn(logger) {
  const captured = [];
  const original = logger.warn;
  logger.warn = (message, meta) => {
    captured.push({ message, meta });
    return original.call(logger, message, meta);
  };
  return {
    captured,
    restore() {
      logger.warn = original;
    },
  };
}

function serializedWarn(entry) {
  return JSON.stringify(
    buildOrderedLogRecord({
      level: "warn",
      message: entry.message,
      ...(entry.meta && typeof entry.meta === "object" ? entry.meta : {}),
    }),
  );
}

function createRateLimitRequest() {
  const headers = {
    authorization: SENTINEL_BEARER,
    cookie: SENTINEL_COOKIE,
  };
  return {
    method: "POST",
    path: "/api/v1/certops/executor/events",
    originalUrl: "/api/v1/certops/executor/events",
    baseUrl: "/api/v1/certops/executor",
    route: { path: "/events" },
    ip: "203.0.113.7",
    params: {},
    headers,
    apiToken: {
      id: "token-1",
      workspaceId: WORKSPACE_A,
      tokenPrefix: `ttx_${TOKEN_ID}`,
      scopes: ["certops:events:write"],
      name: "Executor",
      createdBy: 42,
      lastUsedAt: null,
    },
    get(name) {
      return headers[String(name).toLowerCase()];
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
  };
}

describe("production error and rate-limit log paths", () => {
  it("does not log bearer tokens or cookies on a CertOps machine-token 429", async () => {
    const spy = captureWarn(apiLogger);
    const res = createResponse();
    try {
      const middleware = createCertOpsMachineTokenRateLimit({ max: 0 });
      await middleware(createRateLimitRequest(), res, () => {});
      assert.equal(res.statusCode, 429);
      assert.equal(res.body.code, CERTOPS_MACHINE_RATE_LIMITED);

      assert.equal(spy.captured.length > 0, true);
      assert.equal(spy.captured[0].message, "RATE_LIMIT_EXCEEDED");
      const raw = dumpLogs(spy.captured);
      const sanitized = spy.captured.map(serializedWarn).join("\n");
      assertNoSentinels(raw);
      assertNoSentinels(sanitized);
      assertKeepsSafeDiagnostics(raw, { message: "RATE_LIMIT_EXCEEDED" });
      assert.equal(raw.includes("certops_machine_token"), true);
      assert.equal(raw.includes("post_auth"), true);
    } finally {
      spy.restore();
    }
  });

  it("does not log request headers or payloads when a webhook is SSRF-blocked", async () => {
    process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK = "true";
    delete process.env.WEBHOOK_ALLOW_PRIVATE_IPS;
    const spy = captureWarn(apiLogger);
    try {
      await assert.rejects(
        () =>
          webhookSafety.postWebhook("https://192.168.50.10/hooks/example", {
            body: { text: SENTINEL_PAYLOAD },
            headers: {
              Authorization: SENTINEL_BEARER,
              Cookie: SENTINEL_COOKIE,
            },
            lookupAll: async () => [{ address: "192.168.50.10", family: 4 }],
          }),
        (err) => err && err.code === "WEBHOOK_PRIVATE_IP_BLOCKED",
      );
      assert.equal(spy.captured.length, 1);
      assert.equal(spy.captured[0].message, "SSRF_BLOCKED");
      const raw = dumpLogs(spy.captured);
      const sanitized = serializedWarn(spy.captured[0]);
      assertNoSentinels(raw);
      assertNoSentinels(sanitized);
      assertKeepsSafeDiagnostics(raw, { message: "SSRF_BLOCKED" });
      assert.equal(spy.captured[0].meta.hostname, "192.168.50.10");
      assert.equal(spy.captured[0].meta.resolvedIP, "192.168.50.10");
    } finally {
      spy.restore();
    }
  });

  it("does not log a worker delivery payload when private-IP enforcement blocks", async () => {
    process.env.NODE_ENV = "production";
    delete process.env.WEBHOOK_ALLOW_PRIVATE_IPS;
    delete process.env.WEBHOOK_ENFORCE_PRIVATE_IP_CHECK;
    const loggerHref = pathToFileURL(
      path.resolve(__dirname, "../../apps/worker/src/logger.js"),
    ).href;
    const { logger: workerLogger } = await import(loggerHref);
    const spy = captureWarn(workerLogger);
    try {
      const webhooksHref = `${pathToFileURL(
        path.resolve(__dirname, "../../apps/worker/src/notify/webhooks.js"),
      ).href}?t=${Date.now()}-${Math.random()}`;
      const webhooks = await import(webhooksHref);
      const result = await webhooks.postJson(
        "https://192.168.50.10/hooks/rocketchat",
        { text: SENTINEL_PAYLOAD, authorization: SENTINEL_BEARER },
        "generic",
      );
      assert.equal(result.success, false);
      assert.match(String(result.error), /private\/reserved IP/i);
      const raw = dumpLogs(spy.captured);
      assertNoSentinels(raw);
      const ssrf = spy.captured.find((row) => row.message === "SSRF_BLOCKED");
      assert.ok(ssrf, "worker should emit SSRF_BLOCKED");
      assert.equal(ssrf.meta.hostname, "192.168.50.10");
      assert.equal(ssrf.meta.resolvedIP, "192.168.50.10");
    } finally {
      spy.restore();
    }
  });
});

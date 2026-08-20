"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { createCsrfTokenLimiter } = require(
  path.resolve(__dirname, "../../apps/api/middleware/rateLimit.js"),
);

function createRequest({ ip = "203.0.113.1", forwardedFor } = {}) {
  const headers = {};
  if (forwardedFor) headers["x-forwarded-for"] = forwardedFor;
  return {
    ip,
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
    headers: {},
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
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
  const result = { req, res, nextCalled: false };

  await middleware(req, res, (error) => {
    result.nextCalled = !error;
  });

  return result;
}

describe("CSRF token endpoint rate limiter", () => {
  it("allows requests under the configured limit", async () => {
    const limiter = createCsrfTokenLimiter({ windowMs: 60_000, max: 2 });
    const req = createRequest();

    const r1 = await runMiddleware(limiter, req);
    const r2 = await runMiddleware(limiter, req);

    assert.equal(r1.nextCalled, true);
    assert.equal(r2.nextCalled, true);
  });

  it("returns 429 after the per-IP limit is exceeded", async () => {
    const limiter = createCsrfTokenLimiter({ windowMs: 60_000, max: 2 });
    const req = createRequest();

    await runMiddleware(limiter, req);
    await runMiddleware(limiter, req);
    const r3 = await runMiddleware(limiter, req);

    assert.equal(r3.nextCalled, false);
    assert.equal(r3.res.statusCode, 429);
  });

  it("different client IPs get independent buckets", async () => {
    const limiter = createCsrfTokenLimiter({ windowMs: 60_000, max: 2 });
    const clientA = createRequest({ ip: "1.2.3.4" });
    const clientB = createRequest({ ip: "5.6.7.8" });

    await runMiddleware(limiter, clientA);
    await runMiddleware(limiter, clientA);
    const r3a = await runMiddleware(limiter, clientA);
    assert.equal(r3a.nextCalled, false, "client A should be rate limited");
    assert.equal(r3a.res.statusCode, 429);

    const r1b = await runMiddleware(limiter, clientB);
    assert.equal(r1b.nextCalled, true, "client B should not be affected");
  });

  it("allows requests again once the rate-limit window elapses", async () => {
    const limiter = createCsrfTokenLimiter({ windowMs: 100, max: 1 });
    const req = createRequest();

    assert.equal((await runMiddleware(limiter, req)).nextCalled, true);
    assert.equal((await runMiddleware(limiter, req)).nextCalled, false);

    await new Promise((resolve) => setTimeout(resolve, 150));

    assert.equal((await runMiddleware(limiter, req)).nextCalled, true);
  });
});

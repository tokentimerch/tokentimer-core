"use strict";

const { describe, it, beforeEach } = require("node:test");
const assert = require("node:assert");
const {
  consumeToken,
  extractProviderSlug,
  clientIp,
  _resetBucketsForTests,
} = require("../../apps/api/sso/sso-rate-limit.js");

describe("sso-rate-limit", () => {
  beforeEach(() => {
    _resetBucketsForTests();
  });

  it("extracts provider slug from auth path", () => {
    assert.strictEqual(
      extractProviderSlug({ path: "/auth/oidc/azure-ad" }),
      "azure-ad",
    );
    assert.strictEqual(
      extractProviderSlug({ path: "/auth/saml/keycloak/callback" }),
      "keycloak",
    );
  });

  it("uses req.ip instead of raw X-Forwarded-For", () => {
    assert.strictEqual(
      clientIp({
        ip: "10.0.0.5",
        headers: { "x-forwarded-for": "203.0.113.99" },
        socket: { remoteAddress: "127.0.0.1" },
      }),
      "10.0.0.5",
    );
    assert.strictEqual(
      clientIp({
        headers: { "x-forwarded-for": "203.0.113.99" },
        socket: { remoteAddress: "192.168.1.20" },
      }),
      "192.168.1.20",
    );
  });

  it("allows burst then rejects with retry-after", () => {
    const limits = { perMin: 60, burst: 2 };
    const key = "127.0.0.1:test:start";
    assert.strictEqual(consumeToken(key, limits).allowed, true);
    assert.strictEqual(consumeToken(key, limits).allowed, true);
    const denied = consumeToken(key, limits);
    assert.strictEqual(denied.allowed, false);
    assert.ok(denied.retryAfterSec >= 1);
  });
});

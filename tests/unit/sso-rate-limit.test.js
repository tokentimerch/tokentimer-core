"use strict";

const { describe, it, beforeEach } = require("node:test");
const assert = require("node:assert");
const { EventEmitter } = require("node:events");
const {
  consumeToken,
  createSsoRateLimitMiddleware,
  getLimits,
  markSsoCallbackFailure,
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

  it("charges rejected callback redirects more than successful redirects", (t) => {
    t.mock.timers.enable({ apis: ["Date"] });
    const names = ["SSO_RATE_LIMIT_CALLBACK_BURST", "SSO_RATE_LIMIT_CALLBACK_FAILURE_WEIGHT"];
    const previous = names.map((name) => process.env[name]);
    process.env[names[0]] = "3";
    process.env[names[1]] = "2";
    t.after(() => names.forEach((name, i) => {
      if (previous[i] === undefined) delete process.env[name];
      else process.env[name] = previous[i];
    }));

    function redirect(slug, rejected) {
      const req = { ip: "127.0.0.1", path: `/auth/oidc/${slug}/callback` };
      const res = Object.assign(new EventEmitter(), { statusCode: 302, setHeader() {} });
      createSsoRateLimitMiddleware({ phase: "callback" })(req, res, () => {
        if (rejected) markSsoCallbackFailure(res);
        res.emit("finish");
      });
    }

    const limits = getLimits("callback");
    redirect("success", false);
    redirect("rejected", true);
    assert.equal(consumeToken("127.0.0.1:success:callback", limits).remaining, 1);
    assert.equal(consumeToken("127.0.0.1:rejected:callback", limits).remaining, 0);
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

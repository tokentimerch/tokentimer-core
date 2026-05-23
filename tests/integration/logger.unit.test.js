"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");

const {
  buildOrderedLogRecord,
  resolveClientIp,
  LOG_FIELD_ORDER,
} = require("../../apps/api/utils/logger");

describe("logger structured output", () => {
  it("orders canonical fields before metadata", () => {
    const ordered = buildOrderedLogRecord({
      providerSlug: "keycloak",
      level: "info",
      message: "OIDC callback: starting token exchange",
      service: "tokentimer-enterprise-api",
      timestamp: "2026-05-23T11:55:46.331Z",
      tokenUrl: "https://auth.example/token",
    });
    assert.deepStrictEqual(Object.keys(ordered).slice(0, 4), LOG_FIELD_ORDER);
    assert.strictEqual(ordered.level, "info");
    assert.strictEqual(ordered.message, "OIDC callback: starting token exchange");
    assert.strictEqual(ordered.providerSlug, "keycloak");
    assert.ok(Object.keys(ordered).indexOf("tokenUrl") > Object.keys(ordered).indexOf("timestamp"));
  });

  it("resolveClientIp extracts string from request-like objects", () => {
    assert.strictEqual(
      resolveClientIp({
        ip: "10.0.0.5",
        headers: { "x-forwarded-for": "203.0.113.1, 10.0.0.1" },
      }),
      "10.0.0.5",
    );
    assert.strictEqual(resolveClientIp("203.0.113.9"), "203.0.113.9");
    assert.strictEqual(resolveClientIp(null), null);
  });

  it("sanitizes req-like ip values instead of circular placeholders", () => {
    const ordered = buildOrderedLogRecord({
      level: "info",
      message: "Rate limiting key generated",
      service: "tokentimer-enterprise-api",
      timestamp: "2026-05-23T11:56:06.622Z",
      ip: {
        ip: "213.55.247.13",
        headers: { "x-forwarded-for": "213.55.247.13" },
      },
      type: "api_ip_enterprise",
    });
    assert.strictEqual(ordered.ip, "213.55.247.13");
  });
});

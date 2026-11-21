"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { createRequire } = require("node:module");
const request = require("supertest");
const apiRequire = createRequire(require.resolve("../../apps/api/package.json"));
const express = apiRequire("express");
const passport = apiRequire("passport");
const { mountSsoRoutes } = require("../../apps/api/sso/core-sso.js");

function appWithProviders(rows) {
  const app = express();
  mountSsoRoutes(app, {
    express,
    passport,
    pool: { query: async (_sql, [protocol]) => ({ rows: rows.filter((row) => row.type === protocol) }) },
  });
  return app;
}

describe("Core per-protocol SSO routes", () => {
  it("gates only the protocol with multiple enabled providers", async () => {
    const rows = [
      { slug: "first", type: "oidc", enabled: true },
      { slug: "other", type: "oidc", enabled: true },
      { slug: "second", type: "saml", enabled: true },
    ];
    const app = appWithProviders(rows);
    await request(app).get("/auth/oidc/first").expect(404);
    await request(app).get("/auth/oidc/first/callback").expect(404);
    await request(app).get("/auth/oidc/other").expect(404);
    await request(app).get("/auth/saml/second").expect(302);
  });

  it("dispatches one enabled provider of each protocol", async () => {
    const app = appWithProviders([{ type: "oidc", slug: "openid" }, { type: "saml", slug: "assertion" }]);
    await request(app).get("/auth/oidc/openid").expect(302);
    await request(app).get("/auth/saml/assertion").expect(302);
    await request(app).get("/auth/oidc/assertion").expect(404);
  });

  it("keeps encoded and slugless routes outside the authentication handlers", async () => {
    const app = appWithProviders([{ slug: "first", type: "oidc", enabled: true }]);
    await request(app).get("/auth/oidc/%66irst").expect(404);
    await request(app).get("/auth/oidc/callback").expect(404);
    await request(app).get("/auth/saml/metadata").expect(404);
    await request(app).get("/auth/oidc/first").expect(302);
  });

  it("routes an enabled provider even when its slug is callback or metadata", async () => {
    for (const [type, slug] of [["oidc", "callback"], ["saml", "callback"], ["saml", "metadata"]]) {
      const app = appWithProviders([{ type, slug, enabled: true }]);
      await request(app).get("/auth/" + type + "/" + slug).expect(302);
    }
  });

  it("leaves local authentication routes available without any SSO provider", async () => {
    const app = appWithProviders([]);
    app.post("/api/login", (_req, res) => res.sendStatus(204));
    const response = await request(app).get("/auth/oidc/first").expect(404);
    assert.equal(response.body.code, "NOT_FOUND");
    await request(app).post("/api/login").expect(204);
  });
});

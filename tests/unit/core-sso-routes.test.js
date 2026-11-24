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
    pool: { query: async () => ({ rows: rows.filter((row) => row.enabled !== false).slice(0, 2) }) },
  });
  return app;
}

describe("Core single-provider SSO routes", () => {
  it("gates all sign-in routes while enabled providers conflict", async () => {
    const rows = [
      { slug: "first", type: "oidc", enabled: true },
      { slug: "other", type: "oidc", enabled: true },
      { slug: "second", type: "saml", enabled: true },
    ];
    const app = appWithProviders(rows);
    await request(app).get("/auth/oidc/first").expect(404);
    await request(app).get("/auth/oidc/first/callback").expect(404);
    await request(app).get("/auth/oidc/other").expect(404);
    await request(app).get("/auth/saml/second").expect(404);
    await request(app).post("/auth/saml/second/callback").expect(404);
    await request(app).get("/auth/saml/second/metadata").expect(404);
  });

  it("dispatches either protocol only when it is the single enabled provider", async () => {
    const oidc = { type: "oidc", slug: "openid", enabled: true };
    const saml = { type: "saml", slug: "assertion", enabled: true };
    const withOidc = appWithProviders([oidc, { ...saml, enabled: false }]);
    await request(withOidc).get("/auth/oidc/openid").expect(302);
    await request(withOidc).get("/auth/saml/assertion").expect(404);
    const withSaml = appWithProviders([saml]);
    await request(withSaml).get("/auth/saml/assertion").expect(302);
    await request(withSaml).get("/auth/oidc/assertion").expect(404);
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

it("keeps SSO metadata audit failures generic while retaining fetch diagnostics", async (t) => {
  const { pool } = require("../../apps/api/db/database");
  const audit = require("../../apps/api/services/audit");
  const rateLimit = require("../../apps/api/middleware/rateLimit");
  const metadata = require("../../apps/api/sso/fetch-idp-metadata");
  const outbound = require("../../apps/api/sso/safe-fetch");
  const { logger } = require("../../apps/api/utils/logger");
  const url = "https://idp.example.test/metadata";
  const route = "/api/admin/sso/fetch-idp-metadata";
  let transportUnavailable = false;
  const writeAudit = t.mock.method(audit, "writeAudit", async () => {
    throw new Error("synthetic audit storage details");
  });
  t.mock.method(pool, "query", async () => ({ rows: [{ is_admin: true }] }));
  t.mock.method(rateLimit, "getApiLimiter", () => (_req, _res, next) => next());
  t.mock.method(outbound, "validateOutboundUrl", async () => ({ ok: true, parsed: new URL(url) }));
  t.mock.method(metadata, "fetchIdpMetadataXml", async () => {
    if (transportUnavailable) throw new Error("HTTP 404");
    return "<EntityDescriptor />";
  });
  t.mock.method(logger, "error", () => {});

  const app = express();
  app.use(express.json(), (req, _res, next) => {
    req.user = { id: 1 };
    req.isAuthenticated = () => true;
    next();
  });
  const routerPath = require.resolve("../../apps/api/routes/sso-providers");
  t.after(() => { delete require.cache[routerPath]; });
  app.use(require(routerPath));

  const failedAudit = await request(app).post(route).send({ url }).expect(502);
  assert.deepEqual(failedAudit.body, { error: "Fetch failed", code: "fetch_failed" });
  assert.equal(writeAudit.mock.callCount(), 1);

  transportUnavailable = true;
  const failedFetch = await request(app).post(route).send({ url }).expect(502);
  assert.deepEqual(failedFetch.body, { error: "HTTP 404", code: "fetch_failed" });
  assert.equal(writeAudit.mock.callCount(), 1);
});

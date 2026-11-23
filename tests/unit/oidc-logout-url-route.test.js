"use strict";

/**
 * Route-level behaviour of GET /api/sso/logout-url across session shapes.
 *
 * Exercises the real Express router from apps/api/auth/oidc.js with a stubbed provider
 * runtime, so the session -> end-session-URL wiring is verified rather than assumed.
 */

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert");
const apiRequire = require("node:module").createRequire(require.resolve("../../apps/api/package.json"));
const express = apiRequire("express");
const request = require("supertest");

const oidcProvider = require("../../apps/api/auth/oidc");

const END_SESSION =
  "https://auth.example.com/realms/tt/protocol/openid-connect/logout";

const STRATEGY_CONFIG = {
  issuer: "https://auth.example.com/realms/tt",
  clientID: "tokentimer",
  clientSecret: "secret",
  callbackURL: "https://tt.example.com/auth/oidc/kc/callback",
  authorizationURL: "https://auth.example.com/authorize",
  tokenURL: "https://auth.example.com/token",
  endSessionURL: END_SESSION,
};

/**
 * @param {object|null} ssoSession value to expose as req.session.sso
 */
function buildApp(ssoSession) {
  const app = express();
  app.use((req, _res, next) => {
    req.session = ssoSession ? { sso: ssoSession } : {};
    next();
  });
  app.use(oidcProvider.oidcRoutes(null, express));
  return app;
}

describe("GET /api/sso/logout-url", () => {
  let previousDisable;
  let previousRedirect;

  beforeEach(() => {
    previousDisable = process.env.SSO_DISABLE_SINGLE_LOGOUT;
    previousRedirect = process.env.SSO_POST_LOGOUT_REDIRECT;
    delete process.env.SSO_DISABLE_SINGLE_LOGOUT;
    delete process.env.SSO_POST_LOGOUT_REDIRECT;
    process.env.APP_URL = "https://tt.example.com";
    oidcProvider._setOidcRuntimeForTests("kc", {
      providerSlug: "kc",
      enabled: true,
      strategyConfig: STRATEGY_CONFIG,
      client: null,
      openIdClient: null,
    });
  });

  afterEach(() => {
    if (previousDisable === undefined) {
      delete process.env.SSO_DISABLE_SINGLE_LOGOUT;
    } else {
      process.env.SSO_DISABLE_SINGLE_LOGOUT = previousDisable;
    }
    if (previousRedirect === undefined) {
      delete process.env.SSO_POST_LOGOUT_REDIRECT;
    } else {
      process.env.SSO_POST_LOGOUT_REDIRECT = previousRedirect;
    }
  });

  it("returns the IdP end-session URL for an OIDC session", async () => {
    const res = await request(buildApp({ providerSlug: "kc", protocol: "oidc", idToken: "IDTOK" }))
      .get("/api/sso/logout-url")
      .expect(200);

    assert.ok(res.body.url, "expected an end-session URL");
    const parsed = new URL(res.body.url);
    assert.equal(`${parsed.origin}${parsed.pathname}`, END_SESSION);
    assert.equal(parsed.searchParams.get("id_token_hint"), "IDTOK");
    assert.equal(
      parsed.searchParams.get("client_id"),
      null,
      "client_id must not accompany id_token_hint",
    );
  });

  it("omits post_logout_redirect_uri by default", async () => {
    const res = await request(
      buildApp({ providerSlug: "kc", protocol: "oidc", idToken: "IDTOK" }),
    )
      .get("/api/sso/logout-url")
      .expect(200);
    assert.equal(
      new URL(res.body.url).searchParams.get("post_logout_redirect_uri"),
      null,
      "an unregistered redirect URI makes Keycloak answer 400 Invalid redirect uri, so it must be opt-in",
    );
  });

  it("includes post_logout_redirect_uri when explicitly enabled", async () => {
    process.env.SSO_POST_LOGOUT_REDIRECT = "true";
    const res = await request(
      buildApp({ providerSlug: "kc", protocol: "oidc", idToken: "IDTOK" }),
    )
      .get("/api/sso/logout-url")
      .expect(200);
    assert.equal(
      new URL(res.body.url).searchParams.get("post_logout_redirect_uri"),
      "https://tt.example.com/login",
    );
  });

  it("returns null for a SAML session (SAML SLO is not implemented)", async () => {
    const res = await request(buildApp({ providerSlug: "kc", protocol: "saml" }))
      .get("/api/sso/logout-url")
      .expect(200);
    assert.deepEqual(res.body, { url: null });
  });

  it("returns null for a local password session", async () => {
    const res = await request(buildApp(null))
      .get("/api/sso/logout-url")
      .expect(200);
    assert.deepEqual(res.body, { url: null });
  });

  it("returns null when the provider runtime is gone", async () => {
    const res = await request(
      buildApp({ providerSlug: "deleted-provider", protocol: "oidc", idToken: "t" }),
    )
      .get("/api/sso/logout-url")
      .expect(200);
    assert.deepEqual(res.body, { url: null });
  });

  it("honours the SSO_DISABLE_SINGLE_LOGOUT escape hatch", async () => {
    process.env.SSO_DISABLE_SINGLE_LOGOUT = "true";
    const res = await request(
      buildApp({ providerSlug: "kc", protocol: "oidc", idToken: "IDTOK" }),
    )
      .get("/api/sso/logout-url")
      .expect(200);
    assert.deepEqual(res.body, { url: null });
  });

  it("still returns a URL when no id_token was retained, using client_id", async () => {
    const res = await request(buildApp({ providerSlug: "kc", protocol: "oidc" }))
      .get("/api/sso/logout-url")
      .expect(200);
    const parsed = new URL(res.body.url);
    assert.equal(parsed.searchParams.get("client_id"), "tokentimer");
    assert.equal(parsed.searchParams.get("id_token_hint"), null);
  });

  it("normalises a trailing slash on APP_URL", async () => {
    process.env.SSO_POST_LOGOUT_REDIRECT = "true";
    process.env.APP_URL = "https://tt.example.com/";
    const res = await request(
      buildApp({ providerSlug: "kc", protocol: "oidc", idToken: "IDTOK" }),
    )
      .get("/api/sso/logout-url")
      .expect(200);
    assert.equal(
      new URL(res.body.url).searchParams.get("post_logout_redirect_uri"),
      "https://tt.example.com/login",
      "a doubled slash would not match the URI registered at the IdP",
    );
  });

  it("returns null instead of failing when the provider has no end-session endpoint", async () => {
    oidcProvider._setOidcRuntimeForTests("kc", {
      providerSlug: "kc",
      enabled: true,
      strategyConfig: { ...STRATEGY_CONFIG, endSessionURL: undefined },
      client: null,
      openIdClient: null,
    });
    const res = await request(
      buildApp({ providerSlug: "kc", protocol: "oidc", idToken: "IDTOK" }),
    )
      .get("/api/sso/logout-url")
      .expect(200);
    assert.deepEqual(res.body, { url: null });
  });
});

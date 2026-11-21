"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const apiRequire = require("node:module").createRequire(require.resolve("../../apps/api/package.json"));
const express = apiRequire("express");
const cookieParser = apiRequire("cookie-parser");
const saml = require("../../apps/api/auth/saml");
const { setProviderRuntimeStatus, removeProviderRuntimeStatus } = require("../../apps/api/sso/sso-runtime-status");

test("SAML POST recovers a request through a host-only cross-site cookie and records bounded failures", async (t) => {
  const slug = "browser";
  const callbackPath = `/auth/saml/${slug}/callback`;
  const audit = [];
  const records = new Map();
  const relayStates = [];
  let failSessionSave = false;
  const passport = {
    authenticate(_name, callback) {
      return async (req, res) => {
        if (req.method === "GET") {
          relayStates.push(req.samlRelayState);
          await req.samlBrowserCache.saveAsync("request", "pending");
          return res.sendStatus(200);
        }
        assert.equal(await req.samlBrowserCache.consumeAsync("request"), "pending");
        return failSessionSave ? callback(null, { id: 1 }) : callback(new Error("sample upstream detail"));
      };
    },
  };
  await saml.setupSamlStrategy(passport, {}, class {}, {
    loadProviders: async () => [],
    writeAudit: async (entry) => audit.push(entry),
  });
  saml._setSamlRuntimeForTests(slug, {
    enabled: true,
    strategyConfig: {
      callbackUrl: "https://api.example.test" + callbackPath,
      authnRequestBinding: "HTTP-POST",
      entryPoint: "https://idp.example.test/saml",
    },
    cacheProvider: {
      ttlMs: 60000,
      saveAsync: async (key, value) => records.set(key, value),
      consumeAsync: async (key) => {
        const value = records.get(key);
        records.delete(key);
        return value ?? null;
      },
    },
  });
  setProviderRuntimeStatus(slug, { type: "saml", signInReady: true });
  t.after(() => {
    saml._resetSamlRuntimeForTests();
    removeProviderRuntimeStatus(slug);
  });

  const app = express();
  app.use(cookieParser());
  app.use((req, _res, next) => {
    req.logIn = (_user, done) => done(new Error("sample session detail"));
    next();
  });
  app.use(saml.samlRoutes(passport, express));
  const server = await new Promise((resolve) => {
    const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const start = await fetch(origin + "/auth/saml/" + slug + "?next=%2Faccount");
  assert.equal(start.status, 200);
  assert.deepEqual(relayStates, ["/account"]);
  assert.match(start.headers.get("content-security-policy"), /form-action https:\/\/idp.example.test;/);
  assert.match(start.headers.get("content-security-policy"), /script-src 'unsafe-hashes' 'sha256-/);
  const cookie = start.headers.get("set-cookie");
  assert.match(cookie, /^__Host-tt-saml-browser=[0-9a-f]{64};/);
  assert.match(cookie, /; HttpOnly/i);
  assert.match(cookie, /; Secure/i);
  assert.match(cookie, /; SameSite=None/i);
  assert.match(cookie, /; Path=\//i);
  assert.doesNotMatch(cookie, /; Domain=/i);
  const callback = await fetch(origin + callbackPath + "?state=sample", {
    method: "POST",
    redirect: "manual",
    headers: { cookie: cookie.split(";")[0] },
    body: new URLSearchParams({ RelayState: "/dashboard?code=sample" }),
  });
  assert.equal(callback.status, 302);
  assert.deepEqual(audit.at(-1).metadata, {
    method: "saml", provider_slug: slug, protocol: "saml",
    reason: "callback_error", path: callbackPath,
  });

  // Session-store failures get the same public redirect as assertion failures.
  failSessionSave = true;
  const browserCookie = cookie.split(";")[0];
  await fetch(origin + "/auth/saml/" + slug, { headers: { cookie: browserCookie } });
  assert.deepEqual(relayStates, ["/account", null]);
  const sessionFailure = await fetch(origin + callbackPath, {
    method: "POST", redirect: "manual", headers: { cookie: browserCookie },
    body: new URLSearchParams(),
  });
  assert.equal(sessionFailure.status, 302);
  assert.equal(new URL(sessionFailure.headers.get("location")).search, "?error=saml_failed");
  assert.deepEqual(audit.at(-1).metadata, {
    method: "saml", provider_slug: slug, reason: "session_login_error",
  });
});

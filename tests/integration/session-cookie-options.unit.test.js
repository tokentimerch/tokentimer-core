"use strict";

const { expect } = require("chai");
const {
  resolveSessionCookieOptions,
  resolveClearSessionCookieOptions,
  resolveCsrfCookieName,
  buildCorsOrigins,
  resolveEffectiveOrigins,
  shouldUseCrossOriginCookies,
} = require("../../apps/api/session-cookie-options");

describe("session-cookie-options", () => {
  describe("shouldUseCrossOriginCookies", () => {
    it("is false for same origin", () => {
      expect(
        shouldUseCrossOriginCookies(
          "https://tokentimer.example.com",
          "https://tokentimer.example.com",
        ),
      ).to.equal(false);
    });

    it("is true for HTTPS split-host", () => {
      expect(
        shouldUseCrossOriginCookies(
          "https://api.example.com",
          "https://app.example.com",
        ),
      ).to.equal(true);
    });

    it("is false for stock Compose localhost HTTP split ports", () => {
      expect(
        shouldUseCrossOriginCookies(
          "http://localhost:4000",
          "http://localhost:5173",
        ),
      ).to.equal(false);
    });

    it("is false for Helm port-forward localhost HTTP (8080 + 4000)", () => {
      expect(
        shouldUseCrossOriginCookies(
          "http://localhost:4000",
          "http://localhost:8080",
        ),
      ).to.equal(false);
    });

    it("is false for LAN HTTP split ports", () => {
      expect(
        shouldUseCrossOriginCookies(
          "http://192.168.1.10:4000",
          "http://192.168.1.10:8080",
        ),
      ).to.equal(false);
    });

    it("is false for mixed-scheme split-host", () => {
      expect(
        shouldUseCrossOriginCookies(
          "http://api.example.com",
          "https://app.example.com",
        ),
      ).to.equal(false);
    });
  });

  describe("resolveSessionCookieOptions", () => {
    it("keeps lax for stock Compose localhost split ports", () => {
      const cookie = resolveSessionCookieOptions({
        NODE_ENV: "production",
        API_URL: "http://localhost:4000",
        APP_URL: "http://localhost:5173",
      });
      expect(cookie.sameSite).to.equal("lax");
      expect(cookie.secure).to.equal(true);
    });

    it("uses SameSite=None only for HTTPS split-host", () => {
      const cookie = resolveSessionCookieOptions({
        NODE_ENV: "production",
        API_URL: "https://api.example.com",
        APP_URL: "https://app.example.com",
      });
      expect(cookie.sameSite).to.equal("none");
      expect(cookie.secure).to.equal(true);
    });

    it("does not use SameSite=None for HTTP split-host on real hostnames", () => {
      const cookie = resolveSessionCookieOptions({
        NODE_ENV: "production",
        API_URL: "http://api.internal.corp",
        APP_URL: "http://app.internal.corp",
      });
      expect(cookie.sameSite).to.equal("lax");
    });

    it("sets SESSION_COOKIE_DOMAIN when provided", () => {
      const cookie = resolveSessionCookieOptions({
        NODE_ENV: "production",
        API_URL: "https://api.example.com",
        APP_URL: "https://app.example.com",
        SESSION_COOKIE_DOMAIN: "example.com",
      });
      expect(cookie.domain).to.equal(".example.com");
      expect(cookie.sameSite).to.equal("none");
    });

    it("honours SESSION_COOKIE_SECURE_LOCALHOST_OVERRIDE on local HTTP", () => {
      const cookie = resolveSessionCookieOptions({
        NODE_ENV: "production",
        API_URL: "http://localhost:4000",
        APP_URL: "http://localhost:5173",
        SESSION_COOKIE_SECURE_LOCALHOST_OVERRIDE: "true",
      });
      expect(cookie.sameSite).to.equal("lax");
      expect(cookie.secure).to.equal(false);
    });
    it("ignores SESSION_COOKIE_SECURE_LOCALHOST_OVERRIDE on public HTTPS", () => {
      const cookie = resolveSessionCookieOptions({
        NODE_ENV: "production",
        API_URL: "https://api.example.com",
        APP_URL: "https://app.example.com",
        SESSION_COOKIE_SECURE_LOCALHOST_OVERRIDE: "true",
      });
      expect(cookie.secure).to.equal(true);
      expect(cookie.sameSite).to.equal("none");
    });
  });

  describe("resolveCsrfCookieName", () => {
    it("uses __Host- prefix only without session cookie Domain", () => {
      const cookie = resolveSessionCookieOptions({
        NODE_ENV: "production",
        API_URL: "https://api.example.com",
        APP_URL: "https://app.example.com",
      });
      expect(
        resolveCsrfCookieName({ NODE_ENV: "production" }, cookie),
      ).to.equal("__Host-psifi.x-csrf-token");
    });

    it("avoids __Host- when SESSION_COOKIE_DOMAIN is set", () => {
      const cookie = resolveSessionCookieOptions({
        NODE_ENV: "production",
        API_URL: "https://api.example.com",
        APP_URL: "https://app.example.com",
        SESSION_COOKIE_DOMAIN: "example.com",
      });
      expect(
        resolveCsrfCookieName({ NODE_ENV: "production" }, cookie),
      ).to.equal("x-csrf-token");
    });
  });

  describe("resolveClearSessionCookieOptions", () => {
    it("matches session cookie attributes for logout", () => {
      const env = {
        NODE_ENV: "production",
        API_URL: "http://localhost:4000",
        APP_URL: "http://localhost:5173",
        SESSION_COOKIE_SECURE_LOCALHOST_OVERRIDE: "true",
      };
      const session = resolveSessionCookieOptions(env);
      const clearOpts = resolveClearSessionCookieOptions(env);
      expect(clearOpts.sameSite).to.equal(session.sameSite);
      expect(clearOpts.secure).to.equal(session.secure);
      expect(clearOpts.path).to.equal("/");
      expect(clearOpts.domain).to.equal(session.domain);
    });

    it("includes domain when SESSION_COOKIE_DOMAIN is set", () => {
      const clearOpts = resolveClearSessionCookieOptions({
        NODE_ENV: "production",
        API_URL: "https://api.example.com",
        APP_URL: "https://app.example.com",
        SESSION_COOKIE_DOMAIN: "example.com",
      });
      expect(clearOpts.domain).to.equal(".example.com");
      expect(clearOpts.sameSite).to.equal("none");
    });

    it("does not use SameSite=Strict (logout regression guard)", () => {
      const clearOpts = resolveClearSessionCookieOptions({
        NODE_ENV: "production",
        API_URL: "http://localhost:4000",
        APP_URL: "http://localhost:5173",
      });
      expect(clearOpts.sameSite).to.not.equal("strict");
    });
  });

  describe("resolveEffectiveOrigins", () => {
    it("falls back API origin to APP_URL when API_URL is unset", () => {
      const { apiOrigin, appOrigin } = resolveEffectiveOrigins({
        APP_URL: "https://tokentimer.example.com",
      });
      expect(apiOrigin).to.equal("https://tokentimer.example.com");
      expect(appOrigin).to.equal("https://tokentimer.example.com");
      expect(shouldUseCrossOriginCookies(apiOrigin, appOrigin)).to.equal(false);
    });
  });

  describe("buildCorsOrigins", () => {
    it("includes API_URL without trailing slash", () => {
      const origins = buildCorsOrigins({
        APP_URL: "https://app.example.com",
        API_URL: "https://api.example.com/",
      });
      expect(origins).to.include("https://app.example.com");
      expect(origins).to.include("https://api.example.com");
      expect(origins).to.not.include("https://api.example.com/");
    });

    it("includes default local API port for dev CORS", () => {
      const origins = buildCorsOrigins({
        APP_URL: "http://localhost:5173",
      });
      expect(origins).to.include("http://localhost:4000");
    });
    it("omits localhost dev origins in production unless ALLOW_LOCAL_DEV_CORS", () => {
      const origins = buildCorsOrigins({
        NODE_ENV: "production",
        APP_URL: "https://app.example.com",
        API_URL: "https://api.example.com",
      });
      expect(origins).to.not.include("http://localhost:5173");
      expect(origins).to.not.include("http://127.0.0.1:4000");
    });

    it("allows localhost dev origins in production when ALLOW_LOCAL_DEV_CORS=true", () => {
      const origins = buildCorsOrigins({
        NODE_ENV: "production",
        APP_URL: "https://app.example.com",
        API_URL: "https://api.example.com",
        ALLOW_LOCAL_DEV_CORS: "true",
      });
      expect(origins).to.include("http://localhost:5173");
    });  
  });
});

"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");

const { buildEndSessionUrl } = require("../../apps/api/auth/oidc-flow");
const { normalizeBaseUrl } = require("../../apps/api/sso/callback-urls");
const { createProviderStrategyConfig } = require("../../apps/api/sso/strategy-config");

const BASE = {
  issuer: "https://issuer.example.com",
  clientID: "tokentimer",
  clientSecret: "secret",
  callbackURL: "https://tt.example.com/auth/oidc/kc/callback",
  authorizationURL: "https://issuer.example.com/authorize",
  tokenURL: "https://issuer.example.com/token",
};

const POST_LOGOUT = "https://tt.example.com/login";

/**
 * end_session_endpoint shapes taken from real provider discovery documents, so a
 * provider-specific URL layout cannot silently break single logout. Covers every
 * OIDC provider with an entry in src/sso/oidc-provider-hints.js that advertises
 * an end-session endpoint.
 */
const PROVIDER_ENDPOINTS = {
  keycloak:
    "https://auth.example.com/realms/tt/protocol/openid-connect/logout",
  entra: "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/logout",
  okta: "https://dev-1.okta.com/oauth2/v1/logout",
  auth0: "https://tenant.eu.auth0.com/oidc/logout",
  ping: "https://sso.example.com/as/signoff.oauth2",
  zitadel: "https://instance.zitadel.cloud/oidc/v1/end_session",
  authentik:
    "https://authentik.example.com/application/o/tt/end-session/",
  adfs: "https://adfs.example.com/adfs/oauth2/logout",
};

const PROVIDERS_WITHOUT_END_SESSION = ["google", "gitlab"];

function cfg(endSessionURL) {
  return { ...BASE, endSessionURL };
}

describe("discovered OIDC logout endpoints", () => {
  const cognitoDomain = "https://tt.auth.eu-west-1.amazoncognito.com";
  const cognitoIssuers = [
    "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_pool",
    "https://issuer-cognito-idp.eu-west-1.amazonaws.com/eu-west-1_pool",
  ];
  const discovery = {
    authorization_endpoint: cognitoDomain + "/oauth2/authorize",
    token_endpoint: cognitoDomain + "/oauth2/token",
    userinfo_endpoint: cognitoDomain + "/oauth2/userInfo",
    end_session_endpoint: cognitoDomain + "/logout",
  };
  const { buildOidcStrategyConfigFromProvider } = createProviderStrategyConfig({
    fetchImpl: async () => ({ ok: true, json: async () => discovery }),
    validateOutboundUrl: async () => ({ ok: true }),
  });

  function buildStrategy(issuer, overrides = {}) {
    return buildOidcStrategyConfigFromProvider(
      null,
      { slug: "cognito", config: { issuer, client_id: BASE.clientID, ...overrides } },
      { client_secret: BASE.clientSecret },
    );
  }

  for (const issuer of cognitoIssuers) {
    it(`keeps sign-out local for Cognito discovery from ${new URL(issuer).hostname}`, async () => {
      const strategy = await buildStrategy(issuer);
      assert.equal(strategy.tokenURL, discovery.token_endpoint);
      assert.equal(buildEndSessionUrl(strategy, { idToken: "fixture" }), null);
    });
  }

  it("preserves a Cognito operator's explicit OIDC-compatible end-session override", async () => {
    const endpoint = "https://logout.example.com/oidc/end-session";
    const strategy = await buildStrategy(cognitoIssuers[0], { end_session_url: endpoint });
    assert.equal(strategy.endSessionURL, endpoint);
  });

  it("preserves a standard provider's discovered end-session endpoint", async () => {
    const strategy = await buildStrategy(BASE.issuer);
    assert.equal(strategy.endSessionURL, discovery.end_session_endpoint);
  });
});

describe("buildEndSessionUrl (RP-initiated logout)", () => {
  it("returns null when the provider advertises no end_session_endpoint", () => {
    assert.equal(
      buildEndSessionUrl(cfg(undefined), { idToken: "tok" }),
      null,
      "providers without an end-session endpoint must degrade to a local-only sign-out, not throw",
    );
  });

  it("returns null for a missing strategy config", () => {
    assert.equal(buildEndSessionUrl(null, {}), null);
    assert.equal(buildEndSessionUrl(undefined, {}), null);
  });

  for (const name of PROVIDERS_WITHOUT_END_SESSION) {
    it(`degrades to local-only sign-out for ${name} (publishes no end_session_endpoint)`, () => {
      assert.equal(
        buildEndSessionUrl(cfg(null), { idToken: "tok" }),
        null,
        `${name} must not break sign-out; the local session is still cleared`,
      );
    });
  }

  it("honours a manually configured end_session_url for such providers", () => {
    const endpoint = "https://logout.example.com/oidc/end-session";
    const url = buildEndSessionUrl(
      cfg(endpoint),
      { postLogoutRedirectUri: POST_LOGOUT },
    );
    assert.equal(new URL(url).origin + new URL(url).pathname, endpoint);
    assert.equal(new URL(url).searchParams.get("client_id"), "tokentimer");
  });

  for (const [name, endpoint] of Object.entries(PROVIDER_ENDPOINTS)) {
    it(`builds a valid end-session URL for ${name}`, () => {
      const url = buildEndSessionUrl(cfg(endpoint), {
        idToken: "ID_TOKEN_VALUE",
        postLogoutRedirectUri: POST_LOGOUT,
      });
      const parsed = new URL(url);

      assert.equal(
        `${parsed.origin}${parsed.pathname}`,
        endpoint,
        "must preserve the provider's advertised endpoint path",
      );
      assert.equal(
        parsed.searchParams.get("id_token_hint"),
        "ID_TOKEN_VALUE",
        "Okta rejects an end-session request without id_token_hint",
      );
      assert.equal(
        parsed.searchParams.get("post_logout_redirect_uri"),
        POST_LOGOUT,
      );
    });
  }

  it("falls back to client_id when no id_token was retained", () => {
    const url = buildEndSessionUrl(cfg(PROVIDER_ENDPOINTS.keycloak), {
      postLogoutRedirectUri: POST_LOGOUT,
    });
    const parsed = new URL(url);
    assert.equal(parsed.searchParams.get("id_token_hint"), null);
    assert.equal(
      parsed.searchParams.get("client_id"),
      "tokentimer",
      "Keycloak, Entra ID and Auth0 accept client_id when no ID token is available",
    );
  });

  it("omits client_id when id_token_hint is present", () => {
    const url = buildEndSessionUrl(cfg(PROVIDER_ENDPOINTS.okta), {
      idToken: "ID_TOKEN_VALUE",
      postLogoutRedirectUri: POST_LOGOUT,
    });
    const parsed = new URL(url);
    assert.equal(
      parsed.searchParams.get("client_id"),
      null,
      "Okta documents client_id as unsupported on its logout endpoint and answers invalid_client; openid-client injects it unless suppressed",
    );
    assert.equal(parsed.searchParams.get("id_token_hint"), "ID_TOKEN_VALUE");
  });

  it("never sends both id_token_hint and client_id for any provider", () => {
    for (const [name, endpoint] of Object.entries(PROVIDER_ENDPOINTS)) {
      const parsed = new URL(
        buildEndSessionUrl(cfg(endpoint), {
          idToken: "tok",
          postLogoutRedirectUri: POST_LOGOUT,
        }),
      );
      const both =
        parsed.searchParams.has("id_token_hint") &&
        parsed.searchParams.has("client_id");
      assert.equal(both, false, `${name} must not receive both identifiers`);
    }
  });

  it("produces exactly one slash before /login regardless of APP_URL slash", () => {
    // IdPs compare post_logout_redirect_uri as an exact string; "host//login"
    // is not the registered "host/login" and gets rejected.
    for (const appUrl of [
      "https://tt.example.com",
      "https://tt.example.com/",
      "https://tt.example.com///",
    ]) {
      const redirect = `${normalizeBaseUrl(appUrl) || appUrl}/login`;
      assert.equal(
        redirect,
        "https://tt.example.com/login",
        `APP_URL '${appUrl}' must normalise to a single slash`,
      );
    }
  });

  it("omits post_logout_redirect_uri when none is supplied", () => {
    const url = buildEndSessionUrl(cfg(PROVIDER_ENDPOINTS.keycloak), {
      idToken: "tok",
    });
    assert.equal(
      new URL(url).searchParams.get("post_logout_redirect_uri"),
      null,
      "an unregistered redirect URI makes some IdPs reject the request outright",
    );
  });

  it("passes state through when supplied", () => {
    const url = buildEndSessionUrl(cfg(PROVIDER_ENDPOINTS.okta), {
      idToken: "tok",
      state: "xyz",
    });
    assert.equal(new URL(url).searchParams.get("state"), "xyz");
  });

  it("does not leak the client secret into the logout URL", () => {
    const url = buildEndSessionUrl(cfg(PROVIDER_ENDPOINTS.keycloak), {
      idToken: "tok",
      postLogoutRedirectUri: POST_LOGOUT,
    });
    assert.ok(
      !url.includes(BASE.clientSecret),
      "the end-session URL is browser-visible and must never carry the client secret",
    );
  });

  it("reuses a provided client instead of constructing a new one", () => {
    let called = 0;
    const stubClient = {
      endSessionUrl: (params) => {
        called += 1;
        return `https://stub.test/logout?hint=${params.id_token_hint}`;
      },
    };
    const url = buildEndSessionUrl(cfg(PROVIDER_ENDPOINTS.keycloak), {
      idToken: "tok",
      client: stubClient,
    });
    assert.equal(called, 1);
    assert.equal(url, "https://stub.test/logout?hint=tok");
  });
});

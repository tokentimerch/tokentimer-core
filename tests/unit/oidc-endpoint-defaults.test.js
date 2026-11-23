"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const {
  suggestJwksUriFromIssuer,
  suggestOidcEndpointsFromIssuer,
  discoveryDocumentUrlFromIssuer,
  isAuth0LikeIssuer,
} = require("../../apps/api/sso/oidc-endpoint-defaults.js");

describe("oidc-endpoint-defaults", () => {
  it("suggests Keycloak realm OIDC endpoints (not /authorize)", () => {
    const kc = suggestOidcEndpointsFromIssuer(
      "https://idp.example.com/realms/tt-test",
    );
    assert.strictEqual(
      kc.authorizationURL,
      "https://idp.example.com/realms/tt-test/protocol/openid-connect/auth",
    );
    assert.strictEqual(
      kc.tokenURL,
      "https://idp.example.com/realms/tt-test/protocol/openid-connect/token",
    );
    assert.strictEqual(
      kc.jwksURL,
      "https://idp.example.com/realms/tt-test/protocol/openid-connect/certs",
    );
    assert.strictEqual(
      kc.endSessionURL,
      "https://idp.example.com/realms/tt-test/protocol/openid-connect/logout",
    );
    assert.strictEqual(
      suggestJwksUriFromIssuer("https://idp.example.com/realms/tokentimer/"),
      "https://idp.example.com/realms/tokentimer/protocol/openid-connect/certs",
    );
  });

  it("does not invent Auth0-shaped endpoints for unknown issuers", () => {
    const generic = suggestOidcEndpointsFromIssuer("https://idp.example.com/");
    assert.strictEqual(generic.authorizationURL, "");
    assert.strictEqual(generic.tokenURL, "");
    assert.strictEqual(generic.jwksURL, "");
    assert.strictEqual(generic.endSessionURL, "");
    assert.strictEqual(suggestJwksUriFromIssuer("https://idp.example.com/"), "");
  });

  it("suggests Auth0-shaped endpoints for Auth0 tenant issuers", () => {
    assert.ok(isAuth0LikeIssuer("https://tenant.eu.auth0.com/"));
    const auth0 = suggestOidcEndpointsFromIssuer("https://tenant.eu.auth0.com/");
    assert.strictEqual(
      auth0.authorizationURL,
      "https://tenant.eu.auth0.com/authorize",
    );
    assert.strictEqual(
      auth0.jwksURL,
      "https://tenant.eu.auth0.com/.well-known/jwks.json",
    );
    assert.strictEqual(
      auth0.endSessionURL,
      "https://tenant.eu.auth0.com/oidc/logout",
    );
  });

  it("builds discovery document URL from issuer", () => {
    assert.strictEqual(
      discoveryDocumentUrlFromIssuer("https://idp.example.com"),
      "https://idp.example.com/.well-known/openid-configuration",
    );
  });
});

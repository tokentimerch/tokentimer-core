"use strict";

const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert");

const { createProviderStrategyConfig } = require("../../apps/api/sso/strategy-config.js");
const { buildComputedUrls } = require("../../apps/api/sso/sso-computed-urls.js");
const { getSamlMetadataUrl } = require("../../apps/api/sso/callback-urls.js");

describe("SAML metadata URL vs AuthnRequest binding preference", () => {
  const builders = createProviderStrategyConfig();
  const pool = { query: async () => ({ rows: [] }) };

  beforeEach(() => {
    process.env.API_URL = "https://api.example.com";
  });

  afterEach(() => {
    delete process.env.API_URL;
  });

  it("computed metadata URL is GET endpoint separate from AuthnRequest binding", () => {
    const computed = buildComputedUrls({
      slug: "keycloak-saml",
      type: "saml",
      config: {},
    });
    assert.strictEqual(
      computed.metadata_url,
      getSamlMetadataUrl("keycloak-saml"),
    );
    assert.match(computed.metadata_url, /\/metadata$/);
    assert.match(computed.callback_url, /\/callback$/);
  });

  it("AuthnRequest binding preference does not alter metadata URL", async () => {
    const provider = {
      slug: "keycloak-saml",
      type: "saml",
      config: {
        entry_point: "https://idp/saml",
        issuer: "tokentimer-sp",
        cert: "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
        authn_request_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
      },
      security: { sign_authn_requests: true },
    };
    const cfg = await builders.buildSamlStrategyConfigFromProvider(
      pool,
      provider,
      { signing_key: "-----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----" },
    );
    const computed = buildComputedUrls(provider);
    assert.strictEqual(
      cfg.authnRequestBinding,
      "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
    );
    assert.strictEqual(
      computed.metadata_url,
      "https://api.example.com/auth/saml/keycloak-saml/metadata",
    );
  });
});

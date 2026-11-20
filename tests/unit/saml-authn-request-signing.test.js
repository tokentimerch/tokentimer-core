"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");

const { createProviderStrategyConfig } = require("../../apps/api/sso/strategy-config.js");

describe("SAML AuthnRequest signing", () => {
  const builders = createProviderStrategyConfig();
  const pool = { query: async () => ({ rows: [] }) };

  it("does not set privateKey when sign_authn_requests is false", async () => {
    const cfg = await builders.buildSamlStrategyConfigFromProvider(
      pool,
      {
        slug: "keycloak",
        config: {
          entry_point: "https://idp/saml",
          issuer: "tokentimer-sp",
          cert: "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
        },
        security: { sign_authn_requests: false },
      },
      { signing_key: "-----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----" },
    );
    assert.ok(cfg);
    assert.strictEqual(cfg.privateKey, undefined);
  });

  it("sets privateKey and authnRequestBinding when signing enabled", async () => {
    const cfg = await builders.buildSamlStrategyConfigFromProvider(
      pool,
      {
        slug: "keycloak",
        config: {
          entry_point: "https://idp/saml",
          issuer: "tokentimer-sp",
          cert: "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
          authn_request_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          signing_cert: "-----BEGIN CERTIFICATE-----\nSP\n-----END CERTIFICATE-----",
        },
        security: { sign_authn_requests: true, signature_algorithm: "sha256" },
      },
      { signing_key: "-----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----" },
    );
    assert.ok(cfg.privateKey);
    assert.strictEqual(
      cfg.authnRequestBinding,
      "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
    );
    assert.strictEqual(cfg.signatureAlgorithm, "sha256");
    assert.strictEqual(cfg.publicCert, "-----BEGIN CERTIFICATE-----\nSP\n-----END CERTIFICATE-----");
  });

  it("defaults authnRequestBinding to HTTP-Redirect", async () => {
    const cfg = await builders.buildSamlStrategyConfigFromProvider(
      pool,
      {
        slug: "keycloak",
        config: {
          entry_point: "https://idp/saml",
          issuer: "tokentimer-sp",
          cert: "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
        },
        security: { sign_authn_requests: true },
      },
      { signing_key: "-----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----" },
    );
    assert.strictEqual(
      cfg.authnRequestBinding,
      "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
    );
  });
});

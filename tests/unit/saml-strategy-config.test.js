"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");

const { createProviderStrategyConfig } = require("../../apps/api/sso/strategy-config");

const PRIMARY_CERT =
  "-----BEGIN CERTIFICATE-----\nPRIMARY\n-----END CERTIFICATE-----";

function makeSamlProvider(overrides = {}) {
  const {
    config: configOverrides = {},
    security: securityOverrides = {},
    ...rest
  } = overrides;
  return {
    slug: "test-saml",
    type: "saml",
    enabled: true,
    config: {
      entry_point: "https://idp.example.com/saml/sso",
      issuer: "tokentimer",
      cert: PRIMARY_CERT,
      ...configOverrides,
    },
    claim_mapping: {},
    security: {
      clock_skew_sec: 60,
      sign_authn_requests: false,
      ...securityOverrides,
    },
    ...rest,
  };
}

describe("SAML strategy config (multi-provider)", () => {
  const builders = createProviderStrategyConfig();

  it("emits idpCert (not cert) for node-saml@5", async () => {
    const cfg = await builders.buildSamlStrategyConfigFromProvider(
      {},
      makeSamlProvider(),
      {},
    );
    assert.strictEqual(typeof cfg.idpCert, "string");
    assert.match(cfg.idpCert, /PRIMARY/);
    assert.strictEqual(cfg.cert, undefined);
  });

  it("supports secondary cert rollover as an array", async () => {
    const cfg = await builders.buildSamlStrategyConfigFromProvider(
      {},
      makeSamlProvider({
        config: {
          secondary_cert:
            "-----BEGIN CERTIFICATE-----\nSECONDARY\n-----END CERTIFICATE-----",
        },
      }),
      {},
    );
    assert.ok(Array.isArray(cfg.idpCert));
    assert.strictEqual(cfg.idpCert.length, 2);
  });

  it("returns null when required fields are missing", async () => {
    const cfg = await builders.buildSamlStrategyConfigFromProvider(
      {},
      makeSamlProvider({ config: { cert: "" } }),
      {},
    );
    assert.strictEqual(cfg, null);
  });

  it("defaults validateInResponseTo to always", async () => {
    const cfg = await builders.buildSamlStrategyConfigFromProvider(
      {},
      makeSamlProvider(),
      {},
    );
    assert.strictEqual(cfg.validateInResponseTo, "always");
  });

  it("honours validate_in_response_to overrides", async () => {
    const never = await builders.buildSamlStrategyConfigFromProvider(
      {},
      makeSamlProvider({ config: { validate_in_response_to: "never" } }),
      {},
    );
    assert.strictEqual(never.validateInResponseTo, "never");

    const ifPresent = await builders.buildSamlStrategyConfigFromProvider(
      {},
      makeSamlProvider({ config: { validate_in_response_to: "ifpresent" } }),
      {},
    );
    assert.strictEqual(ifPresent.validateInResponseTo, "ifPresent");
  });

  it("applies nested saml claim_mapping overrides", () => {
    const { buildClaimConfigFromProvider } = createProviderStrategyConfig();
    const cfg = buildClaimConfigFromProvider({
      type: "saml",
      claim_mapping: {
        saml: {
          email:
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
          display_name:
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
        },
      },
    });
    assert.match(
      cfg.saml.email,
      /claims\/emailaddress/,
    );
    assert.match(
      cfg.saml.displayName,
      /claims\/name/,
    );
    assert.doesNotMatch(cfg.saml.email, /^nameID,/);
  });

  it("accepts legacy flat claim_mapping from wizard", () => {
    const { buildClaimConfigFromProvider } = createProviderStrategyConfig();
    const cfg = buildClaimConfigFromProvider({
      type: "saml",
      claim_mapping: {
        email:
          "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        display_name:
          "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
      },
    });
    assert.match(cfg.saml.email, /claims\/emailaddress/);
    assert.match(cfg.saml.displayName, /claims\/name/);
  });
});

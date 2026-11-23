"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const serverHints = require("../../apps/api/sso/oidc-provider-hints.js");
const serverDefaults = require("../../apps/api/sso/oidc-endpoint-defaults.js");
const dashboardHints = require("../../apps/dashboard/src/lib/oidc-provider-hints.js");
const dashboardDefaults = require("../../apps/dashboard/src/lib/oidc-endpoint-defaults.js");
const {
  OIDC_WIZARD_TEMPLATES,
  SAML_WIZARD_TEMPLATES,
  defaultOidcClaimMapping,
  defaultSamlClaimMapping,
} = require("../../apps/dashboard/src/lib/sso-oidc-ui-helpers.js");

describe("SSO provider catalog", () => {
  it("offers the inherited wizard templates for both protocols", () => {
    assert.deepEqual(OIDC_WIZARD_TEMPLATES.map(({ id }) => id), [
      "entra", "keycloak", "okta", "auth0", "google", "generic",
    ]);
    assert.deepEqual(SAML_WIZARD_TEMPLATES.map(({ id }) => id), [
      "entra", "keycloak", "okta", "generic",
    ]);
    assert.deepEqual(defaultOidcClaimMapping("generic"), {
      oidc: {
        email: "email",
        display_name: "name,preferred_username",
        groups: "groups,roles",
        subject: "sub",
      },
    });
    assert.deepEqual(defaultSamlClaimMapping("generic"), {
      saml: {
        email: "email,nameID",
        display_name: "displayName",
        groups: "groups,memberOf",
        subject: "nameID",
      },
    });
  });

  const issuersByProvider = {
    keycloak: "https://idp.example.com/realms/my-realm",
    entra: "https://login.microsoftonline.com/tenant/v2.0",
    okta: "https://tenant.okta.com/oauth2/default",
    google: "https://accounts.google.com",
    auth0: "https://tenant.auth0.com/",
    cognito: "https://cognito-idp.eu-central-1.amazonaws.com/pool",
    gitlab: "https://gitlab.example.com",
    zitadel: "https://instance.zitadel.cloud",
    authentik: "https://idp.example.com/application/o/tokentimer/",
  };

  it("keeps dashboard and server provider catalog behavior aligned", () => {
    assert.deepEqual(
      serverHints.OIDC_PROVIDER_HINTS.map(({ id }) => id),
      Object.keys(issuersByProvider),
    );
    assert.deepEqual(dashboardHints.OIDC_PROVIDER_HINTS, serverHints.OIDC_PROVIDER_HINTS);
    assert.equal(dashboardHints.OVERRIDE_FIELD_HELP, serverHints.OVERRIDE_FIELD_HELP);

    for (const [id, issuer] of Object.entries(issuersByProvider)) {
      const serverHint = serverHints.matchIssuerProviderHint(issuer);
      const dashboardHint = dashboardHints.matchIssuerProviderHint(issuer);
      assert.equal(serverHint?.id, id);
      assert.deepEqual(dashboardHint, serverHint);
      assert.deepEqual(
        dashboardHints.applyProviderEndpointTemplates(dashboardHint, issuer),
        serverHints.applyProviderEndpointTemplates(serverHint, issuer),
      );
      assert.deepEqual(
        dashboardDefaults.suggestOidcEndpointsFromIssuer(issuer),
        serverDefaults.suggestOidcEndpointsFromIssuer(issuer),
      );
      assert.equal(
        dashboardDefaults.discoveryDocumentUrlFromIssuer(issuer),
        serverDefaults.discoveryDocumentUrlFromIssuer(issuer),
      );
    }

    const unknownIssuer = "https://idp.example.com";
    assert.equal(dashboardHints.matchIssuerProviderHint(unknownIssuer), null);
    assert.equal(serverHints.matchIssuerProviderHint(unknownIssuer), null);
  });

  it("uses the issuer hostname for hosted provider hints", () => {
    for (const hints of [serverHints, dashboardHints]) {
      assert.equal(hints.matchIssuerProviderHint("https://docs.example.test/setup/accounts.google.com"), null);
      assert.equal(hints.matchIssuerProviderHint("https://example.test/?from=okta.com"), null);
      assert.equal(hints.matchIssuerProviderHint("invalid issuer"), null);
      assert.equal(hints.matchIssuerProviderHint("https://demo.oktapreview.com")?.id, "okta");
      assert.equal(
        hints.matchIssuerProviderHint("https://issuer-cognito-idp.eu-central-1.amazonaws.com/pool")?.id,
        "cognito",
      );
    }
  });

  it("retains the inherited manual endpoint hints for open-source providers", () => {
    const openSourcePrefills = {
      gitlab: { authorization_url: "https://gitlab.example.com/oauth/authorize" },
      zitadel: { jwks_uri: "https://instance.zitadel.cloud/oauth/v2/keys" },
      authentik: {
        authorization_url: "https://idp.example.com/application/o/authorize/",
        token_url: "https://idp.example.com/application/o/token/",
        userinfo_url: "https://idp.example.com/application/o/userinfo/",
        jwks_uri: "https://idp.example.com/application/o/tokentimer/jwks/",
      },
    };

    for (const [id, prefill] of Object.entries(openSourcePrefills)) {
      const issuer = issuersByProvider[id];
      const hint = dashboardHints.matchIssuerProviderHint(issuer);
      const endpoints = dashboardHints.applyProviderEndpointTemplates(hint, issuer);
      for (const [field, url] of Object.entries(prefill)) {
        assert.equal(endpoints[field], url);
      }
    }
  });
});

"use strict";

/**
 * Operator-facing hints for OIDC endpoint overrides in SSO Providers (advanced).
 * Discovery ({issuer}/.well-known/openid-configuration) is always tried first
 * unless OIDC_DISABLE_DISCOVERY=true. Any value saved in advanced fields (or
 * via OIDC_*_URL env vars) overrides discovery and API fallbacks.
 */

/** @typedef {{ id: string, name: string, issuerHint: string, discoveryNote: string, overrideWhen: string, endpoints: { auth: string, token: string, userinfo: string, jwks: string } }} OidcProviderHint */

/** @type {OidcProviderHint[]} */
const OIDC_PROVIDER_HINTS = [
  {
    id: "keycloak",
    name: "Keycloak",
    issuerHint: "https://idp.example.com/realms/my-realm",
    discoveryNote:
      "Usually works when the API pod can reach the issuer. Server applies Keycloak-shaped fallbacks if discovery fails.",
    overrideWhen:
      "Only if discovery fails from the cluster or paths are custom. Do not use /authorize on the realm URL.",
    endpoints: {
      auth: "{issuer}/protocol/openid-connect/auth",
      token: "{issuer}/protocol/openid-connect/token",
      userinfo: "{issuer}/protocol/openid-connect/userinfo",
      jwks: "{issuer}/protocol/openid-connect/certs",
    },
  },
  {
    id: "entra",
    name: "Microsoft Entra ID",
    issuerHint: "https://login.microsoftonline.com/{tenant-id}/v2.0",
    discoveryNote: "Standard discovery on the v2.0 issuer URL.",
    overrideWhen:
      "Air-gapped API, B2C custom policies, or token encryption policies that need ?appid= on discovery (set endpoints manually from Entra app registration).",
    endpoints: {
      auth: "(from discovery)",
      token: "(from discovery)",
      userinfo: "(from discovery)",
      jwks: "(from discovery; may include ?appid=)",
    },
  },
  {
    id: "okta",
    name: "Okta",
    issuerHint: "https://{yourOktaDomain} or custom authorization server issuer",
    discoveryNote: "Use the authorization server issuer URL shown in Okta admin.",
    overrideWhen: "Custom authorization server or discovery blocked from the API pod.",
    endpoints: {
      auth: "(from discovery)",
      token: "(from discovery)",
      userinfo: "(from discovery)",
      jwks: "(from discovery)",
    },
  },
  {
    id: "google",
    name: "Google / Google Workspace",
    issuerHint: "https://accounts.google.com",
    discoveryNote: "Discovery is required; JWKS is not under the issuer host.",
    overrideWhen:
      "Always rely on discovery or paste endpoints from Google Cloud Console (do not guess JWKS from issuer alone).",
    endpoints: {
      auth: "https://accounts.google.com/o/oauth2/v2/auth",
      token: "https://oauth2.googleapis.com/token",
      userinfo: "https://openidconnect.googleapis.com/v1/userinfo",
      jwks: "(from discovery document only)",
    },
  },
  {
    id: "auth0",
    name: "Auth0",
    issuerHint: "https://{tenant}.auth0.com/ or custom domain",
    discoveryNote:
      "Discovery preferred. Auth0-shaped API fallbacks apply only to *.auth0.com tenant issuers when discovery fails.",
    overrideWhen: "Custom domains or discovery unreachable from the cluster.",
    endpoints: {
      auth: "{issuer}/authorize",
      token: "{issuer}/oauth/token",
      userinfo: "{issuer}/userinfo",
      jwks: "(from discovery)",
    },
  },
  {
    id: "cognito",
    name: "Amazon Cognito",
    issuerHint: "https://cognito-idp.{region}.amazonaws.com/{userPoolId}",
    discoveryNote: "Discovery at issuer/.well-known/openid-configuration.",
    overrideWhen: "Rare; use if discovery is blocked.",
    endpoints: {
      auth: "(from discovery)",
      token: "(from discovery)",
      userinfo: "(from discovery)",
      jwks: "{issuer}/.well-known/jwks.json",
    },
  },
  {
    id: "gitlab",
    name: "GitLab / GitLab.com",
    issuerHint: "https://gitlab.example.com",
    discoveryNote: "Discovery on the instance root issuer.",
    overrideWhen:
      "If discovery fails: GitLab uses /oauth/authorize, not /authorize.",
    endpoints: {
      auth: "{issuer}/oauth/authorize",
      token: "{issuer}/oauth/token",
      userinfo: "{issuer}/oauth/userinfo",
      jwks: "(from discovery)",
    },
  },
  {
    id: "zitadel",
    name: "ZITADEL",
    issuerHint: "https://{instance}.zitadel.cloud or your ZITADEL domain",
    discoveryNote: "Discovery on the instance domain root.",
    overrideWhen: "If discovery fails, set all four endpoints from ZITADEL docs.",
    endpoints: {
      auth: "{issuer}/oauth/v2/authorize",
      token: "{issuer}/oauth/v2/token",
      userinfo: "{issuer}/oidc/v1/userinfo",
      jwks: "{issuer}/oauth/v2/keys",
    },
  },
  {
    id: "authentik",
    name: "authentik",
    issuerHint: "https://authentik.example.com/application/o/{slug}/",
    discoveryNote:
      "Issuer must be the authentik application issuer URL (includes /application/o/...).",
    overrideWhen:
      "If discovery fails, copy endpoints from the authentik provider page.",
    endpoints: {
      auth: "{issuer}/authorize/",
      token: "{issuer}/token/",
      userinfo: "{issuer}/userinfo/",
      jwks: "{issuer}/jwks/",
    },
  },
];

/**
 * @param {string} issuer
 * @returns {OidcProviderHint|null}
 */
function matchIssuerProviderHint(issuer) {
  let url;
  try {
    url = new URL(issuer);
  } catch {
    return null;
  }
  const host = url.hostname.toLowerCase();
  const path = url.pathname.toLowerCase();
  const isDomain = domain => host === domain || host.endsWith("." + domain);
  if (/\/realms\/[^/]+/.test(path)) {
    return OIDC_PROVIDER_HINTS.find((h) => h.id === "keycloak") || null;
  }
  if (path.includes("/application/o/")) {
    return OIDC_PROVIDER_HINTS.find((h) => h.id === "authentik") || null;
  }
  if (host === "login.microsoftonline.com") {
    return OIDC_PROVIDER_HINTS.find((h) => h.id === "entra") || null;
  }
  if (isDomain("okta.com") || isDomain("oktapreview.com")) {
    return OIDC_PROVIDER_HINTS.find((h) => h.id === "okta") || null;
  }
  if (host === "accounts.google.com") {
    return OIDC_PROVIDER_HINTS.find((h) => h.id === "google") || null;
  }
  if (isDomain("auth0.com")) {
    return OIDC_PROVIDER_HINTS.find((h) => h.id === "auth0") || null;
  }
  if (host.startsWith("cognito-idp.") && isDomain("amazonaws.com")) {
    return OIDC_PROVIDER_HINTS.find((h) => h.id === "cognito") || null;
  }
  if (host.includes("gitlab")) {
    return OIDC_PROVIDER_HINTS.find((h) => h.id === "gitlab") || null;
  }
  if (host.includes("zitadel")) {
    return OIDC_PROVIDER_HINTS.find((h) => h.id === "zitadel") || null;
  }
  return null;
}

const OVERRIDE_FIELD_HELP =
  "Optional. Any value you save here overrides issuer discovery and API fallbacks.";

/**
 * @param {string} template
 * @param {string} issuer
 * @returns {string}
 */
function substituteIssuerInTemplate(template, issuer) {
  const base = String(issuer || "").trim().replace(/\/$/, "");
  return String(template).replace(/\{issuer\}/g, base);
}

/**
 * @param {OidcProviderHint} hint
 * @param {string} issuer
 * @returns {{ authorization_url?: string, token_url?: string, userinfo_url?: string, jwks_uri?: string }|null}
 */
function applyProviderEndpointTemplates(hint, issuer) {
  if (!hint?.endpoints || !issuer) return null;
  const ep = hint.endpoints;
  const out = {};
  if (ep.auth && !ep.auth.startsWith("(")) {
    out.authorization_url = substituteIssuerInTemplate(ep.auth, issuer);
  }
  if (ep.token && !ep.token.startsWith("(")) {
    out.token_url = substituteIssuerInTemplate(ep.token, issuer);
  }
  if (ep.userinfo && !ep.userinfo.startsWith("(")) {
    out.userinfo_url = substituteIssuerInTemplate(ep.userinfo, issuer);
  }
  if (ep.jwks && !ep.jwks.startsWith("(")) {
    out.jwks_uri = substituteIssuerInTemplate(ep.jwks, issuer);
  }
  return Object.keys(out).length > 0 ? out : null;
}

module.exports = {
  OIDC_PROVIDER_HINTS,
  matchIssuerProviderHint,
  OVERRIDE_FIELD_HELP,
  substituteIssuerInTemplate,
  applyProviderEndpointTemplates,
};

"use strict";

/**
 * Heuristic OIDC endpoint defaults when discovery is unavailable.
 * Discovery ({issuer}/.well-known/openid-configuration) remains the
 * preferred source; these URLs are fallbacks and optional UI prefills.
 */

function stripIssuerTrailingSlash(issuer) {
  return String(issuer || "").trim().replace(/\/$/, "");
}

/**
 * Best-effort JWKS URI from issuer alone (Keycloak realms path, else RFC 8414-style).
 * @param {string} issuer
 * @returns {string}
 */
function isKeycloakRealmIssuer(issuer) {
  return /\/realms\/[^/]+/i.test(stripIssuerTrailingSlash(issuer));
}

/**
 * Auth0 tenant issuers only. Custom Auth0 domains are not detected here;
 * those require discovery or manual endpoint overrides.
 * @param {string} issuer
 * @returns {boolean}
 */
function isAuth0LikeIssuer(issuer) {
  const s = stripIssuerTrailingSlash(issuer).toLowerCase();
  return /\.auth0\.com$/i.test(s) || /\.auth0\.com\//i.test(s);
}

/**
 * Auth0-shaped fallbacks used when discovery is unavailable (Auth0 tenants only).
 */
function suggestAuth0ShapedEndpointsFromIssuer(issuer) {
  const stripped = stripIssuerTrailingSlash(issuer);
  if (!stripped) {
    return {
      authorizationURL: "",
      tokenURL: "",
      userInfoURL: "",
      jwksURL: "",
      endSessionURL: "",
    };
  }
  return {
    authorizationURL: `${stripped}/authorize`,
    tokenURL: `${stripped}/oauth/token`,
    userInfoURL: `${stripped}/userinfo`,
    jwksURL: `${stripped}/.well-known/jwks.json`,
    endSessionURL: `${stripped}/oidc/logout`,
  };
}

/**
 * Keycloak realm issuers use /protocol/openid-connect/*, not /authorize.
 */
function suggestKeycloakEndpointsFromIssuer(issuer) {
  const stripped = stripIssuerTrailingSlash(issuer);
  const base = `${stripped}/protocol/openid-connect`;
  return {
    authorizationURL: `${base}/auth`,
    tokenURL: `${base}/token`,
    userInfoURL: `${base}/userinfo`,
    jwksURL: `${base}/certs`,
    endSessionURL: `${base}/logout`,
  };
}

const EMPTY_OIDC_ENDPOINTS = {
  authorizationURL: "",
  tokenURL: "",
  userInfoURL: "",
  jwksURL: "",
  endSessionURL: "",
};

/**
 * Endpoint fallbacks when discovery is unavailable.
 * Keycloak realms and Auth0 tenants only; other issuers return empty URLs
 * so the runtime does not invent /authorize paths (Entra, Google, Okta, …).
 * @param {string} issuer
 * @returns {{ authorizationURL: string, tokenURL: string, userInfoURL: string, jwksURL: string }}
 */
function suggestOidcEndpointsFromIssuer(issuer) {
  if (isKeycloakRealmIssuer(issuer)) {
    return suggestKeycloakEndpointsFromIssuer(issuer);
  }
  if (isAuth0LikeIssuer(issuer)) {
    return suggestAuth0ShapedEndpointsFromIssuer(issuer);
  }
  return { ...EMPTY_OIDC_ENDPOINTS };
}

function suggestJwksUriFromIssuer(issuer) {
  return suggestOidcEndpointsFromIssuer(issuer).jwksURL;
}

/**
 * Well-known discovery document URL for an issuer (for docs/UI hints).
 * @param {string} issuer
 * @returns {string}
 */
function discoveryDocumentUrlFromIssuer(issuer) {
  const stripped = stripIssuerTrailingSlash(issuer);
  if (!stripped) return "";
  return `${stripped}/.well-known/openid-configuration`;
}

module.exports = {
  stripIssuerTrailingSlash,
  isKeycloakRealmIssuer,
  isAuth0LikeIssuer,
  suggestAuth0ShapedEndpointsFromIssuer,
  suggestKeycloakEndpointsFromIssuer,
  suggestOidcEndpointsFromIssuer,
  suggestJwksUriFromIssuer,
  discoveryDocumentUrlFromIssuer,
};

/**
 * Dashboard ESM copy of apps/api/sso/oidc-endpoint-defaults.js (keep in sync).
 */

function stripIssuerTrailingSlash(issuer) {
  return String(issuer || '')
    .trim()
    .replace(/\/$/, '');
}

function isKeycloakRealmIssuer(issuer) {
  return /\/realms\/[^/]+/i.test(stripIssuerTrailingSlash(issuer));
}

function isAuth0LikeIssuer(issuer) {
  const s = stripIssuerTrailingSlash(issuer).toLowerCase();
  return /\.auth0\.com$/i.test(s) || /\.auth0\.com\//i.test(s);
}

function suggestAuth0ShapedEndpointsFromIssuer(issuer) {
  const stripped = stripIssuerTrailingSlash(issuer);
  if (!stripped) {
    return {
      authorizationURL: '',
      tokenURL: '',
      userInfoURL: '',
      jwksURL: '',
      endSessionURL: '',
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
  authorizationURL: '',
  tokenURL: '',
  userInfoURL: '',
  jwksURL: '',
  endSessionURL: '',
};

export function suggestOidcEndpointsFromIssuer(issuer) {
  if (isKeycloakRealmIssuer(issuer)) {
    return suggestKeycloakEndpointsFromIssuer(issuer);
  }
  if (isAuth0LikeIssuer(issuer)) {
    return suggestAuth0ShapedEndpointsFromIssuer(issuer);
  }
  return { ...EMPTY_OIDC_ENDPOINTS };
}

export function suggestJwksUriFromIssuer(issuer) {
  return suggestOidcEndpointsFromIssuer(issuer).jwksURL;
}

export function discoveryDocumentUrlFromIssuer(issuer) {
  const stripped = stripIssuerTrailingSlash(issuer);
  if (!stripped) return '';
  return `${stripped}/.well-known/openid-configuration`;
}

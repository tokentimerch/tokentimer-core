/**
 * openid-client wiring for the OIDC login flow.
 * Kept separate from oidc.js so PKCE/state/nonce behaviour is unit-testable.
 */

"use strict";

const { assertOutboundUrl } = require("@tokentimer/config/network");

const DEFAULT_OPENID_CLIENT = () => require("openid-client");
const {
  resolveIdpHttpTimeoutMs: resolveGlobalIdpHttpTimeoutMs,
} = require("../sso/sso-global-settings.js");

const DEFAULT_IDP_HTTP_TIMEOUT_MS = 20_000;

function resolveIdpHttpTimeoutMs(env = process.env) {
  return resolveGlobalIdpHttpTimeoutMs(env);
}

/**
 * openid-client only forwards a fixed set of HTTP options (timeout, lookup, …).
 * servername is stripped, so a custom dns.lookup that returns IPs breaks TLS/SNI
 * and hangs until timeout while wget by hostname works. IdP URLs are admin-configured
 * and validated via validateOutboundUrl at save/test time; use default DNS here.
 */
function createOpenIdHttpOptionsProvider(timeoutMs) {
  return (url) => {
    assertOutboundUrl(url, { proxyMode: "node" });
    return { timeout: timeoutMs };
  };
}

function createIssuerFromStrategyConfig(strategyConfig, openidClient) {
  const oidc = openidClient || DEFAULT_OPENID_CLIENT();
  const metadata = {
    issuer: strategyConfig.issuer,
    authorization_endpoint: strategyConfig.authorizationURL,
    token_endpoint: strategyConfig.tokenURL,
    userinfo_endpoint: strategyConfig.userInfoURL,
  };
  if (strategyConfig.jwksURL) {
    metadata.jwks_uri = strategyConfig.jwksURL;
  }
  if (strategyConfig.endSessionURL) {
    metadata.end_session_endpoint = strategyConfig.endSessionURL;
  }
  return new oidc.Issuer(metadata);
}

function createOidcClient(strategyConfig, openidClient) {
  const oidc = openidClient || DEFAULT_OPENID_CLIENT();
  const issuer = createIssuerFromStrategyConfig(strategyConfig, oidc);
  const client = new issuer.Client({
    client_id: strategyConfig.clientID,
    client_secret: strategyConfig.clientSecret,
    redirect_uris: [strategyConfig.callbackURL],
    response_types: ["code"],
  });
  const skewMs = Number(strategyConfig.acceptedClockSkewMs) || 0;
  if (skewMs > 0 && oidc.custom?.clock_tolerance) {
    client[oidc.custom.clock_tolerance] = skewMs / 1000;
  }
  if (oidc.custom?.http_options) {
    const timeoutMs = resolveIdpHttpTimeoutMs();
    const httpOptions = createOpenIdHttpOptionsProvider(timeoutMs);
    issuer[oidc.custom.http_options] = httpOptions;
    client[oidc.custom.http_options] = httpOptions;
  }
  return { issuer, client, openidClient: oidc };
}

/**
 * @returns {{ state: string, nonce: string, codeVerifier: string|null, authorizationUrl: string, authParams: object }}
 */
function buildAuthorizationRequest(strategyConfig, client, openidClient, { pkceEnabled = true } = {}) {
  const oidc = openidClient || DEFAULT_OPENID_CLIENT();
  const state = oidc.generators.state();
  const nonce = oidc.generators.nonce();
  const scope = Array.isArray(strategyConfig.scope)
    ? strategyConfig.scope.join(" ")
    : String(strategyConfig.scope || "openid profile email");

  const authParams = {
    scope,
    state,
    nonce,
    redirect_uri: strategyConfig.callbackURL,
  };

  let codeVerifier = null;
  if (pkceEnabled) {
    codeVerifier = oidc.generators.codeVerifier();
    authParams.code_challenge = oidc.generators.codeChallenge(codeVerifier);
    authParams.code_challenge_method = "S256";
  }

  const authorizationUrl = client.authorizationUrl(authParams);
  return {
    state,
    nonce,
    codeVerifier,
    authorizationUrl,
    authParams,
  };
}

/**
 * Builds an RP-Initiated Logout 1.0 URL, or null when the provider advertises no
 * end_session_endpoint (in which case only the local session can be cleared).
 *
 * Signing out of TokenTimer destroys only the TokenTimer session. The IdP SSO
 * cookie outlives it, so the next authorization request is satisfied silently and
 * the user is signed back in without being asked for credentials. Ending the IdP
 * session is what makes a sign-out actually stick.
 *
 * id_token_hint is preferred: Okta requires it, and it is the spec's RECOMMENDED
 * way to identify the session. client_id is sent only as the fallback identifier
 * when no ID token was retained, which Keycloak, Entra ID, and Auth0 accept.
 *
 * @returns {string|null}
 */
function buildEndSessionUrl(
  strategyConfig,
  {
    idToken = null,
    postLogoutRedirectUri = null,
    state = null,
    client = null,
    openidClient = null,
  } = {},
) {
  if (!strategyConfig?.endSessionURL) return null;
  const oidc = openidClient || DEFAULT_OPENID_CLIENT();
  const activeClient =
    client || createOidcClient(strategyConfig, oidc).client;

  const params = {};
  if (idToken) {
    params.id_token_hint = idToken;
    // openid-client injects client_id on every end-session URL. Okta documents
    // client_id as unsupported on its logout endpoint and answers invalid_client,
    // so send the hint alone; null is dropped before the query is built.
    params.client_id = null;
  } else if (strategyConfig.clientID) {
    params.client_id = strategyConfig.clientID;
  }
  if (postLogoutRedirectUri) {
    params.post_logout_redirect_uri = postLogoutRedirectUri;
  }
  if (state) {
    params.state = state;
  }

  return activeClient.endSessionUrl(params);
}

async function exchangeAuthorizationCode({
  client,
  strategyConfig,
  callbackParams,
  sessionAuth,
  pkceEnabled = true,
}) {
  const checks = {
    state: sessionAuth.state,
    nonce: sessionAuth.nonce,
  };
  if (pkceEnabled) {
    checks.code_verifier = sessionAuth.codeVerifier;
  }
  const tokenSet = await client.callback(
    strategyConfig.callbackURL,
    callbackParams,
    checks,
  );
  const idClaims = tokenSet.claims();
  if (!idClaims?.sub) {
    throw new Error("OIDC ID Token is missing sub");
  }
  return { tokenSet, idClaims };
}

/**
 * OIDC Core 5.3.2: UserInfo sub must match ID Token sub when UserInfo is used.
 */
function validateUserinfoSubject(idSub, userinfoClaims, { logger, issuer } = {}) {
  if (!userinfoClaims) {
    return { trusted: false, reason: "no_userinfo" };
  }
  const uiSub = userinfoClaims.sub || null;
  if (!uiSub) {
    logger?.warn?.(
      "OIDC: UserInfo response missing sub; discarding UserInfo claims",
      { issuer },
    );
    return { trusted: false, reason: "userinfo_missing_sub" };
  }
  if (uiSub !== idSub) {
    return {
      trusted: false,
      reason: "userinfo_sub_mismatch",
      id_token_sub: idSub,
      userinfo_sub: uiSub,
    };
  }
  return { trusted: true, userinfoClaims };
}

function buildPassportStyleProfiles(idClaims, userinfoClaims, trustedUserinfo) {
  const idProfile = claimsToProfile(idClaims);
  let trustedUiProfile = null;
  if (trustedUserinfo && userinfoClaims) {
    trustedUiProfile = claimsToProfile(userinfoClaims);
  }
  const profile = trustedUiProfile
    ? {
        ...idProfile,
        ...trustedUiProfile,
        _json: { ...idProfile._json, ...trustedUiProfile._json },
      }
    : { ...idProfile };
  return { profile, idProfile, trustedUiProfile };
}

function claimsToProfile(claims) {
  const sub = claims.sub || claims.oid || claims.id || null;
  return {
    id: sub,
    displayName: claims.name || claims.preferred_username || null,
    name: {
      givenName: claims.given_name,
      familyName: claims.family_name,
    },
    emails: claims.email ? [{ value: claims.email }] : undefined,
    _json: { ...claims },
  };
}

module.exports = {
  DEFAULT_OPENID_CLIENT,
  DEFAULT_IDP_HTTP_TIMEOUT_MS,
  resolveIdpHttpTimeoutMs,
  createOpenIdHttpOptionsProvider,
  createOidcClient,
  createIssuerFromStrategyConfig,
  buildAuthorizationRequest,
  buildEndSessionUrl,
  exchangeAuthorizationCode,
  validateUserinfoSubject,
  buildPassportStyleProfiles,
  claimsToProfile,
};

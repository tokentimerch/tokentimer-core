/**
 * Build SAML / OIDC strategy options per provider row in sso_providers.
 */

"use strict";

const { getOidcCallbackUrl, getSamlCallbackUrl } = require("./callback-urls");
const { safeFetch, validateOutboundUrl, outboundBlockHint } = require("./safe-fetch.js");
const { resolveIdpHttpTimeoutMs } = require("./sso-global-settings.js");
const { matchIssuerProviderHint } = require("./oidc-provider-hints.js");

const isSet = (v) =>
  typeof v === "string" && v.trim().length > 0 && v !== "undefined" && v !== "null";

function toBool(value, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  if (typeof value === "boolean") return value;
  const s = String(value).trim().toLowerCase();
  if (s === "true" || s === "1" || s === "yes") return true;
  if (s === "false" || s === "0" || s === "no") return false;
  return fallback;
}

function parseScopes(value) {
  if (Array.isArray(value)) return value;
  if (!isSet(value)) return null;
  return String(value)
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function pickConfigString(config, key) {
  const value = config?.[key];
  return isSet(value) ? String(value).trim() : "";
}

/**
 * Tiny in-memory cache for OIDC discovery documents. Keyed by issuer URL.
 * IdPs publish the document at a stable URL and almost never change it; a
 * short TTL is plenty to avoid hammering the well-known endpoint during a
 * burst of SSO logins, while still picking up rotations within minutes.
 */
const DISCOVERY_CACHE = new Map();
const DISCOVERY_TTL_MS = 5 * 60 * 1000;

/**
 * Reject non-HTTPS issuer / endpoint URLs in production. OIDC Core 3.1.3
 * requires the token endpoint to use TLS, and treating any of the other
 * endpoints as plaintext is just as bad (an attacker that can intercept
 * the authorization URL can steer the user to a phishing IdP).
 *
 * We tolerate http://localhost and http://127.0.0.1 outside production so
 * local IdPs (Keycloak dev container, mockoidc, ...) keep working.
 *
 * Throws an Error with a deterministic message so the strategy-build path
 * can surface "config_build_failed" and skip registration rather than
 * registering an insecure strategy.
 */
function assertSecureOidcUrl(rawUrl, name, { allowDev = false } = {}) {
  if (!isSet(rawUrl)) return;
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch (_err) {
    throw new Error(`OIDC ${name} is not a valid URL: ${rawUrl}`, { cause: _err });
  }
  if (parsed.protocol === "https:") return;
  if (
    allowDev &&
    parsed.protocol === "http:" &&
    (parsed.hostname === "localhost" ||
      parsed.hostname === "127.0.0.1" ||
      parsed.hostname === "::1")
  ) {
    return;
  }
  throw new Error(
    `OIDC ${name} must use https:// (got ${parsed.protocol}//${parsed.host}). ` +
      `Set NODE_ENV=development to allow http://localhost for local IdPs.`,
  );
}

async function assertOutboundSafeOidcUrl(rawUrl, name, validateFn) {
  if (!isSet(rawUrl)) return;
  const result = await validateFn(rawUrl);
  if (!result.ok) {
    const hint = outboundBlockHint(result.reason);
    throw new Error(
      `OIDC ${name} blocked by outbound URL policy (${result.reason})` +
        (hint ? `. ${hint}` : ""),
    );
  }
}

async function assertOutboundSafeOidcEndpoints(endpoints, validateFn) {
  const entries = Object.entries(endpoints).filter(([, url]) => isSet(url));
  await Promise.all(
    entries.map(([name, url]) => assertOutboundSafeOidcUrl(url, name, validateFn)),
  );
}

async function fetchOidcDiscovery(issuer, { fetchImpl, logger } = {}) {
  if (!isSet(issuer)) return null;
  const cached = DISCOVERY_CACHE.get(issuer);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.doc;
  }
  const url = `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
  const timeoutMs = resolveIdpHttpTimeoutMs();
  try {
    let doc = null;
    if (typeof fetchImpl === "function") {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await fetchImpl(url, { signal: controller.signal });
        if (!res.ok) {
          logger?.warn?.("OIDC discovery returned non-2xx", {
            issuer,
            status: res.status,
          });
          return null;
        }
        doc = await res.json();
      } finally {
        clearTimeout(timer);
      }
    } else {
      const res = await safeFetch(url, { timeoutMs });
      if (!res.ok) {
        logger?.warn?.("OIDC discovery fetch failed", {
          issuer,
          reason: res.reason,
          ...(outboundBlockHint(res.reason)
            ? { hint: outboundBlockHint(res.reason) }
            : {}),
        });
        return null;
      }
      doc = JSON.parse(res.body || "{}");
    }
    if (!doc || typeof doc !== "object") return null;
    DISCOVERY_CACHE.set(issuer, {
      doc,
      expiresAt: Date.now() + DISCOVERY_TTL_MS,
    });
    return doc;
  } catch (err) {
    logger?.warn?.("OIDC discovery fetch failed", {
      issuer,
      error: err?.message,
    });
    return null;
  }
}

function clearOidcDiscoveryCache() {
  DISCOVERY_CACHE.clear();
}

/**
 * Default claim path lists. Broad, widely-supported defaults so that
 * common IdPs (Azure AD, Okta, Auth0, Cognito, Keycloak, Google
 * Workspace) work without any explicit per-claim configuration.
 */
const { suggestOidcEndpointsFromIssuer } = require("./oidc-endpoint-defaults.js");
const {
  createPostgresSamlCacheProvider,
} = require("./saml-cache-provider.js");
const { resolveProviderSecurityConfig } = require("./sso-global-settings.js");

const DEFAULT_CLAIMS = {
  saml: {
    email:
      "email,urn:oid:0.9.2342.19200300.100.1.3,http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress,nameID",
    displayName:
      "displayName,urn:oid:2.16.840.1.113730.3.1.241,http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
    groups:
      "groups,Groups,http://schemas.xmlsoap.org/claims/Group,http://schemas.microsoft.com/ws/2008/06/identity/claims/groups,http://schemas.microsoft.com/ws/2008/06/identity/claims/role,http://schemas.microsoft.com/ws/2008/06/identity/claims/wids,http://schemas.microsoft.com/identity/claims/groups,memberOf",
    subject: "nameID",
  },
  oidc: {
    email: "email,emails.0.value",
    displayName: "displayName,name,name.givenName",
    groups:
      "groups,roles,cognito:groups,wids,http://schemas.microsoft.com/ws/2008/06/identity/claims/groups,http://schemas.microsoft.com/ws/2008/06/identity/claims/role,http://schemas.microsoft.com/identity/claims/groups",
    subject: "sub,oid,id",
  },
};

function mergeClaimPathLists(overridePaths, defaultPaths) {
  const seen = new Set();
  const merged = [];
  for (const raw of [overridePaths, defaultPaths]) {
    if (!isSet(raw)) continue;
    for (const path of String(raw)
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)) {
      const key = path.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      merged.push(path);
    }
  }
  return merged.length > 0 ? merged.join(",") : defaultPaths;
}

/**
 * Per-provider strategy builders (multi-provider SSO). Provider rows come from
 * provider-registry.js; secrets are decrypted separately.
 *
 * @param {{ logger?: object, fetchImpl?: Function }} [factoryDeps]
 */
function createProviderStrategyConfig(factoryDeps = {}) {
  const factoryLogger = factoryDeps.logger || null;
  const factoryFetch = factoryDeps.fetchImpl || null;
  const validateOutbound =
    typeof factoryDeps.validateOutboundUrl === "function"
      ? factoryDeps.validateOutboundUrl
      : (url) => validateOutboundUrl(url, factoryDeps.env || process.env);

  function pickProtocolClaimMapping(mapping, protocol) {
    const nested = mapping?.[protocol];
    if (nested && typeof nested === "object") return nested;
    // Legacy flat shape saved by older wizard builds: { email, display_name, ... }
    if (
      mapping?.email ||
      mapping?.display_name ||
      mapping?.groups ||
      mapping?.subject
    ) {
      return mapping;
    }
    return {};
  }

  function buildClaimConfigFromProvider(provider) {
    const mapping = provider?.claim_mapping || {};
    const saml = { ...DEFAULT_CLAIMS.saml };
    const oidc = { ...DEFAULT_CLAIMS.oidc };
    const samlMapping = pickProtocolClaimMapping(mapping, "saml");
    const oidcMapping = pickProtocolClaimMapping(mapping, "oidc");
    if (isSet(samlMapping.email)) saml.email = samlMapping.email;
    if (isSet(samlMapping.display_name)) saml.displayName = samlMapping.display_name;
    if (isSet(samlMapping.groups)) {
      saml.groups = mergeClaimPathLists(
        samlMapping.groups,
        DEFAULT_CLAIMS.saml.groups,
      );
    }
    if (isSet(samlMapping.subject)) saml.subject = samlMapping.subject;
    if (isSet(samlMapping.name_id_format)) saml.nameIdFormat = samlMapping.name_id_format;
    if (isSet(oidcMapping.email)) oidc.email = oidcMapping.email;
    if (isSet(oidcMapping.display_name)) oidc.displayName = oidcMapping.display_name;
    if (isSet(oidcMapping.groups)) {
      oidc.groups = mergeClaimPathLists(
        oidcMapping.groups,
        DEFAULT_CLAIMS.oidc.groups,
      );
    }
    if (isSet(oidcMapping.subject)) oidc.subject = oidcMapping.subject;
    return { saml, oidc };
  }

  function buildSecurityConfigFromProvider(provider) {
    return resolveProviderSecurityConfig(provider);
  }

  async function buildOidcStrategyConfigFromProvider(pool, provider, secrets = {}) {
    const config = provider?.config || {};
    const slug = provider.slug;
    const issuer = pickConfigString(config, "issuer");
    const clientID = pickConfigString(config, "client_id");
    const clientSecret = secrets.client_secret || null;
    const callbackOverride = pickConfigString(config, "callback_url");
    const callbackURL = callbackOverride || getOidcCallbackUrl(slug);
    const security = buildSecurityConfigFromProvider(provider);

    if (!isSet(issuer) || !isSet(clientID) || !isSet(clientSecret)) {
      return null;
    }

    const authorizationURL = pickConfigString(config, "authorization_url");
    const tokenURL = pickConfigString(config, "token_url");
    const userInfoURL = pickConfigString(config, "userinfo_url");
    const jwksURI = pickConfigString(config, "jwks_uri");
    const endSessionURL = pickConfigString(config, "end_session_url");
    const scopeList = parseScopes(pickConfigString(config, "scopes")) || [
      "openid",
      "profile",
      "email",
    ];

    const skipDiscovery = security.disableDiscovery;
    const discovery = skipDiscovery
      ? null
      : await fetchOidcDiscovery(issuer, {
          fetchImpl: factoryFetch,
          logger: factoryLogger,
        });

    const pickUrl = (override, discoveryKey, fallback) => {
      if (isSet(override)) return override;
      if (discovery && isSet(discovery[discoveryKey])) {
        return discovery[discoveryKey];
      }
      return fallback;
    };

    const issuerFallbacks = suggestOidcEndpointsFromIssuer(issuer);
    const resolvedAuth = pickUrl(
      authorizationURL,
      "authorization_endpoint",
      issuerFallbacks.authorizationURL || null,
    );
    const resolvedToken = pickUrl(
      tokenURL,
      "token_endpoint",
      issuerFallbacks.tokenURL || null,
    );
    const resolvedUserInfo = pickUrl(
      userInfoURL,
      "userinfo_endpoint",
      issuerFallbacks.userInfoURL || null,
    );
    const resolvedJwks = pickUrl(jwksURI, "jwks_uri", issuerFallbacks.jwksURL || null);
    // Cognito discovery advertises managed logout, which uses its own parameters.
    // An explicit override may point to an OIDC-compatible logout endpoint.
    const resolvedEndSession =
      matchIssuerProviderHint(issuer)?.id === "cognito"
        ? endSessionURL
        : pickUrl(endSessionURL, "end_session_endpoint", issuerFallbacks.endSessionURL || null);

    const allowDev = process.env.NODE_ENV !== "production";
    assertSecureOidcUrl(issuer, "issuer", { allowDev });
    assertSecureOidcUrl(resolvedAuth, "authorization_endpoint", { allowDev });
    assertSecureOidcUrl(resolvedToken, "token_endpoint", { allowDev });
    assertSecureOidcUrl(resolvedUserInfo, "userinfo_endpoint", { allowDev });
    if (isSet(resolvedJwks)) {
      assertSecureOidcUrl(resolvedJwks, "jwks_uri", { allowDev });
    }
    if (isSet(resolvedEndSession)) {
      assertSecureOidcUrl(resolvedEndSession, "end_session_endpoint", { allowDev });
    }

    await assertOutboundSafeOidcEndpoints(
      {
        issuer,
        authorization_endpoint: resolvedAuth,
        token_endpoint: resolvedToken,
        userinfo_endpoint: resolvedUserInfo,
        jwks_uri: resolvedJwks,
        end_session_endpoint: resolvedEndSession,
      },
      validateOutbound,
    );

    if (!isSet(resolvedAuth) || !isSet(resolvedToken)) {
      if (!discovery && !issuerFallbacks.authorizationURL) {
        throw new Error(
          "discovery_required_or_manual_endpoints_missing",
        );
      }
      throw new Error(
        "OIDC authorization and token endpoints could not be resolved for provider " +
          slug,
      );
    }

    const cfg = {
      issuer,
      clientID,
      clientSecret,
      callbackURL,
      authorizationURL: resolvedAuth,
      tokenURL: resolvedToken,
      userInfoURL: resolvedUserInfo,
      scope: scopeList,
      acceptedClockSkewMs: security.clockSkewSec * 1000,
      pkceRequested: security.pkce,
    };
    if (isSet(resolvedJwks)) cfg.jwksURL = resolvedJwks;
    if (isSet(resolvedEndSession)) cfg.endSessionURL = resolvedEndSession;
    if (discovery) {
      cfg.discoverySource = "discovery";
    } else if (isSet(jwksURI)) {
      cfg.discoverySource = "manual";
    } else if (
      isSet(resolvedAuth) &&
      resolvedAuth === issuerFallbacks.authorizationURL
    ) {
      cfg.discoverySource = "issuer_endpoint_fallback";
    } else {
      cfg.discoverySource = "fallback";
    }
    return cfg;
  }

  async function buildSamlStrategyConfigFromProvider(pool, provider, secrets = {}) {
    const config = provider?.config || {};
    const slug = provider.slug;
    const security = buildSecurityConfigFromProvider(provider);
    const entryPoint = pickConfigString(config, "entry_point");
    const issuer = pickConfigString(config, "issuer");
    const primaryCert = pickConfigString(config, "cert");
    const callbackOverride = pickConfigString(config, "callback_url");
    const callbackUrl = callbackOverride || getSamlCallbackUrl(slug);

    if (!isSet(entryPoint) || !isSet(issuer) || !isSet(primaryCert)) {
      return null;
    }

    const secondaryCert = pickConfigString(config, "secondary_cert");
    const authnRequestBinding = pickConfigString(config, "authn_request_binding");
    const usesHttpPost = authnRequestBinding === "HTTP-POST" ||
      authnRequestBinding === "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    const audience = pickConfigString(config, "audience");
    const nameIdFormat = pickConfigString(config, "name_id_format");
    const wantAuthnResponseSigned = config.want_authn_response_signed;
    const validateInResponseToSetting = pickConfigString(
      config,
      "validate_in_response_to",
    );
    const decryptionKey = secrets.decryption_key || null;
    const signingKey = secrets.signing_key || null;
    const signingCert = pickConfigString(config, "signing_cert");

    const certList = [primaryCert, isSet(secondaryCert) ? secondaryCert : null].filter(
      Boolean,
    );
    const idpCert = certList.length > 1 ? certList : certList[0];

    const validateInResponseTo = (() => {
      const raw = String(validateInResponseToSetting || "")
        .trim()
        .toLowerCase();
      if (raw === "never" || raw === "ifpresent" || raw === "always") {
        return raw === "ifpresent" ? "ifPresent" : raw;
      }
      return "always";
    })();

    const cfg = {
      entryPoint,
      issuer,
      callbackUrl,
      idpCert,
      authnRequestBinding: usesHttpPost ? "HTTP-POST" : "HTTP-Redirect",
      skipRequestCompression: usesHttpPost,
      wantAssertionsSigned: true,
      wantAuthnResponseSigned: toBool(wantAuthnResponseSigned, false),
      acceptedClockSkewMs: security.clockSkewSec * 1000,
      validateInResponseTo,
      audience: isSet(audience) ? audience : issuer,
    };
    if (validateInResponseTo !== "never") {
      if (!pool) {
        throw new Error(
          "SAML shared InResponseTo cache requires a database pool " +
            `(validateInResponseTo=${validateInResponseTo}).`,
        );
      }
      cfg.cacheProvider = createPostgresSamlCacheProvider(pool, {
        providerSlug: slug,
        logger: factoryLogger,
        ttlSec: (() => {
          const n = Number(process.env.SAML_CACHE_TTL_SEC);
          return Number.isFinite(n) && n > 0 ? Math.trunc(n) : undefined;
        })(),
      });
    }
    if (isSet(nameIdFormat)) cfg.identifierFormat = nameIdFormat;
    if (isSet(decryptionKey)) cfg.decryptionPvk = decryptionKey;
    if (security.signAuthnRequests && !isSet(signingKey)) {
      const err = new Error("signing_key_missing");
      err.code = "signing_key_missing";
      throw err;
    }
    if (security.signAuthnRequests && isSet(signingKey)) {
      cfg.privateKey = signingKey;
      cfg.signatureAlgorithm = security.signatureAlgorithm;
      if (isSet(signingCert)) {
        cfg.publicCert = signingCert;
      }
    }
    return cfg;
  }

  return {
    buildOidcStrategyConfigFromProvider,
    buildSamlStrategyConfigFromProvider,
    buildClaimConfigFromProvider,
    buildSecurityConfigFromProvider,
  };
}

module.exports = {
  createProviderStrategyConfig,
  DEFAULT_CLAIMS,
  // exported for tests / ops tooling
  fetchOidcDiscovery,
  clearOidcDiscoveryCache,
  assertSecureOidcUrl,
  pickConfigString,
};

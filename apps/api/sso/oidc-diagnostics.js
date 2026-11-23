"use strict";

const { discoveryDocumentUrlFromIssuer } = require("./oidc-endpoint-defaults.js");
const { createProviderStrategyConfig } = require("./strategy-config.js");
const { isOidcConfigured } = require("./sso-config-status.js");
const { safeFetch } = require("./safe-fetch.js");
const {
  getProvider,
  loadDecryptedSecret,
} = require("./provider-registry.js");
const { getProviderRuntimeStatus } = require("./sso-runtime-status.js");

const isSet = (v) =>
  v && String(v).trim().length > 0 && v !== "undefined" && v !== "null";

/**
 * Admin diagnostics for one OIDC provider (discovery + resolved endpoints).
 *
 * @param {import('pg').Pool} pool
 * @param {{ slug: string }} opts
 * @param {{ fetchImpl?: Function, logger?: object }} [runOpts]
 */
async function runOidcDiagnosticsForProvider(pool, opts, runOpts = {}) {
  const slug = String(opts?.slug || "").trim().toLowerCase();
  const logger = runOpts.logger || null;
  const fetchImpl = runOpts.fetchImpl;

  if (!slug) {
    return {
      slug: null,
      fieldsConfigured: false,
      signInReady: false,
      registered: false,
      reason: "slug_required",
      discovery: null,
      endpoints: null,
    };
  }

  const provider = await getProvider(pool, slug);
  if (!provider || provider.type !== "oidc") {
    return {
      slug,
      fieldsConfigured: false,
      signInReady: false,
      registered: false,
      reason: "provider_not_found",
      discovery: null,
      endpoints: null,
    };
  }

  const issuer = provider.config?.issuer || null;
  const discoveryUrl = discoveryDocumentUrlFromIssuer(issuer);
  let discovery = {
    url: discoveryUrl,
    reachable: false,
    status: null,
    error: null,
  };

  if (isSet(issuer)) {
    try {
      const res = await (fetchImpl || safeFetch)(discoveryUrl);
      discovery.status = res.status;
      discovery.reachable = res.ok;
      if (!res.ok) {
        discovery.error = `HTTP ${res.status}`;
      }
    } catch (err) {
      discovery.error = err?.message || "fetch failed";
    }
  } else {
    discovery.error = "issuer not set";
  }

  const builders = createProviderStrategyConfig({
    logger,
    fetchImpl,
  });
  let endpoints = null;
  let discoverySource = null;
  let buildError = null;
  const runtime = getProviderRuntimeStatus(slug);
  let clientSecret = null;
  try {
    clientSecret = await loadDecryptedSecret(pool, slug, "client_secret");
  } catch (secretErr) {
    buildError = secretErr?.message || "secret_decrypt_failed";
  }

  try {
    const cfg = await builders.buildOidcStrategyConfigFromProvider(
      pool,
      provider,
      { client_secret: clientSecret },
    );
    if (cfg) {
      discoverySource = cfg.discoverySource || null;
      endpoints = {
        authorizationURL: cfg.authorizationURL || null,
        tokenURL: cfg.tokenURL || null,
        userInfoURL: cfg.userInfoURL || null,
        jwksURL: cfg.jwksURL || null,
        callbackURL: cfg.callbackURL || null,
      };
    }
  } catch (err) {
    buildError = err?.message || "config build failed";
  }

  const fieldsConfigured = !!(
    isSet(issuer) &&
    isSet(provider.config?.client_id) &&
    isSet(clientSecret)
  );
  const signInReady =
    runtime.signInReady === true || runtime.registered === true;

  return {
    slug,
    displayName: provider.displayName,
    fieldsConfigured,
    signInReady,
    registered: runtime.registered,
    reason: runtime.reason || (signInReady ? undefined : "not_registered"),
    discovery,
    discoverySource,
    endpoints,
    buildError,
    disableDiscovery: !!provider.security?.disable_discovery,
  };
}

/**
 * Diagnostics for all enabled OIDC providers, or one slug when provided.
 *
 * @param {import('pg').Pool} pool
 * @param {{ slug?: string }} [opts]
 * @param {{ fetchImpl?: Function, logger?: object }} [runOpts]
 */
async function runOidcDiagnostics(pool, opts = {}, runOpts = {}) {
  const slug = opts.slug ? String(opts.slug).trim().toLowerCase() : null;

  if (slug) {
    return runOidcDiagnosticsForProvider(pool, { slug }, runOpts);
  }

  const anyConfigured = await isOidcConfigured(pool);
  if (!anyConfigured) {
    return {
      fieldsConfigured: false,
      signInReady: false,
      registered: false,
      reason: "not_configured",
      providers: [],
    };
  }

  const { listProviders } = require("./provider-registry.js");
  const providers = (await listProviders(pool)).filter(
    (p) => p.type === "oidc" && p.enabled,
  );
  const results = [];
  for (const p of providers) {
    results.push(await runOidcDiagnosticsForProvider(pool, { slug: p.slug }, runOpts));
  }

  return {
    fieldsConfigured: results.some((r) => r.fieldsConfigured),
    signInReady: results.some((r) => r.signInReady),
    registered: results.some((r) => r.registered),
    providers: results,
  };
}

module.exports = {
  runOidcDiagnostics,
  runOidcDiagnosticsForProvider,
};

"use strict";

const { listProviders } = require("./provider-registry.js");
const {
  getObservedSsoConfigVersion,
  getSsoSyncAggregateFlags,
} = require("./sso-config-sync.js");
const { getProviderRuntimeStatus } = require("./sso-runtime-status.js");

/**
 * @param {import('pg').Pool} pool
 * @param {{ packageVersion?: string }} [opts]
 */
async function buildSsoDiagnosticBundle(pool, opts = {}) {
  const providers = await listProviders(pool, { includeStatuses: true });
  const observed = getObservedSsoConfigVersion();
  const { allProvidersApplied, staleProviders, failedProviders } =
    await getSsoSyncAggregateFlags(pool);

  const redactedProviders = providers.map((p) => {
    const runtime = getProviderRuntimeStatus(p.slug);
    return {
      slug: p.slug,
      type: p.type,
      enabled: p.enabled,
      signInReady: p.runtime?.signInReady ?? false,
      displayName: p.displayName,
      computed: p.computed,
      config_keys_present: Object.keys(p.config || {}),
      secrets_set: p.secrets_set,
      locked_fields: p.locked_fields,
      runtime: {
        lastReason: p.runtime?.lastReason ?? null,
        lastReloadAt: p.runtime?.lastReloadAt ?? null,
        discoverySource: runtime.discoverySource || null,
      },
      last_test_checks: runtime.lastTestChecks || [],
    };
  });

  return {
    exported_at: new Date().toISOString(),
    tokentimer_version:
      opts.packageVersion ||
      process.env.TT_VERSION ||
      process.env.npm_package_version ||
      "unknown",
    providers: redactedProviders,
    ssoConfigVersion: {
      observed,
      allProvidersApplied,
      staleProviders,
      failedProviders,
    },
    ha: {
      replicas_observed: null,
      session_store: process.env.SESSION_STORE || "connect-pg-simple",
    },
    redactions:
      "tokens, assertions, ciphertext, secret values, JWKS contents, assertion XML are excluded by construction",
  };
}

module.exports = {
  buildSsoDiagnosticBundle,
};

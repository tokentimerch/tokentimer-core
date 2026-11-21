"use strict";

/**
 * Reload OIDC/SAML runtimes from sso_providers registry (multi-provider).
 */

/** @type {object|null} */
let reloadContext = null;

function __getReloadContextForSync() {
  return reloadContext;
}

/**
 * @param {object} ctx
 */
function configureSsoStrategyReload(ctx) {
  reloadContext = ctx;
}

/**
 * Reload all provider runtimes (OIDC map + SAML MultiSamlStrategy).
 * @returns {Promise<{ oidc?: object, saml?: object }>}
 */
async function reloadAllSsoProviders() {
  if (!reloadContext) {
    return {};
  }

  const {
    passport,
    pool,
    systemSettings,
    SamlStrategy,
    setupOidcStrategy,
    setupSamlStrategy,
    deps,
    logger,
  } = reloadContext;

  const { refreshGlobalSsoSettings } = require("./sso-global-settings.js");
  await refreshGlobalSsoSettings(pool, systemSettings);

  const results = {};

  try {
    const { clearOidcDiscoveryCache } = require("./strategy-config.js");
    clearOidcDiscoveryCache();
    results.oidc = await setupOidcStrategy(passport, pool, null, deps);
    logger?.info?.("OIDC runtimes reloaded", {
      registered: results.oidc?.registered,
      loaded: results.oidc?.loaded,
      reason: results.oidc?.reason,
    });
  } catch (err) {
    logger?.warn?.("OIDC runtime reload failed", { error: err?.message });
    results.oidc = { registered: false, reason: "reload_failed" };
  }

  try {
    results.saml = await setupSamlStrategy(
      passport,
      pool,
      SamlStrategy,
      deps,
    );
    logger?.info?.("SAML runtime reloaded", {
      registered: results.saml?.registered,
      loaded: results.saml?.loaded,
      reason: results.saml?.reason,
    });
  } catch (err) {
    logger?.warn?.("SAML runtime reload failed", { error: err?.message });
    results.saml = { registered: false, reason: "reload_failed" };
  }

  return results;
}

module.exports = {
  configureSsoStrategyReload,
  reloadAllSsoProviders,
  __getReloadContextForSync,
  _resetReloadContextForTests: () => {
    reloadContext = null;
  },
};

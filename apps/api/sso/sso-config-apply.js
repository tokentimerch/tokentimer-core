"use strict";

/**
 * Decide when a pod may treat sso_config_version as fully applied locally.
 */

/**
 * @param {{ registered?: boolean, reason?: string }|undefined} providerResult
 * @returns {boolean}
 */
function isProviderReloadAcceptable(providerResult) {
  if (!providerResult) return true;
  if (providerResult.registered === true) return true;
  return providerResult.reason === "not_configured";
}

/**
 * After a full HA sync reload (all providers).
 * @param {{ oidc?: object, saml?: object }} reloadResult
 * @returns {boolean}
 */
function isFullSsoSyncReloadAcceptable(reloadResult) {
  if (!reloadResult || typeof reloadResult !== "object") return false;
  return (
    isProviderReloadAcceptable(reloadResult.oidc) &&
    isProviderReloadAcceptable(reloadResult.saml)
  );
}

module.exports = {
  isProviderReloadAcceptable,
  isFullSsoSyncReloadAcceptable,
};

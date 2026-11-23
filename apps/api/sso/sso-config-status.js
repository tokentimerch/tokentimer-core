"use strict";

const { listProviders } = require("./provider-registry.js");

const isSet = (v) =>
  typeof v === "string" &&
  v.trim().length > 0 &&
  v !== "undefined" &&
  v !== "null";

/**
 * Whether at least one enabled SAML provider exists in sso_providers.
 */
async function isSamlConfigured(pool) {
  const providers = await listProviders(pool);
  return providers.some((p) => p.type === "saml" && p.enabled);
}

/**
 * Whether at least one enabled OIDC provider exists in sso_providers.
 */
async function isOidcConfigured(pool) {
  const providers = await listProviders(pool);
  return providers.some((p) => p.type === "oidc" && p.enabled);
}

module.exports = {
  isSamlConfigured,
  isOidcConfigured,
  isSet,
};

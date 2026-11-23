"use strict";

const { envPrefixFromSlug } = require("./provider-config-schema.js");

/**
 * Env-managed SSO provider fields (Helm/Compose) appear in locked_fields and reject writes.
 * Env keys use SSO_<SLUG>_* (see envPrefixFromSlug); locked paths use secrets.client_secret, etc.
 */

function envPrefix(slug) {
  return envPrefixFromSlug(slug);
}

/**
 * @param {string} slug
 * @param {'oidc'|'saml'} type
 * @returns {string[]}
 */
function detectEnvLockedFields(slug, type) {
  const prefix = envPrefix(slug);
  const locked = [];
  const check = (envSuffix, fieldPath) => {
    const key = `${prefix}${envSuffix}`;
    if (process.env[key] != null && String(process.env[key]).trim() !== "") {
      locked.push(fieldPath);
    }
  };
  if (type === "oidc") {
    check("OIDC_ISSUER", "config.issuer");
    check("OIDC_CLIENT_ID", "config.client_id");
    check("OIDC_CLIENT_SECRET", "secrets.client_secret");
  } else {
    check("SAML_ENTRY_POINT", "config.entry_point");
    check("SAML_ISSUER", "config.issuer");
    check("SAML_CERT", "config.cert");
    check("SAML_DECRYPTION_KEY", "secrets.decryption_key");
  }
  return locked;
}

/**
 * @param {string[]} lockedFields
 * @param {string} path e.g. config.issuer or secrets.client_secret
 */
function isFieldLocked(lockedFields, path) {
  return Array.isArray(lockedFields) && lockedFields.includes(path);
}

/**
 * @param {string[]} lockedFields
 * @param {string[]} paths
 * @returns {string|null} first blocked path
 */
function firstLockedViolation(lockedFields, paths) {
  for (const p of paths) {
    if (isFieldLocked(lockedFields, p)) return p;
  }
  return null;
}

/**
 * Throw field_locked when incomingPatch touches locked fields on a provider row.
 *
 * @param {object} provider row with locked_fields
 * @param {object} incomingPatch
 */
function enforceLocksOnUpdate(provider, incomingPatch) {
  const locked = [
    ...(Array.isArray(provider?.locked_fields) ? provider.locked_fields : []),
  ];
  const paths = [];
  if (incomingPatch?.config) {
    for (const key of Object.keys(incomingPatch.config)) {
      paths.push(`config.${key}`);
    }
  }
  if (incomingPatch?.secrets) {
    for (const key of Object.keys(incomingPatch.secrets)) {
      paths.push(`secrets.${key}`);
    }
  }
  if (Array.isArray(incomingPatch?.clearSecrets)) {
    for (const name of incomingPatch.clearSecrets) {
      paths.push(`secrets.${name}`);
    }
  }
  const blocked = firstLockedViolation(locked, paths);
  if (blocked) {
    const err = new Error("field_locked");
    err.code = "field_locked";
    err.statusCode = 409;
    err.field = blocked;
    throw err;
  }
}

module.exports = {
  envPrefix,
  detectEnvLockedFields,
  isFieldLocked,
  firstLockedViolation,
  enforceLocksOnUpdate,
};

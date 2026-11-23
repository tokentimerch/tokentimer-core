"use strict";

const {
  SSO_GLOBAL_SETTINGS_COLUMN,
  SSO_GLOBAL_DEFAULTS,
} = require("./sso-global-settings-schema.js");

/** @type {Record<string, boolean | number | string>} */
let cachedGlobal = { ...SSO_GLOBAL_DEFAULTS };

function toBool(value, fallback) {
  if (value === true || value === false) return value;
  if (typeof value === "string") {
    const s = value.trim().toLowerCase();
    if (s === "true" || s === "1" || s === "yes") return true;
    if (s === "false" || s === "0" || s === "no") return false;
  }
  return fallback;
}

function toPositiveInt(value, fallback, { min = 1, max = 600_000 } = {}) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(n)));
}

function resolveBoolPolicy(providerValue, globalValue, defaultValue = false) {
  if (providerValue === true || providerValue === false) return providerValue;
  if (globalValue === true || globalValue === false) return globalValue;
  return defaultValue;
}

/**
 * @param {import('pg').Pool} pool
 * @param {object} [systemSettings]
 */
async function refreshGlobalSsoSettings(pool, systemSettings) {
  try {
    systemSettings ??= require("../services/systemSettings.js");
  } catch (_) {
    cachedGlobal = { ...SSO_GLOBAL_DEFAULTS };
    return cachedGlobal;
  }

  if (!pool || typeof systemSettings.getJsonSettingValue !== "function") {
    cachedGlobal = { ...SSO_GLOBAL_DEFAULTS };
    return cachedGlobal;
  }

  const fresh = typeof systemSettings.getFreshJsonSettingValues === "function"
    ? await systemSettings.getFreshJsonSettingValues(pool, SSO_GLOBAL_SETTINGS_COLUMN)
    : null;
  if (!fresh) systemSettings.invalidateCache?.();
  const next = { ...SSO_GLOBAL_DEFAULTS };
  for (const [key, defaultValue] of Object.entries(SSO_GLOBAL_DEFAULTS)) {
    const value = fresh
      ? fresh[key]
      : await systemSettings.getJsonSettingValue(pool, SSO_GLOBAL_SETTINGS_COLUMN, key);
    if (value === null || value === undefined || value === "") continue;
    if (typeof defaultValue === "boolean") {
      next[key] = toBool(value, defaultValue);
    } else if (typeof defaultValue === "string") {
      next[key] = String(value).trim();
    } else {
      next[key] = toPositiveInt(value, defaultValue);
    }
  }
  cachedGlobal = next;
  return cachedGlobal;
}

function getGlobalSsoSettingsSync() {
  return { ...cachedGlobal };
}

/**
 * Merge per-provider security with installation-wide defaults.
 * Undefined provider keys inherit the global value.
 *
 * @param {object} provider
 * @param {object} [globalSettings]
 */
function resolveProviderSecurityConfig(provider, globalSettings = cachedGlobal) {
  const security = provider?.security || {};
  const global = globalSettings || SSO_GLOBAL_DEFAULTS;
  return {
    allowAutoLinkLocalAccounts: resolveBoolPolicy(
      security.allow_auto_link_local_accounts,
      global.allow_auto_link_local_accounts,
      false,
    ),
    strictMembershipSync: resolveBoolPolicy(
      security.strict_membership_sync,
      global.strict_membership_sync,
      false,
    ),
    pkce: toBool(security.pkce, true),
    signAuthnRequests: toBool(security.sign_authn_requests, false),
    signatureAlgorithm:
      typeof security.signature_algorithm === "string" &&
      security.signature_algorithm.trim()
        ? security.signature_algorithm.trim()
        : "sha256",
    clockSkewSec: toPositiveInt(security.clock_skew_sec, 60, {
      min: 0,
      max: 600,
    }),
    disableDiscovery: toBool(security.disable_discovery, false),
  };
}

function resolveConfigSyncIntervalMs(env = process.env) {
  const fromEnv = Number(env.SSO_CONFIG_SYNC_INTERVAL_MS);
  if (Number.isFinite(fromEnv) && fromEnv > 0) return Math.trunc(fromEnv);
  return toPositiveInt(cachedGlobal.config_sync_interval_ms, 45_000, {
    min: 5_000,
    max: 600_000,
  });
}

function resolveIdpHttpTimeoutMs(env = process.env) {
  const fromEnv = Number(env.SSO_IDP_HTTP_TIMEOUT_MS);
  if (Number.isFinite(fromEnv) && fromEnv > 0) {
    return Math.min(120_000, Math.max(5_000, Math.trunc(fromEnv)));
  }
  return toPositiveInt(cachedGlobal.idp_http_timeout_ms, 20_000, {
    min: 5_000,
    max: 120_000,
  });
}

function resolveAllowPrivateIdpUrls(env = process.env) {
  const raw = env.SSO_ALLOW_PRIVATE_IDP_URLS;
  if (raw !== undefined && raw !== null && String(raw).trim() !== "") {
    return toBool(raw, false);
  }
  return toBool(cachedGlobal.allow_private_idp_urls, false);
}

function resolveAllowedIdpCidrs(env = process.env) {
  const raw = env.SSO_ALLOWED_IDP_CIDRS;
  if (raw !== undefined && raw !== null && String(raw).trim() !== "") {
    return String(raw).trim();
  }
  return String(cachedGlobal.allowed_idp_cidrs || "").trim();
}

module.exports = {
  refreshGlobalSsoSettings,
  getGlobalSsoSettingsSync,
  resolveProviderSecurityConfig,
  resolveBoolPolicy,
  resolveConfigSyncIntervalMs,
  resolveIdpHttpTimeoutMs,
  resolveAllowPrivateIdpUrls,
  resolveAllowedIdpCidrs,
};

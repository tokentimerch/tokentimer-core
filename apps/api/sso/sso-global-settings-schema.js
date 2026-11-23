"use strict";

/** DB column on system_settings (JSONB). */
const SSO_GLOBAL_SETTINGS_COLUMN = "sso_global_settings";

/** API response / PUT body key under /api/admin/system-settings. */
const SSO_GLOBAL_SETTINGS_RESPONSE_KEY = "sso";

/**
 * Installation-wide SSO policy keys. Each maps to an env var via
 * registerJsonColumn in register-sso-system-settings.js.
 *
 * Ops-only (no UI): SSO_SECRETS_KEYRING*, SSO_PROVIDERS_BOOTSTRAP_FILE,
 * SSO_<SLUG>_* provider secrets (provider edit / Helm).
 */
const SSO_GLOBAL_DEFAULTS = {
  allow_auto_link_local_accounts: false,
  strict_membership_sync: true,
  config_sync_interval_ms: 45_000,
  idp_http_timeout_ms: 20_000,
  allow_private_idp_urls: false,
  allowed_idp_cidrs: "",
};

const SSO_GLOBAL_ENV_MAP = {
  allow_auto_link_local_accounts: "SSO_ALLOW_AUTO_LINK_LOCAL_ACCOUNTS",
  strict_membership_sync: "SSO_STRICT_MEMBERSHIP_SYNC",
  config_sync_interval_ms: "SSO_CONFIG_SYNC_INTERVAL_MS",
  idp_http_timeout_ms: "SSO_IDP_HTTP_TIMEOUT_MS",
  allow_private_idp_urls: "SSO_ALLOW_PRIVATE_IDP_URLS",
  allowed_idp_cidrs: "SSO_ALLOWED_IDP_CIDRS",
};

module.exports = {
  SSO_GLOBAL_SETTINGS_COLUMN,
  SSO_GLOBAL_SETTINGS_RESPONSE_KEY,
  SSO_GLOBAL_DEFAULTS,
  SSO_GLOBAL_ENV_MAP,
};

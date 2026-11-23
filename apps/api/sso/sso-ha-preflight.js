"use strict";

/**
 * Verify multi-provider SSO schema objects exist (HA sync + SAML cache).
 */

async function verifySsoHaSchema(pool, logger) {
  const missing = [];
  if (!pool) {
    return { ok: false, missing: ["pool"] };
  }

  const checks = [
    {
      name: "system_settings.sso_config_version",
      sql: `SELECT 1 FROM information_schema.columns
             WHERE table_schema = 'public' AND table_name = 'system_settings'
               AND column_name = 'sso_config_version' LIMIT 1`,
    },
    {
      name: "saml_request_cache",
      sql: `SELECT 1 FROM information_schema.tables
             WHERE table_schema = 'public' AND table_name = 'saml_request_cache' LIMIT 1`,
    },
    {
      name: "sso_providers",
      sql: `SELECT 1 FROM information_schema.tables
             WHERE table_schema = 'public' AND table_name = 'sso_providers' LIMIT 1`,
    },
  ];

  for (const check of checks) {
    try {
      const res = await pool.query(check.sql);
      if (res.rowCount === 0) missing.push(check.name);
    } catch (err) {
      missing.push(`${check.name} (${err.message})`);
    }
  }

  if (missing.length > 0) {
    logger?.error?.(
      "SSO HA schema incomplete — apply the current database migrations.",
      { missing },
    );
    return { ok: false, missing };
  }

  return { ok: true, missing: [] };
}

/**
 * Remind operators that bootstrap manifest + keyring drive provider config;
 * per-secret env vars do not bump sso_config_version automatically.
 */
function warnIfEnvOnlySsoConfigured(logger) {
  const manifest = process.env.SSO_PROVIDERS_BOOTSTRAP_FILE;
  const keyring =
    process.env.SSO_SECRETS_KEYRING_FILE || process.env.SSO_SECRETS_KEYRING;
  if (!manifest && !keyring) {
    return;
  }
  logger?.info?.(
    "SSO providers are bootstrapped from SSO_PROVIDERS_BOOTSTRAP_FILE and the secrets keyring. " +
      "UI or API changes to sso_providers bump sso_config_version for HA sync. " +
      "Update the manifest or provider rows and bump the version (or restart pods) after GitOps env changes.",
    {
      bootstrapFile: manifest || null,
      keyringConfigured: !!keyring,
    },
  );
}

module.exports = {
  verifySsoHaSchema,
  warnIfEnvOnlySsoConfigured,
};

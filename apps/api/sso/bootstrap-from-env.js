"use strict";

/**
 * GitOps bootstrap: read SSO_PROVIDERS_BOOTSTRAP_FILE (JSON manifest), upsert sso_providers rows,
 * resolve secrets from env, encrypt into sso_provider_secrets.
 *
 * Manifest secrets use secret names as keys (e.g. client_secret, decryption_key); values are env
 * var names (typically SSO_<SLUG>_*). SAML IdP signing cert uses cert_env -> config.cert (not a secret row).
 */

const fs = require("fs");
const {
  envPrefixFromSlug,
  detectSlugEnvCollisions,
} = require("./provider-config-schema.js");
const {
  getProvider,
  createProvider,
  updateProvider,
  listProviders,
  lockProviderChanges,
  enabledProviderRows,
} = require("./provider-registry.js");
const { bumpSsoConfigVersion } = require("./sso-config-version.js");

function readManifestFile() {
  const path = String(process.env.SSO_PROVIDERS_BOOTSTRAP_FILE || "").trim();
  if (!path) return null;
  const raw = fs.readFileSync(path, "utf8");
  return JSON.parse(raw);
}

/**
 * Build locked_fields for every config/secret key sourced from bootstrap manifest + env.
 *
 * @param {object} entry
 * @param {Record<string, string>} resolvedSecrets plaintext by secret_name
 */
function buildLockedFields(entry, resolvedSecrets) {
  const locked = [];
  const config = entry.config || {};
  for (const key of Object.keys(config)) {
    if (config[key] !== undefined && config[key] !== null && String(config[key]).trim() !== "") {
      locked.push(`config.${key}`);
    }
  }
  for (const secretName of Object.keys(resolvedSecrets)) {
    if (resolvedSecrets[secretName]) {
      locked.push(`secrets.${secretName}`);
    }
  }
  return [...new Set(locked)];
}

/**
 * Resolve manifest secrets map (secret_name -> env var name) from process.env.
 * Example: { client_secret: "SSO_AZURE_AD_OIDC_CLIENT_SECRET" } -> { client_secret: "<value>" }.
 * cert_env is handled separately in applyPublicCertFromEnv and must not appear here.
 *
 * @param {object} secretsMap
 * @returns {{ resolved: Record<string,string>, errors: string[] }}
 */
function resolveSecretEnvs(secretsMap) {
  const resolved = {};
  const errors = [];
  if (!secretsMap || typeof secretsMap !== "object") {
    return { resolved, errors };
  }
  for (const [secretName, envVar] of Object.entries(secretsMap)) {
    const envKey = String(envVar || "").trim();
    if (!envKey) continue;
    const value = process.env[envKey];
    if (value == null || String(value).trim() === "") {
      errors.push(`missing_env:${envKey}`);
      continue;
    }
    resolved[secretName] = String(value);
  }
  return { resolved, errors };
}

/**
 * SAML bootstrap helper: secrets.cert_env names an env var holding the IdP PEM; value is copied to
 * config.cert and cert_env is removed before resolveSecretEnvs (cert is not an encrypted secret row).
 *
 * @param {object} entry manifest provider
 */
function applyPublicCertFromEnv(entry) {
  const config = { ...(entry.config || {}) };
  const secrets = { ...(entry.secrets || {}) };
  if (secrets.cert_env) {
    const pem = process.env[String(secrets.cert_env).trim()];
    if (pem && String(pem).trim()) {
      config.cert = String(pem).trim();
    }
    delete secrets.cert_env;
  }
  return { config, secrets };
}

async function upsertManifestProvider(pool, entry, meta = {}, txOpts = {}) {
  const slug = entry.slug;
  const existing = await getProvider(txOpts.dbClient || pool, slug);
  const { config, secrets: secretsMap } = applyPublicCertFromEnv(entry);
  const { resolved: secrets, errors: secretErrors } = resolveSecretEnvs(secretsMap);
  if (secretErrors.length > 0) {
    const err = new Error(secretErrors.join(","));
    err.code = "bootstrap_secret_missing";
    throw err;
  }
  const locked_fields = buildLockedFields({ ...entry, config }, secrets);
  const payload = {
    slug,
    type: entry.type,
    displayName: entry.displayName,
    enabled: entry.enabled === true,
    selectForSignIn: txOpts.selectForSignIn === true,
    sortOrder: entry.sort_order ?? 100,
    config,
    claim_mapping: entry.claim_mapping || {},
    security: entry.security || {},
    locked_fields,
    secrets,
  };
  const registryOpts = {
    dbClient: txOpts.dbClient,
    skipVersionBump: txOpts.skipVersionBump,
    skipReturn: true,
    // The bootstrap owns the fields it locks; locks only guard UI/API edits.
    // Without this the upsert rejects its own secrets with field_locked.
    bypassLocks: true,
  };
  if (existing) {
    return updateProvider(pool, slug, payload, meta, registryOpts);
  }
  return createProvider(pool, payload, meta, registryOpts);
}

/**
 * Disable providers that were env-managed but removed from manifest.
 *
 * @param {import('pg').Pool} pool
 * @param {Set<string>} manifestSlugs
 * @param {{ userId?: number }} meta
 * @param {{ dbClient?: object }} [txOpts]
 */
async function disableRemovedProviders(pool, manifestSlugs, meta = {}, txOpts = {}) {
  const all = await listProviders(txOpts.dbClient || pool);
  for (const p of all) {
    if (manifestSlugs.has(p.slug)) continue;
    const locks = p.locked_fields || [];
    if (!locks.length) continue;
    await updateProvider(
      pool,
      p.slug,
      {
        enabled: false,
        locked_fields: [],
      },
      meta,
      {
        dbClient: txOpts.dbClient,
        skipVersionBump: true,
        skipReturn: true,
        bypassLocks: true,
      },
    );
  }
}

/**
 * @param {import('pg').Pool} pool
 * @param {{ logger?: object, pruneRemoved?: boolean, forcePrune?: boolean }} [opts]
 */
async function reconcileSsoProvidersFromEnv(pool, opts = {}) {
  const logger = opts.logger || console;
  const manifest = readManifestFile();
  if (!manifest) {
    return { skipped: true, reason: "no_bootstrap_file" };
  }
  if (!Array.isArray(manifest.providers)) {
    throw new Error("The SSO bootstrap manifest requires a providers array.");
  }
  const { providers } = manifest;
  const enabledEntries = providers.filter((entry) => entry.enabled === true);
  if (enabledEntries.length > 1) {
    const err = new Error("Core allows one active SSO provider. Set enabled: true for at most one OIDC or SAML provider in the bootstrap manifest.");
    err.code = "active_provider_exists";
    logger.error?.(err.message);
    throw err;
  }
  const [configuredProvider] = enabledEntries;
  const slugs = providers.map((p) => p.slug);
  const collision = detectSlugEnvCollisions(slugs);
  if (!collision.ok) {
    const err = new Error(`slug_env_collision:${collision.slugs.join(",")}`);
    err.code = "slug_env_collision";
    throw err;
  }

  const client = await pool.connect();
  let acquired = false;
  try {
    const lockRes = await client.query(
      `SELECT pg_try_advisory_lock(hashtext('tokentimer:sso-bootstrap')) AS ok`,
    );
    acquired = lockRes.rows[0]?.ok === true;
    if (!acquired) {
      return { skipped: true, reason: "advisory_lock_busy" };
    }

    const manifestSlugs = new Set(slugs);
    const txOpts = { dbClient: client, skipVersionBump: true };
    await client.query("BEGIN");
    try {
      await lockProviderChanges(client);
      const enabledRows = await enabledProviderRows(client);
      let selectedSlug;
      if (enabledRows.length > 1) {
        if (configuredProvider && enabledRows.some((row) =>
          row.slug === configuredProvider.slug && row.type === configuredProvider.type)) {
          try {
            await upsertManifestProvider(pool, configuredProvider, {}, { ...txOpts, selectForSignIn: true });
            selectedSlug = configuredProvider.slug;
          } catch (err) {
            if (err.code !== "last_login_method") throw err;
          }
        }
        if (!selectedSlug) {
          await client.query("ROLLBACK");
          logger.warn?.("SSO bootstrap requires a usable local administrator and selection of one currently enabled provider.");
          return { skipped: true, reason: "provider_selection_required" };
        }
      }
      await disableRemovedProviders(pool, manifestSlugs, {}, txOpts);
      const ordered = providers.filter((entry) => entry.slug !== selectedSlug).sort(
        (a, b) => Number(a.enabled === true) - Number(b.enabled === true),
      );
      for (const entry of ordered) {
        const prefix = envPrefixFromSlug(entry.slug);
        logger.info?.("SSO bootstrap upsert", { slug: entry.slug, prefix });
        await upsertManifestProvider(pool, entry, {}, txOpts);
      }

      if (opts.pruneRemoved) {
        logger.warn?.(
          "sso.bootstrap.pruneRemovedProviders is set; explicit prune not implemented in v1 (providers are disabled only)",
        );
      }

      await bumpSsoConfigVersion(client);
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    }
    return { ok: true, count: providers.length };
  } finally {
    if (acquired) {
      await client.query(`SELECT pg_advisory_unlock(hashtext('tokentimer:sso-bootstrap'))`);
    }
    client.release();
  }
}

module.exports = {
  readManifestFile,
  reconcileSsoProvidersFromEnv,
  buildLockedFields,
  resolveSecretEnvs,
  upsertManifestProvider,
};

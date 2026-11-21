"use strict";

const { bumpSsoConfigVersion } = require("./sso-config-version.js");
const {
  validateSlug,
  validateProviderConfig,
  normalizeSecurity,
} = require("./provider-config-schema.js");
const {
  detectEnvLockedFields,
  firstLockedViolation,
  enforceLocksOnUpdate,
} = require("./provider-locks.js");
const {
  buildComputedUrls,
  isRedundantCallbackOverride,
} = require("./sso-computed-urls.js");
const {
  loadKeyring,
  encryptSecret,
  decryptSecret,
  secretAad,
} = require("./secrets-keyring.js");
const {
  getProviderRuntimeStatus,
  deriveSignInReady,
} = require("./sso-runtime-status.js");

const { isDeepStrictEqual } = require("node:util");
const { assertNotLastLoginMethod, hasUsableLocalAdmin } = require("./login-reachability.js");
const { writeAudit } = require("../services/audit");
const { recomputeSystemAdmin } = require("./system-admin-sync.js");
const { lockSystemAdminMutation } = require("../services/systemAdmin.js");
const { SECRET_NAMES } = require("./secret-names.js");

async function lockProviderChanges(client) {
  await client.query("SELECT pg_advisory_xact_lock(hashtext('tokentimer:core-sso-providers'))");
}

function providerChangeError(code, message) {
  return Object.assign(new Error(message), { code });
}

async function enabledProviderRows(client) {
  const { rows } = await client.query("SELECT slug, type FROM sso_providers WHERE enabled");
  return rows;
}

function conflictingProviderTypes(providers) {
  const seen = new Set();
  const conflicts = new Set();
  for (const { type, enabled } of providers) {
    if (enabled === false) continue;
    if (seen.has(type)) conflicts.add(type);
    seen.add(type);
  }
  return conflicts;
}

function selectionRequired() {
  return providerChangeError(
    "provider_selection_required",
    "Select an enabled provider of this protocol to resume sign-in.",
  );
}

async function requireLocalAdmin(client) {
  if (!(await hasUsableLocalAdmin(client, { lock: true }))) {
    throw providerChangeError(
      "last_login_method",
      "Set a local administrator password before proceeding with this provider change.",
    );
  }
}

async function activateProvider(client, { slug, type, enabled }, { select, userId } = {}) {
  const peers = (await enabledProviderRows(client)).filter((row) => row.type === type);
  if (peers.length > 1) {
    if (!select || !enabled) throw selectionRequired();
    await client.query("SELECT slug FROM sso_providers WHERE enabled AND type = $1 FOR UPDATE", [type]);
    await lockSystemAdminMutation(client);
    await requireLocalAdmin(client);
    const { rows } = await client.query(
      "UPDATE sso_providers SET enabled = FALSE, updated_at = NOW() WHERE enabled AND type = $1 AND slug <> $2 RETURNING slug",
      [type, slug],
    );
    for (const peer of rows) {
      await writeAudit({
        client, actorUserId: userId, subjectUserId: null, action: "SSO_PROVIDER_DISABLED",
        targetType: "sso_provider",
        metadata: { slug: peer.slug, type, selected_provider_slug: slug },
      });
    }
    return;
  }
  if (peers.length === 1 && peers[0].slug !== slug) {
    throw providerChangeError(
      "active_provider_exists",
      "Disable the active provider of this protocol before enabling another one.",
    );
  }
}

async function assertProviderCanBeDisabled(client, provider) {
  if (!provider.enabled) return;
  if (conflictingProviderTypes(await enabledProviderRows(client)).has(provider.type)) {
    throw selectionRequired();
  }
  await lockSystemAdminMutation(client);
  const guard = await assertNotLastLoginMethod(client, {
    changingSlug: provider.slug,
    getRuntimeStatus: getProviderRuntimeStatus,
    lockLocalAdmin: true,
  });
  if (!guard.allowed) {
    throw Object.assign(providerChangeError(
      "last_login_method",
      "Set a local administrator password before removing the last administrator sign-in method.",
    ), { reachability: guard.reachability });
  }
}

function attachSecretWarnings(provider, skippedSecretNames) {
  if (!skippedSecretNames?.length) return provider;
  return {
    ...provider,
    warnings: [
      {
        code: "secrets_not_persisted",
        message:
          "SSO secrets keyring is not configured. The provider was saved but secrets were not stored. Configure SSO_SECRETS_KEYRING or SSO_SECRETS_KEYRING_FILE, or set secrets via environment variables (advanced / GitOps).",
        secrets: skippedSecretNames,
      },
    ],
  };
}

function redactSecretFields(value) {
  return Object.fromEntries(
    Object.entries(value || {}).filter(([key]) =>
      !["client_secret", "decryption_key", "signing_key", "private_key"].includes(key),
    ),
  );
}

function rowToProvider(row, { secretsSet = [], includeRuntime = true, selectionRequired = false } = {}) {
  const locked = Array.isArray(row.locked_fields) ? row.locked_fields : [];
  const envLocked = detectEnvLockedFields(row.slug, row.type);
  const locked_fields = [...new Set([...locked, ...envLocked])];
  const computed = buildComputedUrls({
    slug: row.slug,
    type: row.type,
    config: row.config,
  });
  const runtimeStatus = includeRuntime
    ? getProviderRuntimeStatus(row.slug)
    : null;
  const signInReady = includeRuntime
    ? !selectionRequired && deriveSignInReady(row, runtimeStatus)
    : undefined;
  return {
    slug: row.slug,
    type: row.type,
    displayName: row.display_name,
    enabled: row.enabled,
    sortOrder: row.sort_order,
    config: redactSecretFields(row.config),
    claim_mapping: row.claim_mapping || {},
    security: redactSecretFields(row.security),
    secrets_set: secretsSet,
    locked_fields,
    computed,
    runtime: includeRuntime
      ? {
          signInReady: !!signInReady,
          lastReason: selectionRequired ? "provider_selection_required" : runtimeStatus?.reason || null,
          lastReloadAt: runtimeStatus?.lastReloadAt || null,
          appliedConfigVersion: runtimeStatus?.appliedConfigVersion ?? null,
        }
      : undefined,
  };
}

async function listSecretNames(pool, providerId) {
  const res = await pool.query(
    `SELECT secret_name FROM sso_provider_secrets WHERE provider_id = $1`,
    [providerId],
  );
  return res.rows.map((r) => r.secret_name);
}

/**
 * @param {import('pg').Pool} pool
 * @param {{ includeStatuses?: boolean }} [opts]
 */
async function listProviders(pool, opts = {}) {
  const res = await pool.query(
    `SELECT id, slug, type, display_name, enabled, sort_order, config,
            claim_mapping, security, locked_fields, created_at, updated_at
       FROM sso_providers
      ORDER BY sort_order, display_name`,
  );
  const conflicts = conflictingProviderTypes(res.rows);
  const out = [];
  for (const row of res.rows) {
    const secretsSet = await listSecretNames(pool, row.id);
    out.push(
      rowToProvider(row, {
        secretsSet,
        includeRuntime: opts.includeStatuses !== false,
        selectionRequired: row.enabled && conflicts.has(row.type),
      }),
    );
  }
  return out;
}

async function getProviderRow(pool, slug, { forUpdate = false } = {}) {
  const res = await pool.query(
    `SELECT id, slug, type, display_name, enabled, sort_order, config,
            claim_mapping, security, locked_fields, created_at, updated_at
       FROM sso_providers WHERE slug = $1${forUpdate ? " FOR UPDATE" : ""}`,
    [slug],
  );
  return res.rows[0] || null;
}

async function getProvider(pool, slug) {
  const row = await getProviderRow(pool, slug);
  if (!row) return null;
  const secretsSet = await listSecretNames(pool, row.id);
  const conflicts = row.enabled && conflictingProviderTypes(await enabledProviderRows(pool));
  return rowToProvider(row, { secretsSet, selectionRequired: conflicts && conflicts.has(row.type) });
}

function stripComputedFromConfigPayload(config, slug, type) {
  const next = redactSecretFields(config);
  const computed = buildComputedUrls({ slug, type, config: next });
  if (isRedundantCallbackOverride(next.callback_url, computed.callback_url)) {
    const err = new Error("redundant_override");
    err.code = "redundant_override";
    throw err;
  }
  delete next.metadata_url;
  return next;
}

/**
 * @param {import('pg').Pool} pool
 * @param {object} payload
 * @param {{ userId?: number }} [meta]
 * @param {{ dbClient?: object, skipVersionBump?: boolean, skipReturn?: boolean, bypassLocks?: boolean, secretChanges?: {set: string[], cleared: string[]} }} [opts]
 *   opts.bypassLocks is reserved for the env/GitOps bootstrap, which owns the
 *   locked fields it writes; locks only reject UI/API edits.
 */
async function createProvider(pool, payload, meta = {}, opts = {}) {
  const slug = payload.slug;
  const v = validateSlug(slug);
  if (!v.ok) {
    const err = new Error("invalid_slug");
    err.code = "invalid_slug";
    throw err;
  }
  const type = payload.type;
  if (type !== "oidc" && type !== "saml") {
    const err = new Error("invalid_type");
    err.code = "invalid_type";
    throw err;
  }
  const config = stripComputedFromConfigPayload(payload.config, slug, type);
  const schema = validateProviderConfig(type, config);
  if (!schema.ok) {
    const err = new Error(schema.errors.join(","));
    err.code = "invalid_config";
    throw err;
  }
  const security = normalizeSecurity(redactSecretFields(payload.security));
  const locked_fields = [
    ...new Set([
      ...(opts.bypassLocks ? payload.locked_fields || [] : []),
      ...detectEnvLockedFields(slug, type),
    ]),
  ];
  const client = opts.dbClient || (await pool.connect());
  const ownsClient = !opts.dbClient;
  try {
    if (ownsClient) await client.query("BEGIN");
    await lockProviderChanges(client);
    if (payload.enabled === true) await activateProvider(client, { slug, type });
    const ins = await client.query(
      `INSERT INTO sso_providers
         (slug, type, display_name, enabled, sort_order, config, claim_mapping, security, locked_fields)
       VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9::jsonb)
       RETURNING id, slug, type, display_name, enabled, sort_order, config,
                 claim_mapping, security, locked_fields`,
      [
        slug,
        type,
        payload.displayName || slug,
        payload.enabled === true,
        payload.sortOrder ?? 100,
        JSON.stringify(config),
        JSON.stringify(payload.claim_mapping || {}),
        JSON.stringify(security),
        JSON.stringify(locked_fields),
      ],
    );
    const row = ins.rows[0];
    let skippedSecrets = [];
    if (payload.secrets && typeof payload.secrets === "object") {
      skippedSecrets = await applySecrets(
        client,
        row,
        payload.secrets,
        meta.userId,
        opts.bypassLocks ? [] : locked_fields,
        opts.secretChanges,
      );
    }
    if (!opts.skipVersionBump) {
      await bumpSsoConfigVersion(client);
    }
    const provider = opts.skipReturn ? null : await getProvider(client, slug);
    if (ownsClient) await client.query("COMMIT");
    return provider && attachSecretWarnings(provider, skippedSecrets);
  } catch (err) {
    if (ownsClient) await client.query("ROLLBACK");
    throw err;
  } finally {
    if (ownsClient) client.release();
  }
}

async function upsertEncryptedSecret(client, providerId, secretName, plaintext, userId) {
  const aad = secretAad(providerId, secretName);
  const encrypted = encryptSecret(String(plaintext), aad);
  await client.query(
    `INSERT INTO sso_provider_secrets (provider_id, secret_name, encrypted_value, updated_by)
     VALUES ($1,$2,$3::jsonb,$4)
     ON CONFLICT (provider_id, secret_name)
     DO UPDATE SET encrypted_value = EXCLUDED.encrypted_value,
                   updated_at = NOW(), updated_by = EXCLUDED.updated_by`,
    [providerId, secretName, JSON.stringify(encrypted), userId || null],
  );
}

async function applySecrets(client, row, secrets, userId, lockedFields, secretChanges) {
  const skipped = [];
  const keyring = loadKeyring();
  for (const [name, value] of Object.entries(secrets)) {
    if (value === undefined || value === null || value === "") continue;
    const path = `secrets.${name}`;
    if (firstLockedViolation(lockedFields, [path])) {
      const err = new Error("field_locked");
      err.code = "field_locked";
      err.field = path;
      throw err;
    }
    if (!keyring) {
      skipped.push(name);
      continue;
    }
    await upsertEncryptedSecret(client, row.id, name, value, userId);
    secretChanges?.set.push(name);
  }
  return skipped;
}

/**
 * @param {import('pg').Pool} pool
 * @param {string} slug
 * @param {object} payload
 * @param {{ userId?: number }} [meta]
 * @param {{ dbClient?: object, skipVersionBump?: boolean, skipReturn?: boolean, bypassLocks?: boolean, secretChanges?: {set: string[], cleared: string[]} }} [opts]
 *   opts.bypassLocks is reserved for the env/GitOps bootstrap, which owns the
 *   locked fields it writes; locks only reject UI/API edits.
 */
async function updateProvider(pool, slug, payload, meta = {}, opts = {}) {
  const client = opts.dbClient || (await pool.connect());
  const ownsClient = !opts.dbClient;
  try {
    if (ownsClient) await client.query("BEGIN");
    await lockProviderChanges(client);
    const existing = await getProviderRow(client, slug, { forUpdate: true });
    if (!existing) {
      const err = new Error("not_found");
      err.code = "not_found";
      throw err;
    }
    if (payload.slug && payload.slug !== slug) {
      const err = new Error("slug_immutable");
      err.code = "slug_immutable";
      throw err;
    }
    if (payload.type && payload.type !== existing.type) {
      const err = new Error("type_immutable");
      err.code = "type_immutable";
      throw err;
    }
    const locked_fields = Array.isArray(existing.locked_fields)
      ? existing.locked_fields
      : [];
    const envLocked = detectEnvLockedFields(slug, existing.type);
    const mergedLocks = [...new Set([...locked_fields, ...envLocked])];
    const config = payload.config
      ? stripComputedFromConfigPayload(
          { ...existing.config, ...payload.config },
          slug,
          existing.type,
        )
      : existing.config;
    if (existing.type === "oidc" && String(config.issuer).trim() !== String(existing.config.issuer).trim()) {
      const linked = await client.query(
        "SELECT 1 FROM external_identities WHERE provider_slug = $1 LIMIT 1",
        [slug],
      );
      if (linked.rowCount > 0) {
        throw Object.assign(new Error("Create a new provider to change the issuer after accounts have linked."), {
          code: "issuer_has_linked_accounts",
        });
      }
    }
    if (payload.config) {
      const schema = validateProviderConfig(existing.type, config);
      if (!schema.ok) {
        const err = new Error(schema.errors.join(","));
        err.code = "invalid_config";
        throw err;
      }
    }
    if (!opts.bypassLocks) {
      const changedConfig = Object.fromEntries(
        Object.entries(payload.config || {}).filter(
          ([key, value]) => !isDeepStrictEqual(value, existing.config?.[key]),
        ),
      );
      enforceLocksOnUpdate({ locked_fields: mergedLocks }, { config: changedConfig });
    }
    if (payload.selectForProtocol === true && (payload.enabled !== true || !existing.enabled || payload.clearSecrets?.length)) {
      throw selectionRequired();
    }
    if ((payload.enabled === true && !existing.enabled) || payload.selectForProtocol === true) {
      await activateProvider(client, existing, { select: payload.selectForProtocol === true, userId: meta.userId });
    }
    if (payload.enabled === false || payload.clearSecrets?.length) {
      await assertProviderCanBeDisabled(client, existing);
    }
    await client.query(
      `UPDATE sso_providers SET
         display_name = COALESCE($2, display_name),
         enabled = COALESCE($3, enabled),
         sort_order = COALESCE($4, sort_order),
         config = COALESCE($5::jsonb, config),
         claim_mapping = COALESCE($6::jsonb, claim_mapping),
         security = COALESCE($7::jsonb, security),
         locked_fields = COALESCE($8::jsonb, locked_fields),
         updated_at = NOW()
       WHERE slug = $1`,
      [
        slug,
        payload.displayName ?? null,
        typeof payload.enabled === "boolean" ? payload.enabled : null,
        payload.sortOrder ?? null,
        payload.config ? JSON.stringify(config) : null,
        payload.claim_mapping
          ? JSON.stringify(payload.claim_mapping)
          : null,
        payload.security
          ? JSON.stringify(normalizeSecurity(redactSecretFields(payload.security)))
          : null,
        opts.bypassLocks && payload.locked_fields
          ? JSON.stringify(payload.locked_fields)
          : null,
      ],
    );
    const row = (await getProviderRow(client, slug)) || existing;
    let skippedSecrets = [];
    if (payload.secrets) {
      skippedSecrets = await applySecrets(
        client,
        row,
        payload.secrets,
        meta.userId,
        opts.bypassLocks ? [] : mergedLocks,
        opts.secretChanges,
      );
    }
    if (Array.isArray(payload.clearSecrets)) {
      for (const name of payload.clearSecrets) {
        const path = `secrets.${name}`;
        if (!opts.bypassLocks && firstLockedViolation(mergedLocks, [path])) {
          const err = new Error("field_locked");
          err.code = "field_locked";
          err.field = path;
          throw err;
        }
        const removed = await client.query(
          `DELETE FROM sso_provider_secrets
            WHERE provider_id = $1 AND secret_name = $2`,
          [row.id, name],
        );
        if (removed.rowCount) opts.secretChanges?.cleared.push(name);
      }
    }
    if (!opts.skipVersionBump) {
      await bumpSsoConfigVersion(client);
    }
    const provider = opts.skipReturn ? null : await getProvider(client, slug);
    if (ownsClient) await client.query("COMMIT");
    return provider && attachSecretWarnings(provider, skippedSecrets);
  } catch (err) {
    if (ownsClient) await client.query("ROLLBACK");
    throw err;
  } finally {
    if (ownsClient) client.release();
  }
}

async function countDependencies(pool, slug) {
  const [identities, memberships, mappings, adminGrants] = await Promise.all([
    pool.query(
      `SELECT COUNT(*)::int AS c FROM external_identities WHERE provider_slug = $1`,
      [slug],
    ),
    pool.query(
      `SELECT COUNT(*)::int AS c FROM workspace_memberships
        WHERE source = 'sso' AND source_provider_slug = $1`,
      [slug],
    ),
    pool.query(
      `SELECT COUNT(*)::int AS c FROM sso_group_role_mappings WHERE provider_slug = $1`,
      [slug],
    ),
    pool.query(
      `SELECT COUNT(*)::int AS c FROM sso_system_admin_grants WHERE provider_slug = $1`,
      [slug],
    ),
  ]);
  return {
    identities_count: identities.rows[0]?.c || 0,
    memberships_count: memberships.rows[0]?.c || 0,
    group_mappings_count: mappings.rows[0]?.c || 0,
    admin_grants_count: adminGrants.rows[0]?.c || 0,
  };
}

/**
 * @param {import('pg').Pool} pool
 * @param {string} slug
 * @param {{ dbClient?: object }} [opts]
 */
async function deleteProvider(pool, slug, opts = {}) {
  const client = opts.dbClient || (await pool.connect());
  const ownsClient = !opts.dbClient;
  try {
    if (ownsClient) await client.query("BEGIN");
    await lockProviderChanges(client);
    const row = await getProviderRow(client, slug, { forUpdate: true });
    if (!row) throw providerChangeError("not_found", "Provider not found.");
    await assertProviderCanBeDisabled(client, row);
    const dependencies = await countDependencies(client, slug);
    const used = Object.values(dependencies).some((count) => count > 0);
    const { confirmRetirement, membershipPolicy, identityPolicy, userId } = opts;
    if ((membershipPolicy !== undefined && !["convert-to-manual", "delete"].includes(membershipPolicy)) ||
        (identityPolicy !== undefined && !["archive", "drop"].includes(identityPolicy))) {
      throw providerChangeError("invalid_retirement_policy", "Invalid provider retirement policy.");
    }
    if (used && (!confirmRetirement ||
        (dependencies.memberships_count > 0 && !membershipPolicy) ||
        (dependencies.identities_count > 0 && !identityPolicy))) {
      throw Object.assign(providerChangeError(
        "provider_in_use",
        "Review the provider dependencies and confirm how to retire them.",
      ), { dependencies });
    }
    if (used) {
      await lockSystemAdminMutation(client);
      await requireLocalAdmin(client);
    }
    if (dependencies.identities_count > 0 && identityPolicy === "archive") {
      await client.query(
        `INSERT INTO sso_deleted_external_identities_archive
           (provider_slug, provider_id, original_identity_id, user_id, subject_id,
            protocol, email_at_link, display_name_at_link, linked_at, deleted_by, delete_reason)
         SELECT provider_slug, $2, id, user_id, subject_id, protocol, email_at_link,
                display_name_at_link, linked_at, $3, 'provider_retired'
           FROM external_identities WHERE provider_slug = $1`,
        [slug, row.id, userId ?? null],
      );
    }
    if (dependencies.memberships_count > 0) {
      const sql = membershipPolicy === "convert-to-manual"
        ? "UPDATE workspace_memberships SET source = 'manual', source_provider_slug = NULL"
        : "DELETE FROM workspace_memberships";
      await client.query(sql + " WHERE source = 'sso' AND source_provider_slug = $1", [slug]);
    }
    if (dependencies.admin_grants_count > 0) {
      const { rows } = await client.query(
        "DELETE FROM sso_system_admin_grants WHERE provider_slug = $1 RETURNING user_id",
        [slug],
      );
      for (const grant of rows) await recomputeSystemAdmin(client, grant.user_id);
      // The retiring provider cannot be the source of the recovery account's admin rights.
      await requireLocalAdmin(client);
    }
    await client.query("DELETE FROM saml_request_cache WHERE provider_slug = $1", [slug]);
    await client.query("DELETE FROM sso_providers WHERE slug = $1", [slug]);
    await bumpSsoConfigVersion(client);
    if (ownsClient) await client.query("COMMIT");
    return { ok: true, dependencies };
  } catch (err) {
    if (ownsClient) await client.query("ROLLBACK");
    throw err;
  } finally {
    if (ownsClient) client.release();
  }
}

async function loadDecryptedSecret(pool, slug, secretName) {
  const row = await getProviderRow(pool, slug);
  if (!row) return null;
  const res = await pool.query(
    `SELECT encrypted_value FROM sso_provider_secrets
      WHERE provider_id = $1 AND secret_name = $2`,
    [row.id, secretName],
  );
  if (!res.rows.length) return null;
  const aad = secretAad(row.id, secretName);
  return decryptSecret(res.rows[0].encrypted_value, aad);
}

async function setProviderSecret(pool, slug, secretName, plaintext, meta = {}) {
  const row = await getProviderRow(pool, slug);
  if (!row) {
    const err = new Error("not_found");
    err.code = "not_found";
    throw err;
  }
  const locked = [
    ...new Set([
      ...(Array.isArray(row.locked_fields) ? row.locked_fields : []),
      ...detectEnvLockedFields(slug, row.type),
    ]),
  ];
  const path = `secrets.${secretName}`;
  if (firstLockedViolation(locked, [path])) {
    const err = new Error("field_locked");
    err.code = "field_locked";
    err.field = path;
    throw err;
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await upsertEncryptedSecret(client, row.id, secretName, plaintext, meta.userId);
    await bumpSsoConfigVersion(client);
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

async function clearProviderSecret(pool, slug, secretName) {
  await updateProvider(pool, slug, { clearSecrets: [secretName] }, {}, { skipReturn: true });
}

module.exports = {
  listProviders,
  getProvider,
  getProviderRow,
  lockProviderChanges,
  enabledProviderRows,
  conflictingProviderTypes,
  createProvider,
  updateProvider,
  deleteProvider,
  setProviderSecret,
  clearProviderSecret,
  loadDecryptedSecret,
  upsertEncryptedSecret,
  countDependencies,
  rowToProvider,
  SECRET_NAMES,
};

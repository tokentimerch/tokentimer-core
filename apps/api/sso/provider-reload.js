"use strict";

const { isProviderReloadAcceptable } = require("./sso-config-apply.js");
const {
  setProviderRuntimeStatus,
  probeProviderReadiness,
  providerRuntimeStatuses,
} = require("./sso-runtime-status.js");

async function listProviderRows(pool) {
  try {
    const res = await pool.query(
      `SELECT p.id, p.slug, p.type, p.enabled, p.config,
              COALESCE(
                (SELECT json_agg(s.secret_name)
                   FROM sso_provider_secrets s
                  WHERE s.provider_id = p.id),
                '[]'::json
              ) AS secret_names
         FROM sso_providers p`,
    );
    return res.rows.map((r) => ({
      ...r,
      secret_names: Array.isArray(r.secret_names)
        ? r.secret_names
        : r.secret_names
          ? JSON.parse(r.secret_names)
          : [],
    }));
  } catch (err) {
    if (err.code === "42P01") return [];
    throw err;
  }
}

/**
 * Reload runtime status for every provider row (Map diff on HA sync).
 * @param {import('pg').Pool} pool
 * @param {number} observedVersion
 * @returns {Promise<Record<string, { registered: boolean, reason?: string, applied?: boolean }>>}
 */
async function reloadAllProvidersFromRegistry(pool, observedVersion) {
  const rows = await listProviderRows(pool);
  const seen = new Set();
  const results = {};

  for (const row of rows) {
    seen.add(row.slug);
    const secretsSet = row.secret_names || [];
    const probe = probeProviderReadiness(row, secretsSet);
    const acceptable = isProviderReloadAcceptable(probe);
    setProviderRuntimeStatus(row.slug, {
      ...probe,
      type: row.type,
      appliedConfigVersion: acceptable ? observedVersion : null,
    });
    results[row.slug] = {
      registered: probe.registered,
      reason: probe.reason,
      applied: acceptable,
    };
  }

  for (const slug of [...providerRuntimeStatuses.keys()]) {
    if (!seen.has(slug)) {
      providerRuntimeStatuses.delete(slug);
    }
  }

  return results;
}

module.exports = {
  reloadAllProvidersFromRegistry,
  listProviderRows,
};

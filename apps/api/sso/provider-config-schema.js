"use strict";

const SLUG_RE = /^[a-z0-9][a-z0-9_-]{0,62}$/;

/**
 * @param {string} slug
 * @returns {{ ok: boolean, errors?: string[] }}
 */
function validateSlug(slug) {
  if (!SLUG_RE.test(String(slug || ""))) {
    return { ok: false, errors: ["invalid_slug"] };
  }
  return { ok: true };
}

/**
 * @param {'oidc'|'saml'} type
 * @param {object} config
 * @returns {{ ok: boolean, errors: string[] }}
 */
function validateProviderConfig(type, config) {
  const errors = [];
  const cfg = config && typeof config === "object" ? config : {};
  if (type === "oidc") {
    if (!cfg.issuer) errors.push("issuer_required");
    if (!cfg.client_id) errors.push("client_id_required");
  } else if (type === "saml") {
    if (!cfg.entry_point) errors.push("entry_point_required");
    if (!cfg.issuer) errors.push("issuer_required");
    if (!cfg.cert) errors.push("cert_required");
  } else {
    errors.push("invalid_type");
  }
  return { ok: errors.length === 0, errors };
}

/**
 * @param {object} security
 * @returns {object}
 */
function normalizeSecurity(security) {
  const s = security && typeof security === "object" ? { ...security } : {};
  if (s.pkce === undefined) s.pkce = true;
  // allow_auto_link_local_accounts / strict_membership_sync: undefined = inherit global
  return s;
}

function envPrefixFromSlug(slug) {
  return `SSO_${String(slug || "")
    .toUpperCase()
    .replace(/-/g, "_")}_`;
}

function detectSlugEnvCollisions(slugs) {
  const byPrefix = new Map();
  for (const slug of slugs) {
    const prefix = envPrefixFromSlug(slug);
    const existing = byPrefix.get(prefix);
    if (existing) {
      return { ok: false, code: "slug_env_collision", slugs: [existing, slug] };
    }
    byPrefix.set(prefix, slug);
  }
  return { ok: true };
}

module.exports = {
  SLUG_RE,
  validateSlug,
  validateProviderConfig,
  normalizeSecurity,
  envPrefixFromSlug,
  detectSlugEnvCollisions,
};

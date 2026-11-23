"use strict";

const {
  evaluateLoginReachability,
  hasUsableLocalAdmin,
} = require("./login-reachability.js");
const {
  getProviderRuntimeStatus,
  deriveSignInReady,
} = require("./sso-runtime-status.js");
const { countDependencies } = require("./provider-registry.js");
const { buildComputedUrls } = require("./sso-computed-urls.js");

async function getProviderRowLocal(pool, slug) {
  const res = await pool.query(
    `SELECT id, slug, type, display_name, enabled, sort_order, config,
            claim_mapping, security, locked_fields
       FROM sso_providers WHERE slug = $1`,
    [slug],
  );
  return res.rows[0] || null;
}

/**
 * @param {import('pg').Pool} pool
 * @param {string} slug
 * @param {object} proposed
 */
async function previewProviderChangeImpact(pool, slug, proposed, { localAuthEnabled = true } = {}) {
  const existing = await getProviderRowLocal(pool, slug);
  if (!existing) {
    const err = new Error("not_found");
    err.code = "not_found";
    throw err;
  }

  const merged = {
    ...existing,
    enabled:
      proposed.enabled !== undefined ? proposed.enabled : existing.enabled,
    config: proposed.config
      ? { ...existing.config, ...proposed.config }
      : existing.config,
    security: proposed.security
      ? { ...existing.security, ...proposed.security }
      : existing.security,
  };

  const impact = {
    slug,
    affected_users: 0,
    linked_identities_count: 0,
    is_last_login_method: false,
    runtime_breakage_likely: false,
    signInReady_after: false,
    memberships_at_risk: 0,
    admins_added: 0,
    users_who_would_no_longer_match_admin_mapping: 0,
  };

  const idRes = await pool.query(
    `SELECT COUNT(DISTINCT user_id)::int AS users,
            COUNT(*)::int AS links
       FROM external_identities
      WHERE provider_slug = $1`,
    [slug],
  );
  impact.linked_identities_count = idRes.rows[0]?.links || 0;
  impact.affected_users = idRes.rows[0]?.users || 0;

  const disabling =
    proposed.enabled === false ||
    proposed.delete === true ||
    proposed.clearSecrets?.length > 0;
  if (disabling || proposed.enabled === false) {
    const reach = await evaluateLoginReachability(pool, {
      changingSlug: slug,
      localAuthEnabled,
      getRuntimeStatus: (s) => {
        if (s === slug) {
          return { signInReady: false };
        }
        return getProviderRuntimeStatus(s);
      },
    });
    impact.is_last_login_method = reach.wouldLockOut;
  }

  const runtimeBefore = deriveSignInReady(existing, getProviderRuntimeStatus(slug));
  const runtimeAfter = deriveSignInReady(merged, {
    ...getProviderRuntimeStatus(slug),
    registered: merged.enabled && runtimeBefore,
  });
  impact.signInReady_after = !!runtimeAfter;

  const computedBefore = buildComputedUrls(existing);
  const computedAfter = buildComputedUrls(merged);
  if (
    proposed.config?.issuer ||
    proposed.config?.callback_url ||
    proposed.clearSecrets?.length
  ) {
    impact.runtime_breakage_likely =
      computedBefore.callback_url !== computedAfter.callback_url ||
      !!proposed.clearSecrets?.length ||
      proposed.config?.issuer !== undefined;
    if (impact.runtime_breakage_likely) {
      impact.signInReady_after = false;
    }
  }

  if (proposed.delete === true) {
    impact.dependency_counts = await countDependencies(pool, slug);
    impact.memberships_at_risk = impact.dependency_counts.memberships_count;
    impact.requires_local_admin = Object.values(impact.dependency_counts).some((count) => count > 0);
    impact.has_usable_local_admin = localAuthEnabled && await hasUsableLocalAdmin(pool, { retiringSlug: slug });
    impact.is_last_login_method = impact.requires_local_admin ? !impact.has_usable_local_admin : impact.is_last_login_method;
    impact.signInReady_after = false;
  } else {
    const { resolveProviderSecurityConfig } = require("./sso-global-settings.js");
    const effectiveStrict = resolveProviderSecurityConfig({
      security: merged.security,
    }).strictMembershipSync;
    if (effectiveStrict) {
      const m = await pool.query(
        `SELECT COUNT(*)::int AS c FROM workspace_memberships
          WHERE source = 'sso' AND source_provider_slug = $1`,
        [slug],
      );
      impact.memberships_at_risk = m.rows[0]?.c || 0;
    }
  }

  return impact;
}

module.exports = {
  previewProviderChangeImpact,
};

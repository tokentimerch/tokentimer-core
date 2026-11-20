"use strict";

/**
 * @param {import('pg').Pool | import('pg').PoolClient} db
 * @param {string} providerSlug
 */
async function loadConfiguredAdminIdpGroups(db, providerSlug) {
  const slug = String(providerSlug || "").trim();
  if (!slug) return [];
  const { rows } = await db.query(
    `SELECT idp_group
       FROM sso_group_role_mappings
      WHERE provider_slug = $1
        AND role = 'admin'
        AND workspace_id IS NULL
      ORDER BY LOWER(idp_group)`,
    [slug],
  );
  return rows.map((row) => row.idp_group);
}

/**
 * @param {object} args
 */
function buildSsoLoginSuccessMetadata({
  method,
  providerSlug,
  protocol,
  issuer,
  resolved,
  resolution,
  applied,
  userAfterLogin,
  subjectId,
  idpGroups,
  configuredAdminIdpGroups,
}) {
  const meta = {
    method,
    provider_slug: providerSlug,
    protocol,
    new_user: resolved.isNewUser,
    link_created: resolved.isNewLink,
    previous_auth_method: resolved.authMethodBefore,
    subject_id: subjectId || null,
    idp_groups_seen: idpGroups.length,
    idp_groups_sample: idpGroups.slice(0, 20),
    matched_groups: resolution.matchedGroups,
    matched_groups_count: resolution.matchedGroups.length,
    is_admin_resolved: resolution.isAdmin === true,
    effective_system_admin: resolution.effectiveSystemAdmin === true,
    is_admin_after_login: userAfterLogin?.is_admin === true,
    admin_granted: applied.adminGranted,
    admin_mapping_matched: resolution.isAdmin === true,
    configured_admin_idp_groups: configuredAdminIdpGroups || [],
    workspace_grants_count: applied.workspaceGrantsApplied,
    workspace_revocations_count: applied.workspaceRevocationsApplied,
  };
  if (issuer) meta.issuer = issuer;
  return meta;
}

module.exports = {
  loadConfiguredAdminIdpGroups,
  buildSsoLoginSuccessMetadata,
};

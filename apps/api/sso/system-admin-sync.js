"use strict";

const {
  ensureSystemAdminWorkspaceAccess: coreEnsure,
  lockSystemAdminMutation,
} = require("../services/systemAdmin.js");

/**
 * Whether the user should receive all-workspace workspace_manager access.
 * Covers manual system admins and durable SSO admin grants.
 */
async function hasPersistentSystemAdminAccess(db, userId) {
  const { rows } = await db.query(
    `SELECT 1
       FROM users u
      WHERE u.id = $1
        AND (
          u.is_admin_manual = TRUE
          OR EXISTS (
            SELECT 1
              FROM sso_system_admin_grants g
             WHERE g.user_id = u.id
          )
        )
      LIMIT 1`,
    [userId],
  );
  return rows.length > 0;
}

async function ensureSystemAdminWorkspaceAccess(db, userId) {
  const result = await coreEnsure(db, userId);
  if (result.applied === 0) {
    return result;
  }

  // Track membership provenance for strict SSO sync.
  await db.query(
    `UPDATE workspace_memberships
        SET source = CASE
              WHEN source = 'sso' THEN source
              ELSE 'manual'
            END,
            source_provider_slug = CASE
              WHEN source = 'sso' THEN source_provider_slug
              ELSE NULL
            END
      WHERE user_id = $1
        AND role = 'workspace_manager'`,
    [userId],
  );
  return result;
}

/**
 * Recompute users.is_admin from manual flag + durable SSO grant rows.
 */
async function recomputeSystemAdmin(client, userId) {
  const { rows } = await client.query(
    `UPDATE users
        SET is_admin = (
              is_admin_manual
              OR EXISTS (
                SELECT 1
                  FROM sso_system_admin_grants g
                 WHERE g.user_id = users.id
              )
            ),
            updated_at = NOW()
      WHERE id = $1
      RETURNING id, is_admin, is_admin_manual`,
    [userId],
  );
  return rows[0] || null;
}

/**
 * Grant-only SSO system-admin sync.
 * Matching an admin mapping inserts a durable grant and promotes is_admin.
 * Non-matching logins are a no-op; demotion is manual via Workspaces.
 *
 * @returns {{ adminGranted: boolean, adminRevoked: boolean, skippedLastAdmin: boolean }}
 */
async function syncSsoSystemAdminGrant(
  client,
  { userId, providerSlug, grant, recompute = false },
) {
  const slug = String(providerSlug || "").trim();
  if (!slug) {
    throw new Error("system-admin-sync: providerSlug is required");
  }

  if (!grant && !recompute) {
    return {
      adminGranted: false,
      adminRevoked: false,
      skippedLastAdmin: false,
      isAdmin: false,
    };
  }

  const before = await client.query(
    "SELECT is_admin FROM users WHERE id = $1",
    [userId],
  );

  if (grant) {
    await client.query(
      `INSERT INTO sso_system_admin_grants (user_id, provider_slug)
       VALUES ($1, $2)
       ON CONFLICT (user_id, provider_slug) DO NOTHING`,
      [userId, slug],
    );
    await client.query(
      `UPDATE users
          SET is_admin = TRUE,
              updated_at = NOW()
        WHERE id = $1`,
      [userId],
    );
  }

  const after = await recomputeSystemAdmin(client, userId);
  const isAdmin = after?.is_admin === true;
  return {
    adminGranted: before.rows[0]?.is_admin !== true && isAdmin,
    adminRevoked: false,
    skippedLastAdmin: false,
    isAdmin,
  };
}

/**
 * Manual system-admin toggle from Workspaces UI / PATCH API.
 */
async function applyManualSystemAdmin(client, { userId, isAdminManual }) {
  await lockSystemAdminMutation(client);

  if (isAdminManual === false) {
    await client.query(
      `DELETE FROM sso_system_admin_grants WHERE user_id = $1`,
      [userId],
    );
  }
  await client.query(
    `UPDATE users
        SET is_admin_manual = $2,
            updated_at = NOW()
      WHERE id = $1`,
    [userId, isAdminManual === true],
  );
  const updated = await recomputeSystemAdmin(client, userId);
  if (isAdminManual === true) {
    await ensureSystemAdminWorkspaceAccess(client, userId);
  }
  return updated;
}

module.exports = {
  hasPersistentSystemAdminAccess,
  ensureSystemAdminWorkspaceAccess,
  recomputeSystemAdmin,
  syncSsoSystemAdminGrant,
  applyManualSystemAdmin,
};

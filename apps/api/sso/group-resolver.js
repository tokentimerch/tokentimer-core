"use strict";

/**
 * Resolve SSO role bindings from `sso_group_role_mappings` keyed by provider_slug.
 */

const { syncSsoSystemAdminGrant, hasPersistentSystemAdminAccess, ensureSystemAdminWorkspaceAccess } = require("./system-admin-sync");

const ROLE_RANK = {
  admin: 3,
  workspace_manager: 2,
  viewer: 1,
};

function pickHighest(a, b) {
  if (!a) return b;
  if (!b) return a;
  return ROLE_RANK[a] >= ROLE_RANK[b] ? a : b;
}

function normalise(value) {
  return String(value || "").trim().toLowerCase();
}

/**
 * @param {object} args
 * @param {object} args.pool
 * @param {string} args.providerSlug
 * @param {number} args.userId
 * @param {string[]} args.idpGroups
 * @param {boolean} [args.strictSync]
 * @param {string[]} [args.bootstrapAdminGroups]
 */
async function resolveSsoBindings({
  pool,
  providerSlug,
  userId,
  idpGroups,
  strictSync = false,
  bootstrapAdminGroups = [],
}) {
  if (!providerSlug || typeof providerSlug !== "string") {
    throw new Error("group-resolver: providerSlug is required");
  }
  const slug = providerSlug;

  const groupSet = new Set(
    (idpGroups || []).map(normalise).filter((g) => g.length > 0),
  );
  const matchedGroups = [];
  let isAdmin = false;

  const bootstrapSet = new Set(
    (bootstrapAdminGroups || []).map(normalise).filter(Boolean),
  );
  if (bootstrapSet.size > 0) {
    for (const g of groupSet) {
      if (bootstrapSet.has(g)) {
        isAdmin = true;
        matchedGroups.push(g);
      }
    }
  }

  const grantsByWorkspace = new Map();
  const globalNonAdminRoles = [];
  if (groupSet.size > 0) {
    const groupArray = Array.from(groupSet);
    const { rows } = await pool.query(
      `SELECT id, provider_slug, idp_group, role, workspace_id
         FROM sso_group_role_mappings
        WHERE provider_slug = $1
          AND LOWER(idp_group) = ANY ($2::text[])`,
      [slug, groupArray],
    );
    for (const row of rows) {
      matchedGroups.push(normalise(row.idp_group));
      if (row.role === "admin" && row.workspace_id === null) {
        isAdmin = true;
        continue;
      }
      if (row.workspace_id === null) {
        globalNonAdminRoles.push(row.role);
        continue;
      }
      const existing = grantsByWorkspace.get(row.workspace_id);
      grantsByWorkspace.set(row.workspace_id, pickHighest(existing, row.role));
    }
  }

  let effectiveSystemAdmin = isAdmin;
  if (!isAdmin && userId) {
    effectiveSystemAdmin = await hasPersistentSystemAdminAccess(pool, userId);
  }

  let allWorkspaces = null;
  async function loadAllWorkspaces() {
    if (!allWorkspaces) {
      const { rows } = await pool.query("SELECT id FROM workspaces");
      allWorkspaces = rows;
    }
    return allWorkspaces;
  }

  if (globalNonAdminRoles.length > 0) {
    let bestGlobalRole = null;
    for (const role of globalNonAdminRoles) {
      bestGlobalRole = pickHighest(bestGlobalRole, role);
    }
    for (const { id } of await loadAllWorkspaces()) {
      const existing = grantsByWorkspace.get(id);
      grantsByWorkspace.set(id, pickHighest(existing, bestGlobalRole));
    }
  }

  // System admins need workspace_manager on every existing workspace so they
  // can use the dashboard and manage tokens without a separate global mapping.
  // Manual system admins and durable SSO admin grants count even when the
  // current login no longer matches an admin mapping (grant-only SSO model).
  if (effectiveSystemAdmin) {
    for (const { id } of await loadAllWorkspaces()) {
      const existing = grantsByWorkspace.get(id);
      grantsByWorkspace.set(id, pickHighest(existing, "workspace_manager"));
    }
  }

  const workspaceGrants = Array.from(grantsByWorkspace.entries()).map(
    ([workspace_id, role]) => ({ workspace_id, role }),
  );

  let revoked = [];
  if (strictSync) {
    const { rows: existingSso } = await pool.query(
      `SELECT workspace_id
         FROM workspace_memberships
        WHERE user_id = $1
          AND source = 'sso'
          AND source_provider_slug = $2`,
      [userId, slug],
    );
    const granted = new Set(workspaceGrants.map((g) => g.workspace_id));
    for (const r of existingSso) {
      if (!granted.has(r.workspace_id)) {
        revoked.push({ workspace_id: r.workspace_id });
      }
    }
  }

  return {
    isAdmin,
    effectiveSystemAdmin,
    workspaceGrants,
    revoked,
    matchedGroups: Array.from(new Set(matchedGroups)),
  };
}

/**
 * Mirrors Core's own `ensureInitialWorkspaceForUser` gating query, so the
 * strict-membership-sync deny-on-no-match path is exactly consistent with
 * whether that function would otherwise auto-join the user into the Default
 * workspace.
 *
 * @param {import('pg').Pool} pool
 * @param {number} userId
 * @returns {Promise<boolean>}
 */
async function hasAnyWorkspaceMembership(pool, userId) {
  const { rows } = await pool.query(
    `SELECT 1 FROM workspace_memberships WHERE user_id = $1 LIMIT 1`,
    [userId],
  );
  return rows.length > 0;
}

/**
 * @param {object} args
 * @param {string} args.providerSlug
 */
async function applyResolution({
  pool,
  userId,
  providerSlug,
  resolution,
  matchedGroups,
  writeAudit,
  logger,
}) {
  const slug = providerSlug;
  if (!slug || typeof slug !== "string") {
    throw new Error("group-resolver: providerSlug is required");
  }
  if (!resolution) {
    return {
      adminGranted: false,
      adminRevoked: false,
      adminRevokeSkippedLastAdmin: false,
      workspaceGrantsApplied: 0,
      workspaceRevocationsApplied: 0,
    };
  }
  let adminGranted;
  let adminRevoked;
  let adminRevokeSkippedLastAdmin;
  let promotedSystemAdmin;
  const appliedGrants = [];
  const appliedRevocations = [];

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const activeProvider = await client.query(
      "SELECT 1 FROM sso_providers WHERE slug = $1 AND enabled FOR SHARE",
      [slug],
    );
    if (!activeProvider.rows.length) throw new Error("SSO provider was disabled during sign-in");

    const adminSync = await syncSsoSystemAdminGrant(client, {
      userId,
      providerSlug: slug,
      grant: resolution.isAdmin === true,
      recompute: resolution.effectiveSystemAdmin === true,
    });
    adminGranted = adminSync.adminGranted;
    adminRevoked = adminSync.adminRevoked;
    adminRevokeSkippedLastAdmin = adminSync.skippedLastAdmin;
    promotedSystemAdmin = adminSync.isAdmin === true;

    if (resolution.workspaceGrants.length > 0) {
      const wsIds = resolution.workspaceGrants.map((g) => g.workspace_id);
      const roles = resolution.workspaceGrants.map((g) => g.role);
      const grantQuery = await client.query(
        `INSERT INTO workspace_memberships
           (user_id, workspace_id, role, invited_by, source, source_provider_slug)
         SELECT $1::int, t.ws_id::uuid, t.role, NULL, 'sso', $4::text
           FROM UNNEST($2::text[], $3::text[]) AS t(ws_id, role)
         ON CONFLICT (user_id, workspace_id) DO UPDATE
           SET role = EXCLUDED.role,
               source = 'sso',
               source_provider_slug = EXCLUDED.source_provider_slug
           WHERE (
             workspace_memberships.source = 'sso'
             AND workspace_memberships.source_provider_slug = $4
             AND workspace_memberships.role IS DISTINCT FROM EXCLUDED.role
           )
         RETURNING workspace_id, role AS new_role, xmax = 0 AS inserted`,
        [userId, wsIds, roles, slug],
      );
      for (const row of grantQuery.rows) {
        appliedGrants.push({
          workspace_id: row.workspace_id,
          role: row.new_role,
          change: row.inserted ? "created" : "role_changed",
        });
      }
    }

    if (resolution.revoked.length > 0) {
      const revokeIds = resolution.revoked.map((r) => r.workspace_id);
      const del = await client.query(
        `DELETE FROM workspace_memberships
          WHERE user_id = $1
            AND source = 'sso'
            AND source_provider_slug = $2
            AND workspace_id = ANY($3::uuid[])
          RETURNING workspace_id, role AS previous_role`,
        [userId, slug, revokeIds],
      );
      for (const row of del.rows) {
        appliedRevocations.push({
          workspace_id: row.workspace_id,
          previous_role: row.previous_role,
        });
      }
    }

    if (promotedSystemAdmin) await ensureSystemAdminWorkspaceAccess(client, userId);
    await client.query("COMMIT");
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch (_) {
      // ignore rollback errors
    }
    throw err;
  } finally {
    client.release();
  }

  if (typeof writeAudit === "function") {
    const safe = async (params) => {
      try {
        await writeAudit(params);
      } catch (e) {
        logger?.warn?.("Audit write failed (MEMBERSHIP_SYNCED_FROM_SSO)", {
          error: e?.message,
        });
      }
    };
    if (adminGranted) {
      await safe({
        actorUserId: null,
        subjectUserId: userId,
        action: "MEMBERSHIP_SYNCED_FROM_SSO",
        targetType: "user",
        targetId: userId,
        channel: null,
        workspaceId: null,
        metadata: {
          provider_slug: slug,
          change: "admin_granted",
          matched_groups: matchedGroups || [],
        },
      });
    }
    if (adminRevoked) {
      await safe({
        actorUserId: null,
        subjectUserId: userId,
        action: "MEMBERSHIP_SYNCED_FROM_SSO",
        targetType: "user",
        targetId: userId,
        channel: null,
        workspaceId: null,
        metadata: {
          provider_slug: slug,
          change: "admin_revoked",
          matched_groups: matchedGroups || [],
        },
      });
    }
    for (const grant of appliedGrants) {
      await safe({
        actorUserId: null,
        subjectUserId: userId,
        action: "MEMBERSHIP_SYNCED_FROM_SSO",
        targetType: "workspace_membership",
        targetId: null,
        channel: null,
        workspaceId: grant.workspace_id,
        metadata: {
          provider_slug: slug,
          change: grant.change,
          role: grant.role,
          matched_groups: matchedGroups || [],
        },
      });
    }
    for (const r of appliedRevocations) {
      await safe({
        actorUserId: null,
        subjectUserId: userId,
        action: "MEMBERSHIP_SYNCED_FROM_SSO",
        targetType: "workspace_membership",
        targetId: null,
        channel: null,
        workspaceId: r.workspace_id,
        metadata: {
          provider_slug: slug,
          change: "revoked",
          previous_role: r.previous_role,
          reason: "strict_membership_sync",
        },
      });
    }
  }

  return {
    adminGranted,
    adminRevoked,
    adminRevokeSkippedLastAdmin,
    workspaceGrantsApplied: appliedGrants.length,
    workspaceRevocationsApplied: appliedRevocations.length,
  };
}

module.exports = {
  resolveSsoBindings,
  applyResolution,
  hasAnyWorkspaceMembership,
  ROLE_RANK,
  pickHighest,
};

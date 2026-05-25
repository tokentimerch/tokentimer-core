"use strict";

/** Postgres advisory lock key for system-admin mutations (TTSA). */
const SYSTEM_ADMIN_LOCK_KEY = 0x5454_5341;

/** SQL predicate for a live system administrator (excludes GDPR tombstones). */
const ACTIVE_SYSTEM_ADMIN_WHERE = `
  is_admin = TRUE
  AND email NOT LIKE '%@example.invalid'
  AND display_name IS DISTINCT FROM 'Deleted Account'
`;

function isActiveSystemAdminRow(row) {
  if (!row || row.is_admin !== true) return false;
  const email = String(row.email || "");
  if (email.endsWith("@example.invalid")) return false;
  if (row.display_name === "Deleted Account") return false;
  return true;
}

async function lockSystemAdminMutation(client) {
  await client.query("SELECT pg_advisory_xact_lock($1)", [SYSTEM_ADMIN_LOCK_KEY]);
}

async function countActiveSystemAdmins(queryable) {
  const { rows } = await queryable.query(
    `SELECT COUNT(*)::int AS c FROM users WHERE ${ACTIVE_SYSTEM_ADMIN_WHERE}`,
  );
  return rows[0]?.c || 0;
}

async function countOtherActiveSystemAdmins(queryable, userId) {
  const { rows } = await queryable.query(
    `SELECT COUNT(*)::int AS c FROM users WHERE id <> $1 AND ${ACTIVE_SYSTEM_ADMIN_WHERE}`,
    [userId],
  );
  return rows[0]?.c || 0;
}

/**
 * Grant workspace_manager on every workspace for installation system admins.
 * On conflict, upgrades viewer to workspace_manager only. Existing workspace
 * admin memberships are preserved. Inserts workspace_manager where missing.
 *
 * @returns {{ applied: number }}
 */
async function ensureSystemAdminWorkspaceAccess(db, userId) {
  const { rows: adminRows } = await db.query(
    "SELECT is_admin FROM users WHERE id = $1 LIMIT 1",
    [userId],
  );
  if (adminRows.length === 0 || adminRows[0].is_admin !== true) {
    return { applied: 0 };
  }

  const result = await db.query(
    `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
     SELECT $1::int, w.id, 'workspace_manager', NULL
       FROM workspaces w
     ON CONFLICT (user_id, workspace_id) DO UPDATE
       SET role = CASE
             WHEN workspace_memberships.role = 'viewer'
               THEN 'workspace_manager'
             ELSE workspace_memberships.role
           END
     RETURNING workspace_id`,
    [userId],
  );
  return { applied: result.rowCount || 0 };
}

module.exports = {
  SYSTEM_ADMIN_LOCK_KEY,
  ACTIVE_SYSTEM_ADMIN_WHERE,
  isActiveSystemAdminRow,
  lockSystemAdminMutation,
  countActiveSystemAdmins,
  countOtherActiveSystemAdmins,
  ensureSystemAdminWorkspaceAccess,
};

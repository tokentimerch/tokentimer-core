"use strict";

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

module.exports = {
  ACTIVE_SYSTEM_ADMIN_WHERE,
  isActiveSystemAdminRow,
  countActiveSystemAdmins,
  countOtherActiveSystemAdmins,
};

"use strict";

/**
 * Resolve users.id values to the label operators already see on Audit
 * (display_name, email if that is empty). Used so job approval attribution
 * does not have to show a bare numeric user id.
 */

function normalizeUserId(value) {
  if (value === undefined || value === null || value === "") return null;
  const asNumber = Number(value);
  if (Number.isInteger(asNumber) && asNumber > 0) return asNumber;
  return null;
}

function labelFromUserRow(row) {
  const displayName =
    typeof row?.display_name === "string" ? row.display_name.trim() : "";
  if (displayName) return displayName;
  const email = typeof row?.email === "string" ? row.email.trim() : "";
  return email || null;
}

function displayNameForUserId(names, userId) {
  const id = normalizeUserId(userId);
  if (id == null || !names) return null;
  return names.get(id) ?? null;
}

async function lookupUserDisplayNames(db, userIds) {
  const ids = [
    ...new Set((userIds || []).map(normalizeUserId).filter((id) => id != null)),
  ];
  const names = new Map();
  if (ids.length === 0 || !db?.query) return names;

  const result = await db.query(
    `SELECT id, display_name, email
       FROM users
      WHERE id = ANY($1::int[])`,
    [ids],
  );
  for (const row of result.rows || []) {
    const id = normalizeUserId(row.id);
    const label = labelFromUserRow(row);
    if (id != null && label) names.set(id, label);
  }
  return names;
}

async function attachUserDisplayNames({ db, records, idKey, nameKey }) {
  const list = Array.isArray(records) ? records : [];
  const names = await lookupUserDisplayNames(
    db,
    list.map((record) => record?.[idKey]),
  );
  return list.map((record) => ({
    ...record,
    [nameKey]: displayNameForUserId(names, record?.[idKey]),
  }));
}

module.exports = {
  attachUserDisplayNames,
  displayNameForUserId,
  lookupUserDisplayNames,
  _test: {
    labelFromUserRow,
    normalizeUserId,
  },
};

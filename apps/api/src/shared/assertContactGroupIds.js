"use strict";

const { normalizeAssignedGroupIds } = require("./contactGroups");

function invalidContactGroupError() {
  const err = new Error("Invalid contact_group_id for workspace");
  err.code = "VALIDATION_ERROR";
  return err;
}

async function assertContactGroupIds(client, workspaceId, ids) {
  const normalized = normalizeAssignedGroupIds(ids);
  if (normalized.length === 0) return;

  const res = await client.query(
    "SELECT contact_groups FROM workspace_settings WHERE workspace_id = $1",
    [workspaceId],
  );
  const row = res.rows && res.rows[0];
  if (!row) {
    throw invalidContactGroupError();
  }

  const groups = Array.isArray(row.contact_groups) ? row.contact_groups : [];
  const known = new Set(
    groups.filter((group) => group && group.id != null).map((group) => String(group.id)),
  );
  for (const id of normalized) {
    if (!known.has(id)) {
      throw invalidContactGroupError();
    }
  }
}

module.exports = { assertContactGroupIds };

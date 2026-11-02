"use strict";

// Modern assets have an authoritative workspace. Legacy routing prefers an
// owner's workspace, then admin/manager membership, as discovery already does.
// Multiple candidates at the preferred level are ambiguous: never guess a
// tenant or persist an ownership/RBAC change just to deliver a notification.
function resolvedTokenWorkspaceSql(tokenAlias) {
  return `COALESCE(${tokenAlias}.workspace_id, CASE
    WHEN EXISTS (SELECT 1 FROM workspaces legacy_owned WHERE legacy_owned.created_by = ${tokenAlias}.user_id)
    THEN (SELECT CASE WHEN COUNT(*) = 1 THEN (array_agg(legacy_owned.id))[1] END
      FROM workspaces legacy_owned WHERE legacy_owned.created_by = ${tokenAlias}.user_id)
    ELSE (SELECT CASE WHEN COUNT(*) = 1 THEN (array_agg(legacy_member.id))[1] END
      FROM workspaces legacy_member JOIN workspace_memberships legacy_membership
        ON legacy_membership.workspace_id = legacy_member.id
      WHERE legacy_membership.user_id = ${tokenAlias}.user_id
        AND legacy_membership.role IN ('admin','workspace_manager')) END)`;
}

module.exports = { resolvedTokenWorkspaceSql };

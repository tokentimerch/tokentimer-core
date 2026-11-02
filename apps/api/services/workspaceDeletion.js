"use strict";

// Distribution tables reference each other and certificate_jobs with plain
// composite foreign keys and no cascade from workspaces. A bare
// DELETE FROM workspaces therefore fails once a workspace has published
// material, so the leaves go first and the group back-reference is cleared.
async function deleteWorkspaces(client, workspaceIds) {
  const ids = [...new Set(workspaceIds || [])].filter(Boolean);
  if (ids.length === 0) return 0;
  const scope = "workspace_id = ANY($1::uuid[])";
  for (const table of [
    "certops_consumer_current_state",
    "certops_consumer_deployments",
    "certops_distribution_rollouts",
    "certops_consumer_bindings",
  ]) {
    await client.query(`DELETE FROM ${table} WHERE ${scope}`, [ids]);
  }
  await client.query(
    `UPDATE certops_distribution_groups SET latest_material_version_id = NULL
      WHERE ${scope} AND latest_material_version_id IS NOT NULL`,
    [ids],
  );
  await client.query(`DELETE FROM certops_material_versions WHERE ${scope}`, [
    ids,
  ]);
  await client.query(
    "DELETE FROM certops_distribution_groups WHERE workspace_id = ANY($1::uuid[])",
    [ids],
  );
  const res = await client.query(
    "DELETE FROM workspaces WHERE id = ANY($1::uuid[])",
    [ids],
  );
  return res.rowCount;
}

module.exports = { deleteWorkspaces };

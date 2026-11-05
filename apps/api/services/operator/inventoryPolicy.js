"use strict";

// Edition seam: hosted imports add their normal plan/freeze/quota checks.
async function assertInventoryImportAllowed({ client, workspaceId, actorLocks }) {
  const result = await client.query("SELECT id,created_by FROM workspaces WHERE id = $1 FOR SHARE", [workspaceId]);
  if (!result.rowCount) throw Object.assign(new Error("Workspace unavailable"), { code: "NOT_FOUND" });
  if (String(result.rows[0].created_by) !== String(actorLocks.workspaceOwnerId)) throw Object.assign(new Error("Workspace ownership changed; preview again"), { code: "OPERATOR_INTENT_STALE" });
}
module.exports = { assertInventoryImportAllowed, AUTO_SYNC_PROJECTION: "auto_sync_managed" };

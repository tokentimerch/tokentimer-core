"use strict";

const { lockConnectionAuthority } = require("./connections");

// Approval and fresh dispatch use the same live delegated authority as submit.
// Claim already owns the job row, so it skips busy authority rows rather than
// waiting in the reverse order of revocation (connection before jobs).
async function lockOperatorJobAuthority({ client, connectionId, workspaceId, requesterUserId, operation, skipLocked = false, requireWriteGates = false }) {
  if (!connectionId) return true;
  const result = await lockConnectionAuthority({ client, connectionId, skipLocked });
  // Without a human approval, admission remains conditional on MCP writes.
  // Claim owns the job row: skip a busy workspace instead of reversing the
  // write-disable lock order (workspace before cancellation of queued jobs).
  if (requireWriteGates) {
    if (String(process.env.MCP_OPERATOR_INTERFACE_ENABLED).toLowerCase() !== "true" ||
        String(process.env.MCP_OPERATOR_WRITES_ENABLED).toLowerCase() !== "true") return false;
    const workspace = await client.query(
      `SELECT operator_writes_enabled FROM workspaces WHERE id = $1 FOR SHARE${skipLocked ? " SKIP LOCKED" : ""}`,
      [workspaceId],
    );
    if (workspace.rows[0]?.operator_writes_enabled !== true) return false;
  }
  return Boolean(result.valid && result.connection.workspaceId === workspaceId &&
    String(result.connection.userId) === String(requesterUserId) &&
    operation === "renew" && result.authority.scopes.includes("mcp:renew:request"));
}

module.exports = { lockOperatorJobAuthority };

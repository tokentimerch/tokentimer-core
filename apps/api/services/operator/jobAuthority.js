"use strict";

const { lockConnectionAuthority } = require("./connections");

// Approval and fresh dispatch use the same live delegated authority as submit.
// Claim already owns the job row, so it skips busy authority rows rather than
// waiting in the reverse order of revocation (connection before jobs).
async function lockOperatorJobAuthority({ client, connectionId, workspaceId, requesterUserId, operation, skipLocked = false, requireWriteGates = false }) {
  if (!connectionId) return true;
  const policy = {
    renew: { scope: "mcp:renew:request", setting: "operator_writes_enabled" },
    issue: { scope: "mcp:issue:request", setting: "operator_issuance_enabled" },
  }[operation];
  if (!policy) return false;
  const result = await lockConnectionAuthority({ client, connectionId, skipLocked });
  // Without a human approval, admission remains conditional on MCP writes.
  // Claim owns the job row: skip a busy workspace instead of reversing the
  // write-disable lock order (workspace before cancellation of queued jobs).
  if (requireWriteGates) {
    if (String(process.env.MCP_OPERATOR_INTERFACE_ENABLED || "").trim().toLowerCase() !== "true" ||
        String(process.env.MCP_OPERATOR_WRITES_ENABLED || "").trim().toLowerCase() !== "true") return false;
    const workspace = await client.query(
      `SELECT ${policy.setting} AS enabled FROM workspaces WHERE id = $1 FOR SHARE${skipLocked ? " SKIP LOCKED" : ""}`,
      [workspaceId],
    );
    if (workspace.rows[0]?.enabled !== true) return false;
  }
  return Boolean(result.valid && result.connection.workspaceId === workspaceId &&
    String(result.connection.userId) === String(requesterUserId) &&
    result.authority.scopes.includes(policy.scope));
}

module.exports = { lockOperatorJobAuthority };

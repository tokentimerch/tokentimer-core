"use strict";

const { lockConnectionAuthority } = require("./connections");

// Approval and fresh dispatch use the same live delegated authority as submit.
// Claim already owns the job row, so it skips busy authority rows rather than
// waiting in the reverse order of revocation (connection before jobs).
async function lockOperatorJobAuthority({ client, connectionId, workspaceId, requesterUserId, operation, skipLocked = false }) {
  if (!connectionId) return true;
  const result = await lockConnectionAuthority({ client, connectionId, skipLocked });
  return Boolean(result.valid && result.connection.workspaceId === workspaceId &&
    String(result.connection.userId) === String(requesterUserId) &&
    operation === "renew" && result.authority.scopes.includes("mcp:renew:request"));
}

module.exports = { lockOperatorJobAuthority };

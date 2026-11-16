"use strict";

// The validated credential snapshot stays in process memory only. Rechecking it
// while holding the agent row lock prevents a request authenticated before an
// atomic credential replacement from mutating state afterwards.
const crypto = require("node:crypto");
const credentials = new WeakMap();
const CERTOPS_AGENT_CREDENTIAL_STALE = "CERTOPS_AGENT_CREDENTIAL_STALE";

function staleCredential() {
  const error = new Error("Agent credential no longer valid");
  error.code = CERTOPS_AGENT_CREDENTIAL_STALE;
  return error;
}

function bindAuthenticatedAgent(agent, hash) {
  if (!agent || typeof agent !== "object" || !agent.id || !agent.workspaceId || !agent.agentId ||
      typeof hash !== "string" || !/^[a-f0-9]{64}$/.test(hash)) {
    throw new Error("Invalid authenticated agent credential snapshot");
  }
  const digest = Buffer.from(hash, "hex");
  const previous = credentials.get(agent);
  if (previous) {
    if (agent.id !== previous.id || agent.workspaceId !== previous.workspaceId || agent.agentId !== previous.agentId ||
        !crypto.timingSafeEqual(previous.hash, digest)) throw staleCredential();
    return agent;
  }
  credentials.set(agent, { hash: digest, id: agent.id, workspaceId: agent.workspaceId, agentId: agent.agentId });
  return agent;
}

// The raw-token adapter shares the same object identity and snapshot.
function bindAuthenticatedCredential(agent, rawCredential) {
  if (typeof rawCredential !== "string" || !rawCredential) throw new Error("authenticated agent credential required");
  return bindAuthenticatedAgent(agent, crypto.createHash("sha256").update(rawCredential, "utf8").digest("hex"));
}

async function lockCurrentAgentCredential(client, agent) {
  const snapshot = agent && credentials.get(agent);
  if (!client || typeof client.query !== "function" || !snapshot || agent.id !== snapshot.id ||
      agent.workspaceId !== snapshot.workspaceId || agent.agentId !== snapshot.agentId) throw staleCredential();
  const result = await client.query(
    "SELECT credential_hash, status FROM certops_agents WHERE id = $1 AND workspace_id = $2 AND agent_id = $3 FOR UPDATE", [snapshot.id, snapshot.workspaceId, snapshot.agentId],
  );
  const current = result.rows[0]?.credential_hash;
  if (typeof current !== "string" || !/^[a-f0-9]{64}$/.test(current) ||
      !crypto.timingSafeEqual(snapshot.hash, Buffer.from(current, "hex"))) {
    throw staleCredential();
  }
  // Retirement retains normal-agent credentials for the frozen 410 response.
  // A request authenticated immediately before retirement must not mutate
  // state after the retirement transaction commits.
  if (result.rows[0].status === "retired") {
    const error = new Error("Agent is retired");
    error.code = "CERTOPS_AGENT_RETIRED";
    throw error;
  }
  if (!["active", "offline"].includes(result.rows[0].status)) {
    throw staleCredential();
  }
}

// Compatibility wrapper for callers using the named-argument interface.
async function assertCurrentAgentCredential(options) {
  return lockCurrentAgentCredential(options?.client, options?.agent);
}

module.exports = { bindAuthenticatedAgent, bindAuthenticatedCredential, lockCurrentAgentCredential, assertCurrentAgentCredential, CERTOPS_AGENT_CREDENTIAL_STALE };

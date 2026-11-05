"use strict";

// The validated credential snapshot stays in process memory only. Rechecking it
// while holding the agent row lock prevents a request authenticated before an
// atomic credential replacement from mutating state afterwards.
const crypto = require("node:crypto");
const credentials = new WeakMap();
const CERTOPS_AGENT_CREDENTIAL_STALE = "CERTOPS_AGENT_CREDENTIAL_STALE";

function bindAuthenticatedAgent(agent, hash) {
  if (!agent || typeof agent !== "object" || !/^[a-f0-9]{64}$/.test(hash)) {
    throw new Error("Invalid authenticated agent credential snapshot");
  }
  credentials.set(agent, Buffer.from(hash, "hex"));
  return agent;
}

async function lockCurrentAgentCredential(client, agent) {
  const snapshot = agent && credentials.get(agent);
  if (!snapshot || !agent.id) {
    const error = new Error("Agent credential no longer valid");
    error.code = CERTOPS_AGENT_CREDENTIAL_STALE;
    throw error;
  }
  const result = await client.query(
    "SELECT credential_hash, status FROM certops_agents WHERE id = $1 FOR UPDATE", [agent.id],
  );
  const current = result.rows[0]?.credential_hash;
  if (typeof current !== "string" || !/^[a-f0-9]{64}$/.test(current) ||
      !crypto.timingSafeEqual(snapshot, Buffer.from(current, "hex"))) {
    const error = new Error("Agent credential no longer valid");
    error.code = CERTOPS_AGENT_CREDENTIAL_STALE;
    throw error;
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
    const error = new Error("Agent credential no longer valid");
    error.code = CERTOPS_AGENT_CREDENTIAL_STALE;
    throw error;
  }
}

module.exports = { bindAuthenticatedAgent, lockCurrentAgentCredential, CERTOPS_AGENT_CREDENTIAL_STALE };

"use strict";
const crypto = require("node:crypto");
const AUTHENTICATED_CREDENTIAL_HASH = Symbol("authenticated agent credential hash");

function bindAuthenticatedCredential(agent, rawCredential) {
  if (!agent || typeof rawCredential !== "string" || !rawCredential) throw new Error("authenticated agent credential required");
  const bound = { ...agent };
  Object.defineProperty(bound, AUTHENTICATED_CREDENTIAL_HASH, {
    value: crypto.createHash("sha256").update(rawCredential, "utf8").digest("hex"), enumerable: false,
  });
  return bound;
}

async function assertCurrentAgentCredential({ client, agent }) {
  const fingerprint = agent?.[AUTHENTICATED_CREDENTIAL_HASH];
  const fail = () => { const error = new Error("Agent credential is no longer valid"); error.code = "CERTOPS_AGENT_CREDENTIAL_INVALID"; throw error; };
  if (!client || typeof client.query !== "function" || !agent?.id || !agent?.workspaceId || !agent?.agentId ||
      typeof fingerprint !== "string" || !/^[a-f0-9]{64}$/.test(fingerprint)) fail();
  const row = (await client.query(`SELECT status,agent_id,credential_hash FROM certops_agents
    WHERE workspace_id=$1::uuid AND id=$2::uuid FOR UPDATE`, [agent.workspaceId, agent.id])).rows[0];
  if (!row || row.status === "retired" || row.agent_id !== agent.agentId || !/^[a-f0-9]{64}$/.test(row.credential_hash || "")) fail();
  if (!crypto.timingSafeEqual(Buffer.from(fingerprint, "hex"), Buffer.from(row.credential_hash, "hex"))) fail();
}

module.exports = { bindAuthenticatedCredential, assertCurrentAgentCredential };

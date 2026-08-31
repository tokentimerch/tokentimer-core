/**
 * Operator-facing agent labels. `name` is the optional install-time label;
 * `hostname` is what the agent reported. The public `agentId`
 * (`candidate-<host>-<pid>`) and the row UUID are both valid lookup keys
 * because audit metadata and job routing fields mix the two.
 */

export function agentDisplayName(agent) {
  if (!agent || typeof agent !== 'object') return '';
  return String(agent.name || agent.hostname || '').trim();
}

export function indexAgentsByAnyId(agents) {
  const map = new Map();
  for (const agent of agents || []) {
    if (!agent || typeof agent !== 'object') continue;
    if (agent.id) map.set(String(agent.id), agent);
    if (agent.agentId) map.set(String(agent.agentId), agent);
  }
  return map;
}

export function formatAgentLabel(agentId, agentsById, metadata = {}) {
  const id = agentId != null && agentId !== '' ? String(agentId) : '';
  if (!id) return '';
  const agent = agentsById instanceof Map ? agentsById.get(id) : null;
  const name = String(
    metadata.agentName || metadata.hostname || agentDisplayName(agent) || ''
  ).trim();
  if (name && name !== id) return `${name} (${id})`;
  return id;
}

/**
 * Audit-row fragments for an agent reference. Prefer a human name, keep the
 * id, and drop `host` when it is just the same UUID the job stored as
 * `agentId` (trust-anchor jobs currently persist host = agent row id).
 */
export function formatAgentAuditParts(md, agentsById) {
  const parts = [];
  const agentId =
    md?.agentId != null && md.agentId !== '' ? String(md.agentId) : '';
  if (agentId) {
    parts.push(`Agent: ${formatAgentLabel(agentId, agentsById, md || {})}`);
  }
  const host = md?.host != null ? String(md.host).trim() : '';
  if (!host) return parts;
  const label = agentId ? formatAgentLabel(agentId, agentsById, md || {}) : '';
  if (host !== agentId && host !== label && !label.startsWith(`${host} (`)) {
    parts.push(`Host: ${host}`);
  }
  return parts;
}

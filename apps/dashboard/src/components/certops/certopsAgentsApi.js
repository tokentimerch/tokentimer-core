import apiClient from '../../utils/apiClient';

/**
 * CertOps agent fleet + agent bootstrap-token helpers (session surface).
 *
 * Additive module scoped to `/api/v1/workspaces/:id/certops/agents*` and
 * `/api/v1/workspaces/:id/certops/agent-bootstrap-tokens*`, following the
 * certopsTokensApi.js style. All routes are manager-only server-side
 * (403 INSUFFICIENT_ROLE) and return 404 while `certops.enabled` is off.
 */

export const AGENT_BOOTSTRAP_TOKEN_NAME_MAX_LENGTH = 128;

/** Server-enforced maximum bootstrap-token TTL (30 days). */
export const AGENT_BOOTSTRAP_TOKEN_MAX_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/** Agent statuses reported by the fleet list. */
export const CERTOPS_AGENT_STATUSES = ['active', 'offline', 'retired'];

function workspaceBase(workspaceId) {
  return `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/certops`;
}

/**
 * List registered agents for a workspace.
 * Items carry: id (row UUID used by retire), agentId, name, hostname,
 * platform, agentVersion, protocolVersion, status (active/offline/retired),
 * lastSeenAt, clockOffsetMs, createdAt, retiredAt, retireReason.
 * @returns {Promise<{ items: object[] }>}
 */
export async function listAgents(workspaceId, { signal } = {}) {
  const res = await apiClient.get(`${workspaceBase(workspaceId)}/agents`, {
    signal,
  });
  return res.data;
}

/**
 * Retire an agent (idempotent server-side). A non-forced retire is refused
 * with 409 CERTOPS_AGENT_RETIRE_BLOCKED while the agent holds active job
 * leases; pass `force: true` with a `reason` to override.
 * @returns {Promise<{ agent: object }>}
 */
export async function retireAgent(
  workspaceId,
  agentRowId,
  { force, reason } = {}
) {
  const body = {};
  if (force) body.force = true;
  if (reason) body.reason = reason;
  const res = await apiClient.post(
    `${workspaceBase(workspaceId)}/agents/${encodeURIComponent(agentRowId)}/retire`,
    body
  );
  return res.data;
}

/**
 * List agent bootstrap tokens (metadata only; the ttboot_ secret is never
 * returned). Items carry: id, name, tokenPrefix, status
 * (active/used/revoked/expired), expiresAt, usedAt, usedByAgentId,
 * revokedAt, createdAt.
 * @returns {Promise<{ items: object[] }>}
 */
export async function listBootstrapTokens(workspaceId, { signal } = {}) {
  const res = await apiClient.get(
    `${workspaceBase(workspaceId)}/agent-bootstrap-tokens`,
    { signal }
  );
  return res.data;
}

/**
 * Create an agent bootstrap token. `expiresAt` is required by the server
 * (future, at most 30 days out). The plaintext ttboot_ secret is returned
 * once in `plaintextToken` and cannot be retrieved again.
 * @returns {Promise<{ token: object, plaintextToken: string }>}
 */
export async function createBootstrapToken(
  workspaceId,
  { name, expiresAt } = {}
) {
  const res = await apiClient.post(
    `${workspaceBase(workspaceId)}/agent-bootstrap-tokens`,
    { name, expiresAt }
  );
  return res.data;
}

/**
 * Revoke an agent bootstrap token (idempotent server-side).
 * @returns {Promise<{ token: object }>}
 */
export async function revokeBootstrapToken(workspaceId, tokenId) {
  const res = await apiClient.post(
    `${workspaceBase(workspaceId)}/agent-bootstrap-tokens/${encodeURIComponent(tokenId)}/revoke`
  );
  return res.data;
}

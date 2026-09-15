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
 *
 * `pagination.total` is the full agent count for the workspace regardless of
 * limit/offset. Omitting `limit` asks for the whole fleet, and the server
 * answers that with `pagination.limit: null`, which is its signal that the
 * response holds every agent rather than a first page. Callers that render a
 * page control pass a limit; callers that need the fleet as a lookup source
 * (an agent picker, a "has any agent" check) deliberately do not.
 * @returns {Promise<{ items: object[], pagination: { limit: number|null, offset: number, total: number } }>}
 */
export async function listAgents(
  workspaceId,
  { limit, offset, sort, direction, signal } = {}
) {
  const params = {};
  if (Number.isFinite(Number(limit)) && Number(limit) > 0) {
    params.limit = Number(limit);
  }
  if (Number.isFinite(Number(offset)) && Number(offset) > 0) {
    params.offset = Number(offset);
  }
  if (sort) params.sort = sort;
  if (direction) params.direction = direction;
  const res = await apiClient.get(`${workspaceBase(workspaceId)}/agents`, {
    params,
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
 *
 * Same envelope and pagination convention as listAgents: omitting `limit`
 * asks for the whole inventory and the server answers with
 * `pagination.limit: null`; a caller rendering a page control passes one.
 * @returns {Promise<{ items: object[], pagination: { limit: number|null, offset: number, total: number } }>}
 */
export async function listBootstrapTokens(
  workspaceId,
  { limit, offset, signal } = {}
) {
  const params = {};
  if (Number.isFinite(Number(limit)) && Number(limit) > 0) {
    params.limit = Number(limit);
  }
  if (Number.isFinite(Number(offset)) && Number(offset) > 0) {
    params.offset = Number(offset);
  }
  const res = await apiClient.get(
    `${workspaceBase(workspaceId)}/agent-bootstrap-tokens`,
    { params, signal }
  );
  return res.data;
}

/**
 * Create an agent bootstrap token. `expiresAt` is required by the server
 * (future, at most 30 days out). The plaintext ttboot_ secret is returned
 * once in `plaintextToken` and cannot be retrieved again.
 *
 * `downtimeAlertsEnabled`/`contactGroupId` are optional: the agent row does
 * not exist yet at token-creation time, so alert settings are attached here
 * and copied onto the agent when the token is consumed during registration.
 * Omitting them defaults the resulting agent to alerts-enabled with the
 * workspace's default contact group (server-side default).
 * @returns {Promise<{ token: object, plaintextToken: string }>}
 */
export async function createBootstrapToken(
  workspaceId,
  { name, expiresAt, downtimeAlertsEnabled, contactGroupId } = {}
) {
  const body = { name, expiresAt };
  if (downtimeAlertsEnabled !== undefined) {
    body.downtimeAlertsEnabled = downtimeAlertsEnabled;
  }
  if (contactGroupId !== undefined) {
    body.contactGroupId = contactGroupId || null;
  }
  const res = await apiClient.post(
    `${workspaceBase(workspaceId)}/agent-bootstrap-tokens`,
    body
  );
  return res.data;
}

/**
 * Update an already-registered agent's downtime alert settings.
 * At least one of `downtimeAlertsEnabled`/`contactGroupId` must be supplied.
 * Pass `contactGroupId: null` to fall back to the workspace default group.
 * @returns {Promise<{ agent: object }>}
 */
export async function updateAgentAlertSettings(
  workspaceId,
  agentRowId,
  { downtimeAlertsEnabled, contactGroupId } = {}
) {
  const body = {};
  if (downtimeAlertsEnabled !== undefined) {
    body.downtimeAlertsEnabled = downtimeAlertsEnabled;
  }
  if (contactGroupId !== undefined) {
    body.contactGroupId = contactGroupId || null;
  }
  const res = await apiClient.patch(
    `${workspaceBase(workspaceId)}/agents/${encodeURIComponent(agentRowId)}/alert-settings`,
    body
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

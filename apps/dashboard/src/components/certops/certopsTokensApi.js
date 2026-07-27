import apiClient from '../../utils/apiClient';

/**
 * CertOps API-token management helpers (session-authenticated surface).
 *
 * Additive module scoped to `/api/v1/workspaces/:id/certops/tokens/*`.
 * Create/revoke require workspace_manager (backend returns 403 INSUFFICIENT_ROLE).
 * Returns 404 when `certops.enabled` is off.
 */

export const CERTOPS_TOKEN_SCOPES = [
  'certops:read',
  'certops:events:write',
  'certops:jobs:read',
  'certops:evidence:write',
  'certops:observations:write',
  'certops:provision:execute',
];

/** Scopes that bind the token to a single cluster; the server requires
 * `controllerClusterId` when either is present and rejects it otherwise. */
export const CERTOPS_CONTROLLER_TOKEN_SCOPES = [
  'certops:observations:write',
  'certops:provision:execute',
];

export const CERTOPS_TOKEN_NAME_MAX_LENGTH = 128;

function workspaceBase(workspaceId) {
  return `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/certops`;
}

/**
 * List CertOps API tokens for a workspace (metadata only; plaintext never returned).
 *
 * `pagination.total` is the full token count for the workspace regardless of
 * limit/offset. Omitting `limit` asks for the whole inventory, and the server
 * answers that with `pagination.limit: null`, which is its signal that the
 * response holds every token rather than a first page. Callers rendering a
 * page control pass a limit; a credential inventory being silently truncated
 * is a security-relevant wrong answer, so the panel always passes one.
 * @returns {Promise<{ items: object[], pagination: { limit: number|null, offset: number, total: number } }>}
 */
export async function listApiTokens(
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
  const res = await apiClient.get(`${workspaceBase(workspaceId)}/tokens`, {
    params,
    signal,
  });
  return res.data;
}

/**
 * Create a CertOps API token. The plaintext secret is returned once in
 * `plaintextToken` and cannot be retrieved again.
 *
 * `controllerClusterId` is required by the server exactly when `scopes`
 * includes either controller scope, and rejected otherwise; the caller is
 * responsible for clearing it when the last controller scope is deselected.
 * @returns {Promise<{ token: object, plaintextToken: string }>}
 */
export async function createApiToken(
  workspaceId,
  { name, scopes, expiresAt, controllerClusterId } = {}
) {
  const body = { name, scopes };
  if (expiresAt) body.expiresAt = expiresAt;
  if (controllerClusterId) body.controllerClusterId = controllerClusterId;

  const res = await apiClient.post(
    `${workspaceBase(workspaceId)}/tokens`,
    body
  );
  return res.data;
}

/**
 * Revoke a CertOps API token.
 * @returns {Promise<{ token: object }>}
 */
export async function revokeApiToken(workspaceId, tokenId) {
  const res = await apiClient.post(
    `${workspaceBase(workspaceId)}/tokens/${encodeURIComponent(tokenId)}/revoke`
  );
  return res.data;
}

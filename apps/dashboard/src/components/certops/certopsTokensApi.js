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
];

export const CERTOPS_TOKEN_NAME_MAX_LENGTH = 128;

function workspaceBase(workspaceId) {
  return `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/certops`;
}

/**
 * List CertOps API tokens for a workspace (metadata only; plaintext never returned).
 *
 * `pagination.total` is the full token count for the workspace regardless of
 * limit/offset. No limit is sent here, and the server answers an omitted limit
 * with `pagination.limit: null`, which is its signal that the response holds
 * the whole credential inventory rather than a first page.
 * @returns {Promise<{ items: object[], pagination: { limit: number|null, offset: number, total: number } }>}
 */
export async function listApiTokens(workspaceId, { signal } = {}) {
  const res = await apiClient.get(`${workspaceBase(workspaceId)}/tokens`, {
    signal,
  });
  return res.data;
}

/**
 * Create a CertOps API token. The plaintext secret is returned once in
 * `plaintextToken` and cannot be retrieved again.
 * @returns {Promise<{ token: object, plaintextToken: string }>}
 */
export async function createApiToken(
  workspaceId,
  { name, scopes, expiresAt } = {}
) {
  const body = { name, scopes };
  if (expiresAt) body.expiresAt = expiresAt;

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

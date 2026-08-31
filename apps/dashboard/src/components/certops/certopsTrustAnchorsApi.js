import apiClient from '../../utils/apiClient';

/**
 * CertOps trust-anchor API helpers (session surface).
 *
 * Additive module scoped to `/api/v1/workspaces/:id/certops/trust-anchors*`,
 * following the certopsAgentsApi.js style. Every route here is admin-only
 * server-side (certops.trust_anchor.manage, above workspace_manager) and
 * returns 404 while `certops.enabled` is off.
 */

/** Trust-anchor types a CA certificate can be approved as. */
export const CERTOPS_TRUST_ANCHOR_TYPES = ['root', 'intermediate'];

/** Trust-anchor lifecycle statuses reported by the list. */
export const CERTOPS_TRUST_ANCHOR_STATUSES = ['active', 'revoked'];

function workspaceBase(workspaceId) {
  return `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/certops`;
}

/**
 * List approved trust anchors for a workspace. Items carry: id, name,
 * anchorType (root/intermediate), fingerprintSha256, subjectCommonName,
 * status (active/revoked), source, publicMetadata, createdAt/updatedAt/
 * revokedAt.
 * @returns {Promise<{ items: object[] }>}
 */
export async function listTrustAnchors(workspaceId, { status, signal } = {}) {
  const params = {};
  if (status !== undefined) params.status = status;
  const res = await apiClient.get(
    `${workspaceBase(workspaceId)}/trust-anchors`,
    { params, signal }
  );
  return res.data;
}

/**
 * Approve a CA certificate as a trust anchor. Re-submitting the same
 * fingerprint updates the existing row in place and reactivates it if it
 * was previously retired, rather than creating a duplicate.
 * @returns {Promise<{ trustAnchor: object }>}
 */
export async function createTrustAnchor(
  workspaceId,
  { name, anchorType, pem, metadata } = {}
) {
  const body = { name, anchorType, pem };
  if (metadata !== undefined) body.metadata = metadata;
  const res = await apiClient.post(
    `${workspaceBase(workspaceId)}/trust-anchors`,
    body
  );
  return res.data;
}

/**
 * Retire a trust anchor (idempotent server-side; `retiredNow: false` when
 * it was already revoked). Does not remove any material already installed
 * on an agent; that requires a separate revoke-trust job.
 * @returns {Promise<{ trustAnchor: object, retiredNow: boolean }>}
 */
export async function retireTrustAnchor(
  workspaceId,
  anchorId,
  { reason } = {}
) {
  const body = {};
  if (reason) body.reason = reason;
  const res = await apiClient.post(
    `${workspaceBase(workspaceId)}/trust-anchors/${encodeURIComponent(anchorId)}/retire`,
    body
  );
  return res.data;
}

/**
 * List every installation reference row for one trust anchor: where it
 * landed (agent, store), transitionState, provenance, and lastError. Used
 * to show an admin what a distribute/revoke action will actually affect
 * before they take it.
 * @returns {Promise<{ items: object[] }>}
 */
export async function listTrustAnchorInstallations(
  workspaceId,
  anchorId,
  { signal } = {}
) {
  const res = await apiClient.get(
    `${workspaceBase(workspaceId)}/trust-anchors/${encodeURIComponent(anchorId)}/installations`,
    { signal }
  );
  return res.data;
}

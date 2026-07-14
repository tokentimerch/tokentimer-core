import apiClient from '../../utils/apiClient';

/**
 * CertOps API helpers (M1 inventory surface).
 *
 * Kept in a dedicated module rather than the shared apiClient.js so the CertOps
 * feature stays additive and self-contained (new files, minimal wiring edits).
 * Every call is workspace-scoped against the frozen route namespace
 * `/api/v1/workspaces/:id/certops/*`.
 */

function workspaceBase(workspaceId) {
  return `/api/v1/workspaces/${encodeURIComponent(workspaceId)}/certops`;
}

/**
 * List managed certificates for a workspace.
 * @returns {Promise<{ items: object[], pagination: { limit: number, offset: number } }>}
 */
export async function listCertificates(
  workspaceId,
  { limit = 50, offset = 0, signal } = {}
) {
  const res = await apiClient.get(
    `${workspaceBase(workspaceId)}/certificates`,
    {
      params: { limit, offset },
      signal,
    }
  );
  return res.data;
}

/**
 * Fetch a single managed certificate by id.
 * @returns {Promise<{ certificate: object }>}
 */
export async function getCertificate(
  workspaceId,
  certificateId,
  { signal } = {}
) {
  const res = await apiClient.get(
    `${workspaceBase(workspaceId)}/certificates/${encodeURIComponent(
      certificateId
    )}`,
    { signal }
  );
  return res.data;
}

/**
 * Fetch deployment instances (observation history) for a certificate.
 *
 * The read endpoint is part of the frozen route namespace but may not be
 * implemented yet in the current core build. Callers should treat a 404 as
 * "no history available yet" rather than an error.
 * @returns {Promise<{ items: object[] }>}
 */
export async function getCertificateInstances(
  workspaceId,
  certificateId,
  { signal } = {}
) {
  const res = await apiClient.get(
    `${workspaceBase(workspaceId)}/certificates/${encodeURIComponent(
      certificateId
    )}/instances`,
    { signal, _suppressLog: true }
  );
  return res.data;
}

/**
 * Import public certificate material (PEM, public material only).
 * Maps to POST /imports which returns 202 with the upserted records.
 * @returns {Promise<{ items: object[], count: number }>}
 */
export async function importCertificates(workspaceId, payload) {
  const res = await apiClient.post(
    `${workspaceBase(workspaceId)}/imports`,
    payload
  );
  return res.data;
}

/**
 * Import PEM material and classify the outcome against a fresh inventory snapshot.
 * The CertOps API upserts by fingerprint; ids present before submit count as updates.
 */
export async function importCertificateMaterial(
  workspaceId,
  payload,
  { signal } = {}
) {
  const existingIndex = await loadCertOpsInventoryIndex(workspaceId, {
    signal,
    force: true,
  });
  const result = await importCertificates(workspaceId, payload);
  const items = Array.isArray(result?.items) ? result.items : [];
  const existingCount = items.filter(item =>
    existingIndex.byCertId.has(item?.id)
  ).length;
  const newCount = Math.max(0, items.length - existingCount);
  return { result, items, existingCount, newCount };
}

/**
 * Retire a managed certificate (soft lifecycle transition, not a row delete).
 *
 * Maps to POST /certops/certificates/:id/retire with `{ status, reason }` where
 * status is `revoked` or `decommissioned` (plan D7 / section 10.1). The backend
 * keeps the certificate row and its evidence and mirrors the status onto the
 * linked token; nothing is purged. The endpoint may not exist yet in the current
 * core build (see PR #47), so callers should handle a 404 gracefully.
 * @returns {Promise<{ certificate: object }>}
 */
export async function retireCertificate(
  workspaceId,
  certificateId,
  { status, reason } = {}
) {
  const res = await apiClient.post(
    `${workspaceBase(workspaceId)}/certificates/${encodeURIComponent(
      certificateId
    )}/retire`,
    { status, reason }
  );
  invalidateCertOpsInventoryCache(workspaceId);
  return res.data;
}

/**
 * Lightweight availability probe used to gate CertOps UI behind the
 * `certops.enabled` rollout flag. The backend hides the routes with a 404 when
 * the flag is off, so a successful list call means CertOps is available to this
 * workspace. Only HTTP 404 means disabled; other failures propagate.
 * @returns {Promise<{ enabled: boolean }>}
 */
export async function probeCertOpsEnabled(workspaceId, { signal } = {}) {
  try {
    await apiClient.get(`${workspaceBase(workspaceId)}/certificates`, {
      params: { limit: 1, offset: 0 },
      signal,
      _suppressLog: true,
    });
    return { enabled: true };
  } catch (err) {
    if (err?.response?.status === 404) {
      return { enabled: false };
    }
    throw err;
  }
}

/** @type {Map<string, { at: number, byTokenId: Map<number, object>, byCertId: Map<string, object> }>} */
const inventoryIndexCache = new Map();

/**
 * Drop cached CertOps inventory lookups for a workspace (or all workspaces).
 */
export function invalidateCertOpsInventoryCache(workspaceId) {
  if (workspaceId) inventoryIndexCache.delete(String(workspaceId));
  else inventoryIndexCache.clear();
}

/**
 * Loads the workspace CertOps inventory once and indexes by tokenId / cert id.
 * Used to enrich existing cert tokens in the dashboard without a separate list UI.
 */
export async function loadCertOpsInventoryIndex(
  workspaceId,
  { signal, force = false } = {}
) {
  const key = String(workspaceId);
  const cached = inventoryIndexCache.get(key);
  if (!force && cached && Date.now() - cached.at < 60_000) return cached;

  const items = [];
  let offset = 0;
  const pageSize = 100;
  while (true) {
    const data = await listCertificates(workspaceId, {
      limit: pageSize,
      offset,
      signal,
    });
    const batch = Array.isArray(data?.items) ? data.items : [];
    items.push(...batch);
    if (batch.length < pageSize) break;
    offset += pageSize;
  }

  const byTokenId = new Map();
  const byCertId = new Map();
  for (const cert of items) {
    byCertId.set(cert.id, cert);
    if (cert.tokenId != null) byTokenId.set(Number(cert.tokenId), cert);
  }

  const index = { at: Date.now(), byTokenId, byCertId, items };
  inventoryIndexCache.set(key, index);
  return index;
}

/**
 * Resolve the managed_certificate row linked to an existing tokens.id.
 */
export async function getManagedCertificateForToken(
  workspaceId,
  tokenId,
  opts = {}
) {
  const index = await loadCertOpsInventoryIndex(workspaceId, opts);
  return index.byTokenId.get(Number(tokenId)) || null;
}

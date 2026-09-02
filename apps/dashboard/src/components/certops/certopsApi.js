import apiClient from '../../utils/apiClient';
import { pickPrimaryCertificate } from './certopsFormat';

/**
 * CertOps API helpers (inventory surface).
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
 * @returns {Promise<{ items: object[], pagination: { limit: number, offset: number, total: number } }>}
 */
export async function listCertificates(
  workspaceId,
  { limit = 50, offset = 0, status, source, excludeRetired, signal } = {}
) {
  const params = { limit, offset };
  if (status) params.status = status;
  if (source) params.source = source;
  if (excludeRetired !== undefined) params.excludeRetired = excludeRetired;
  const res = await apiClient.get(
    `${workspaceBase(workspaceId)}/certificates`,
    {
      params,
      signal,
    }
  );
  return res.data;
}

/**
 * List certificate targets for a workspace (deployment/observation
 * locations: hosts, endpoints, load balancers, k8s secrets, etc.).
 * @returns {Promise<{ items: object[], pagination: { limit: number, offset: number } }>}
 */
export async function listCertificateTargets(
  workspaceId,
  { limit = 50, offset = 0, signal } = {}
) {
  const res = await apiClient.get(`${workspaceBase(workspaceId)}/targets`, {
    params: { limit, offset },
    signal,
  });
  return res.data;
}

/**
 * List certificate instances across the whole workspace (flat browse, not
 * scoped to one managed certificate). Distinct from getCertificateInstances,
 * which is nested under a single certificate id.
 * @returns {Promise<{ items: object[], pagination: { limit: number, offset: number } }>}
 */
export async function listWorkspaceCertificateInstances(
  workspaceId,
  { limit = 50, offset = 0, signal } = {}
) {
  const res = await apiClient.get(`${workspaceBase(workspaceId)}/instances`, {
    params: { limit, offset },
    signal,
  });
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
 * Create a cert-manager provisioning intent: the manager-only human surface
 * that hands a strict public desired state (namespace, certificate/secret
 * name, issuerRef, dnsNames) to a controller bound to `clusterId`, without
 * ever accepting a manifest, Secret data, CSR, or private key material.
 *
 * Maps to POST /certops/provision-intents. `idempotencyKey` is required by
 * the server as the `Idempotency-Key` header (not a body field); a retried
 * request with the same key returns the existing job (`duplicate: true`)
 * instead of provisioning a second certificate. See
 * apps/api/services/certops/controllerProvisioning.js and the
 * CertOpsProvisionIntentRequest schema in openapi.yaml.
 * @returns {Promise<{ job: object, managedCertificateId: string, targetId: string, duplicate: boolean }>}
 */
export async function createControllerProvisionIntent(
  workspaceId,
  {
    idempotencyKey,
    clusterId,
    namespace,
    certificateName,
    secretName,
    issuerRef,
    dnsNames,
  } = {}
) {
  const body = {
    schemaVersion: 1,
    clusterId,
    namespace,
    certificateName,
    secretName,
    issuerRef,
    dnsNames,
  };
  const res = await apiClient.post(
    `${workspaceBase(workspaceId)}/provision-intents`,
    body,
    { headers: { 'Idempotency-Key': idempotencyKey } }
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
 * status is `revoked` or `decommissioned`. The backend
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
 * Adopt-via-issuance: "Set up automatic renewal" for an already-active,
 * unprofiled certificate.
 *
 * Maps to POST .../certificates/:id/renewal-setup. This creates a renew job
 * immediately (it is not a settings save) and, only on a non-dry-run
 * request, records a durable `profile_derivation_requested` outbox intent in
 * the same transaction, so a renewal profile is derived from the job once it
 * succeeds. A dry run creates the job but arms no intent, so it can never
 * adopt anything on its own even if it succeeds.
 * @returns {Promise<{ job: object }>}
 */
export async function setUpCertificateRenewal(
  workspaceId,
  certificateId,
  { dryRun = false, payload, assignedAgentId, idempotencyKey } = {}
) {
  const body = {};
  if (dryRun) body.dryRun = true;
  if (payload && Object.keys(payload).length) body.payload = payload;
  if (assignedAgentId) body.assignedAgentId = assignedAgentId;
  if (idempotencyKey) body.idempotencyKey = idempotencyKey;
  const res = await apiClient.post(
    `${workspaceBase(workspaceId)}/certificates/${encodeURIComponent(
      certificateId
    )}/renewal-setup`,
    body
  );
  invalidateCertOpsInventoryCache(workspaceId);
  return res.data;
}

/**
 * Detach a certificate from its renewal profile (U8). The profile row is
 * left alone since other certificates may share it; only this
 * certificate's link is cleared, and any outstanding adoption intent is
 * invalidated in the same transaction so the drain cannot re-attach it.
 * @returns {Promise<{ certificateId: string, detachedProfileId: string, invalidatedIntents: number }>}
 */
export async function detachCertificateRenewalProfile(
  workspaceId,
  certificateId
) {
  const res = await apiClient.delete(
    `${workspaceBase(workspaceId)}/certificates/${encodeURIComponent(
      certificateId
    )}/profile`
  );
  invalidateCertOpsInventoryCache(workspaceId);
  return res.data;
}

/**
 * Retry a parked (`failed`) automatic-renewal setup intent. Refused for a
 * `skipped` row (a decision, not a failure) by the backend.
 * @returns {Promise<object>}
 */
export async function retryRenewalSetupIntent(workspaceId, outboxId) {
  const res = await apiClient.post(
    `${workspaceBase(workspaceId)}/renewal-setup-intents/${encodeURIComponent(
      outboxId
    )}/retry`
  );
  invalidateCertOpsInventoryCache(workspaceId);
  return res.data;
}

/**
 * Fetch the workspace CertOps kill-switch state.
 *
 * Maps to GET /certops/settings, which stays available even while the
 * deployment-wide certops.enabled rollout flag is off, so incident controls
 * can be inspected and staged ahead of a rollout. Any human session member
 * can read it; only workspace admins can change it (see
 * updateWorkspaceCertOpsPauseState).
 * @returns {Promise<{ workspaceId: string, certOpsPaused: boolean, certOpsEnabled: boolean, certOpsActive: boolean, certOpsRequireApprovalAlways: boolean }>}
 */
export async function getWorkspaceCertOpsPauseState(
  workspaceId,
  { signal } = {}
) {
  const res = await apiClient.get(`${workspaceBase(workspaceId)}/settings`, {
    signal,
  });
  return res.data;
}

/**
 * Pause or resume CertOps for a workspace (the local kill switch).
 *
 * Maps to PUT /certops/settings. Requires the workspace admin role
 * server-side (certops.kill_switch.manage); a 403 surfaces for
 * managers/viewers. `reason` is optional free text recorded on the
 * pause/resume audit event, not persisted as ongoing state.
 * @returns {Promise<{ workspaceId: string, certOpsPaused: boolean, certOpsEnabled: boolean, certOpsActive: boolean, certOpsRequireApprovalAlways: boolean, changed: boolean }>}
 */
export async function updateWorkspaceCertOpsPauseState(
  workspaceId,
  { certOpsPaused, reason } = {}
) {
  const res = await apiClient.put(`${workspaceBase(workspaceId)}/settings`, {
    certOpsPaused,
    reason,
  });
  return res.data;
}

/**
 * Toggle the workspace-wide "always require approval" policy: when on,
 * every new CertOps job starts at pending_approval regardless of the
 * per-job requiresApproval flag a caller passes. Same PUT endpoint and
 * admin-only gate as updateWorkspaceCertOpsPauseState.
 * @returns {Promise<{ workspaceId: string, certOpsPaused: boolean, certOpsEnabled: boolean, certOpsActive: boolean, certOpsRequireApprovalAlways: boolean, changed: boolean }>}
 */
export async function updateWorkspaceCertOpsRequireApprovalAlways(
  workspaceId,
  { certOpsRequireApprovalAlways } = {}
) {
  const res = await apiClient.put(`${workspaceBase(workspaceId)}/settings`, {
    certOpsRequireApprovalAlways,
  });
  return res.data;
}

/** @type {Map<string, { at: number, enabled: boolean }>} */
const enabledProbeCache = new Map();
const ENABLED_PROBE_TTL_MS = 60_000;

/**
 * Synchronously reads the last known `certops.enabled` result for a
 * workspace, if it was probed within the last `ENABLED_PROBE_TTL_MS`.
 * Lets callers seed state immediately (no "resolving" flash) instead of
 * always starting from `null` while a fresh probe is in flight.
 * @returns {{ enabled: boolean }|null}
 */
export function getCachedCertOpsEnabled(workspaceId) {
  const cached = enabledProbeCache.get(String(workspaceId));
  if (!cached || Date.now() - cached.at >= ENABLED_PROBE_TTL_MS) return null;
  return { enabled: cached.enabled };
}

/**
 * Lightweight availability probe used to gate CertOps UI behind the
 * `certops.enabled` rollout flag. The backend hides the routes with a 404 when
 * the flag is off, so a successful list call means CertOps is available to this
 * workspace. Only HTTP 404 means disabled; other failures propagate.
 *
 * Every screen under CertOps (Jobs, Certificates, Agents, a single job's
 * evidence timeline, ...) mounts its own copy of this probe. Without a cache,
 * re-opening e.g. a job's evidence timeline re-probes from scratch every time
 * and the UI briefly reports "not available" until that round-trip resolves.
 * Callers combine this with `getCachedCertOpsEnabled` to avoid that flash.
 * @returns {Promise<{ enabled: boolean }>}
 */
export async function probeCertOpsEnabled(workspaceId, { signal } = {}) {
  try {
    await apiClient.get(`${workspaceBase(workspaceId)}/certificates`, {
      params: { limit: 1, offset: 0 },
      signal,
      _suppressLog: true,
    });
    enabledProbeCache.set(String(workspaceId), {
      at: Date.now(),
      enabled: true,
    });
    return { enabled: true };
  } catch (err) {
    if (err?.response?.status === 404) {
      enabledProbeCache.set(String(workspaceId), {
        at: Date.now(),
        enabled: false,
      });
      return { enabled: false };
    }
    throw err;
  }
}

/** @type {Map<string, { at: number, byTokenId: Map<number, object[]>, byCertId: Map<string, object> }>} */
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
 *
 * `byTokenId` maps tokenId -> certificate[] because the backend allows multiple
 * managed_certificates rows to reference the same token (e.g. one imported and
 * one monitor-observed for the same site). Use `getManagedCertificateForToken`
 * or `pickPrimaryCertificate` for single-cert display contexts.
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
    if (cert.tokenId != null) {
      const tokenKey = Number(cert.tokenId);
      const existing = byTokenId.get(tokenKey);
      if (existing) existing.push(cert);
      else byTokenId.set(tokenKey, [cert]);
    }
  }

  const index = { at: Date.now(), byTokenId, byCertId, items };
  inventoryIndexCache.set(key, index);
  return index;
}

/**
 * All managed_certificate rows linked to an existing tokens.id (several
 * certificates may reference the same token).
 */
export async function getManagedCertificatesForToken(
  workspaceId,
  tokenId,
  opts = {}
) {
  const index = await loadCertOpsInventoryIndex(workspaceId, opts);
  return index.byTokenId.get(Number(tokenId)) || [];
}

/**
 * Resolve the primary managed_certificate row linked to an existing tokens.id.
 * When several certificates reference the token, the deterministic pick from
 * `pickPrimaryCertificate` applies (active preferred, most recently updated).
 */
export async function getManagedCertificateForToken(
  workspaceId,
  tokenId,
  opts = {}
) {
  const certs = await getManagedCertificatesForToken(
    workspaceId,
    tokenId,
    opts
  );
  return pickPrimaryCertificate(certs);
}

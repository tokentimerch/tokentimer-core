"use strict";

const { isCertOpsEnabled } = require("./settings");
const {
  CERTOPS_MONITOR_BRIDGE_SKIPPED,
  normalizeFingerprintSha256,
} = require("./monitorBridge");

async function loadWorkspace(client, workspaceId) {
  const result = await client.query(
    "SELECT id FROM workspaces WHERE id = $1",
    [workspaceId],
  );
  return result.rows[0] || null;
}

async function existingMonitorManagedCertificate(
  client,
  workspaceId,
  domainMonitorId,
) {
  const result = await client.query(
    `SELECT id, fingerprint_sha256
       FROM managed_certificates
      WHERE workspace_id = $1
        AND source = 'endpoint_monitor'
        AND source_ref = $2
        AND status NOT IN ('revoked', 'decommissioned')
      ORDER BY updated_at DESC, created_at DESC
      LIMIT 1`,
    [workspaceId, String(domainMonitorId)],
  );
  return result.rows[0] || null;
}

async function activeManagedCertByFingerprint(
  client,
  workspaceId,
  fingerprintSha256,
) {
  if (!fingerprintSha256) return null;
  const result = await client.query(
    `SELECT id
       FROM managed_certificates
      WHERE workspace_id = $1
        AND fingerprint_sha256 = $2
        AND status NOT IN ('revoked', 'decommissioned')
      LIMIT 1`,
    [workspaceId, fingerprintSha256],
  );
  return result.rows[0] || null;
}

/**
 * True when bridging would create a new managed certificate row rather than
 * updating an existing monitor or fingerprint match (idempotent paths).
 * Core OSS has no quota enforcement; Cloud overlays add plan/frozen/quota gates.
 */
async function wouldConsumeNewManagedCertificateObservation(
  client,
  workspaceId,
  domainMonitorId,
  fingerprintSha256,
) {
  const existingForMonitor = await existingMonitorManagedCertificate(
    client,
    workspaceId,
    domainMonitorId,
  );
  if (existingForMonitor) return false;

  const normalizedFingerprint = normalizeFingerprintSha256(fingerprintSha256);
  if (normalizedFingerprint) {
    const existingByFingerprint = await activeManagedCertByFingerprint(
      client,
      workspaceId,
      normalizedFingerprint,
    );
    if (existingByFingerprint) return false;
  }

  return true;
}

/**
 * Evaluate Core OSS CertOps gates before bridging endpoint monitor observations.
 * Checks certops enabled and workspace exists only. SaaS overlays add plan,
 * frozen, and managed-cert quota on top of this gate.
 */
async function evaluateCertOpsMonitorBridgeGate(options = {}) {
  const {
    client,
    workspaceId,
    domainMonitorId,
    fingerprintSha256: _fingerprintSha256,
    env = process.env,
  } = options;

  if (!client || !workspaceId || !domainMonitorId) {
    throw new Error("client, workspaceId, and domainMonitorId are required");
  }

  const enabled = await isCertOpsEnabled({ dbPool: client, env });
  if (!enabled) {
    return {
      allowed: false,
      skipped: true,
      code: CERTOPS_MONITOR_BRIDGE_SKIPPED,
      reason: "certops_disabled",
    };
  }

  const workspace = await loadWorkspace(client, workspaceId);
  if (!workspace) {
    return {
      allowed: false,
      skipped: true,
      code: CERTOPS_MONITOR_BRIDGE_SKIPPED,
      reason: "workspace_not_found",
    };
  }

  return { allowed: true, skipped: false };
}

module.exports = {
  evaluateCertOpsMonitorBridgeGate,
  wouldConsumeNewManagedCertificateObservation,
};

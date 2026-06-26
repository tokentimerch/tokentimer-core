"use strict";

const {
  PRIVATE_KEY_MATERIAL_REJECTED,
  toInventoryRecord,
  upsertManagedCertificate,
} = require("./inventory");
const { isCertOpsEnabled } = require("./settings");
const { containsPrivateKeyMaterial } = require("../../utils/secretMaterial");

const CERTOPS_MONITOR_BRIDGE_SKIPPED = "CERTOPS_MONITOR_BRIDGE_SKIPPED";

function compactObject(value) {
  return Object.fromEntries(
    Object.entries(value).filter(([_key, item]) => item !== undefined),
  );
}

function normalizeText(value) {
  if (value === null || value === undefined) return null;
  const text = String(value).trim();
  return text ? text : null;
}

function normalizeDate(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date;
}

function normalizeFingerprintSha256(value) {
  const text = normalizeText(value);
  if (!text) return null;
  const compact = text.replace(/[:\s-]/g, "").toLowerCase();
  if (/^[a-f0-9]{32,}$/.test(compact)) return compact;
  return text.toLowerCase();
}

function commonNameFromSubject(subject) {
  const text = normalizeText(subject);
  if (!text) return null;
  const match = text.match(/(?:^|\n|,\s*)CN\s*=\s*([^,\n]+)/i);
  return match?.[1]?.trim() || null;
}

function rejectPrivateMaterial(value) {
  if (!containsPrivateKeyMaterial(value)) return;
  const error = new Error("Private key material is not accepted by CertOps");
  error.code = PRIVATE_KEY_MATERIAL_REJECTED;
  error.status = 422;
  throw error;
}

function certificateFromObservation(options) {
  const input = options.certificate || {};
  rejectPrivateMaterial(input);

  const subject = normalizeText(
    input.subject || input.ssl_subject || input.commonName,
  );
  const issuer = normalizeText(input.issuer || input.ssl_issuer);
  const serialNumber = normalizeText(
    input.serialNumber || input.serial_number || input.ssl_serial,
  );
  const fingerprintSha256 = normalizeFingerprintSha256(
    input.fingerprintSha256 ||
      input.fingerprint256 ||
      input.fingerprint ||
      input.ssl_fingerprint,
  );
  const notBefore = normalizeDate(
    input.notBefore || input.validFrom || input.ssl_valid_from,
  );
  const notAfter = normalizeDate(
    input.notAfter ||
      input.validTo ||
      input.expiration ||
      input.ssl_valid_to,
  );
  const certificatePem = normalizeText(
    input.certificatePem || input.publicCertificatePem,
  );

  return {
    commonName:
      normalizeText(input.commonName) ||
      commonNameFromSubject(subject) ||
      normalizeText(options.hostname),
    subjectAltNames: Array.isArray(input.subjectAltNames)
      ? input.subjectAltNames.filter(Boolean)
      : [],
    issuer,
    subject,
    serialNumber,
    certificatePem,
    fingerprintSha256,
    notBefore,
    notAfter,
  };
}

function hasPublicObservation(certificate) {
  return Boolean(
    certificate.fingerprintSha256 ||
      certificate.serialNumber ||
      certificate.subject ||
      certificate.issuer ||
      certificate.notAfter ||
      certificate.certificatePem,
  );
}

async function withBridgeClient(options, fn) {
  if (options.client) return fn(options.client);
  if (!options.dbPool || typeof options.dbPool.connect !== "function") {
    throw new Error("CertOps monitor bridge requires a client or dbPool");
  }

  const client = await options.dbPool.connect();
  try {
    await client.query("BEGIN");
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

function bridgeSource(options) {
  return normalizeText(options.source) || "endpoint_monitor";
}

function bridgeSourceRef(options) {
  return normalizeText(options.sourceRef || options.domainMonitorId);
}

async function updateManagedCertificateToken(client, managedCertificate, tokenId) {
  if (!tokenId || !managedCertificate?.id) return managedCertificate;
  const result = await client.query(
    `UPDATE managed_certificates
        SET token_id = $1,
            updated_at = NOW()
      WHERE workspace_id = $2
        AND id = $3
      RETURNING *`,
    [tokenId, managedCertificate.workspaceId, managedCertificate.id],
  );
  return toInventoryRecord(result.rows[0]);
}

async function existingManagedCertificate(client, options) {
  const sourceRef = bridgeSourceRef(options);
  if (!sourceRef) return null;

  const result = await client.query(
    `SELECT *
       FROM managed_certificates
      WHERE workspace_id = $1
        AND source = $2
        AND source_ref = $3
      ORDER BY updated_at DESC, created_at DESC
      LIMIT 1`,
    [options.workspaceId, bridgeSource(options), sourceRef],
  );
  return result.rows[0] ? toInventoryRecord(result.rows[0]) : null;
}

async function updateManagedCertificateFromObservation(
  client,
  managedCertificate,
  certificate,
  options,
) {
  const metadata = compactObject({
    bridge: "certops-monitor-observation",
    source: bridgeSource(options),
    sourceRef: bridgeSourceRef(options),
    domainMonitorId: normalizeText(options.domainMonitorId),
    hostname: normalizeText(options.hostname),
    url: normalizeText(options.url),
  });
  const result = await client.query(
    `UPDATE managed_certificates
        SET status = $3,
            token_id = COALESCE($4, token_id),
            name = COALESCE($5, name),
            common_name = COALESCE($6, common_name),
            issuer = COALESCE($7, issuer),
            subject = COALESCE($8, subject),
            serial_number = COALESCE($9, serial_number),
            certificate_pem = COALESCE($10, certificate_pem),
            not_before = COALESCE($11, not_before),
            not_after = COALESCE($12, not_after),
            public_metadata = public_metadata || $13::jsonb,
            updated_at = NOW()
      WHERE workspace_id = $1
        AND id = $2
      RETURNING *`,
    [
      options.workspaceId,
      managedCertificate.id,
      options.status || "discovered",
      options.tokenId || null,
      normalizeText(options.name || options.hostname),
      certificate.commonName,
      certificate.issuer,
      certificate.subject,
      certificate.serialNumber,
      certificate.certificatePem,
      certificate.notBefore,
      certificate.notAfter,
      JSON.stringify(metadata),
    ],
  );
  return toInventoryRecord(result.rows[0]);
}

async function upsertObservedManagedCertificate(client, certificate, options) {
  let managedCertificate = null;

  if (!certificate.fingerprintSha256) {
    managedCertificate = await existingManagedCertificate(client, options);
    if (managedCertificate) {
      return updateManagedCertificateFromObservation(
        client,
        managedCertificate,
        certificate,
        options,
      );
    }
  }

  managedCertificate = await upsertManagedCertificate(
    client,
    certificate,
    {
      workspaceId: options.workspaceId,
      status: options.status || "discovered",
      source: bridgeSource(options),
      sourceRef: bridgeSourceRef(options),
      name: options.name || options.hostname,
      createdBy: options.createdBy || null,
    },
    0,
  );

  return updateManagedCertificateToken(client, managedCertificate, options.tokenId);
}

async function upsertCertificateTarget(client, options) {
  const source = bridgeSource(options);
  const sourceRef = bridgeSourceRef(options);
  const hostname = normalizeText(options.hostname);
  const url = normalizeText(options.url);
  const name = normalizeText(options.targetName || hostname || url) || "endpoint";
  const metadata = compactObject({
    bridge: "certops-monitor-observation",
    source,
    sourceRef,
    hostname,
    url,
  });

  const existing = await client.query(
    `SELECT *
       FROM certificate_targets
      WHERE workspace_id = $1
        AND domain_monitor_id = $2
      ORDER BY updated_at DESC, created_at DESC
      LIMIT 1`,
    [options.workspaceId, options.domainMonitorId],
  );

  if (existing.rows[0]) {
    const result = await client.query(
      `UPDATE certificate_targets
          SET token_id = COALESCE($3, token_id),
              name = COALESCE($4, name),
              target_type = $5,
              status = 'active',
              source = $6,
              source_ref = COALESCE($7, source_ref),
              hostname = COALESCE($8, hostname),
              url = COALESCE($9, url),
              deployment_reference = COALESCE($10, deployment_reference),
              public_metadata = public_metadata || $11::jsonb,
              updated_at = NOW()
        WHERE workspace_id = $1
          AND id = $2
        RETURNING *`,
      [
        options.workspaceId,
        existing.rows[0].id,
        options.tokenId || null,
        name,
        options.targetType || "endpoint",
        source,
        sourceRef,
        hostname,
        url,
        url || hostname,
        JSON.stringify(metadata),
      ],
    );
    return result.rows[0];
  }

  const result = await client.query(
    `INSERT INTO certificate_targets (
       workspace_id,
       domain_monitor_id,
       token_id,
       name,
       target_type,
       status,
       source,
       source_ref,
       hostname,
       url,
       deployment_reference,
       public_metadata,
       created_by
     )
     VALUES ($1, $2, $3, $4, $5, 'active', $6, $7, $8, $9, $10, $11::jsonb, $12)
     RETURNING *`,
    [
      options.workspaceId,
      options.domainMonitorId,
      options.tokenId || null,
      name,
      options.targetType || "endpoint",
      source,
      sourceRef,
      hostname,
      url,
      url || hostname,
      JSON.stringify(metadata),
      options.createdBy || null,
    ],
  );
  return result.rows[0];
}

async function upsertCertificateInstance(
  client,
  certificate,
  managedCertificate,
  target,
  options,
) {
  const source = bridgeSource(options);
  const sourceRef = bridgeSourceRef(options);
  const metadata = compactObject({
    bridge: "certops-monitor-observation",
    source,
    sourceRef,
    domainMonitorId: normalizeText(options.domainMonitorId),
    hostname: normalizeText(options.hostname),
    url: normalizeText(options.url),
    tokenLinked: Boolean(options.tokenId),
  });
  const observedAt = normalizeDate(options.observedAt) || new Date();

  const result = await client.query(
    `INSERT INTO certificate_instances (
       workspace_id,
       managed_certificate_id,
       target_id,
       domain_monitor_id,
       token_id,
       status,
       source,
       source_ref,
       observed_fingerprint_sha256,
       observed_serial_number,
       observed_subject,
       observed_issuer,
       observed_not_before,
       observed_not_after,
       deployment_reference,
       observed_at,
       public_metadata,
       created_by
     )
     VALUES (
       $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
       $11, $12, $13, $14, $15, $16, $17::jsonb, $18
     )
     ON CONFLICT (workspace_id, target_id, managed_certificate_id)
     DO UPDATE SET
       domain_monitor_id = EXCLUDED.domain_monitor_id,
       token_id = COALESCE(EXCLUDED.token_id, certificate_instances.token_id),
       status = EXCLUDED.status,
       source = EXCLUDED.source,
       source_ref = COALESCE(EXCLUDED.source_ref, certificate_instances.source_ref),
       observed_fingerprint_sha256 = EXCLUDED.observed_fingerprint_sha256,
       observed_serial_number = EXCLUDED.observed_serial_number,
       observed_subject = EXCLUDED.observed_subject,
       observed_issuer = EXCLUDED.observed_issuer,
       observed_not_before = EXCLUDED.observed_not_before,
       observed_not_after = EXCLUDED.observed_not_after,
       deployment_reference = EXCLUDED.deployment_reference,
       observed_at = EXCLUDED.observed_at,
       public_metadata = EXCLUDED.public_metadata,
       updated_at = NOW()
     RETURNING *`,
    [
      options.workspaceId,
      managedCertificate.id,
      target.id,
      options.domainMonitorId,
      options.tokenId || null,
      options.instanceStatus || "active",
      source,
      sourceRef,
      certificate.fingerprintSha256,
      certificate.serialNumber,
      certificate.subject,
      certificate.issuer,
      certificate.notBefore,
      certificate.notAfter,
      normalizeText(options.deploymentReference || options.url),
      observedAt,
      JSON.stringify(metadata),
      options.createdBy || null,
    ],
  );

  return result.rows[0];
}

async function bridgeEndpointCertificateObservation(options = {}) {
  if (!options.workspaceId || !options.domainMonitorId) {
    throw new Error("workspaceId and domainMonitorId are required");
  }

  const db = options.client || options.dbPool;
  const enabled = await isCertOpsEnabled({
    dbPool: db,
    env: options.env || process.env,
  });
  if (!enabled) {
    return {
      skipped: true,
      code: CERTOPS_MONITOR_BRIDGE_SKIPPED,
      reason: "certops_disabled",
    };
  }

  const certificate = certificateFromObservation(options);
  if (!hasPublicObservation(certificate)) {
    return {
      skipped: true,
      code: CERTOPS_MONITOR_BRIDGE_SKIPPED,
      reason: "no_public_certificate_observation",
    };
  }

  return withBridgeClient(options, async (client) => {
    const managedCertificate = await upsertObservedManagedCertificate(
      client,
      certificate,
      options,
    );
    const target = await upsertCertificateTarget(client, options);
    const instance = await upsertCertificateInstance(
      client,
      certificate,
      managedCertificate,
      target,
      options,
    );

    return {
      skipped: false,
      managedCertificate,
      target,
      instance,
    };
  });
}

module.exports = {
  CERTOPS_MONITOR_BRIDGE_SKIPPED,
  bridgeEndpointCertificateObservation,
  normalizeFingerprintSha256,
};

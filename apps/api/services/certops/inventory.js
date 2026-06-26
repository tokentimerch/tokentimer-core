"use strict";

const { pool } = require("../../db/database");
const {
  CERTOPS_CERTIFICATE_PARSE_FAILED,
  PRIVATE_KEY_MATERIAL_REJECTED,
  parsePublicCertificateMaterial,
} = require("./parser");

const CERTOPS_CERTIFICATE_NOT_FOUND = "CERTOPS_CERTIFICATE_NOT_FOUND";

function dateToIso(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
}

function compactObject(value) {
  return Object.fromEntries(
    Object.entries(value).filter(([_key, item]) => item !== undefined),
  );
}

function chooseCertificateName(certificate, fallbackName) {
  const trimmedFallback =
    typeof fallbackName === "string" ? fallbackName.trim() : "";
  if (trimmedFallback) return trimmedFallback;
  return (
    certificate.commonName ||
    certificate.subjectAltNames?.[0] ||
    certificate.subject ||
    null
  );
}

function toInventoryRecord(row) {
  if (!row) return null;

  return {
    schemaVersion: 1,
    id: row.id,
    workspaceId: row.workspace_id,
    tokenId: row.token_id,
    profileId: row.profile_id,
    status: row.status,
    source: row.source,
    sourceRef: row.source_ref,
    commonName: row.common_name,
    subjectAltNames: Array.isArray(row.subject_alt_names)
      ? row.subject_alt_names
      : [],
    issuer: row.issuer,
    serialNumber: row.serial_number,
    fingerprintSha256: row.fingerprint_sha256,
    spkiFingerprintSha256: row.spki_fingerprint_sha256,
    certificatePem: row.certificate_pem,
    publicKeyAlgorithm: row.public_key_algorithm,
    publicKeySize: row.public_key_size,
    signatureAlgorithm: row.signature_algorithm,
    notBefore: dateToIso(row.not_before),
    notAfter: dateToIso(row.not_after),
    keyMode: row.key_mode,
    keyReference: row.key_reference,
    createdAt: dateToIso(row.created_at),
    updatedAt: dateToIso(row.updated_at),
  };
}

function normalizeLimit(value) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return 50;
  return Math.max(1, Math.min(100, parsed));
}

function normalizeOffset(value) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return 0;
  return Math.max(0, parsed);
}

function publicMetadataFor(certificate, options, chainIndex) {
  return compactObject({
    parser: "certops-public-certificate-parser",
    chainIndex,
    subject: certificate.subject || null,
    subjectAltName: certificate.subjectAltName || null,
    fingerprint512: certificate.fingerprint512 || null,
    publicKeyMetadata: certificate.publicKeyMetadata || null,
    signatureAlgorithmOid: certificate.signatureAlgorithmOid || null,
    requestSource: options.source || null,
  });
}

async function upsertManagedCertificate(client, certificate, options, chainIndex) {
  const params = [
    options.workspaceId,
    options.status || "discovered",
    options.source || "import",
    options.sourceRef || null,
    chooseCertificateName(certificate, options.name),
    certificate.commonName || null,
    certificate.subjectAltNames || [],
    certificate.issuer || null,
    certificate.subject || null,
    certificate.serialNumber || null,
    certificate.certificatePem || null,
    certificate.fingerprintSha256 || certificate.fingerprint256 || null,
    certificate.spkiFingerprintSha256 || null,
    certificate.publicKeyAlgorithm || null,
    certificate.publicKeySize || null,
    certificate.signatureAlgorithm || null,
    certificate.notBefore || certificate.validFrom || null,
    certificate.notAfter || certificate.validTo || null,
    options.keyMode || null,
    options.keyReference || null,
    JSON.stringify(publicMetadataFor(certificate, options, chainIndex)),
    options.createdBy || null,
  ];

  const result = await client.query(
    `INSERT INTO managed_certificates (
       workspace_id,
       status,
       source,
       source_ref,
       name,
       common_name,
       subject_alt_names,
       issuer,
       subject,
       serial_number,
       certificate_pem,
       fingerprint_sha256,
       spki_fingerprint_sha256,
       public_key_algorithm,
       public_key_size,
       signature_algorithm,
       not_before,
       not_after,
       key_mode,
       key_reference,
       public_metadata,
       created_by
     )
     VALUES (
       $1, $2, $3, $4, $5, $6, $7::text[], $8, $9, $10, $11, $12,
       $13, $14, $15, $16, $17, $18, $19, $20, $21::jsonb, $22
     )
     ON CONFLICT (workspace_id, fingerprint_sha256)
       WHERE fingerprint_sha256 IS NOT NULL
     DO UPDATE SET
       status = EXCLUDED.status,
       source = EXCLUDED.source,
       source_ref = EXCLUDED.source_ref,
       name = COALESCE(EXCLUDED.name, managed_certificates.name),
       common_name = EXCLUDED.common_name,
       subject_alt_names = EXCLUDED.subject_alt_names,
       issuer = EXCLUDED.issuer,
       subject = EXCLUDED.subject,
       serial_number = EXCLUDED.serial_number,
       certificate_pem = EXCLUDED.certificate_pem,
       spki_fingerprint_sha256 = EXCLUDED.spki_fingerprint_sha256,
       public_key_algorithm = EXCLUDED.public_key_algorithm,
       public_key_size = EXCLUDED.public_key_size,
       signature_algorithm = EXCLUDED.signature_algorithm,
       not_before = EXCLUDED.not_before,
       not_after = EXCLUDED.not_after,
       key_mode = COALESCE(EXCLUDED.key_mode, managed_certificates.key_mode),
       key_reference = COALESCE(EXCLUDED.key_reference, managed_certificates.key_reference),
       public_metadata = EXCLUDED.public_metadata,
       created_by = COALESCE(managed_certificates.created_by, EXCLUDED.created_by),
       updated_at = NOW()
     RETURNING *`,
    params,
  );

  return toInventoryRecord(result.rows[0]);
}

async function importPublicCertificates(options) {
  const certificates = parsePublicCertificateMaterial(options.certificatePem);
  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    const items = [];
    for (let index = 0; index < certificates.length; index += 1) {
      items.push(
        await upsertManagedCertificate(client, certificates[index], options, index),
      );
    }
    await client.query("COMMIT");
    return items;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

async function listManagedCertificates({ workspaceId, limit, offset }) {
  const normalizedLimit = normalizeLimit(limit);
  const normalizedOffset = normalizeOffset(offset);
  const result = await pool.query(
    `SELECT *
       FROM managed_certificates
      WHERE workspace_id = $1
      ORDER BY not_after ASC NULLS LAST, created_at DESC, id ASC
      LIMIT $2 OFFSET $3`,
    [workspaceId, normalizedLimit, normalizedOffset],
  );

  return {
    items: result.rows.map(toInventoryRecord),
    pagination: {
      limit: normalizedLimit,
      offset: normalizedOffset,
    },
  };
}

async function getManagedCertificate({ workspaceId, certId }) {
  const result = await pool.query(
    `SELECT *
       FROM managed_certificates
      WHERE workspace_id = $1
        AND id = $2
      LIMIT 1`,
    [workspaceId, certId],
  );

  return toInventoryRecord(result.rows[0] || null);
}

module.exports = {
  CERTOPS_CERTIFICATE_NOT_FOUND,
  CERTOPS_CERTIFICATE_PARSE_FAILED,
  PRIVATE_KEY_MATERIAL_REJECTED,
  getManagedCertificate,
  importPublicCertificates,
  listManagedCertificates,
  normalizeLimit,
  normalizeOffset,
  toInventoryRecord,
};

"use strict";

const { pool } = require("../../db/database");
const {
  CERTOPS_CERTIFICATE_PARSE_FAILED,
  PRIVATE_KEY_MATERIAL_REJECTED,
  parsePublicCertificateMaterial,
} = require("./parser");
const { containsPrivateKeyMaterial } = require("../../utils/secretMaterial");

const CERTOPS_CERTIFICATE_NOT_FOUND = "CERTOPS_CERTIFICATE_NOT_FOUND";
const CERTOPS_CERTIFICATE_RETIRE_REASON_INVALID =
  "CERTOPS_CERTIFICATE_RETIRE_REASON_INVALID";
const CERTOPS_CERTIFICATE_RETIRE_STATUS_INVALID =
  "CERTOPS_CERTIFICATE_RETIRE_STATUS_INVALID";
const CERTOPS_KEY_MODE_INVALID = "CERTOPS_KEY_MODE_INVALID";

const ALLOWED_KEY_MODES = new Set([
  "agent-local",
  "proxy-agent-local",
  "cert-manager-managed",
  "appliance-managed",
  "hsm-managed",
  "vault-managed",
  "os-store-managed",
  "external-unknown",
]);
const CERTOPS_KEY_REFERENCE_INVALID = "CERTOPS_KEY_REFERENCE_INVALID";
const KEY_REFERENCE_MAX_LENGTH = 256;
const RETIRE_REASON_MAX_LENGTH = 512;
const PEM_MARKER_PATTERN = /-----\s*(?:BEGIN|END)\b/i;
const SECRET_ASSIGNMENT_PATTERN =
  /\b(?:password|secret|token|credential|private_key|privatekey|key_material)\s*=/i;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/;
const RETIRE_STATUSES = new Set(["revoked", "decommissioned"]);
const RETIRE_STATUS_SQL_LIST = "'revoked', 'decommissioned'";

function isRetiredCertificateStatus(status) {
  return RETIRE_STATUSES.has(String(status || "").trim().toLowerCase());
}

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

function formatDateYmd(value) {
  const iso = dateToIso(value);
  return iso ? iso.slice(0, 10) : null;
}

function tokenNameFor(certificate, fallbackName) {
  const name = String(chooseCertificateName(certificate, fallbackName) || "Certificate")
    .trim()
    .slice(0, 100);
  return name.length >= 3 ? name : "Certificate";
}

function certificateDomainsFor(certificate) {
  const domains = [];
  if (Array.isArray(certificate.subjectAltNames)) {
    for (const value of certificate.subjectAltNames) {
      const domain = typeof value === "string" ? value.trim() : "";
      if (domain) domains.push(domain);
    }
  }
  const commonName =
    typeof certificate.commonName === "string" ? certificate.commonName.trim() : "";
  if (commonName) domains.push(commonName);
  return Array.from(new Set(domains));
}

function fingerprintSha256For(certificate) {
  return certificate.fingerprintSha256 || certificate.fingerprint256 || null;
}

function normalizeImportFingerprint(value) {
  if (!value) return null;
  const normalized = String(value).replace(/:/g, "").trim().toLowerCase();
  return /^[a-f0-9]{64}$/.test(normalized) ? normalized : null;
}

function fingerprintsFromCertificates(certificates) {
  if (!Array.isArray(certificates)) return [];
  return [
    ...new Set(
      certificates
        .map((certificate) =>
          normalizeImportFingerprint(fingerprintSha256For(certificate)),
        )
        .filter(Boolean),
    ),
  ];
}

async function acquireManagedCertificateImportLock(client, workspaceId) {
  await client.query(
    `SELECT pg_advisory_xact_lock(hashtext('certops_managed_cert_quota_' || $1::text))`,
    [workspaceId],
  );
}

async function countActiveManagedCertificatesWithClient(client, workspaceId) {
  const result = await client.query(
    `SELECT COUNT(*)::int AS c
       FROM managed_certificates
      WHERE workspace_id = $1
        AND status NOT IN ('revoked', 'decommissioned')`,
    [workspaceId],
  );
  return Number(result.rows[0]?.c || 0);
}

async function countQuotaConsumingNewFingerprints(client, workspaceId, fingerprints) {
  const unique = [...new Set(fingerprints.filter(Boolean))];
  if (unique.length === 0) return 0;

  const result = await client.query(
    `SELECT fingerprint_sha256, status
       FROM managed_certificates
      WHERE workspace_id = $1
        AND fingerprint_sha256 = ANY($2::text[])`,
    [workspaceId, unique],
  );
  const byFingerprint = new Map(
    result.rows.map((row) => [row.fingerprint_sha256, row.status]),
  );

  let consuming = 0;
  for (const fingerprint of unique) {
    const status = byFingerprint.get(fingerprint);
    if (!status) {
      consuming += 1;
      continue;
    }
    // Existing fingerprints are idempotent regardless of lifecycle status.
    // A retired certificate stays retired on re-import and cannot consume a
    // second managed-certificate quota slot.
  }
  return consuming;
}

function certOpsTokenNotes(certificate, domains) {
  const fingerprint = fingerprintSha256For(certificate) || "unknown";
  const domainText = domains.length ? ` Domains: ${domains.join(", ")}.` : "";
  return `Imported by CertOps public PEM import. Fingerprint: ${fingerprint}.${domainText}`;
}

function keyReferenceError() {
  const err = new Error("CertOps keyReference must be a non-secret reference");
  err.code = CERTOPS_KEY_REFERENCE_INVALID;
  return err;
}

function normalizeKeyReference(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") throw keyReferenceError();

  const trimmed = value.trim();
  if (!trimmed) return null;
  if (trimmed.length > KEY_REFERENCE_MAX_LENGTH) throw keyReferenceError();
  if (containsPrivateKeyMaterial(trimmed)) throw keyReferenceError();
  if (PEM_MARKER_PATTERN.test(trimmed)) throw keyReferenceError();
  if (SECRET_ASSIGNMENT_PATTERN.test(trimmed)) throw keyReferenceError();
  if (CONTROL_CHARACTER_PATTERN.test(trimmed)) throw keyReferenceError();

  return trimmed;
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

function toInstanceRecord(row) {
  if (!row) return null;

  return {
    id: row.id,
    workspaceId: row.workspace_id,
    managedCertificateId: row.managed_certificate_id,
    targetId: row.target_id,
    domainMonitorId: row.domain_monitor_id,
    tokenId: row.token_id,
    status: row.status,
    source: row.source,
    sourceRef: row.source_ref,
    observedFingerprintSha256: row.observed_fingerprint_sha256,
    observedSerialNumber: row.observed_serial_number,
    observedSubject: row.observed_subject,
    observedIssuer: row.observed_issuer,
    observedNotBefore: dateToIso(row.observed_not_before),
    observedNotAfter: dateToIso(row.observed_not_after),
    deploymentReference: row.deployment_reference,
    observedAt: dateToIso(row.observed_at),
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

function certOpsValidationError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function privateKeyMaterialError() {
  return certOpsValidationError(
    "Private key material is not accepted in CertOps requests",
    PRIVATE_KEY_MATERIAL_REJECTED,
  );
}

function normalizeRetireStatus(value) {
  if (typeof value !== "string") {
    throw certOpsValidationError(
      "Invalid certificate retire status",
      CERTOPS_CERTIFICATE_RETIRE_STATUS_INVALID,
    );
  }

  const trimmed = value.trim();
  if (RETIRE_STATUSES.has(trimmed)) return trimmed;

  throw certOpsValidationError(
    "Invalid certificate retire status",
    CERTOPS_CERTIFICATE_RETIRE_STATUS_INVALID,
  );
}

function retireReasonError() {
  return certOpsValidationError(
    "Invalid certificate retire reason",
    CERTOPS_CERTIFICATE_RETIRE_REASON_INVALID,
  );
}

function normalizeRetireReason(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") throw retireReasonError();

  const trimmed = value.trim();
  if (!trimmed) return null;
  if (trimmed.length > RETIRE_REASON_MAX_LENGTH) throw retireReasonError();
  if (containsPrivateKeyMaterial(trimmed)) throw privateKeyMaterialError();
  if (PEM_MARKER_PATTERN.test(trimmed)) throw retireReasonError();
  if (SECRET_ASSIGNMENT_PATTERN.test(trimmed)) throw retireReasonError();
  if (CONTROL_CHARACTER_PATTERN.test(trimmed)) throw retireReasonError();

  return trimmed;
}

function normalizeKeyMode(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") {
    throw certOpsValidationError(
      "Invalid CertOps key mode",
      CERTOPS_KEY_MODE_INVALID,
    );
  }

  const trimmed = value.trim();
  if (!trimmed) return null;
  if (ALLOWED_KEY_MODES.has(trimmed)) return trimmed;

  throw certOpsValidationError(
    "Invalid CertOps key mode",
    CERTOPS_KEY_MODE_INVALID,
  );
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
    controllerObservation:
      options.controllerObservationMetadata &&
      typeof options.controllerObservationMetadata === "object"
        ? options.controllerObservationMetadata
        : null,
  });
}

async function existingManagedCertificateForToken(client, certificate, options) {
  const fingerprintSha256 = fingerprintSha256For(certificate);
  if (!fingerprintSha256) return null;
  const result = await client.query(
    `SELECT id, token_id
       FROM managed_certificates
      WHERE workspace_id = $1
        AND fingerprint_sha256 = $2
      LIMIT 1`,
    [options.workspaceId, fingerprintSha256],
  );
  return result.rows[0] || null;
}

async function existingCertOpsToken(client, certificate, options, domains) {
  const fingerprintSha256 = fingerprintSha256For(certificate);
  if (fingerprintSha256) {
    const byFingerprint = await client.query(
      `SELECT id
         FROM tokens
        WHERE workspace_id = $1
          AND type = 'ssl_cert'
          AND notes ILIKE $2
        ORDER BY imported_at DESC NULLS LAST, created_at DESC, id DESC
        LIMIT 1`,
      [
        options.workspaceId,
        `%Imported by CertOps public PEM import. Fingerprint: ${fingerprintSha256}.%`,
      ],
    );
    if (byFingerprint.rows[0]) return byFingerprint.rows[0];
  }

  const expiration = formatDateYmd(certificate.notAfter || certificate.validTo);
  if (!expiration || domains.length === 0) return null;
  const byShape = await client.query(
    `SELECT id
       FROM tokens
      WHERE workspace_id = $1
        AND type = 'ssl_cert'
        AND expiration = $2
        AND COALESCE(issuer, '') = COALESCE($3, '')
        AND domains && $4::text[]
      ORDER BY imported_at DESC NULLS LAST, created_at DESC, id DESC
      LIMIT 1`,
    [options.workspaceId, expiration, certificate.issuer || null, domains],
  );
  return byShape.rows[0] || null;
}

async function ensureManagedCertificateToken(
  client,
  certificate,
  options,
  existingManagedCertificate = null,
) {
  if (options.tokenId) return options.tokenId;

  const existing =
    existingManagedCertificate ||
    (await existingManagedCertificateForToken(client, certificate, options));
  if (existing?.token_id) return existing.token_id;

  const domains = certificateDomainsFor(certificate);
  const existingToken = await existingCertOpsToken(
    client,
    certificate,
    options,
    domains,
  );
  if (existingToken?.id) return existingToken.id;

  const expiration = formatDateYmd(certificate.notAfter || certificate.validTo);
  if (!expiration) {
    throw certOpsValidationError(
      "Certificate expiration is required",
      CERTOPS_CERTIFICATE_PARSE_FAILED,
    );
  }

  const token = await client.query(
    `INSERT INTO tokens
       (user_id, workspace_id, created_by, name, expiration, type, category,
        issuer, serial_number, subject, domains, location, notes, imported_at)
     VALUES ($1, $2, $3, $4, $5, 'ssl_cert', 'cert',
             $6, $7, $8, $9::text[], $10, $11, NOW())
     RETURNING id`,
    [
      options.createdBy || null,
      options.workspaceId,
      options.createdBy || null,
      tokenNameFor(certificate, options.name),
      expiration,
      certificate.issuer || null,
      certificate.serialNumber || null,
      certificate.subject || null,
      domains,
      domains[0] || null,
      certOpsTokenNotes(certificate, domains),
    ],
  );
  return token.rows[0].id;
}

async function upsertManagedCertificate(client, certificate, options, chainIndex) {
  const keyReference = normalizeKeyReference(options.keyReference);
  const params = [
    options.workspaceId,
    options.tokenId || null,
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
    keyReference,
    JSON.stringify(publicMetadataFor(certificate, options, chainIndex)),
    options.createdBy || null,
  ];

  const result = await client.query(
    `INSERT INTO managed_certificates (
       workspace_id,
       token_id,
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
       $1, $2, $3, $4, $5, $6, $7, $8::text[], $9, $10, $11, $12,
       $13, $14, $15, $16, $17, $18, $19, $20, $21, $22::jsonb, $23
     )
     ON CONFLICT (workspace_id, fingerprint_sha256)
       WHERE fingerprint_sha256 IS NOT NULL
         AND source NOT IN ('endpoint_monitor', 'domain_checker', 'cert_manager')
     DO UPDATE SET
       token_id = COALESCE(EXCLUDED.token_id, managed_certificates.token_id),
       status = CASE
         WHEN managed_certificates.status IN (${RETIRE_STATUS_SQL_LIST})
         THEN managed_certificates.status
         ELSE EXCLUDED.status
       END,
       -- Import-scoped unique index: conflict only fires for import rows.
       -- Never overwrite monitor provenance if a non-import row somehow matched.
       source = CASE
         WHEN managed_certificates.source_ref IS NOT NULL
           AND managed_certificates.source <> 'import'
         THEN managed_certificates.source
         ELSE EXCLUDED.source
       END,
       source_ref = CASE
         WHEN managed_certificates.source_ref IS NOT NULL
           AND managed_certificates.source <> 'import'
         THEN managed_certificates.source_ref
         ELSE EXCLUDED.source_ref
       END,
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

/**
 * Upsert a managed certificate keyed by source identity (workspace, source,
 * source_ref). This supports observers whose stable identity must not merge on
 * a shared public certificate fingerprint.
 */
async function upsertManagedCertificateByMonitorSource(
  client,
  certificate,
  options,
  chainIndex,
) {
  const sourceRef = options.sourceRef || null;
  if (!sourceRef) {
    throw new Error("sourceRef is required for monitor-source upsert");
  }

  const keyReference = normalizeKeyReference(options.keyReference);
  const params = [
    options.workspaceId,
    options.tokenId || null,
    options.status || "discovered",
    options.source || "endpoint_monitor",
    sourceRef,
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
    keyReference,
    JSON.stringify(publicMetadataFor(certificate, options, chainIndex)),
    options.createdBy || null,
  ];

  const result = await client.query(
    `INSERT INTO managed_certificates (
       workspace_id,
       token_id,
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
       $1, $2, $3, $4, $5, $6, $7, $8::text[], $9, $10, $11, $12,
       $13, $14, $15, $16, $17, $18, $19, $20, $21, $22::jsonb, $23
     )
     ON CONFLICT (workspace_id, source, source_ref)
       WHERE source_ref IS NOT NULL
         AND source IN ('endpoint_monitor', 'domain_checker', 'cert_manager')
     DO UPDATE SET
       token_id = COALESCE(EXCLUDED.token_id, managed_certificates.token_id),
       status = CASE
         WHEN managed_certificates.status IN (${RETIRE_STATUS_SQL_LIST})
         THEN managed_certificates.status
         ELSE EXCLUDED.status
       END,
       name = COALESCE(EXCLUDED.name, managed_certificates.name),
       common_name = EXCLUDED.common_name,
       subject_alt_names = EXCLUDED.subject_alt_names,
       issuer = EXCLUDED.issuer,
       subject = EXCLUDED.subject,
       serial_number = EXCLUDED.serial_number,
       certificate_pem = EXCLUDED.certificate_pem,
       fingerprint_sha256 = EXCLUDED.fingerprint_sha256,
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
  const normalizedOptions = {
    ...options,
    keyMode: normalizeKeyMode(options.keyMode),
  };
  const ownsClient = !options.client;
  const client = options.client || (await pool.connect());

  try {
    if (ownsClient) await client.query("BEGIN");
    if (typeof normalizedOptions.validateImport === "function") {
      await normalizedOptions.validateImport(client, certificates, normalizedOptions);
    }
    const items = [];
    for (let index = 0; index < certificates.length; index += 1) {
      const certificate = certificates[index];
      const existingManagedCertificate = await existingManagedCertificateForToken(
        client,
        certificate,
        normalizedOptions,
      );
      const tokenId = await ensureManagedCertificateToken(
        client,
        certificate,
        normalizedOptions,
        existingManagedCertificate,
      );
      items.push(
        await upsertManagedCertificate(
          client,
          certificate,
          { ...normalizedOptions, tokenId },
          index,
        ),
      );
    }
    if (ownsClient) await client.query("COMMIT");
    return items;
  } catch (err) {
    if (ownsClient) {
      try {
        await client.query("ROLLBACK");
      } catch (_rollbackError) {
        /* Preserve the original error. */
      }
    }
    throw err;
  } finally {
    if (ownsClient) client.release();
  }
}

async function countActiveManagedCertificates({ workspaceId }) {
  const result = await pool.query(
    `SELECT COUNT(*)::int AS count
       FROM managed_certificates
      WHERE workspace_id = $1
        AND status NOT IN (${RETIRE_STATUS_SQL_LIST})`,
    [workspaceId],
  );

  return result.rows[0].count;
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

async function listCertificateInstances({ workspaceId, certId, limit, offset }) {
  const certificate = await getManagedCertificate({ workspaceId, certId });
  if (!certificate) return null;

  const normalizedLimit = normalizeLimit(limit);
  const normalizedOffset = normalizeOffset(offset);
  const result = await pool.query(
    `SELECT *
       FROM certificate_instances
      WHERE workspace_id = $1
        AND managed_certificate_id = $2
      ORDER BY observed_at DESC NULLS LAST,
               updated_at DESC,
               created_at DESC,
               id ASC
      LIMIT $3 OFFSET $4`,
    [workspaceId, certId, normalizedLimit, normalizedOffset],
  );

  return {
    items: result.rows.map(toInstanceRecord),
    pagination: {
      limit: normalizedLimit,
      offset: normalizedOffset,
    },
  };
}

function resolveRetireArgs(clientOrPool, options) {
  if (options === undefined) {
    return { db: pool, options: clientOrPool || {} };
  }
  return { db: clientOrPool || pool, options: options || {} };
}

async function writeRetireAudit(client, options, certificate, status, reason) {
  await client.query(
    `INSERT INTO audit_events (
       actor_user_id,
       subject_user_id,
       action,
       target_type,
       target_id,
       channel,
       metadata,
       workspace_id
     )
     VALUES ($1, $2, 'CERTOPS_CERTIFICATE_RETIRED', 'managed_certificate',
             NULL, NULL, $3::jsonb, $4)`,
    [
      options.actorUserId || options.createdBy || null,
      options.actorUserId || options.createdBy || null,
      JSON.stringify(
        compactObject({
          managedCertificateId: certificate.id,
          tokenId: certificate.token_id,
          status,
          reason,
          fingerprintSha256: certificate.fingerprint_sha256,
        }),
      ),
      options.workspaceId,
    ],
  );
}

async function retireManagedCertificate(clientOrPool, options) {
  const resolved = resolveRetireArgs(clientOrPool, options);
  const normalizedStatus = normalizeRetireStatus(resolved.options.status);
  const normalizedReason = normalizeRetireReason(resolved.options.reason);
  const db = resolved.db;
  const client =
    db && typeof db.connect === "function" ? await db.connect() : db;
  const shouldRelease = db && typeof db.connect === "function";

  if (!client || typeof client.query !== "function") {
    throw new Error("retireManagedCertificate requires a pg client or pool");
  }

  try {
    await client.query("BEGIN");

    const existing = await client.query(
      `SELECT *
         FROM managed_certificates
        WHERE workspace_id = $1
          AND id = $2
        FOR UPDATE`,
      [resolved.options.workspaceId, resolved.options.certificateId],
    );

    const certificate = existing.rows[0];
    if (!certificate) {
      throw certOpsValidationError(
        "Certificate not found",
        CERTOPS_CERTIFICATE_NOT_FOUND,
      );
    }

    const updated = await client.query(
      `UPDATE managed_certificates
          SET status = $1,
              updated_at = NOW()
        WHERE workspace_id = $2
          AND id = $3
        RETURNING *`,
      [
        normalizedStatus,
        resolved.options.workspaceId,
        resolved.options.certificateId,
      ],
    );

    if (certificate.token_id) {
      // Interim model: several managed certificates may reference the same
      // token. Only mirror a terminal lifecycle status onto the shared token
      // when no sibling certificate remains outside a retired status;
      // otherwise the token would advertise revoked/decommissioned while
      // another linked certificate is still active.
      const activeSiblings = await client.query(
        `SELECT 1
           FROM managed_certificates
          WHERE workspace_id = $1
            AND token_id = $2
            AND id <> $3
            AND status NOT IN ('revoked', 'decommissioned')
          LIMIT 1`,
        [
          resolved.options.workspaceId,
          certificate.token_id,
          resolved.options.certificateId,
        ],
      );
      if (activeSiblings.rowCount === 0) {
        await client.query(
          `UPDATE tokens
              SET cert_lifecycle_status = $1,
                  updated_at = NOW()
            WHERE workspace_id = $2
              AND id = $3`,
          [normalizedStatus, resolved.options.workspaceId, certificate.token_id],
        );
      }
    }

    await writeRetireAudit(
      client,
      resolved.options,
      updated.rows[0],
      normalizedStatus,
      normalizedReason,
    );

    await client.query("COMMIT");
    return toInventoryRecord(updated.rows[0]);
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch (_rollbackError) {
      /* Preserve the original error. */
    }
    throw err;
  } finally {
    if (shouldRelease) client.release();
  }
}

module.exports = {
  CERTOPS_CERTIFICATE_NOT_FOUND,
  CERTOPS_CERTIFICATE_PARSE_FAILED,
  CERTOPS_CERTIFICATE_RETIRE_REASON_INVALID,
  CERTOPS_CERTIFICATE_RETIRE_STATUS_INVALID,
  CERTOPS_KEY_MODE_INVALID,
  CERTOPS_KEY_REFERENCE_INVALID,
  PRIVATE_KEY_MATERIAL_REJECTED,
  RETIRE_STATUSES,
  RETIRE_STATUS_SQL_LIST,
  acquireManagedCertificateImportLock,
  countActiveManagedCertificates,
  countActiveManagedCertificatesWithClient,
  countQuotaConsumingNewFingerprints,
  fingerprintsFromCertificates,
  getManagedCertificate,
  importPublicCertificates,
  isRetiredCertificateStatus,
  listCertificateInstances,
  listManagedCertificates,
  normalizeKeyMode,
  normalizeKeyReference,
  normalizeLimit,
  normalizeOffset,
  retireManagedCertificate,
  toInstanceRecord,
  toInventoryRecord,
  upsertManagedCertificate,
  upsertManagedCertificateByMonitorSource,
};

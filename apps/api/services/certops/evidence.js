"use strict";

const crypto = require("crypto");

const { pool } = require("../../db/database");
const {
  assertNoPrivateKeyMaterial,
  containsPrivateKeyMaterial,
  redactGenericSecretsWithReport,
} = require("../../utils/secretMaterial");
const {
  CERTOPS_JOB_INVALID,
  CERTOPS_JOB_NOT_FOUND,
  PRIVATE_KEY_MATERIAL_REJECTED,
  SUBJECT_TYPES,
  assertSafePublicValue,
  dateToIso,
  getCertificateJobById,
  normalizeLimit,
  normalizeOffset,
  normalizePublicObject,
  normalizeRequiredId,
  normalizeWorkspaceId,
  serviceError,
} = require("./jobs");

const CERTOPS_EVIDENCE_INVALID = "CERTOPS_EVIDENCE_INVALID";
const CERTOPS_EVIDENCE_NOT_FOUND = "CERTOPS_EVIDENCE_NOT_FOUND";
const CERTOPS_EVIDENCE_OUTPUT_TOO_LARGE =
  "CERTOPS_EVIDENCE_OUTPUT_TOO_LARGE";
const CERTOPS_EVIDENCE_TYPE_INVALID = "CERTOPS_EVIDENCE_TYPE_INVALID";

const EVIDENCE_TYPES = Object.freeze([
  "certificate.observed",
  "deployment.checked",
  "deployment.updated",
  "validation.passed",
  "validation.failed",
  "policy.checked",
]);
const EVIDENCE_TYPE_SET = new Set(EVIDENCE_TYPES);
const SUBJECT_TYPE_SET = new Set(SUBJECT_TYPES);
const MAX_REDACTED_OUTPUT_BYTES = 64 * 1024;

const SAFE_EVIDENCE_SELECT_FIELDS = `
  id,
  workspace_id,
  job_id,
  evidence_type,
  subject_type,
  subject_id,
  metadata,
  redacted_output,
  output_truncated,
  output_sha256,
  output_size_bytes,
  observed_at,
  created_by_user_id,
  created_by_api_token_id,
  created_at
`;

function parseJsonb(value) {
  if (value === null || value === undefined) return {};
  if (typeof value === "string") {
    try {
      return JSON.parse(value);
    } catch (_error) {
      return {};
    }
  }
  return value;
}

function normalizeEnum(value, allowedSet, code, fieldName) {
  if (typeof value !== "string") {
    throw serviceError(`${fieldName} is invalid`, code);
  }
  const trimmed = value.trim();
  if (!allowedSet.has(trimmed)) {
    throw serviceError(`${fieldName} is invalid`, code);
  }
  return trimmed;
}

function normalizeOptionalEnum(value, allowedSet, code, fieldName) {
  if (value === undefined || value === null || value === "") return null;
  return normalizeEnum(value, allowedSet, code, fieldName);
}

function normalizeOptionalShortText(value, fieldName) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") {
    throw serviceError(`${fieldName} is invalid`, CERTOPS_EVIDENCE_INVALID);
  }
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (trimmed.length > 128) {
    throw serviceError(`${fieldName} is invalid`, CERTOPS_EVIDENCE_INVALID);
  }
  assertSafePublicValue(trimmed);
  return trimmed;
}

function normalizeOptionalDate(value, fieldName) {
  if (value === undefined || value === null || value === "") return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw serviceError(`${fieldName} is invalid`, CERTOPS_EVIDENCE_INVALID);
  }
  return date;
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function normalizeRedactedOutput(value) {
  if (value === undefined || value === null || value === "") {
    return {
      redactedOutput: null,
      outputTruncated: false,
      outputSha256: null,
      outputSizeBytes: null,
      redactionApplied: false,
      redactionCount: 0,
    };
  }

  if (typeof value !== "string") {
    throw serviceError("evidence output is invalid", CERTOPS_EVIDENCE_INVALID);
  }
  const rawOutputSizeBytes = Buffer.byteLength(value, "utf8");
  if (rawOutputSizeBytes > MAX_REDACTED_OUTPUT_BYTES) {
    throw serviceError(
      "CertOps evidence output is too large",
      CERTOPS_EVIDENCE_OUTPUT_TOO_LARGE,
    );
  }
  if (containsPrivateKeyMaterial(value)) {
    throw serviceError(
      "Private key material is not accepted in CertOps evidence output",
      PRIVATE_KEY_MATERIAL_REJECTED,
    );
  }

  const report = redactGenericSecretsWithReport(value);
  if (typeof report.value !== "string") {
    throw serviceError("evidence output is invalid", CERTOPS_EVIDENCE_INVALID);
  }
  const outputSizeBytes = Buffer.byteLength(report.value, "utf8");
  if (outputSizeBytes > MAX_REDACTED_OUTPUT_BYTES) {
    throw serviceError(
      "CertOps evidence output is too large",
      CERTOPS_EVIDENCE_OUTPUT_TOO_LARGE,
    );
  }

  return {
    redactedOutput: report.value,
    outputTruncated: false,
    outputSha256: sha256Hex(report.value),
    outputSizeBytes,
    redactionApplied: report.redactionApplied,
    redactionCount: report.redactionCount || 0,
  };
}

function normalizeSubject(options) {
  const subjectType = normalizeOptionalEnum(
    options.subjectType,
    SUBJECT_TYPE_SET,
    CERTOPS_EVIDENCE_INVALID,
    "subjectType",
  );
  const subjectId = normalizeOptionalShortText(options.subjectId, "subjectId");
  if (!subjectType && subjectId) {
    throw serviceError(
      "subjectType is required with subjectId",
      CERTOPS_EVIDENCE_INVALID,
    );
  }
  if (subjectType && !subjectId) {
    throw serviceError(
      "subjectId is required with subjectType",
      CERTOPS_EVIDENCE_INVALID,
    );
  }
  return { subjectType, subjectId };
}

function buildPersistedEvidenceMetadata(clientMetadata, output) {
  const metadata = { ...clientMetadata };
  // Server-owned output redaction marker. Never accept a client spoof.
  delete metadata.redaction;
  if (output.redactionApplied) {
    metadata.redaction = {
      applied: true,
      count: output.redactionCount,
    };
  }
  return metadata;
}

function evidenceFromRow(row) {
  if (!row) return null;
  const metadata = parseJsonb(row.metadata);
  const evidence = {
    id: row.id,
    workspaceId: row.workspace_id,
    jobId: row.job_id,
    evidenceType: row.evidence_type,
    subjectType: row.subject_type,
    subjectId: row.subject_id,
    metadata,
    redactedOutput: row.redacted_output,
    outputTruncated: row.output_truncated,
    outputSha256: row.output_sha256,
    outputSizeBytes: row.output_size_bytes,
    observedAt: dateToIso(row.observed_at),
    createdByUserId: row.created_by_user_id,
    createdByApiTokenId: row.created_by_api_token_id,
    createdAt: dateToIso(row.created_at),
  };

  const redaction =
    metadata && typeof metadata === "object" && !Array.isArray(metadata)
      ? metadata.redaction
      : null;
  if (redaction && redaction.applied === true) {
    evidence.outputRedactionApplied = true;
    evidence.outputRedactionCount = Number.isInteger(redaction.count)
      ? redaction.count
      : 0;
  }

  return evidence;
}

async function ensureJobExists(db, workspaceId, jobId) {
  const job = await getCertificateJobById({
    client: db,
    workspaceId,
    jobId,
  });
  if (!job) {
    throw serviceError("Certificate job not found", CERTOPS_JOB_NOT_FOUND);
  }
}

async function createCertificateEvidence(options) {
  assertNoPrivateKeyMaterial(options.evidenceType);
  assertNoPrivateKeyMaterial(options.subjectId);
  assertNoPrivateKeyMaterial(options.metadata);
  const db = options.client || pool;
  const workspaceId = normalizeWorkspaceId(options.workspaceId);
  const jobId = normalizeRequiredId(options.jobId, CERTOPS_JOB_INVALID);
  await ensureJobExists(db, workspaceId, jobId);

  const evidenceType = normalizeEnum(
    options.evidenceType,
    EVIDENCE_TYPE_SET,
    CERTOPS_EVIDENCE_TYPE_INVALID,
    "evidenceType",
  );
  const { subjectType, subjectId } = normalizeSubject(options);
  const output = normalizeRedactedOutput(options.output);
  const metadata = buildPersistedEvidenceMetadata(
    normalizePublicObject(options.metadata, "metadata"),
    output,
  );
  const observedAt = normalizeOptionalDate(options.observedAt, "observedAt");

  const result = await db.query(
    `INSERT INTO certificate_evidence (
       workspace_id,
       job_id,
       evidence_type,
       subject_type,
       subject_id,
       metadata,
       redacted_output,
       output_truncated,
       output_sha256,
       output_size_bytes,
       observed_at,
       created_by_user_id,
       created_by_api_token_id
     )
     VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10, $11, $12, $13)
     RETURNING ${SAFE_EVIDENCE_SELECT_FIELDS}`,
    [
      workspaceId,
      jobId,
      evidenceType,
      subjectType,
      subjectId,
      JSON.stringify(metadata),
      output.redactedOutput,
      output.outputTruncated,
      output.outputSha256,
      output.outputSizeBytes,
      observedAt,
      options.createdByUserId || null,
      options.createdByApiTokenId || null,
    ],
  );

  return evidenceFromRow(result.rows[0]);
}

// This is deliberately narrower than createCertificateEvidence(): controller
// observations and agent discovery reports have no certificate job, but still
// need one bounded, detector-scanned, transaction-owned evidence record. It
// only accepts certificate.observed, so it cannot be used for arbitrary
// jobless evidence; callers are the controller ingestion path and the
// credential-authenticated agent evidence route (discovery scans).
async function createControllerObservationEvidence(options) {
  assertNoPrivateKeyMaterial(options.evidenceType);
  assertNoPrivateKeyMaterial(options.subjectId);
  assertNoPrivateKeyMaterial(options.metadata);
  const db = options.client || pool;
  const workspaceId = normalizeWorkspaceId(options.workspaceId);
  const evidenceType = normalizeEnum(
    options.evidenceType,
    EVIDENCE_TYPE_SET,
    CERTOPS_EVIDENCE_TYPE_INVALID,
    "evidenceType",
  );
  if (evidenceType !== "certificate.observed") {
    throw serviceError(
      "Controller observation evidence type is invalid",
      CERTOPS_EVIDENCE_TYPE_INVALID,
    );
  }
  const { subjectType, subjectId } = normalizeSubject(options);
  const output = normalizeRedactedOutput(options.output);
  const metadata = buildPersistedEvidenceMetadata(
    normalizePublicObject(options.metadata, "metadata"),
    output,
  );
  const observedAt = normalizeOptionalDate(options.observedAt, "observedAt");

  const result = await db.query(
    `INSERT INTO certificate_evidence (
       workspace_id,
       job_id,
       evidence_type,
       subject_type,
       subject_id,
       metadata,
       redacted_output,
       output_truncated,
       output_sha256,
       output_size_bytes,
       observed_at,
       created_by_user_id,
       created_by_api_token_id
     )
     VALUES ($1, NULL, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10, NULL, $11)
     RETURNING ${SAFE_EVIDENCE_SELECT_FIELDS}`,
    [
      workspaceId,
      evidenceType,
      subjectType,
      subjectId,
      JSON.stringify(metadata),
      output.redactedOutput,
      output.outputTruncated,
      output.outputSha256,
      output.outputSizeBytes,
      observedAt,
      options.createdByApiTokenId || null,
    ],
  );

  return evidenceFromRow(result.rows[0]);
}

async function getCertificateEvidenceById(options) {
  const db = options.client || pool;
  const result = await db.query(
    `SELECT ${SAFE_EVIDENCE_SELECT_FIELDS}
       FROM certificate_evidence
      WHERE workspace_id = $1
        AND id = $2
      LIMIT 1`,
    [
      normalizeWorkspaceId(options.workspaceId),
      normalizeRequiredId(options.evidenceId, CERTOPS_EVIDENCE_INVALID),
    ],
  );
  return evidenceFromRow(result.rows[0] || null);
}

async function listCertificateEvidence(options) {
  const db = options.client || pool;
  const workspaceId = normalizeWorkspaceId(options.workspaceId);
  const limit = normalizeLimit(options.limit);
  const offset = normalizeOffset(options.offset);
  const params = [workspaceId];
  const conditions = ["workspace_id = $1"];

  if (options.jobId !== undefined && options.jobId !== null && options.jobId !== "") {
    const jobId = normalizeRequiredId(options.jobId, CERTOPS_JOB_INVALID);
    await ensureJobExists(db, workspaceId, jobId);
    params.push(jobId);
    conditions.push(`job_id = $${params.length}`);
  }

  if (options.subjectType !== undefined && options.subjectType !== null && options.subjectType !== "") {
    const subjectType = normalizeEnum(
      options.subjectType,
      SUBJECT_TYPE_SET,
      CERTOPS_EVIDENCE_INVALID,
      "subjectType",
    );
    params.push(subjectType);
    conditions.push(`subject_type = $${params.length}`);
  }

  if (options.subjectId !== undefined && options.subjectId !== null && options.subjectId !== "") {
    const subjectId = normalizeOptionalShortText(options.subjectId, "subjectId");
    params.push(subjectId);
    conditions.push(`subject_id = $${params.length}`);
  }

  params.push(limit, offset);
  const result = await db.query(
    `SELECT ${SAFE_EVIDENCE_SELECT_FIELDS}
       FROM certificate_evidence
      WHERE ${conditions.join(" AND ")}
      ORDER BY created_at DESC, id ASC
      LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params,
  );

  return {
    items: result.rows.map(evidenceFromRow),
    pagination: { limit, offset },
  };
}

module.exports = {
  CERTOPS_EVIDENCE_INVALID,
  CERTOPS_EVIDENCE_NOT_FOUND,
  CERTOPS_EVIDENCE_OUTPUT_TOO_LARGE,
  CERTOPS_EVIDENCE_TYPE_INVALID,
  EVIDENCE_TYPES,
  MAX_REDACTED_OUTPUT_BYTES,
  PRIVATE_KEY_MATERIAL_REJECTED,
  createCertificateEvidence,
  createControllerObservationEvidence,
  evidenceFromRow,
  getCertificateEvidenceById,
  listCertificateEvidence,
  normalizeRedactedOutput,
  _test: {
    evidenceFromRow,
    normalizeRedactedOutput,
    normalizeSubject,
  },
};

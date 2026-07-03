"use strict";

const { pool } = require("../../db/database");
const {
  CERTOPS_JOB_INVALID,
  CERTOPS_JOB_NOT_FOUND,
  PRIVATE_KEY_MATERIAL_REJECTED,
  SUBJECT_TYPES,
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

const SAFE_EVIDENCE_SELECT_FIELDS = `
  id,
  workspace_id,
  job_id,
  evidence_type,
  subject_type,
  subject_id,
  metadata,
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

function evidenceFromRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    workspaceId: row.workspace_id,
    jobId: row.job_id,
    evidenceType: row.evidence_type,
    subjectType: row.subject_type,
    subjectId: row.subject_id,
    metadata: parseJsonb(row.metadata),
    observedAt: dateToIso(row.observed_at),
    createdByUserId: row.created_by_user_id,
    createdByApiTokenId: row.created_by_api_token_id,
    createdAt: dateToIso(row.created_at),
  };
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
  const metadata = normalizePublicObject(options.metadata, "metadata");
  const observedAt = normalizeOptionalDate(options.observedAt, "observedAt");

  const result = await db.query(
    `INSERT INTO certificate_evidence (
       workspace_id,
       job_id,
       evidence_type,
       subject_type,
       subject_id,
       metadata,
       observed_at,
       created_by_user_id,
       created_by_api_token_id
     )
     VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9)
     RETURNING ${SAFE_EVIDENCE_SELECT_FIELDS}`,
    [
      workspaceId,
      jobId,
      evidenceType,
      subjectType,
      subjectId,
      JSON.stringify(metadata),
      observedAt,
      options.createdByUserId || null,
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
  CERTOPS_EVIDENCE_TYPE_INVALID,
  EVIDENCE_TYPES,
  PRIVATE_KEY_MATERIAL_REJECTED,
  createCertificateEvidence,
  evidenceFromRow,
  getCertificateEvidenceById,
  listCertificateEvidence,
  _test: {
    evidenceFromRow,
    normalizeSubject,
  },
};

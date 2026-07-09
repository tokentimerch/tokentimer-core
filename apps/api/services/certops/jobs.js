"use strict";

const { pool } = require("../../db/database");
const { containsPrivateKeyMaterial } = require("../../utils/secretMaterial");

const CERTOPS_JOB_INVALID = "CERTOPS_JOB_INVALID";
const CERTOPS_JOB_NOT_FOUND = "CERTOPS_JOB_NOT_FOUND";
const CERTOPS_JOB_OPERATION_INVALID = "CERTOPS_JOB_OPERATION_INVALID";
const CERTOPS_JOB_SOURCE_INVALID = "CERTOPS_JOB_SOURCE_INVALID";
const CERTOPS_JOB_STATUS_INVALID = "CERTOPS_JOB_STATUS_INVALID";
const CERTOPS_JOB_LOG_EVENT_TYPE_INVALID =
  "CERTOPS_JOB_LOG_EVENT_TYPE_INVALID";
const CERTOPS_JOB_METADATA_INVALID = "CERTOPS_JOB_METADATA_INVALID";
const CERTOPS_JOB_WORKSPACE_REQUIRED = "CERTOPS_JOB_WORKSPACE_REQUIRED";
const PRIVATE_KEY_MATERIAL_REJECTED = "PRIVATE_KEY_MATERIAL_REJECTED";

const JOB_STATUSES = Object.freeze([
  "pending_approval",
  "approved",
  "rejected",
  "pending",
  "claimed",
  "running",
  "succeeded",
  "failed",
  "blocked",
  "cancelled",
]);
const JOB_STATUS_SET = new Set(JOB_STATUSES);

const LOG_STATUSES = Object.freeze([
  "pending_approval",
  "approved",
  "pending",
  "claimed",
  "accepted",
  "redacted",
  "running",
  "succeeded",
  "failed",
  "rejected",
  "blocked",
  "cancelled",
]);
const LOG_STATUS_SET = new Set(LOG_STATUSES);

const JOB_OPERATIONS = Object.freeze(["renew", "deploy", "reload", "revoke", "noop"]);
const JOB_OPERATION_SET = new Set(JOB_OPERATIONS);

const JOB_SOURCES = Object.freeze([
  "api",
  "executor",
  "system",
  "automation",
  "domain-monitor",
  "endpoint-monitor",
  "control-plane",
  "external",
]);
const JOB_SOURCE_SET = new Set(JOB_SOURCES);

const SUBJECT_TYPES = Object.freeze([
  "managed_certificate",
  "certificate_instance",
  "certificate_target",
  "token",
  "domain",
  "endpoint",
  "external",
]);
const SUBJECT_TYPE_SET = new Set(SUBJECT_TYPES);

const JOB_LOG_EVENT_TYPES = Object.freeze([
  "job.created",
  "job.accepted",
  "job.started",
  "job.progress",
  "job.completed",
  "job.failed",
  "job.rejected",
  "job.cancelled",
  "job.status_updated",
  "evidence.attached",
]);
const JOB_LOG_EVENT_TYPE_SET = new Set(JOB_LOG_EVENT_TYPES);

const SAFE_JOB_SELECT_FIELDS = `
  id,
  workspace_id,
  operation,
  status,
  source,
  requested_by_user_id,
  requested_by_api_token_id,
  idempotency_key,
  subject_type,
  subject_id,
  payload,
  result_metadata,
  error_code,
  error_message,
  created_at,
  updated_at,
  queued_at,
  started_at,
  completed_at,
  canceled_at
`;

const SAFE_JOB_LOG_SELECT_FIELDS = `
  id,
  workspace_id,
  job_id,
  event_type,
  status,
  message,
  metadata,
  created_by_user_id,
  created_by_api_token_id,
  created_at
`;

const MAX_SCAN_DEPTH = 12;
const MAX_TEXT_LENGTH = 1024;
const MAX_SHORT_TEXT_LENGTH = 128;

const FORBIDDEN_PUBLIC_FIELD_FRAGMENTS = Object.freeze([
  "privatekey",
  "privatekeypem",
  "encryptedprivatekey",
  "keymaterial",
  "pfxblob",
  "jksblob",
  "tlskey",
  "caprivatekey",
  "keystorepassword",
  "privatekeypassword",
  "keypassword",
  "password",
  "credential",
  "tokensecret",
  "apisecret",
  "rawsecret",
  "rawprivatekey",
  "rawkey",
  "pemprivatekey",
  "secret",
  "keypem",
  "pem",
  "pfx",
  "jks",
  "keystore",
]);

const CREDENTIAL_DUMP_PATTERN =
  /\b(?:authorization\s*[:=]\s*(?:bearer|basic|token)\s+[A-Za-z0-9._~+/=-]+|(?:password|passwd|secret|credential|api[_-]?secret|token[_-]?secret|private[_-]?key|key[_-]?material)\s*[:=]\s*\S+)/i;

function serviceError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function privateMaterialError() {
  return serviceError(
    "Private key or secret material is not accepted in CertOps job metadata",
    PRIVATE_KEY_MATERIAL_REJECTED,
  );
}

function metadataError(message = "Invalid CertOps public metadata") {
  return serviceError(message, CERTOPS_JOB_METADATA_INVALID);
}

function dateToIso(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
}

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

function normalizeWorkspaceId(value) {
  const workspaceId = typeof value === "string" ? value.trim() : "";
  if (!workspaceId) {
    throw serviceError(
      "Workspace is required for CertOps jobs",
      CERTOPS_JOB_WORKSPACE_REQUIRED,
    );
  }
  return workspaceId;
}

function normalizeRequiredId(value, code = CERTOPS_JOB_INVALID) {
  const id = typeof value === "string" ? value.trim() : "";
  if (!id) throw serviceError("CertOps identifier is required", code);
  return id;
}

function normalizeOptionalShortText(value, fieldName) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") {
    throw serviceError(`${fieldName} is invalid`, CERTOPS_JOB_INVALID);
  }
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (trimmed.length > MAX_SHORT_TEXT_LENGTH) {
    throw serviceError(`${fieldName} is invalid`, CERTOPS_JOB_INVALID);
  }
  assertSafePublicValue(trimmed);
  return trimmed;
}

function normalizeOptionalPublicText(value, fieldName, maxLength = MAX_TEXT_LENGTH) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") {
    throw serviceError(`${fieldName} is invalid`, CERTOPS_JOB_INVALID);
  }
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (trimmed.length > maxLength) {
    throw serviceError(`${fieldName} is invalid`, CERTOPS_JOB_INVALID);
  }
  assertSafePublicValue(trimmed);
  return trimmed;
}

function normalizeOptionalDate(value, fieldName) {
  if (value === undefined || value === null || value === "") return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw serviceError(`${fieldName} is invalid`, CERTOPS_JOB_INVALID);
  }
  assertSafePublicValue(date.toISOString());
  return date;
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

function normalizedFieldName(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
}

function fieldNameLooksForbidden(fieldName) {
  const normalized = normalizedFieldName(fieldName);
  return FORBIDDEN_PUBLIC_FIELD_FRAGMENTS.some((fragment) =>
    normalized.includes(fragment),
  );
}

function assertSafePublicValue(value, depth = 0, seen = new WeakSet()) {
  if (depth > MAX_SCAN_DEPTH) throw privateMaterialError();
  if (containsPrivateKeyMaterial(value)) throw privateMaterialError();

  if (value === null || value === undefined) return;

  if (typeof value === "string") {
    if (CREDENTIAL_DUMP_PATTERN.test(value)) throw privateMaterialError();
    return;
  }

  if (
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return;
  }

  if (
    typeof value === "bigint" ||
    typeof value === "function" ||
    typeof value === "symbol" ||
    Buffer.isBuffer(value)
  ) {
    throw metadataError();
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      assertSafePublicValue(item, depth + 1, seen);
    }
    return;
  }

  if (typeof value === "object") {
    if (seen.has(value)) throw privateMaterialError();
    seen.add(value);
    for (const [key, item] of Object.entries(value)) {
      if (fieldNameLooksForbidden(key)) throw privateMaterialError();
      assertSafePublicValue(item, depth + 1, seen);
    }
    seen.delete(value);
    return;
  }

  throw metadataError();
}

function cloneJsonValue(value, depth = 0) {
  if (depth > MAX_SCAN_DEPTH) throw privateMaterialError();
  if (value === null) return null;
  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => cloneJsonValue(item, depth + 1));
  }
  if (value && typeof value === "object" && !Buffer.isBuffer(value)) {
    const result = {};
    for (const [key, item] of Object.entries(value)) {
      if (item === undefined) continue;
      result[key] = cloneJsonValue(item, depth + 1);
    }
    return result;
  }
  throw metadataError();
}

function normalizePublicObject(value, fieldName) {
  if (value === undefined || value === null) return {};
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw metadataError(`${fieldName} must be a public metadata object`);
  }
  assertSafePublicValue(value);
  return cloneJsonValue(value);
}

function normalizeEnum(value, allowedSet, code, fieldName, fallback = null) {
  const raw = value === undefined || value === null ? fallback : value;
  if (typeof raw !== "string") {
    throw serviceError(`${fieldName} is invalid`, code);
  }
  const trimmed = raw.trim();
  if (!allowedSet.has(trimmed)) {
    throw serviceError(`${fieldName} is invalid`, code);
  }
  return trimmed;
}

function normalizeOptionalEnum(value, allowedSet, code, fieldName) {
  if (value === undefined || value === null || value === "") return null;
  return normalizeEnum(value, allowedSet, code, fieldName);
}

function normalizeSubject(options) {
  const subjectType = normalizeOptionalEnum(
    options.subjectType,
    SUBJECT_TYPE_SET,
    CERTOPS_JOB_INVALID,
    "subjectType",
  );
  const subjectId = normalizeOptionalShortText(options.subjectId, "subjectId");
  if (!subjectType && subjectId) {
    throw serviceError("subjectType is required with subjectId", CERTOPS_JOB_INVALID);
  }
  if (subjectType && !subjectId) {
    throw serviceError("subjectId is required with subjectType", CERTOPS_JOB_INVALID);
  }
  return { subjectType, subjectId };
}

function jobFromRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    workspaceId: row.workspace_id,
    operation: row.operation,
    status: row.status,
    source: row.source,
    requestedByUserId: row.requested_by_user_id,
    requestedByApiTokenId: row.requested_by_api_token_id,
    idempotencyKey: row.idempotency_key,
    subjectType: row.subject_type,
    subjectId: row.subject_id,
    payload: parseJsonb(row.payload),
    resultMetadata: parseJsonb(row.result_metadata),
    errorCode: row.error_code,
    errorMessage: row.error_message,
    createdAt: dateToIso(row.created_at),
    updatedAt: dateToIso(row.updated_at),
    queuedAt: dateToIso(row.queued_at),
    startedAt: dateToIso(row.started_at),
    completedAt: dateToIso(row.completed_at),
    cancelledAt: dateToIso(row.canceled_at),
  };
}

function jobLogFromRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    workspaceId: row.workspace_id,
    jobId: row.job_id,
    eventType: row.event_type,
    status: row.status,
    message: row.message,
    metadata: parseJsonb(row.metadata),
    createdByUserId: row.created_by_user_id,
    createdByApiTokenId: row.created_by_api_token_id,
    createdAt: dateToIso(row.created_at),
  };
}

async function getJobById(db, workspaceId, jobId) {
  const result = await db.query(
    `SELECT ${SAFE_JOB_SELECT_FIELDS}
       FROM certificate_jobs
      WHERE workspace_id = $1
        AND id = $2
      LIMIT 1`,
    [workspaceId, jobId],
  );
  return jobFromRow(result.rows[0] || null);
}

async function getJobByIdempotencyKey(db, workspaceId, idempotencyKey) {
  const result = await db.query(
    `SELECT ${SAFE_JOB_SELECT_FIELDS}
       FROM certificate_jobs
      WHERE workspace_id = $1
        AND idempotency_key = $2
      LIMIT 1`,
    [workspaceId, idempotencyKey],
  );
  return jobFromRow(result.rows[0] || null);
}

async function ensureJobExists(db, workspaceId, jobId) {
  const result = await db.query(
    `SELECT id
       FROM certificate_jobs
      WHERE workspace_id = $1
        AND id = $2
      LIMIT 1`,
    [workspaceId, jobId],
  );
  if (!result.rows[0]) {
    throw serviceError("Certificate job not found", CERTOPS_JOB_NOT_FOUND);
  }
}

async function createCertificateJob(options) {
  const db = options.client || pool;
  const workspaceId = normalizeWorkspaceId(options.workspaceId);
  const operation = normalizeEnum(
    options.operation || options.jobType,
    JOB_OPERATION_SET,
    CERTOPS_JOB_OPERATION_INVALID,
    "operation",
  );
  const status = normalizeEnum(
    options.status,
    JOB_STATUS_SET,
    CERTOPS_JOB_STATUS_INVALID,
    "status",
    "pending",
  );
  const source = normalizeEnum(
    options.source,
    JOB_SOURCE_SET,
    CERTOPS_JOB_SOURCE_INVALID,
    "source",
    "api",
  );
  const { subjectType, subjectId } = normalizeSubject(options);
  const idempotencyKey = normalizeOptionalShortText(
    options.idempotencyKey,
    "idempotencyKey",
  );
  const payload = normalizePublicObject(options.payload, "payload");
  const resultMetadata = normalizePublicObject(
    options.resultMetadata,
    "resultMetadata",
  );
  const errorCode = normalizeOptionalShortText(options.errorCode, "errorCode");
  const errorMessage = normalizeOptionalPublicText(
    options.errorMessage,
    "errorMessage",
  );
  const queuedAt =
    normalizeOptionalDate(options.queuedAt, "queuedAt") ||
    (status === "pending" ? new Date() : null);
  const startedAt = normalizeOptionalDate(options.startedAt, "startedAt");
  const completedAt = normalizeOptionalDate(options.completedAt, "completedAt");
  const cancelledAt = normalizeOptionalDate(
    options.cancelledAt ?? options.canceledAt,
    "cancelledAt",
  );

  try {
    const result = await db.query(
      `INSERT INTO certificate_jobs (
         workspace_id,
         operation,
         status,
         source,
         requested_by_user_id,
         requested_by_api_token_id,
         idempotency_key,
         subject_type,
         subject_id,
         payload,
         result_metadata,
         error_code,
         error_message,
         queued_at,
         started_at,
         completed_at,
        canceled_at
       )
       VALUES (
         $1, $2, $3, $4, $5, $6, $7, $8, $9,
         $10::jsonb, $11::jsonb, $12, $13, $14, $15, $16, $17
       )
       RETURNING ${SAFE_JOB_SELECT_FIELDS}`,
      [
        workspaceId,
        operation,
        status,
        source,
        options.requestedByUserId || null,
        options.requestedByApiTokenId || null,
        idempotencyKey,
        subjectType,
        subjectId,
        JSON.stringify(payload),
        JSON.stringify(resultMetadata),
        errorCode,
        errorMessage,
        queuedAt,
        startedAt,
        completedAt,
        cancelledAt,
      ],
    );

    return jobFromRow(result.rows[0]);
  } catch (error) {
    if (
      idempotencyKey &&
      error?.code === "23505" &&
      String(error.constraint || "").includes(
        "uq_certificate_jobs_workspace_idempotency_key",
      )
    ) {
      const existing = await getJobByIdempotencyKey(
        db,
        workspaceId,
        idempotencyKey,
      );
      if (existing) return existing;
    }
    throw error;
  }
}

async function getCertificateJobById(options) {
  const db = options.client || pool;
  return getJobById(
    db,
    normalizeWorkspaceId(options.workspaceId),
    normalizeRequiredId(options.jobId),
  );
}

async function listCertificateJobs(options) {
  const db = options.client || pool;
  const workspaceId = normalizeWorkspaceId(options.workspaceId);
  const limit = normalizeLimit(options.limit);
  const offset = normalizeOffset(options.offset);
  const params = [workspaceId];
  const conditions = ["workspace_id = $1"];

  if (options.status !== undefined && options.status !== null && options.status !== "") {
    const status = normalizeEnum(
      options.status,
      JOB_STATUS_SET,
      CERTOPS_JOB_STATUS_INVALID,
      "status",
    );
    params.push(status);
    conditions.push(`status = $${params.length}`);
  }

  if (options.operation !== undefined && options.operation !== null && options.operation !== "") {
    const operation = normalizeEnum(
      options.operation,
      JOB_OPERATION_SET,
      CERTOPS_JOB_OPERATION_INVALID,
      "operation",
    );
    params.push(operation);
    conditions.push(`operation = $${params.length}`);
  }

  if (options.source !== undefined && options.source !== null && options.source !== "") {
    const source = normalizeEnum(
      options.source,
      JOB_SOURCE_SET,
      CERTOPS_JOB_SOURCE_INVALID,
      "source",
    );
    params.push(source);
    conditions.push(`source = $${params.length}`);
  }

  if (options.subjectType !== undefined && options.subjectType !== null && options.subjectType !== "") {
    const subjectType = normalizeEnum(
      options.subjectType,
      SUBJECT_TYPE_SET,
      CERTOPS_JOB_INVALID,
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
    `SELECT ${SAFE_JOB_SELECT_FIELDS}
       FROM certificate_jobs
      WHERE ${conditions.join(" AND ")}
      ORDER BY created_at DESC, id ASC
      LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params,
  );

  return {
    items: result.rows.map(jobFromRow),
    pagination: { limit, offset },
  };
}

async function updateCertificateJobStatus(options) {
  const db = options.client || pool;
  const workspaceId = normalizeWorkspaceId(options.workspaceId);
  const jobId = normalizeRequiredId(options.jobId);
  const status = normalizeEnum(
    options.status,
    JOB_STATUS_SET,
    CERTOPS_JOB_STATUS_INVALID,
    "status",
  );
  const hasResultMetadata = Object.prototype.hasOwnProperty.call(
    options,
    "resultMetadata",
  );
  const resultMetadata = hasResultMetadata
    ? normalizePublicObject(options.resultMetadata, "resultMetadata")
    : {};
  const errorCode = normalizeOptionalShortText(options.errorCode, "errorCode");
  const errorMessage = normalizeOptionalPublicText(
    options.errorMessage,
    "errorMessage",
  );

  const result = await db.query(
    `UPDATE certificate_jobs
        SET status = $3,
            result_metadata = CASE WHEN $4 THEN $5::jsonb ELSE result_metadata END,
            error_code = $6,
            error_message = $7,
            updated_at = NOW(),
            started_at = CASE
              WHEN $3 = 'running' THEN COALESCE(started_at, NOW())
              ELSE started_at
            END,
            completed_at = CASE
              WHEN $3 IN ('succeeded', 'failed', 'rejected', 'blocked') THEN COALESCE(completed_at, NOW())
              ELSE completed_at
            END,
            canceled_at = CASE
              WHEN $3 = 'cancelled' THEN COALESCE(canceled_at, NOW())
              ELSE canceled_at
            END
      WHERE workspace_id = $1
        AND id = $2
      RETURNING ${SAFE_JOB_SELECT_FIELDS}`,
    [
      workspaceId,
      jobId,
      status,
      hasResultMetadata,
      JSON.stringify(resultMetadata),
      errorCode,
      errorMessage,
    ],
  );

  return jobFromRow(result.rows[0] || null);
}

async function appendCertificateJobLog(options) {
  const db = options.client || pool;
  const workspaceId = normalizeWorkspaceId(options.workspaceId);
  const jobId = normalizeRequiredId(options.jobId);
  await ensureJobExists(db, workspaceId, jobId);

  const eventType = normalizeEnum(
    options.eventType,
    JOB_LOG_EVENT_TYPE_SET,
    CERTOPS_JOB_LOG_EVENT_TYPE_INVALID,
    "eventType",
  );
  const status = normalizeOptionalEnum(
    options.status,
    LOG_STATUS_SET,
    CERTOPS_JOB_STATUS_INVALID,
    "status",
  );
  const message = normalizeOptionalPublicText(options.message, "message");
  const metadata = normalizePublicObject(options.metadata, "metadata");

  const result = await db.query(
    `INSERT INTO certificate_job_log (
       workspace_id,
       job_id,
       event_type,
       status,
       message,
       metadata,
       created_by_user_id,
       created_by_api_token_id
     )
     VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)
     RETURNING ${SAFE_JOB_LOG_SELECT_FIELDS}`,
    [
      workspaceId,
      jobId,
      eventType,
      status,
      message,
      JSON.stringify(metadata),
      options.createdByUserId || null,
      options.createdByApiTokenId || null,
    ],
  );

  return jobLogFromRow(result.rows[0]);
}

async function listCertificateJobLog(options) {
  const db = options.client || pool;
  const workspaceId = normalizeWorkspaceId(options.workspaceId);
  const jobId = normalizeRequiredId(options.jobId);
  await ensureJobExists(db, workspaceId, jobId);

  const limit = normalizeLimit(options.limit);
  const offset = normalizeOffset(options.offset);
  const result = await db.query(
    `SELECT ${SAFE_JOB_LOG_SELECT_FIELDS}
       FROM certificate_job_log
      WHERE workspace_id = $1
        AND job_id = $2
      ORDER BY created_at DESC, id ASC
      LIMIT $3 OFFSET $4`,
    [workspaceId, jobId, limit, offset],
  );

  return {
    items: result.rows.map(jobLogFromRow),
    pagination: { limit, offset },
  };
}

module.exports = {
  CERTOPS_JOB_INVALID,
  CERTOPS_JOB_LOG_EVENT_TYPE_INVALID,
  CERTOPS_JOB_METADATA_INVALID,
  CERTOPS_JOB_NOT_FOUND,
  CERTOPS_JOB_OPERATION_INVALID,
  CERTOPS_JOB_SOURCE_INVALID,
  CERTOPS_JOB_STATUS_INVALID,
  CERTOPS_JOB_WORKSPACE_REQUIRED,
  JOB_LOG_EVENT_TYPES,
  JOB_OPERATIONS,
  JOB_SOURCES,
  JOB_STATUSES,
  LOG_STATUSES,
  PRIVATE_KEY_MATERIAL_REJECTED,
  SUBJECT_TYPES,
  appendCertificateJobLog,
  assertSafePublicValue,
  createCertificateJob,
  dateToIso,
  fieldNameLooksForbidden,
  getCertificateJobById,
  jobFromRow,
  jobLogFromRow,
  listCertificateJobLog,
  listCertificateJobs,
  normalizeLimit,
  normalizeOffset,
  normalizePublicObject,
  normalizeRequiredId,
  normalizeWorkspaceId,
  serviceError,
  updateCertificateJobStatus,
  _test: {
    assertSafePublicValue,
    fieldNameLooksForbidden,
    normalizePublicObject,
    parseJsonb,
  },
};

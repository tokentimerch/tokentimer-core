"use strict";

const router = require("express").Router;

const {
  createCertOpsApiTokenAuth,
} = require("../middleware/api-token-auth");
const {
  createCertOpsMachineTokenPreAuthRateLimit,
  createCertOpsMachineTokenRateLimit,
} = require("../middleware/machine-token-rate-limit");
const {
  hasCertOpsExecutorPreAuthLimit,
  certOpsMachineWriteRouteFamilyFromRequest,
} = require("../middleware/certops-executor-body-parser");
const {
  requireCertOpsEnabled,
} = require("../middleware/require-certops-enabled");
const { logger } = require("../utils/logger");
const { writeAudit } = require("../services/audit");
const {
  CERTOPS_API_TOKEN_SCOPE_DENIED,
} = require("../services/certops/apiTokens");
const {
  CERTOPS_JOB_INVALID,
  CERTOPS_JOB_LOG_EVENT_TYPE_INVALID,
  CERTOPS_JOB_NOT_FOUND,
  CERTOPS_JOB_STATUS_INVALID,
  CERTOPS_JOB_STATUS_TRANSITION_INVALID,
  LOG_STATUSES,
  PRIVATE_KEY_MATERIAL_REJECTED,
  appendCertificateJobLog,
  getCertificateJobById,
  normalizePublicObject,
  serviceError,
  updateCertificateJobStatus,
} = require("../services/certops/jobs");
const {
  CERTOPS_EVIDENCE_INVALID,
  CERTOPS_EVIDENCE_OUTPUT_TOO_LARGE,
  CERTOPS_EVIDENCE_TYPE_INVALID,
  createCertificateEvidence,
  normalizeRedactedOutput,
} = require("../services/certops/evidence");
const {
  CERTOPS_EXECUTOR_EVENT_CONFLICT,
  ingestExecutorEvent,
} = require("../services/certops/executorEvents");
const {
  GENERIC_SECRET_REDACTION_PLACEHOLDER,
  assertNoPrivateKeyMaterial,
  fieldNameLooksGenericSecret,
  fieldNameLooksPrivateKeyMaterial,
  redactGenericSecretsWithReport,
} = require("../utils/secretMaterial");
const CERTOPS_EXECUTOR_EVENT_INVALID = "CERTOPS_EXECUTOR_EVENT_INVALID";
const CERTOPS_EXECUTOR_EVENT_TYPE_INVALID =
  "CERTOPS_EXECUTOR_EVENT_TYPE_INVALID";
const CERTOPS_EXECUTOR_EVENT_STATUS_MISMATCH =
  "CERTOPS_EXECUTOR_EVENT_STATUS_MISMATCH";
const CERTOPS_EXECUTOR_JOB_REQUIRED = "CERTOPS_EXECUTOR_JOB_REQUIRED";
const CERTOPS_EXECUTOR_WORKSPACE_MISMATCH =
  "CERTOPS_EXECUTOR_WORKSPACE_MISMATCH";
const CERTOPS_SECURITY_AUDIT_UNAVAILABLE =
  "CERTOPS_SECURITY_AUDIT_UNAVAILABLE";

const EXECUTOR_EVENT_SCOPE = "certops:events:write";
const EXECUTOR_EVIDENCE_SCOPE = "certops:evidence:write";
const PUBLIC_ID_PATTERN = /^[A-Za-z0-9_.:-]+$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const METADATA_NAME_PATTERN = /^[A-Za-z0-9_.:-]{1,64}$/;
const METADATA_VALUE_TYPES = new Set(["string", "number", "boolean"]);
const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/;
const RFC3339_TIMESTAMP_PATTERN =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|([+-])(\d{2}):(\d{2}))$/;
const ARTIFACT_REF_TYPES = new Set([
  "log",
  "report",
  "certificate",
  "deployment",
  "external",
]);
const EXECUTOR_EVENT_TYPES = new Set([
  "job.accepted",
  "job.started",
  "job.progress",
  "job.completed",
  "job.failed",
  "job.rejected",
  "evidence.attached",
]);
const EXECUTOR_EVENT_STATUSES = new Set([
  "accepted",
  "claimed",
  "running",
  "succeeded",
  "failed",
  "rejected",
  "blocked",
  "cancelled",
]);
const EVIDENCE_SOURCES = new Set([
  "executor",
  "domain-monitor",
  "endpoint-monitor",
  "control-plane",
  "external",
]);
const EVIDENCE_STATUSES = new Set([
  "accepted",
  "redacted",
  "rejected",
  "failed",
]);
const EVIDENCE_EVENT_TYPES = new Set([
  "certificate.observed",
  "deployment.checked",
  "deployment.updated",
  "validation.passed",
  "validation.failed",
  "policy.checked",
]);
const EXECUTOR_EVENT_TOP_LEVEL_FIELDS = new Set([
  "schemaVersion",
  "eventId",
  "jobId",
  "workspaceId",
  "certificateId",
  "executorId",
  "status",
  "eventType",
  "occurredAt",
  "message",
  "evidence",
  "metadata",
]);
const EVIDENCE_ITEM_FIELDS = new Set([
  "schemaVersion",
  "evidenceId",
  "jobId",
  "workspaceId",
  "certificateId",
  "certificateInstanceId",
  "targetId",
  "eventType",
  "source",
  "status",
  "observedAt",
  "fingerprintSha256",
  "summary",
  "metadata",
  "artifactRefs",
  "output",
  "redactionApplied",
]);
const LOG_STATUSES_SET = new Set(LOG_STATUSES);
const REDACTION_CATEGORIES = new Set([
  "authorization",
  "cookie",
  "generic-secret",
]);
const EVENT_METADATA_RESERVED_NAMES = Object.freeze([
  "executorEventId",
  "executorEventType",
  "executorStatus",
  "occurredAt",
  "certificateId",
  "executorId",
  "jobStatusTransitionApplied",
  "jobStatusTransitionIgnored",
  "jobStatusTransitionIgnoredReason",
]);
const EVIDENCE_METADATA_RESERVED_NAMES = Object.freeze([
  "evidenceId",
  "certificateId",
  "certificateInstanceId",
  "targetId",
  "source",
  "status",
  "fingerprintSha256",
  "summary",
  "artifactRefs",
]);
const SECURITY_METADATA_RESERVED_NAMES = Object.freeze([
  "redactionApplied",
  "redactionCount",
  "redactedFields",
  "redactedSecretCategories",
]);
// Server-owned persisted and idempotency-projection names must be listed here
// (or matched by the dynamic redactedMetadata family below) before clients can
// submit public metadata. Matching is normalized so case and separators cannot
// create a colliding client key.
const RESERVED_METADATA_NAMES = Object.freeze([
  ...new Set([
    ...EVENT_METADATA_RESERVED_NAMES,
    ...EVIDENCE_METADATA_RESERVED_NAMES,
    ...SECURITY_METADATA_RESERVED_NAMES,
  ]),
]);
const RESERVED_METADATA_NORMALIZED_NAMES = new Set(
  RESERVED_METADATA_NAMES.map((value) =>
    String(value).toLowerCase().replace(/[^a-z0-9]/g, ""),
  ),
);

const ALLOWED_STATUSES_BY_EVENT_TYPE = Object.freeze({
  "job.accepted": new Set(["claimed"]),
  "job.started": new Set(["running"]),
  "job.progress": new Set(["claimed", "running"]),
  "job.completed": new Set(["succeeded"]),
  "job.failed": new Set(["failed"]),
  "job.rejected": new Set(["rejected"]),
  "evidence.attached": new Set(["accepted"]),
});

const JOB_STATUS_BY_EVENT_TYPE = Object.freeze({
  "job.accepted": "claimed",
  "job.started": "running",
  "job.completed": "succeeded",
  "job.failed": "failed",
  "job.rejected": "rejected",
});

function executorEventError(message, code) {
  return serviceError(message, code);
}

function privateKeyMaterialError() {
  return executorEventError(
    "Private key material is not accepted in CertOps executor events",
    PRIVATE_KEY_MATERIAL_REJECTED,
  );
}

function safeAuditString(value, maxLength = 128) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > maxLength || !PUBLIC_ID_PATTERN.test(trimmed)) {
    return null;
  }
  return trimmed;
}

function safeAuditUuid(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return UUID_PATTERN.test(trimmed) ? trimmed : null;
}

async function writeExecutorRejectionAudit({
  action,
  workspaceId,
  apiTokenId,
  jobId = null,
  eventId = null,
  eventType = null,
  evidenceIds = [],
  redactionApplied = null,
  redactionCount = null,
  rejectionCode = null,
  routeFamily = null,
}) {
  if (!workspaceId) return;
  await writeAudit({
    actorUserId: null,
    subjectUserId: null,
    action,
    targetType: "certops_executor",
    targetId: null,
    workspaceId,
    metadata: {
      workspaceId,
      jobId: safeAuditUuid(jobId),
      eventId: safeAuditString(eventId),
      eventType: safeAuditString(eventType),
      evidenceIds: Array.isArray(evidenceIds)
        ? evidenceIds.map((id) => safeAuditUuid(id)).filter(Boolean)
        : [],
      redactionApplied: redactionApplied === null ? undefined : Boolean(redactionApplied),
      redactionCount:
        Number.isInteger(redactionCount) && redactionCount >= 0
          ? redactionCount
          : undefined,
      rejectionCode: safeAuditString(rejectionCode),
      createdByApiTokenId: safeAuditUuid(apiTokenId),
      routeFamily: safeAuditString(routeFamily),
    },
  });
}

function safeAuditHintsFromRequest(req) {
  return {
    workspaceId: req.apiToken?.workspaceId || safeAuditUuid(req.body?.workspaceId),
    apiTokenId: req.apiToken?.id || null,
    jobId: safeAuditUuid(req.params?.jobId) || safeAuditUuid(req.body?.jobId),
    eventId: safeAuditString(req.body?.eventId),
    eventType: safeAuditString(req.body?.eventType),
    routeFamily: certOpsMachineWriteRouteFamilyFromRequest(req),
  };
}

function workspaceIdHintFromBody(req) {
  return typeof req.body?.workspaceId === "string" ? req.body.workspaceId : null;
}

function requestCarriesEvidence(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) return false;
  if (body.eventType === "evidence.attached") return true;
  return Object.prototype.hasOwnProperty.call(body, "evidence")
    && body.evidence !== undefined
    && body.evidence !== null;
}

function requiresNonEmptyEvidence(body, mode = null) {
  if (mode === "evidence") return true;
  return (
    body &&
    typeof body === "object" &&
    !Array.isArray(body) &&
    body.eventType === "evidence.attached"
  );
}

function requiredEvidenceError() {
  const error = executorEventError(
    "evidence must contain at least one item",
    CERTOPS_EVIDENCE_INVALID,
  );
  // This is a structural request error, not an executor security event. It
  // must return before any idempotency, audit, log, evidence, or job writes.
  error.skipExecutorRejectionAudit = true;
  return error;
}

function assertRequiredEvidenceItems(body, mode = null) {
  if (!requiresNonEmptyEvidence(body, mode)) return;
  const evidence = body?.evidence;
  if (
    evidence === undefined ||
    evidence === null ||
    (Array.isArray(evidence) && evidence.length === 0) ||
    (typeof evidence === "string" && evidence.trim() === "")
  ) {
    throw requiredEvidenceError();
  }
}

function requireEvidenceItems(req, res, next, options = {}) {
  try {
    const mode = options.mode || null;
    let containsPrivateKeyMaterial = false;

    if (requiresNonEmptyEvidence(req.body, mode)) {
      try {
        // Preserve the global fail-closed precedence for key material. The
        // handler owns the canonical 422 response and synchronous audit.
        rejectPrivateKeyMaterial(req.body);
      } catch (error) {
        if (error?.code !== PRIVATE_KEY_MATERIAL_REJECTED) throw error;
        containsPrivateKeyMaterial = true;
      }
    }

    if (!containsPrivateKeyMaterial) {
      assertRequiredEvidenceItems(req.body, mode);
    }
    return next();
  } catch (error) {
    if (error?.code !== CERTOPS_EVIDENCE_INVALID) return next(error);
    return res.status(400).json({
      error: "Executor evidence is invalid",
      code: CERTOPS_EVIDENCE_INVALID,
    });
  }
}

function requireEvidenceWriteScopeForEvidencePayload(req, body) {
  if (!requestCarriesEvidence(body)) return;
  const scopes = Array.isArray(req.apiToken?.scopes) ? req.apiToken.scopes : [];
  if (scopes.includes(EXECUTOR_EVIDENCE_SCOPE)) return;
  throw executorEventError(
    "CertOps evidence write scope is required",
    CERTOPS_API_TOKEN_SCOPE_DENIED,
  );
}

function bodyWithPathJobContext(req, mode) {
  if (!mode) return req.body;
  if (!req.body || typeof req.body !== "object" || Array.isArray(req.body)) {
    return req.body;
  }

  rejectPrivateKeyMaterial(req.body);
  const workspaceId = req.apiToken?.workspaceId;
  const jobId = requiredUuid(
    req.params?.jobId,
    "jobId",
    CERTOPS_EXECUTOR_JOB_REQUIRED,
  );

  if (req.body.workspaceId !== undefined && req.body.workspaceId !== null) {
    const bodyWorkspaceId = requiredUuid(
      req.body.workspaceId,
      "workspaceId",
      CERTOPS_EXECUTOR_EVENT_INVALID,
    );
    if (!workspaceId || bodyWorkspaceId !== workspaceId) {
      throw executorEventError(
        "Executor event workspace mismatch",
        CERTOPS_EXECUTOR_WORKSPACE_MISMATCH,
      );
    }
  }

  if (req.body.jobId !== undefined && req.body.jobId !== null) {
    const bodyJobId = requiredUuid(
      req.body.jobId,
      "jobId",
      CERTOPS_EXECUTOR_JOB_REQUIRED,
    );
    if (bodyJobId !== jobId) {
      throw executorEventError(
        "Executor event job mismatch",
        CERTOPS_EXECUTOR_EVENT_INVALID,
      );
    }
  }

  const eventBody = {
    ...req.body,
    workspaceId,
    jobId,
  };

  if (mode === "evidence") {
    if (
      req.body.eventType !== undefined &&
      req.body.eventType !== null &&
      req.body.eventType !== "evidence.attached"
    ) {
      throw executorEventError(
        "Executor evidence event type is invalid",
        CERTOPS_EXECUTOR_EVENT_TYPE_INVALID,
      );
    }
    eventBody.eventType = "evidence.attached";
    eventBody.status = req.body.status || "accepted";
  }

  return eventBody;
}

function requiredTrimmedString(value, fieldName, code) {
  if (typeof value !== "string") {
    throw executorEventError(`${fieldName} is required`, code);
  }
  const trimmed = value.trim();
  if (!trimmed) {
    throw executorEventError(`${fieldName} is required`, code);
  }
  return trimmed;
}

function requiredPublicId(value, fieldName, code, maxLength = 128) {
  const trimmed = requiredTrimmedString(value, fieldName, code);
  if (trimmed.length > maxLength || !PUBLIC_ID_PATTERN.test(trimmed)) {
    throw executorEventError(`${fieldName} is invalid`, code);
  }
  rejectPrivateKeyMaterial(trimmed);
  return trimmed;
}

function requiredUuid(value, fieldName, code) {
  const trimmed = requiredTrimmedString(value, fieldName, code);
  if (!UUID_PATTERN.test(trimmed)) {
    throw executorEventError(`${fieldName} is invalid`, code);
  }
  rejectPrivateKeyMaterial(trimmed);
  return trimmed;
}

function optionalPublicId(value, fieldName, maxLength = 128) {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string") {
    throw executorEventError(
      `${fieldName} is invalid`,
      CERTOPS_EXECUTOR_EVENT_INVALID,
    );
  }
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (trimmed.length > maxLength || !PUBLIC_ID_PATTERN.test(trimmed)) {
    throw executorEventError(
      `${fieldName} is invalid`,
      CERTOPS_EXECUTOR_EVENT_INVALID,
    );
  }
  rejectPrivateKeyMaterial(trimmed);
  return trimmed;
}

function createRedactionTracker() {
  return {
    count: 0,
    categories: new Set(),
  };
}

function noteRedaction(tracker, categories = []) {
  if (!tracker) return;
  const safeCategories = Array.isArray(categories) ? categories : [categories];
  if (!safeCategories.every((category) => REDACTION_CATEGORIES.has(category))) {
    throw executorEventError(
      "Executor redaction report is invalid",
      CERTOPS_EXECUTOR_EVENT_INVALID,
    );
  }
  tracker.count += 1;
  for (const category of safeCategories) tracker.categories.add(category);
  if (safeCategories.length === 0) tracker.categories.add("generic-secret");
}

function genericSecretCategory(fieldName) {
  const normalized = String(fieldName || "")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
  if (normalized.includes("authorization")) return "authorization";
  if (normalized.includes("cookie")) return "cookie";
  return "generic-secret";
}

function mergeRedactionReport(tracker, report) {
  if (!tracker || !report?.redactionApplied) return;
  const count = report.redactionCount;
  const categories = report.redactedFields;
  if (
    !Number.isInteger(count) ||
    count < 1 ||
    !Array.isArray(categories) ||
    !categories.length ||
    !categories.every((category) => REDACTION_CATEGORIES.has(category))
  ) {
    throw executorEventError(
      "Executor redaction report is invalid",
      CERTOPS_EXECUTOR_EVENT_INVALID,
    );
  }
  tracker.count += count;
  for (const category of categories) tracker.categories.add(category);
}

function immutableRedactionReport(tracker) {
  const count = tracker?.count || 0;
  const categories = Array.from(tracker?.categories || []).sort();
  if (
    !Number.isInteger(count) ||
    count < 0 ||
    !categories.every((category) => REDACTION_CATEGORIES.has(category)) ||
    (count === 0 && categories.length > 0)
  ) {
    throw executorEventError(
      "Executor redaction report is invalid",
      CERTOPS_EXECUTOR_EVENT_INVALID,
    );
  }
  return Object.freeze({
    count,
    categories: Object.freeze(categories),
  });
}

function redactionMetadata(report) {
  const normalized = immutableRedactionReport(report);
  if (normalized.count === 0) return {};
  return {
    redactionApplied: true,
    redactionCount: normalized.count,
    redactedFields: normalized.categories,
  };
}

function normalizedMetadataName(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
}

function isReservedMetadataName(value) {
  const normalized = normalizedMetadataName(value);
  return (
    RESERVED_METADATA_NORMALIZED_NAMES.has(normalized) ||
    /^redactedmetadata\d+$/.test(normalized)
  );
}

function rejectPrivateKeyMaterial(value) {
  assertNoPrivateKeyMaterial(value);
}

function rejectUnknownTopLevelFields(body) {
  for (const key of Object.keys(body)) {
    if (!EXECUTOR_EVENT_TOP_LEVEL_FIELDS.has(key)) {
      throw executorEventError(
        "Executor event body contains unsupported fields",
        CERTOPS_EXECUTOR_EVENT_INVALID,
      );
    }
  }
}

function rejectUnknownEvidenceItemFields(item) {
  for (const key of Object.keys(item)) {
    if (!EVIDENCE_ITEM_FIELDS.has(key)) {
      throw executorEventError(
        "Evidence item contains unsupported fields",
        CERTOPS_EXECUTOR_EVENT_INVALID,
      );
    }
  }
}

function redactGenericText(value, fieldName, tracker, maxLength = 1024) {
  const report = redactGenericSecretsWithReport(value);
  if (typeof report.value !== "string") {
    throw executorEventError(`${fieldName} is invalid`, CERTOPS_EXECUTOR_EVENT_INVALID);
  }
  if (report.value.length > maxLength) {
    throw executorEventError(`${fieldName} is too long`, CERTOPS_EXECUTOR_EVENT_INVALID);
  }
  mergeRedactionReport(tracker, report);
  return report.value;
}

function optionalPublicText(value, fieldName, maxLength = 1024, tracker = null) {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string") {
    throw executorEventError(`${fieldName} is invalid`, CERTOPS_EXECUTOR_EVENT_INVALID);
  }
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (trimmed.length > maxLength) {
    throw executorEventError(`${fieldName} is too long`, CERTOPS_EXECUTOR_EVENT_INVALID);
  }
  rejectPrivateKeyMaterial(trimmed);
  return redactGenericText(trimmed, fieldName, tracker, maxLength);
}

function requiredPublicText(value, fieldName, maxLength = 512, tracker = null) {
  if (typeof value !== "string") {
    throw executorEventError(
      `${fieldName} is invalid`,
      CERTOPS_EXECUTOR_EVENT_INVALID,
    );
  }
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > maxLength) {
    throw executorEventError(
      `${fieldName} is invalid`,
      CERTOPS_EXECUTOR_EVENT_INVALID,
    );
  }
  rejectPrivateKeyMaterial(trimmed);
  return redactGenericText(trimmed, fieldName, tracker, maxLength);
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (Buffer.isBuffer(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function normalizeRfc3339Timestamp(value, fieldName = "occurredAt") {
  const timestampValue = requiredTrimmedString(
    value,
    fieldName,
    CERTOPS_EXECUTOR_EVENT_INVALID,
  );
  const match = RFC3339_TIMESTAMP_PATTERN.exec(timestampValue);
  const date = new Date(timestampValue);
  const timestamp = date.getTime();
  const offsetHours = Number(match?.[10]);
  const offsetMinutes = Number(match?.[11]);
  if (
    !match ||
    Number.isNaN(timestamp) ||
    Number(match[1]) < 2000 ||
    Number(match[1]) > 2100 ||
    Number(match[2]) < 1 ||
    Number(match[2]) > 12 ||
    Number(match[3]) < 1 ||
    Number(match[3]) > new Date(Date.UTC(Number(match[1]), Number(match[2]), 0)).getUTCDate() ||
    Number(match[4]) > 23 ||
    Number(match[5]) > 59 ||
    Number(match[6]) > 59 ||
    (match[8] !== "Z" &&
      (offsetHours > 14 ||
        offsetMinutes > 59 ||
        (offsetHours === 14 && offsetMinutes !== 0)))
  ) {
    throw executorEventError(
      `${fieldName} is invalid`,
      CERTOPS_EXECUTOR_EVENT_INVALID,
    );
  }
  return date.toISOString();
}

function normalizeOccurredAt(value) {
  return normalizeRfc3339Timestamp(value, "occurredAt");
}

function optionalEvidenceEnum(value, fieldName, allowedValues) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") {
    throw executorEventError(
      `${fieldName} is invalid`,
      CERTOPS_EXECUTOR_EVENT_INVALID,
    );
  }
  rejectPrivateKeyMaterial(value);
  if (!allowedValues.has(value)) {
    throw executorEventError(
      `${fieldName} is invalid`,
      CERTOPS_EXECUTOR_EVENT_INVALID,
    );
  }
  return value;
}

function optionalFingerprintSha256(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || !SHA256_HEX_PATTERN.test(value)) {
    throw executorEventError(
      "fingerprintSha256 is invalid",
      CERTOPS_EXECUTOR_EVENT_INVALID,
    );
  }
  rejectPrivateKeyMaterial(value);
  return value;
}

function normalizeEvidenceEventType(value) {
  const eventType = requiredTrimmedString(
    value,
    "evidence.eventType",
    CERTOPS_EVIDENCE_TYPE_INVALID,
  );
  rejectPrivateKeyMaterial(eventType);
  if (!EVIDENCE_EVENT_TYPES.has(eventType)) {
    throw executorEventError(
      "Evidence event type is invalid",
      CERTOPS_EVIDENCE_TYPE_INVALID,
    );
  }
  return eventType;
}

function normalizeEventType(value) {
  const eventType = requiredTrimmedString(
    value,
    "eventType",
    CERTOPS_EXECUTOR_EVENT_TYPE_INVALID,
  );
  if (!EXECUTOR_EVENT_TYPES.has(eventType)) {
    throw executorEventError(
      "Executor event type is invalid",
      CERTOPS_EXECUTOR_EVENT_TYPE_INVALID,
    );
  }
  return eventType;
}

function normalizeStatus(value) {
  const status = requiredTrimmedString(
    value,
    "status",
    CERTOPS_JOB_STATUS_INVALID,
  );
  if (!EXECUTOR_EVENT_STATUSES.has(status)) {
    throw executorEventError("Executor event status is invalid", CERTOPS_JOB_STATUS_INVALID);
  }
  return status;
}

function assertEventStatusMatch(eventType, status) {
  const allowedStatuses = ALLOWED_STATUSES_BY_EVENT_TYPE[eventType];
  if (!allowedStatuses?.has(status)) {
    throw executorEventError(
      "Executor event status does not match the event type",
      CERTOPS_EXECUTOR_EVENT_STATUS_MISMATCH,
    );
  }
}

function metadataEntriesToObject(
  entries,
  fieldName,
  tracker = null,
  idempotencyMetadata = null,
) {
  if (entries === undefined || entries === null) return {};
  if (!Array.isArray(entries)) {
    throw executorEventError(
      `${fieldName} must be a public metadata array`,
      CERTOPS_EXECUTOR_EVENT_INVALID,
    );
  }
  if (entries.length > 32) {
    throw executorEventError(
      `${fieldName} contains too many entries`,
      CERTOPS_EXECUTOR_EVENT_INVALID,
    );
  }

  const metadata = {};
  const idempotencySecretCategories = [];
  entries.forEach((entry, index) => {
    if (!isPlainObject(entry)) {
      throw executorEventError(
        `${fieldName} entry is invalid`,
        CERTOPS_EXECUTOR_EVENT_INVALID,
      );
    }

    const keys = Object.keys(entry);
    if (
      keys.length !== 2 ||
      !keys.includes("name") ||
      !keys.includes("value")
    ) {
      throw executorEventError(
        `${fieldName} entry is invalid`,
        CERTOPS_EXECUTOR_EVENT_INVALID,
      );
    }

    const name = requiredPublicId(
      entry.name,
      `${fieldName}.name`,
      CERTOPS_EXECUTOR_EVENT_INVALID,
      64,
    );
    if (!METADATA_NAME_PATTERN.test(name)) {
      throw executorEventError(
        `${fieldName}.name is invalid`,
        CERTOPS_EXECUTOR_EVENT_INVALID,
      );
    }
    if (fieldNameLooksPrivateKeyMaterial(name)) throw privateKeyMaterialError();
    if (isReservedMetadataName(name)) {
      throw executorEventError(
        `${fieldName}.name is reserved`,
        CERTOPS_EXECUTOR_EVENT_INVALID,
      );
    }
    if (!Object.prototype.hasOwnProperty.call(entry, "value")) {
      throw executorEventError(
        `${fieldName}.value is required`,
        CERTOPS_EXECUTOR_EVENT_INVALID,
      );
    }

    const value = entry.value;
    rejectPrivateKeyMaterial(value);
    if (value !== null) {
      const valueType = typeof value;
      if (
        !METADATA_VALUE_TYPES.has(valueType) ||
        (valueType === "number" && !Number.isFinite(value))
      ) {
        throw executorEventError(
          `${fieldName}.value is invalid`,
          CERTOPS_EXECUTOR_EVENT_INVALID,
        );
      }
      if (valueType === "string" && value.length > 512) {
        throw executorEventError(
          `${fieldName}.value is too long`,
          CERTOPS_EXECUTOR_EVENT_INVALID,
        );
      }
    }

    if (fieldNameLooksGenericSecret(name)) {
      const redactedMetadataKey = `redactedMetadata${index + 1}`;
      const category = genericSecretCategory(name);
      metadata[redactedMetadataKey] =
        GENERIC_SECRET_REDACTION_PLACEHOLDER;
      noteRedaction(tracker, [category]);
      if (idempotencyMetadata) {
        // The raw client field name may itself be sensitive. The idempotency
        // projection keeps only stable server categories, so equivalent secret
        // values, aliases, and metadata-entry ordering do not conflict on
        // retry. This is not a client redaction report.
        idempotencySecretCategories.push(category);
      }
      return;
    }

    let normalizedValue = value;
    if (typeof value === "string") {
      normalizedValue = redactGenericText(value, `${fieldName}.value`, tracker, 512);
    }

    metadata[name] = normalizedValue;
    if (idempotencyMetadata) idempotencyMetadata[name] = normalizedValue;
  });

  if (idempotencyMetadata && idempotencySecretCategories.length > 0) {
    idempotencyMetadata.redactedSecretCategories =
      idempotencySecretCategories.sort();
  }

  return normalizePublicObject(metadata, fieldName);
}

function eventMetadataFromBody(
  body,
  occurredAt,
  tracker = createRedactionTracker(),
  idempotencyMetadata = null,
) {
  const metadata = {
    executorEventId: body.eventId,
    executorEventType: body.eventType,
    executorStatus: body.status,
    occurredAt,
  };

  for (const [targetKey, sourceKey] of [
    ["certificateId", "certificateId"],
    ["executorId", "executorId"],
  ]) {
    const value = optionalPublicId(body[sourceKey], sourceKey);
    if (value) metadata[targetKey] = value;
  }

  const entries = metadataEntriesToObject(
    body.metadata,
    "metadata",
    tracker,
    idempotencyMetadata,
  );
  const report = immutableRedactionReport(tracker);
  return {
    metadata: normalizePublicObject(
      {
        ...metadata,
        ...entries,
        ...redactionMetadata(report),
      },
      "metadata",
    ),
    redactionReport: report,
  };
}

function evidenceSubjectFromItem(item) {
  const certificateId = optionalPublicId(item.certificateId, "certificateId");
  if (certificateId) {
    return { subjectType: "managed_certificate", subjectId: certificateId };
  }

  const certificateInstanceId = optionalPublicId(
    item.certificateInstanceId,
    "certificateInstanceId",
  );
  if (certificateInstanceId) {
    return {
      subjectType: "certificate_instance",
      subjectId: certificateInstanceId,
    };
  }

  const targetId = optionalPublicId(item.targetId, "targetId");
  if (targetId) {
    return { subjectType: "certificate_target", subjectId: targetId };
  }

  return { subjectType: null, subjectId: null };
}

function normalizeArtifactRefs(value, tracker = null) {
  if (value === undefined || value === null) return undefined;
  if (!Array.isArray(value)) {
    throw executorEventError(
      "artifactRefs must be an array",
      CERTOPS_EXECUTOR_EVENT_INVALID,
    );
  }
  if (value.length > 16) {
    throw executorEventError(
      "artifactRefs contains too many items",
      CERTOPS_EXECUTOR_EVENT_INVALID,
    );
  }

  return value.map((item) => {
    if (!isPlainObject(item)) {
      throw executorEventError(
        "artifactRefs item is invalid",
        CERTOPS_EXECUTOR_EVENT_INVALID,
      );
    }

    const keys = Object.keys(item);
    const allowedKeys = new Set(["type", "reference", "sha256"]);
    if (
      !keys.includes("type") ||
      !keys.includes("reference") ||
      keys.some((key) => !allowedKeys.has(key))
    ) {
      throw executorEventError(
        "artifactRefs item is invalid",
        CERTOPS_EXECUTOR_EVENT_INVALID,
      );
    }

    const type = requiredPublicText(item.type, "artifactRefs.type", 64);
    if (!ARTIFACT_REF_TYPES.has(type)) {
      throw executorEventError(
        "artifactRefs.type is invalid",
        CERTOPS_EXECUTOR_EVENT_INVALID,
      );
    }

    const reference = requiredPublicText(
      item.reference,
      "artifactRefs.reference",
      512,
      tracker,
    );
    const normalized = { type, reference };

    if (Object.prototype.hasOwnProperty.call(item, "sha256")) {
      if (item.sha256 === null) {
        normalized.sha256 = null;
      } else if (
        typeof item.sha256 === "string" &&
        SHA256_HEX_PATTERN.test(item.sha256)
      ) {
        rejectPrivateKeyMaterial(item.sha256);
        normalized.sha256 = item.sha256;
      } else {
        throw executorEventError(
          "artifactRefs.sha256 is invalid",
          CERTOPS_EXECUTOR_EVENT_INVALID,
        );
      }
    }

    return normalized;
  });
}

function evidenceMetadataFromItem(item, idempotencyMetadata = null) {
  const tracker = createRedactionTracker();
  const metadata = {};
  for (const [targetKey, value] of [
    ["source", optionalEvidenceEnum(item.source, "source", EVIDENCE_SOURCES)],
    ["status", optionalEvidenceEnum(item.status, "status", EVIDENCE_STATUSES)],
    ["fingerprintSha256", optionalFingerprintSha256(item.fingerprintSha256)],
    ["summary", optionalPublicText(item.summary, "summary", 1024, tracker)],
  ]) {
    if (value) {
      metadata[targetKey] = value;
      if (idempotencyMetadata) idempotencyMetadata[targetKey] = value;
    }
  }

  for (const [targetKey, sourceKey] of [
    ["evidenceId", "evidenceId"],
    ["certificateId", "certificateId"],
    ["certificateInstanceId", "certificateInstanceId"],
    ["targetId", "targetId"],
  ]) {
    const value = optionalPublicId(item[sourceKey], sourceKey);
    if (value) {
      metadata[targetKey] = value;
      if (idempotencyMetadata) idempotencyMetadata[targetKey] = value;
    }
  }

  const artifactRefs = normalizeArtifactRefs(item.artifactRefs, tracker);
  if (artifactRefs !== undefined) {
    metadata.artifactRefs = artifactRefs;
    if (idempotencyMetadata) idempotencyMetadata.artifactRefs = artifactRefs;
  }

  const customMetadata = {};
  const entries = metadataEntriesToObject(
    item.metadata,
    "evidence.metadata",
    tracker,
    customMetadata,
  );
  if (idempotencyMetadata && Object.keys(customMetadata).length > 0) {
    idempotencyMetadata.metadata = customMetadata;
  }
  const report = immutableRedactionReport(tracker);
  return {
    metadata: normalizePublicObject(
      {
        ...metadata,
        ...entries,
        ...redactionMetadata(report),
      },
      "metadata",
    ),
    redactionReport: report,
  };
}

function evidenceItemsFromBody(body) {
  if (body.evidence === undefined || body.evidence === null) return [];
  if (!Array.isArray(body.evidence)) {
    throw executorEventError(
      "evidence must be an array",
      CERTOPS_EXECUTOR_EVENT_INVALID,
    );
  }
  if (body.evidence.length > 16) {
    throw executorEventError(
      "evidence contains too many items",
      CERTOPS_EXECUTOR_EVENT_INVALID,
    );
  }
  return body.evidence.map((item) => {
    if (!isPlainObject(item)) {
      throw executorEventError(
        "evidence item is invalid",
        CERTOPS_EXECUTOR_EVENT_INVALID,
      );
    }

    rejectPrivateKeyMaterial(item);
    rejectUnknownEvidenceItemFields(item);
    if (item.schemaVersion !== undefined && item.schemaVersion !== 1) {
      throw executorEventError(
        "evidence.schemaVersion is invalid",
        CERTOPS_EXECUTOR_EVENT_INVALID,
      );
    }
    const hasItemJobId = Object.prototype.hasOwnProperty.call(item, "jobId");
    const hasItemWorkspaceId = Object.prototype.hasOwnProperty.call(
      item,
      "workspaceId",
    );
    const itemJobId = hasItemJobId
      ? requiredUuid(item.jobId, "evidence.jobId", CERTOPS_EXECUTOR_EVENT_INVALID)
      : body.jobId;
    const itemWorkspaceId = hasItemWorkspaceId
      ? requiredUuid(
          item.workspaceId,
          "evidence.workspaceId",
          CERTOPS_EXECUTOR_EVENT_INVALID,
        )
      : body.workspaceId;
    if (itemJobId !== body.jobId || itemWorkspaceId !== body.workspaceId) {
      throw executorEventError(
        "Evidence item context does not match the executor event",
        CERTOPS_EXECUTOR_EVENT_INVALID,
      );
    }
    if (
      item.redactionApplied !== undefined &&
      item.redactionApplied !== null &&
      typeof item.redactionApplied !== "boolean"
    ) {
      throw executorEventError(
        "evidence.redactionApplied is invalid",
        CERTOPS_EXECUTOR_EVENT_INVALID,
      );
    }
    const evidenceType = normalizeEvidenceEventType(item.eventType);
    const subject = evidenceSubjectFromItem(item);
    const idempotencyMetadata = {};
    const normalizedMetadata = evidenceMetadataFromItem(
      item,
      idempotencyMetadata,
    );
    const observedAt = normalizeRfc3339Timestamp(
      item.observedAt === undefined || item.observedAt === null
        ? body.occurredAt
        : item.observedAt,
      "observedAt",
    );
    const normalizedOutput = normalizeRedactedOutput(item.output);
    return {
      evidenceType,
      subjectType: subject.subjectType,
      subjectId: subject.subjectId,
      metadata: normalizedMetadata.metadata,
      redactionReport: normalizedMetadata.redactionReport,
      output: item.output,
      observedAt,
      idempotency: {
        schemaVersion: item.schemaVersion || 1,
        evidenceId: idempotencyMetadata.evidenceId || null,
        jobId: itemJobId,
        workspaceId: itemWorkspaceId,
        certificateId: idempotencyMetadata.certificateId || null,
        certificateInstanceId:
          idempotencyMetadata.certificateInstanceId || null,
        targetId: idempotencyMetadata.targetId || null,
        eventType: evidenceType,
        source: idempotencyMetadata.source || null,
        status: idempotencyMetadata.status || null,
        observedAt,
        fingerprintSha256:
          idempotencyMetadata.fingerprintSha256 || null,
        summary: idempotencyMetadata.summary || null,
        metadata: idempotencyMetadata.metadata || {},
        artifactRefs: idempotencyMetadata.artifactRefs || [],
        output:
          normalizedOutput.redactedOutput === null
            ? null
            : {
                redactedOutput: normalizedOutput.redactedOutput,
                outputSha256: normalizedOutput.outputSha256,
                outputSizeBytes: normalizedOutput.outputSizeBytes,
              },
      },
    };
  });
}

function executorEventIdempotencyPayload(event) {
  return {
    schemaVersion: event.schemaVersion,
    eventId: event.eventId,
    jobId: event.jobId,
    workspaceId: event.workspaceId,
    certificateId: event.certificateId,
    executorId: event.executorId,
    status: event.status,
    eventType: event.eventType,
    occurredAt: event.occurredAt,
    message: event.message,
    metadata: event.clientMetadata,
    evidence: event.evidence.map((item) => ({
      schemaVersion: item.idempotency.schemaVersion,
      evidenceId: item.idempotency.evidenceId,
      jobId: item.idempotency.jobId,
      workspaceId: item.idempotency.workspaceId,
      certificateId: item.idempotency.certificateId,
      certificateInstanceId: item.idempotency.certificateInstanceId,
      targetId: item.idempotency.targetId,
      eventType: item.idempotency.eventType,
      source: item.idempotency.source,
      status: item.idempotency.status,
      observedAt: item.idempotency.observedAt,
      fingerprintSha256: item.idempotency.fingerprintSha256,
      summary: item.idempotency.summary,
      metadata: item.idempotency.metadata,
      artifactRefs: item.idempotency.artifactRefs,
      output: item.idempotency.output,
    })),
  };
}

function executorEventRedactionSummary(event) {
  const reports = [
    event.redactionReport,
    ...event.evidence.map((item) => item.redactionReport),
  ];
  const tracker = createRedactionTracker();
  for (const report of reports) {
    const normalized = immutableRedactionReport(report);
    tracker.count += normalized.count;
    for (const category of normalized.categories) tracker.categories.add(category);
  }
  const normalized = immutableRedactionReport(tracker);
  return {
    redactionApplied: normalized.count > 0,
    redactionCount: normalized.count,
    redactedFields: normalized.categories,
  };
}

async function writeExecutorAudit({
  client = null,
  workspaceId,
  action,
  metadata,
}) {
  await writeAudit({
    client,
    actorUserId: null,
    subjectUserId: null,
    action,
    targetType: "certificate_job",
    targetId: null,
    workspaceId,
    metadata,
  });
}

async function recordExecutorKeyMaterialRejection(req) {
  await writeExecutorAudit({
    workspaceId: req.apiToken?.workspaceId || null,
    action: "CERTOPS_KEY_MATERIAL_REJECTED",
    metadata: {
      code: PRIVATE_KEY_MATERIAL_REJECTED,
      method: req.method || null,
      routeFamily: certOpsMachineWriteRouteFamilyFromRequest(req),
      apiTokenId: req.apiToken?.id || null,
    },
  });
}

function normalizeExecutorEventBody(body, apiToken) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw executorEventError(
      "Executor event body is invalid",
      CERTOPS_EXECUTOR_EVENT_INVALID,
    );
  }

  rejectPrivateKeyMaterial(body);
  rejectUnknownTopLevelFields(body);

  if (body.schemaVersion !== 1) {
    throw executorEventError(
      "Executor event schemaVersion is invalid",
      CERTOPS_EXECUTOR_EVENT_INVALID,
    );
  }

  const bodyWorkspaceId = requiredUuid(
    body.workspaceId,
    "workspaceId",
    CERTOPS_EXECUTOR_EVENT_INVALID,
  );
  const workspaceId = apiToken?.workspaceId;
  if (!workspaceId || bodyWorkspaceId !== workspaceId) {
    throw executorEventError(
      "Executor event workspace mismatch",
      CERTOPS_EXECUTOR_WORKSPACE_MISMATCH,
    );
  }

  const eventType = normalizeEventType(body.eventType);
  assertRequiredEvidenceItems(body);
  const status = normalizeStatus(body.status);
  assertEventStatusMatch(eventType, status);
  const jobId = requiredUuid(
    body.jobId,
    "jobId",
    CERTOPS_EXECUTOR_JOB_REQUIRED,
  );
  const eventId = requiredPublicId(
    body.eventId,
    "eventId",
    CERTOPS_EXECUTOR_EVENT_INVALID,
  );
  const occurredAt = normalizeOccurredAt(body.occurredAt);
  const tracker = createRedactionTracker();
  const message = optionalPublicText(body.message, "message", 1024, tracker);
  const clientMetadata = {};
  const normalizedMetadata = eventMetadataFromBody(
    body,
    occurredAt,
    tracker,
    clientMetadata,
  );
  const evidence = evidenceItemsFromBody(body);

  return {
    schemaVersion: 1,
    eventId,
    eventType,
    jobId,
    workspaceId,
    certificateId: normalizedMetadata.metadata.certificateId || null,
    executorId: normalizedMetadata.metadata.executorId || null,
    status,
    message,
    occurredAt,
    logStatus: LOG_STATUSES_SET.has(status) ? status : null,
    jobStatus: JOB_STATUS_BY_EVENT_TYPE[eventType] || null,
    metadata: normalizedMetadata.metadata,
    redactionReport: normalizedMetadata.redactionReport,
    clientMetadata,
    evidence,
  };
}

async function persistEvidenceItems({ client, event, workspaceId, apiToken }) {
  const created = [];
  for (const item of event.evidence) {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw executorEventError(
        "evidence item is invalid",
        CERTOPS_EXECUTOR_EVENT_INVALID,
      );
    }

    const evidence = await createCertificateEvidence({
      client,
      workspaceId,
      jobId: event.jobId,
      evidenceType: item.evidenceType,
      subjectType: item.subjectType,
      subjectId: item.subjectId,
      metadata: item.metadata,
      output: item.output,
      observedAt: item.observedAt,
      createdByApiTokenId: apiToken.id,
    });
    created.push(evidence);
  }
  return created;
}

function redactionSummary(event, evidenceItems) {
  let applied = Boolean(event.metadata?.redactionApplied);
  let count = Number.isInteger(event.metadata?.redactionCount)
    ? event.metadata.redactionCount
    : 0;

  for (const item of evidenceItems || []) {
    if (item.metadata?.redactionApplied) applied = true;
    if (Number.isInteger(item.metadata?.redactionCount)) {
      count += item.metadata.redactionCount;
    }
    if (item.outputRedactionApplied) applied = true;
    if (Number.isInteger(item.outputRedactionCount)) {
      count += item.outputRedactionCount;
    }
  }

  return { redactionApplied: applied, redactionCount: count };
}

function handleExecutorEventError(res, error) {
  if (error?.code === PRIVATE_KEY_MATERIAL_REJECTED) {
    return res.status(422).json({
      error: "Private key material is not accepted in CertOps executor events",
      code: PRIVATE_KEY_MATERIAL_REJECTED,
    });
  }

  if (error?.code === CERTOPS_JOB_NOT_FOUND) {
    return res.status(404).json({
      error: "Certificate job not found",
      code: CERTOPS_JOB_NOT_FOUND,
    });
  }

  if (error?.code === CERTOPS_EXECUTOR_WORKSPACE_MISMATCH) {
    return res.status(403).json({
      error: "Executor event workspace mismatch",
      code: CERTOPS_EXECUTOR_WORKSPACE_MISMATCH,
    });
  }

  if (error?.code === CERTOPS_API_TOKEN_SCOPE_DENIED) {
    return res.status(403).json({
      error: "CertOps API token scope denied",
      code: CERTOPS_API_TOKEN_SCOPE_DENIED,
    });
  }

  if (
    error?.code === CERTOPS_JOB_STATUS_TRANSITION_INVALID ||
    error?.code === CERTOPS_EXECUTOR_EVENT_CONFLICT
  ) {
    return res.status(409).json({
      error:
        error.code === CERTOPS_EXECUTOR_EVENT_CONFLICT
          ? "Executor event conflicts with a previously accepted event"
          : "Executor event conflicts with the current certificate job status",
      code: error.code,
    });
  }

  if (error?.code === CERTOPS_EVIDENCE_OUTPUT_TOO_LARGE) {
    return res.status(413).json({
      error: "CertOps evidence output is too large",
      code: CERTOPS_EVIDENCE_OUTPUT_TOO_LARGE,
    });
  }

  const badRequestCodes = new Set([
    CERTOPS_EXECUTOR_EVENT_INVALID,
    CERTOPS_EXECUTOR_EVENT_TYPE_INVALID,
    CERTOPS_EXECUTOR_EVENT_STATUS_MISMATCH,
    CERTOPS_EXECUTOR_JOB_REQUIRED,
    CERTOPS_JOB_INVALID,
    CERTOPS_JOB_STATUS_INVALID,
    CERTOPS_JOB_LOG_EVENT_TYPE_INVALID,
    CERTOPS_EVIDENCE_INVALID,
    CERTOPS_EVIDENCE_TYPE_INVALID,
  ]);
  if (badRequestCodes.has(error?.code)) {
    return res.status(400).json({
      error: "Executor event is invalid",
      code: error.code,
    });
  }

  return null;
}

async function auditExecutorRejection(req, error, mode) {
  if (error?.skipExecutorRejectionAudit) return;
  const hints = safeAuditHintsFromRequest(req);
  if (error?.code === PRIVATE_KEY_MATERIAL_REJECTED) {
    if (mode === "evidence" || Array.isArray(req.body?.evidence)) {
      await writeExecutorRejectionAudit({
        action: "CERTOPS_EVIDENCE_REJECTED",
        ...hints,
        rejectionCode: PRIVATE_KEY_MATERIAL_REJECTED,
      });
    }
    return;
  }

  if (
    error?.code === CERTOPS_EVIDENCE_INVALID ||
    error?.code === CERTOPS_EVIDENCE_TYPE_INVALID ||
    error?.code === CERTOPS_EVIDENCE_OUTPUT_TOO_LARGE
  ) {
    await writeExecutorRejectionAudit({
      action: "CERTOPS_EVIDENCE_REJECTED",
      ...hints,
      rejectionCode: error?.code || CERTOPS_EXECUTOR_EVENT_INVALID,
    });
  }
}

async function executorEventsHandler(req, res, options = {}) {
  try {
    const workspaceId = req.apiToken.workspaceId;
    const eventBody = bodyWithPathJobContext(req, options.mode);
    // The scope middleware lets a private-key detection reach this handler so
    // the canonical 422 response is coupled to its synchronous security audit.
    // Keep that lightweight scan ahead of scope enforcement without invoking
    // full event normalization for an otherwise unauthorized evidence payload.
    rejectPrivateKeyMaterial(eventBody);
    assertRequiredEvidenceItems(eventBody, options.mode || null);
    requireEvidenceWriteScopeForEvidencePayload(req, eventBody);
    const event = normalizeExecutorEventBody(eventBody, req.apiToken);
    const result = await ingestExecutorEvent({
      workspaceId,
      jobId: event.jobId,
      eventId: event.eventId,
      request: executorEventIdempotencyPayload(event),
      apiTokenId: req.apiToken.id,
      process: async (client, executorEventRecord) => {
        const job = await getCertificateJobById({
          client,
          workspaceId,
          jobId: event.jobId,
        });
        if (!job) {
          throw executorEventError(
            "Certificate job not found",
            CERTOPS_JOB_NOT_FOUND,
          );
        }

        let updatedJob = job;
        if (event.jobStatus) {
          updatedJob = await updateCertificateJobStatus({
            client,
            workspaceId,
            jobId: event.jobId,
            status: event.jobStatus,
          });
        }

        const log = await appendCertificateJobLog({
          client,
          workspaceId,
          jobId: event.jobId,
          eventType: event.eventType,
          status: event.logStatus,
          message: event.message,
          metadata: {
            ...event.metadata,
            jobStatusTransitionApplied:
              updatedJob.statusTransitionApplied ?? false,
            jobStatusTransitionIgnored:
              updatedJob.statusTransitionIgnored ?? false,
            jobStatusTransitionIgnoredReason:
              updatedJob.statusTransitionIgnoredReason || null,
          },
          createdByApiTokenId: req.apiToken.id,
        });

        const evidence = await persistEvidenceItems({
          client,
          event,
          workspaceId,
          apiToken: req.apiToken,
        });
        const persistedRedaction = redactionSummary(event, evidence);

        const safeAuditMetadata = {
          apiTokenId: req.apiToken.id,
          executorEventRecordId: executorEventRecord.id,
          executorEventId: event.eventId,
          eventType: event.eventType,
          jobId: event.jobId,
          logId: log.id,
          status: updatedJob.status,
          evidenceIds: evidence.map((item) => item.id),
        };
        await writeExecutorAudit({
          client,
          workspaceId,
          action: "CERTOPS_EXECUTOR_EVENT_ACCEPTED",
          metadata: safeAuditMetadata,
        });
        if (evidence.length > 0) {
          await writeExecutorAudit({
            client,
            workspaceId,
            action: "CERTOPS_EVIDENCE_ACCEPTED",
            metadata: safeAuditMetadata,
          });
        }

        const metadataRedaction = executorEventRedactionSummary(event);
        if (persistedRedaction.redactionApplied) {
          await writeExecutorAudit({
            client,
            workspaceId,
            action: "CERTOPS_GENERIC_SECRET_REDACTION_APPLIED",
            metadata: {
              ...safeAuditMetadata,
              redactionApplied: true,
              redactionCount: persistedRedaction.redactionCount,
              redactedFields: metadataRedaction.redactedFields,
            },
          });
        }

        const response = {
          ok: true,
          eventId: log.id,
          logId: log.id,
          jobId: event.jobId,
          status: updatedJob.status,
          evidenceId: evidence[0]?.id || null,
          evidenceIds: evidence.map((item) => item.id),
          executorEventRecordId: executorEventRecord?.id || null,
          ...persistedRedaction,
        };
        return response;
      },
    });

    return res.status(202).json({
      ...result.response,
      duplicate: result.duplicate,
      idempotent: result.duplicate,
    });
  } catch (error) {
    const privateKeyMaterialRejected =
      error?.code === PRIVATE_KEY_MATERIAL_REJECTED;
    if (privateKeyMaterialRejected) {
      try {
        await recordExecutorKeyMaterialRejection(req);
      } catch (auditError) {
        logger.warn("Failed to record CertOps key-material rejection audit", {
          code: auditError?.code || null,
          errorName: auditError?.name || null,
          routeFamily: certOpsMachineWriteRouteFamilyFromRequest(req),
          method: req.method || null,
        });
        return res.status(503).json({
          error: "Security audit unavailable",
          code: CERTOPS_SECURITY_AUDIT_UNAVAILABLE,
        });
      }
    }
    try {
      if (!privateKeyMaterialRejected) {
        await auditExecutorRejection(req, error, options.mode);
      }
    } catch (auditError) {
      logger.warn("CertOps executor audit write failed", {
        error: auditError.message,
        code: auditError.code || null,
        workspaceId: req.apiToken?.workspaceId || null,
        apiTokenId: req.apiToken?.id || null,
      });
    }
    const handled = handleExecutorEventError(res, error);
    if (handled) return handled;

    logger.error("CertOps executor event ingestion failed", {
      errorName: error?.name || null,
      code: error.code || null,
      workspaceId: req.apiToken?.workspaceId || null,
      apiTokenId: req.apiToken?.id || null,
    });
    return res.status(500).json({
      error: "Failed to ingest CertOps executor event",
      code: "INTERNAL_ERROR",
    });
  }
}

function requireExecutorEvidenceScope(req, res, next) {
  if (!requestCarriesEvidence(req.body)) return next();

  try {
    // Preserve the fail-closed private-key boundary: the handler converts this
    // class of input into the canonical 422 response and synchronous audit.
    rejectPrivateKeyMaterial(req.body);
  } catch (error) {
    if (error?.code === PRIVATE_KEY_MATERIAL_REJECTED) return next();
    return next(error);
  }

  try {
    requireEvidenceWriteScopeForEvidencePayload(req, req.body);
    return next();
  } catch (error) {
    if (error?.code !== CERTOPS_API_TOKEN_SCOPE_DENIED) return next(error);
    return res.status(403).json({
      error: "CertOps API token scope denied",
      code: CERTOPS_API_TOKEN_SCOPE_DENIED,
    });
  }
}

function createCertOpsExecutorRouter(options = {}) {
  const certOpsExecutorRouter = router();
  const preAuthRateLimitMiddleware =
    options.preAuthRateLimitMiddleware ||
    createCertOpsMachineTokenPreAuthRateLimit(
      options.preAuthRateLimitOptions || options.rateLimitOptions || {},
    );
  const authMiddleware =
    options.authMiddleware ||
    createCertOpsApiTokenAuth({
      scopes: [EXECUTOR_EVENT_SCOPE],
      resolveWorkspaceId: workspaceIdHintFromBody,
    });
  const certOpsEnabledMiddleware =
    options.certOpsEnabledMiddleware || requireCertOpsEnabled;
  const perJobEventAuthMiddleware =
    options.perJobEventAuthMiddleware ||
    createCertOpsApiTokenAuth({
      scopes: [EXECUTOR_EVENT_SCOPE],
      allowTokenWorkspace: true,
    });
  const perJobEvidenceAuthMiddleware =
    options.perJobEvidenceAuthMiddleware ||
    createCertOpsApiTokenAuth({
      scopes: [EXECUTOR_EVIDENCE_SCOPE],
      allowTokenWorkspace: true,
    });
  const rateLimitMiddleware =
    options.rateLimitMiddleware ||
    createCertOpsMachineTokenRateLimit(options.rateLimitOptions || {});
  const preAuthRateLimitFallback = (req, res, next) => {
    if (hasCertOpsExecutorPreAuthLimit(req)) return next();
    return preAuthRateLimitMiddleware(req, res, next);
  };

  certOpsExecutorRouter.post(
    "/api/v1/certops/executor/events",
    preAuthRateLimitFallback,
    certOpsEnabledMiddleware,
    authMiddleware,
    rateLimitMiddleware,
    requireEvidenceItems,
    requireExecutorEvidenceScope,
    executorEventsHandler,
  );

  certOpsExecutorRouter.post(
    "/api/v1/certops/jobs/:jobId/events",
    preAuthRateLimitFallback,
    certOpsEnabledMiddleware,
    perJobEventAuthMiddleware,
    rateLimitMiddleware,
    requireEvidenceItems,
    requireExecutorEvidenceScope,
    (req, res) => executorEventsHandler(req, res, { mode: "event" }),
  );

  certOpsExecutorRouter.post(
    "/api/v1/certops/jobs/:jobId/evidence",
    preAuthRateLimitFallback,
    certOpsEnabledMiddleware,
    perJobEvidenceAuthMiddleware,
    rateLimitMiddleware,
    (req, res, next) => requireEvidenceItems(req, res, next, { mode: "evidence" }),
    (req, res) => executorEventsHandler(req, res, { mode: "evidence" }),
  );

  return certOpsExecutorRouter;
}

const defaultRouter = createCertOpsExecutorRouter();

module.exports = defaultRouter;
module.exports.createCertOpsExecutorRouter = createCertOpsExecutorRouter;
module.exports._test = {
  CERTOPS_EXECUTOR_EVENT_INVALID,
  CERTOPS_EXECUTOR_EVENT_STATUS_MISMATCH,
  CERTOPS_EXECUTOR_EVENT_TYPE_INVALID,
  CERTOPS_EXECUTOR_JOB_REQUIRED,
  CERTOPS_EXECUTOR_WORKSPACE_MISMATCH,
  EXECUTOR_EVENT_TYPES,
  EXECUTOR_EVIDENCE_SCOPE,
  EXECUTOR_EVENT_SCOPE,
  EVIDENCE_SOURCES,
  EVIDENCE_STATUSES,
  EVIDENCE_EVENT_TYPES,
  EVENT_METADATA_RESERVED_NAMES,
  EVIDENCE_METADATA_RESERVED_NAMES,
  SECURITY_METADATA_RESERVED_NAMES,
  RESERVED_METADATA_NAMES,
  REDACTION_CATEGORIES,
  assertEventStatusMatch,
  createRedactionTracker,
  EVIDENCE_ITEM_FIELDS,
  evidenceMetadataFromItem,
  executorEventIdempotencyPayload,
  executorEventRedactionSummary,
  evidenceSubjectFromItem,
  handleExecutorEventError,
  metadataEntriesToObject,
  mergeRedactionReport,
  immutableRedactionReport,
  isReservedMetadataName,
  normalizeExecutorEventBody,
  normalizeRfc3339Timestamp,
  normalizeEvidenceEventType,
  requestCarriesEvidence,
  assertRequiredEvidenceItems,
  requireEvidenceItems,
  requireExecutorEvidenceScope,
};

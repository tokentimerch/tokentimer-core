"use strict";

const router = require("express").Router;

const {
  createCertOpsApiTokenAuth,
} = require("../middleware/api-token-auth");
const {
  createCertOpsMachineTokenRateLimit,
} = require("../middleware/machine-token-rate-limit");
const { logger } = require("../utils/logger");
const {
  CERTOPS_JOB_INVALID,
  CERTOPS_JOB_LOG_EVENT_TYPE_INVALID,
  CERTOPS_JOB_NOT_FOUND,
  CERTOPS_JOB_STATUS_INVALID,
  JOB_LOG_EVENT_TYPES,
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
} = require("../services/certops/evidence");
const {
  CERTOPS_EXECUTOR_EVENT_CONFLICT,
  hashExecutorEventPayload,
  runExecutorEventIdempotently,
} = require("../services/certops/executorEvents");
const {
  GENERIC_SECRET_REDACTION_PLACEHOLDER,
  containsPrivateKeyMaterial,
  fieldNameLooksGenericSecret,
  fieldNameLooksPrivateKeyMaterial,
  redactGenericSecretsWithReport,
} = require("../utils/secretMaterial");
const { writeAudit } = require("../services/audit");

const CERTOPS_EXECUTOR_EVENT_INVALID = "CERTOPS_EXECUTOR_EVENT_INVALID";
const CERTOPS_EXECUTOR_EVENT_TYPE_INVALID =
  "CERTOPS_EXECUTOR_EVENT_TYPE_INVALID";
const CERTOPS_EXECUTOR_JOB_REQUIRED = "CERTOPS_EXECUTOR_JOB_REQUIRED";
const CERTOPS_EXECUTOR_WORKSPACE_MISMATCH =
  "CERTOPS_EXECUTOR_WORKSPACE_MISMATCH";

const EXECUTOR_EVENT_SCOPE = "certops:events:write";
const EVIDENCE_WRITE_SCOPE = "certops:evidence:write";
const PUBLIC_ID_PATTERN = /^[A-Za-z0-9_.:-]+$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const METADATA_NAME_PATTERN = /^[A-Za-z0-9_.:-]{1,64}$/;
const METADATA_VALUE_TYPES = new Set(["string", "number", "boolean"]);
const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/;
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
const EXECUTOR_EVENT_TOP_LEVEL_FIELDS = new Set([
  "schemaVersion",
  "eventId",
  "jobId",
  "workspaceId",
  "certificateId",
  "executorId",
  "attemptId",
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

const LOG_STATUS_BY_EVENT_TYPE = Object.freeze({
  "job.accepted": "claimed",
  "job.started": "running",
  "job.progress": "running",
  "job.completed": "succeeded",
  "job.failed": "failed",
  "job.rejected": "rejected",
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

async function writeExecutorAudit({
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
  };
}

function workspaceIdHintFromBody(req) {
  return typeof req.body?.workspaceId === "string" ? req.body.workspaceId : null;
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
    fields: new Set(),
  };
}

function noteRedaction(tracker, fields = []) {
  if (!tracker) return;
  tracker.count += 1;
  for (const field of fields) tracker.fields.add(field);
  if (fields.length === 0) tracker.fields.add("generic");
}

function mergeRedactionReport(tracker, report, fallbackField) {
  if (!tracker || !report?.redactionApplied) return;
  tracker.count += report.redactionCount || 1;
  const fields = Array.isArray(report.redactedFields)
    ? report.redactedFields
    : [];
  if (fields.length === 0) {
    tracker.fields.add(fallbackField || "generic");
    return;
  }
  for (const _field of fields) tracker.fields.add(fallbackField || "generic");
}

function redactionMetadata(tracker) {
  if (!tracker || tracker.count <= 0) return {};
  return {
    redactionApplied: true,
    redactionCount: tracker.count,
    redactedFields: Array.from(tracker.fields).sort(),
  };
}

function rejectPrivateKeyMaterial(value, depth = 0, seen = new WeakSet()) {
  if (depth > 12) throw privateKeyMaterialError();
  if (containsPrivateKeyMaterial(value)) throw privateKeyMaterialError();
  if (value === null || value === undefined) return;

  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return;
  }
  if (Buffer.isBuffer(value)) throw privateKeyMaterialError();
  if (Array.isArray(value)) {
    for (const item of value) rejectPrivateKeyMaterial(item, depth + 1, seen);
    return;
  }
  if (typeof value === "object") {
    if (seen.has(value)) throw privateKeyMaterialError();
    seen.add(value);
    for (const [key, item] of Object.entries(value)) {
      if (fieldNameLooksPrivateKeyMaterial(key)) throw privateKeyMaterialError();
      rejectPrivateKeyMaterial(item, depth + 1, seen);
    }
    seen.delete(value);
  }
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
  mergeRedactionReport(tracker, report, fieldName);
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

function normalizeOccurredAt(value) {
  const occurredAt = requiredTrimmedString(
    value,
    "occurredAt",
    CERTOPS_EXECUTOR_EVENT_INVALID,
  );
  const date = new Date(occurredAt);
  if (Number.isNaN(date.getTime())) {
    throw executorEventError(
      "occurredAt is invalid",
      CERTOPS_EXECUTOR_EVENT_INVALID,
    );
  }
  return date.toISOString();
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
  if (!LOG_STATUSES_SET.has(status) || status === "queued") {
    throw executorEventError("Executor event status is invalid", CERTOPS_JOB_STATUS_INVALID);
  }
  return status;
}

function metadataEntriesToObject(entries, fieldName, tracker = null) {
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
      metadata[`redactedMetadata${index + 1}`] =
        GENERIC_SECRET_REDACTION_PLACEHOLDER;
      noteRedaction(tracker, [fieldName]);
      return;
    }

    let normalizedValue = value;
    if (typeof value === "string") {
      normalizedValue = redactGenericText(value, `${fieldName}.value`, tracker, 512);
    }

    metadata[name] = normalizedValue;
  });

  return normalizePublicObject(metadata, fieldName);
}

function eventMetadataFromBody(body, occurredAt, tracker = createRedactionTracker()) {
  const metadata = {
    executorEventId: body.eventId,
    executorEventType: body.eventType,
    executorStatus: body.status,
    occurredAt,
  };

  for (const [targetKey, sourceKey] of [
    ["certificateId", "certificateId"],
    ["executorId", "executorId"],
    ["attemptId", "attemptId"],
  ]) {
    const value = optionalPublicId(body[sourceKey], sourceKey);
    if (value) metadata[targetKey] = value;
  }

  const entries = metadataEntriesToObject(body.metadata, "metadata", tracker);
  return normalizePublicObject(
    {
      ...metadata,
      ...entries,
      ...redactionMetadata(tracker),
    },
    "metadata",
  );
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

function evidenceMetadataFromItem(item) {
  const tracker = createRedactionTracker();
  const metadata = {};
  for (const [targetKey, sourceKey] of [
    ["source", "source"],
    ["status", "status"],
    ["fingerprintSha256", "fingerprintSha256"],
    ["summary", "summary"],
  ]) {
    const maxLength =
      sourceKey === "summary" ? 1024 : sourceKey === "fingerprintSha256" ? 64 : 128;
    const value = optionalPublicText(item[sourceKey], sourceKey, maxLength, tracker);
    if (value) metadata[targetKey] = value;
  }

  for (const [targetKey, sourceKey] of [
    ["evidenceId", "evidenceId"],
    ["certificateId", "certificateId"],
    ["certificateInstanceId", "certificateInstanceId"],
    ["targetId", "targetId"],
  ]) {
    const value = optionalPublicId(item[sourceKey], sourceKey);
    if (value) metadata[targetKey] = value;
  }

  const artifactRefs = normalizeArtifactRefs(item.artifactRefs, tracker);
  if (artifactRefs !== undefined) {
    metadata.artifactRefs = artifactRefs;
  }

  const entries = metadataEntriesToObject(item.metadata, "evidence.metadata", tracker);
  return normalizePublicObject(
    {
      ...metadata,
      ...entries,
      ...redactionMetadata(tracker),
    },
    "metadata",
  );
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
    const evidenceType = requiredTrimmedString(
      item.eventType,
      "evidence.eventType",
      CERTOPS_EVIDENCE_TYPE_INVALID,
    );
    rejectPrivateKeyMaterial(evidenceType);
    const subject = evidenceSubjectFromItem(item);
    return {
      evidenceType,
      subjectType: subject.subjectType,
      subjectId: subject.subjectId,
      metadata: evidenceMetadataFromItem(item),
      output: item.output,
      observedAt: item.observedAt || body.occurredAt,
    };
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
  const status = normalizeStatus(body.status);
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

  return {
    eventId,
    eventType,
    jobId,
    message: optionalPublicText(body.message, "message", 1024, tracker),
    occurredAt,
    logStatus: LOG_STATUS_BY_EVENT_TYPE[eventType] || status,
    jobStatus: JOB_STATUS_BY_EVENT_TYPE[eventType] || null,
    metadata: eventMetadataFromBody(body, occurredAt, tracker),
    evidence: evidenceItemsFromBody(body),
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

  if (error?.code === CERTOPS_EXECUTOR_EVENT_CONFLICT) {
    return res.status(409).json({
      error: "Executor event idempotency key conflicts with a different payload",
      code: CERTOPS_EXECUTOR_EVENT_CONFLICT,
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
  const hints = safeAuditHintsFromRequest(req);
  if (error?.code === PRIVATE_KEY_MATERIAL_REJECTED) {
    await writeExecutorAudit({
      action: "CERTOPS_KEY_MATERIAL_REJECTED",
      ...hints,
      rejectionCode: PRIVATE_KEY_MATERIAL_REJECTED,
    });
    if (mode === "evidence" || Array.isArray(req.body?.evidence)) {
      await writeExecutorAudit({
        action: "CERTOPS_EVIDENCE_REJECTED",
        ...hints,
        rejectionCode: PRIVATE_KEY_MATERIAL_REJECTED,
      });
    }
    return;
  }

  if (error?.code === CERTOPS_EXECUTOR_EVENT_CONFLICT) {
    await writeExecutorAudit({
      action: "CERTOPS_EXECUTOR_EVENT_CONFLICT",
      ...hints,
      rejectionCode: CERTOPS_EXECUTOR_EVENT_CONFLICT,
    });
    return;
  }

  if (
    mode === "evidence" ||
    Array.isArray(req.body?.evidence) ||
    error?.code === CERTOPS_EVIDENCE_INVALID ||
    error?.code === CERTOPS_EVIDENCE_TYPE_INVALID ||
    error?.code === CERTOPS_EVIDENCE_OUTPUT_TOO_LARGE
  ) {
    await writeExecutorAudit({
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
    const event = normalizeExecutorEventBody(eventBody, req.apiToken);
    const requestHashSha256 = hashExecutorEventPayload({
      workspaceId,
      jobId: event.jobId,
      event,
    });
    const result = await runExecutorEventIdempotently(
      {
        workspaceId,
        jobId: event.jobId,
        executorEventId: event.eventId,
        eventType: event.eventType,
        requestHashSha256,
        createdByApiTokenId: req.apiToken.id,
      },
      async (client) => {
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

        const log = await appendCertificateJobLog({
          client,
          workspaceId,
          jobId: event.jobId,
          eventType: event.eventType,
          status: event.logStatus,
          message: event.message,
          metadata: event.metadata,
          createdByApiTokenId: req.apiToken.id,
        });

        let updatedJob = null;
        if (event.jobStatus) {
          updatedJob = await updateCertificateJobStatus({
            client,
            workspaceId,
            jobId: event.jobId,
            status: event.jobStatus,
          });
        }

        const evidence = await persistEvidenceItems({
          client,
          event,
          workspaceId,
          apiToken: req.apiToken,
        });
        const redaction = redactionSummary(event, evidence);

        return {
          eventId: log.id,
          logId: log.id,
          jobId: event.jobId,
          status: updatedJob?.status || job.status,
          evidenceId: evidence[0]?.id || null,
          evidenceIds: evidence.map((item) => item.id),
          redactionApplied: redaction.redactionApplied,
          redactionCount: redaction.redactionCount,
        };
      },
    );

    const metadata = result.responseMetadata || {};
    await writeExecutorAudit({
      action: "CERTOPS_EXECUTOR_EVENT_ACCEPTED",
      workspaceId,
      apiTokenId: req.apiToken.id,
      jobId: event.jobId,
      eventId: event.eventId,
      eventType: event.eventType,
      evidenceIds: metadata.evidenceIds || [],
      redactionApplied: metadata.redactionApplied,
      redactionCount: metadata.redactionCount,
    });
    if ((metadata.evidenceIds || []).length > 0) {
      await writeExecutorAudit({
        action: "CERTOPS_EVIDENCE_ACCEPTED",
        workspaceId,
        apiTokenId: req.apiToken.id,
        jobId: event.jobId,
        eventId: event.eventId,
        eventType: event.eventType,
        evidenceIds: metadata.evidenceIds || [],
        redactionApplied: metadata.redactionApplied,
        redactionCount: metadata.redactionCount,
      });
    }
    if (metadata.redactionApplied) {
      await writeExecutorAudit({
        action: "CERTOPS_GENERIC_SECRET_REDACTION_APPLIED",
        workspaceId,
        apiTokenId: req.apiToken.id,
        jobId: event.jobId,
        eventId: event.eventId,
        eventType: event.eventType,
        evidenceIds: metadata.evidenceIds || [],
        redactionApplied: true,
        redactionCount: metadata.redactionCount,
      });
    }

    return res.status(202).json({
      ok: true,
      eventId: metadata.eventId,
      logId: metadata.logId,
      jobId: event.jobId,
      status: metadata.status,
      evidenceId: metadata.evidenceId || undefined,
      evidenceIds: metadata.evidenceIds || [],
      executorEventRecordId: metadata.executorEventRecordId || result.record?.id,
      duplicate: result.duplicate,
      idempotent: result.idempotent,
    });
  } catch (error) {
    try {
      await auditExecutorRejection(req, error, options.mode);
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
      error: error.message,
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

function createCertOpsExecutorRouter(options = {}) {
  const certOpsExecutorRouter = router();
  const authMiddleware =
    options.authMiddleware ||
    createCertOpsApiTokenAuth({
      scopes: [EXECUTOR_EVENT_SCOPE],
      resolveWorkspaceId: workspaceIdHintFromBody,
    });
  const perJobEventAuthMiddleware =
    options.perJobEventAuthMiddleware ||
    createCertOpsApiTokenAuth({
      scopes: [EXECUTOR_EVENT_SCOPE],
      allowTokenWorkspace: true,
    });
  const perJobEvidenceAuthMiddleware =
    options.perJobEvidenceAuthMiddleware ||
    createCertOpsApiTokenAuth({
      scopes: [EVIDENCE_WRITE_SCOPE],
      allowTokenWorkspace: true,
    });
  const rateLimitMiddleware =
    options.rateLimitMiddleware ||
    createCertOpsMachineTokenRateLimit(options.rateLimitOptions || {});

  certOpsExecutorRouter.post(
    "/api/v1/certops/executor/events",
    authMiddleware,
    rateLimitMiddleware,
    executorEventsHandler,
  );

  certOpsExecutorRouter.post(
    "/api/v1/certops/jobs/:jobId/events",
    perJobEventAuthMiddleware,
    rateLimitMiddleware,
    (req, res) => executorEventsHandler(req, res, { mode: "event" }),
  );

  certOpsExecutorRouter.post(
    "/api/v1/certops/jobs/:jobId/evidence",
    perJobEvidenceAuthMiddleware,
    rateLimitMiddleware,
    (req, res) => executorEventsHandler(req, res, { mode: "evidence" }),
  );

  return certOpsExecutorRouter;
}

const defaultRouter = createCertOpsExecutorRouter();

module.exports = defaultRouter;
module.exports.createCertOpsExecutorRouter = createCertOpsExecutorRouter;
module.exports._test = {
  CERTOPS_EXECUTOR_EVENT_INVALID,
  CERTOPS_EXECUTOR_EVENT_TYPE_INVALID,
  CERTOPS_EXECUTOR_JOB_REQUIRED,
  CERTOPS_EXECUTOR_WORKSPACE_MISMATCH,
  EXECUTOR_EVENT_TYPES,
  EVIDENCE_ITEM_FIELDS,
  evidenceMetadataFromItem,
  evidenceSubjectFromItem,
  handleExecutorEventError,
  metadataEntriesToObject,
  normalizeExecutorEventBody,
};

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
  assertSafePublicValue,
  fieldNameLooksForbidden,
  getCertificateJobById,
  normalizePublicObject,
  serviceError,
  updateCertificateJobStatus,
} = require("../services/certops/jobs");
const {
  CERTOPS_EVIDENCE_INVALID,
  CERTOPS_EVIDENCE_TYPE_INVALID,
  createCertificateEvidence,
} = require("../services/certops/evidence");

const CERTOPS_EXECUTOR_EVENT_INVALID = "CERTOPS_EXECUTOR_EVENT_INVALID";
const CERTOPS_EXECUTOR_EVENT_TYPE_INVALID =
  "CERTOPS_EXECUTOR_EVENT_TYPE_INVALID";
const CERTOPS_EXECUTOR_JOB_REQUIRED = "CERTOPS_EXECUTOR_JOB_REQUIRED";
const CERTOPS_EXECUTOR_WORKSPACE_MISMATCH =
  "CERTOPS_EXECUTOR_WORKSPACE_MISMATCH";

const EXECUTOR_EVENT_SCOPE = "certops:executor:events";
const PUBLIC_ID_PATTERN = /^[A-Za-z0-9_.:-]+$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const METADATA_NAME_PATTERN = /^[A-Za-z0-9_.:-]{1,64}$/;
const METADATA_VALUE_TYPES = new Set(["string", "number", "boolean"]);
const EXECUTOR_EVENT_TYPES = new Set([
  "job.accepted",
  "job.started",
  "job.progress",
  "job.completed",
  "job.failed",
  "job.rejected",
  "evidence.attached",
]);
const LOG_STATUSES_SET = new Set(LOG_STATUSES);

const LOG_STATUS_BY_EVENT_TYPE = Object.freeze({
  "job.accepted": "accepted",
  "job.started": "running",
  "job.progress": "running",
  "job.completed": "succeeded",
  "job.failed": "failed",
  "job.rejected": "rejected",
});

const JOB_STATUS_BY_EVENT_TYPE = Object.freeze({
  "job.started": "running",
  "job.completed": "succeeded",
  "job.failed": "failed",
});

function executorEventError(message, code) {
  return serviceError(message, code);
}

function workspaceIdHintFromBody(req) {
  return typeof req.body?.workspaceId === "string" ? req.body.workspaceId : null;
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
  assertSafePublicValue(trimmed);
  return trimmed;
}

function requiredUuid(value, fieldName, code) {
  const trimmed = requiredTrimmedString(value, fieldName, code);
  if (!UUID_PATTERN.test(trimmed)) {
    throw executorEventError(`${fieldName} is invalid`, code);
  }
  assertSafePublicValue(trimmed);
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
  assertSafePublicValue(trimmed);
  return trimmed;
}

function optionalPublicText(value, fieldName, maxLength = 1024) {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string") {
    throw executorEventError(`${fieldName} is invalid`, CERTOPS_EXECUTOR_EVENT_INVALID);
  }
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (trimmed.length > maxLength) {
    throw executorEventError(`${fieldName} is too long`, CERTOPS_EXECUTOR_EVENT_INVALID);
  }
  assertSafePublicValue(trimmed);
  return trimmed;
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

function metadataEntriesToObject(entries, fieldName) {
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
  for (const entry of entries) {
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
    if (!METADATA_NAME_PATTERN.test(name) || fieldNameLooksForbidden(name)) {
      throw executorEventError(
        `${fieldName}.name is invalid`,
        PRIVATE_KEY_MATERIAL_REJECTED,
      );
    }
    if (!Object.prototype.hasOwnProperty.call(entry, "value")) {
      throw executorEventError(
        `${fieldName}.value is required`,
        CERTOPS_EXECUTOR_EVENT_INVALID,
      );
    }

    const value = entry.value;
    assertSafePublicValue(value);
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

    metadata[name] = entry.value;
  }

  return normalizePublicObject(metadata, fieldName);
}

function eventMetadataFromBody(body, occurredAt) {
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

  const entries = metadataEntriesToObject(body.metadata, "metadata");
  return normalizePublicObject({ ...metadata, ...entries }, "metadata");
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

function evidenceMetadataFromItem(item) {
  const metadata = {};
  for (const [targetKey, sourceKey] of [
    ["source", "source"],
    ["status", "status"],
    ["fingerprintSha256", "fingerprintSha256"],
    ["summary", "summary"],
  ]) {
    const maxLength =
      sourceKey === "summary" ? 1024 : sourceKey === "fingerprintSha256" ? 64 : 128;
    const value = optionalPublicText(item[sourceKey], sourceKey, maxLength);
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

  if (typeof item.redactionApplied === "boolean") {
    metadata.redactionApplied = item.redactionApplied;
  }
  if (Array.isArray(item.artifactRefs) && item.artifactRefs.length > 0) {
    metadata.artifactRefs = item.artifactRefs;
  }

  const entries = metadataEntriesToObject(item.metadata, "evidence.metadata");
  return normalizePublicObject({ ...metadata, ...entries }, "metadata");
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
  return body.evidence;
}

function normalizeExecutorEventBody(body, apiToken) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw executorEventError(
      "Executor event body is invalid",
      CERTOPS_EXECUTOR_EVENT_INVALID,
    );
  }

  assertSafePublicValue(body);

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

  return {
    eventId,
    eventType,
    jobId,
    message: optionalPublicText(body.message, "message", 1024),
    occurredAt,
    logStatus: LOG_STATUS_BY_EVENT_TYPE[eventType] || status,
    jobStatus: JOB_STATUS_BY_EVENT_TYPE[eventType] || null,
    metadata: eventMetadataFromBody(body, occurredAt),
    evidence: evidenceItemsFromBody(body),
  };
}

async function persistEvidenceItems({ body, event, workspaceId, apiToken }) {
  const created = [];
  for (const item of event.evidence) {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw executorEventError(
        "evidence item is invalid",
        CERTOPS_EXECUTOR_EVENT_INVALID,
      );
    }

    const evidenceType = requiredTrimmedString(
      item.eventType || item.evidenceType,
      "evidence.eventType",
      CERTOPS_EVIDENCE_TYPE_INVALID,
    );
    const subject = evidenceSubjectFromItem(item);
    const evidence = await createCertificateEvidence({
      workspaceId,
      jobId: event.jobId,
      evidenceType,
      subjectType: subject.subjectType,
      subjectId: subject.subjectId,
      metadata: evidenceMetadataFromItem(item),
      observedAt: item.observedAt || body.occurredAt,
      createdByApiTokenId: apiToken.id,
    });
    created.push(evidence);
  }
  return created;
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

async function executorEventsHandler(req, res) {
  try {
    const workspaceId = req.apiToken.workspaceId;
    const event = normalizeExecutorEventBody(req.body, req.apiToken);
    const job = await getCertificateJobById({
      workspaceId,
      jobId: event.jobId,
    });

    if (!job) {
      throw executorEventError("Certificate job not found", CERTOPS_JOB_NOT_FOUND);
    }

    const log = await appendCertificateJobLog({
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
        workspaceId,
        jobId: event.jobId,
        status: event.jobStatus,
      });
    }

    const evidence = await persistEvidenceItems({
      body: req.body,
      event,
      workspaceId,
      apiToken: req.apiToken,
    });

    return res.status(202).json({
      ok: true,
      eventId: log.id,
      jobId: event.jobId,
      status: updatedJob?.status || job.status,
      evidenceId: evidence[0]?.id,
    });
  } catch (error) {
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
  const rateLimitMiddleware =
    options.rateLimitMiddleware ||
    createCertOpsMachineTokenRateLimit(options.rateLimitOptions || {});

  certOpsExecutorRouter.post(
    "/api/v1/certops/executor/events",
    authMiddleware,
    rateLimitMiddleware,
    executorEventsHandler,
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
  evidenceMetadataFromItem,
  evidenceSubjectFromItem,
  handleExecutorEventError,
  metadataEntriesToObject,
  normalizeExecutorEventBody,
};

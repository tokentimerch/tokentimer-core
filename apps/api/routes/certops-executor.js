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
  requireCertOpsEnabled,
} = require("../middleware/require-certops-enabled");
const { logger } = require("../utils/logger");
const {
  CERTOPS_API_TOKEN_SCOPE_DENIED,
} = require("../services/certops/apiTokens");
const {
  CERTOPS_JOB_INVALID,
  CERTOPS_JOB_LOG_EVENT_TYPE_INVALID,
  CERTOPS_JOB_NOT_FOUND,
  CERTOPS_JOB_STATUS_INVALID,
  CERTOPS_JOB_STATUS_TRANSITION_INVALID,
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
const {
  CERTOPS_EXECUTOR_EVENT_IDEMPOTENCY_CONFLICT,
  ingestExecutorEvent,
} = require("../services/certops/executorEvents");

const CERTOPS_EXECUTOR_EVENT_INVALID = "CERTOPS_EXECUTOR_EVENT_INVALID";
const CERTOPS_EXECUTOR_EVENT_TYPE_INVALID =
  "CERTOPS_EXECUTOR_EVENT_TYPE_INVALID";
const CERTOPS_EXECUTOR_EVENT_STATUS_MISMATCH =
  "CERTOPS_EXECUTOR_EVENT_STATUS_MISMATCH";
const CERTOPS_EXECUTOR_JOB_REQUIRED = "CERTOPS_EXECUTOR_JOB_REQUIRED";
const CERTOPS_EXECUTOR_WORKSPACE_MISMATCH =
  "CERTOPS_EXECUTOR_WORKSPACE_MISMATCH";

const EXECUTOR_EVENT_SCOPE = "certops:events:write";
const EXECUTOR_EVIDENCE_SCOPE = "certops:evidence:write";
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
const LOG_STATUSES_SET = new Set(LOG_STATUSES);

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

function requiredPublicText(value, fieldName, maxLength = 512) {
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

function normalizeArtifactRefs(value) {
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
    );
    const normalized = { type, reference };

    if (Object.prototype.hasOwnProperty.call(item, "sha256")) {
      if (item.sha256 === null) {
        normalized.sha256 = null;
      } else if (
        typeof item.sha256 === "string" &&
        SHA256_HEX_PATTERN.test(item.sha256)
      ) {
        assertSafePublicValue(item.sha256);
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
  const artifactRefs = normalizeArtifactRefs(item.artifactRefs);
  if (artifactRefs !== undefined) {
    metadata.artifactRefs = artifactRefs;
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
  return body.evidence.map((item) => {
    if (!isPlainObject(item)) {
      throw executorEventError(
        "evidence item is invalid",
        CERTOPS_EXECUTOR_EVENT_INVALID,
      );
    }

    return {
      ...item,
      artifactRefs: normalizeArtifactRefs(item.artifactRefs),
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

  return {
    eventId,
    eventType,
    jobId,
    message: optionalPublicText(body.message, "message", 1024),
    occurredAt,
    logStatus: LOG_STATUSES_SET.has(status) ? status : null,
    jobStatus: JOB_STATUS_BY_EVENT_TYPE[eventType] || null,
    metadata: eventMetadataFromBody(body, occurredAt),
    evidence: evidenceItemsFromBody(body),
  };
}

async function persistEvidenceItems({ client, body, event, workspaceId, apiToken }) {
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
      client,
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

  if (
    error?.code === CERTOPS_JOB_STATUS_TRANSITION_INVALID ||
    error?.code === CERTOPS_EXECUTOR_EVENT_IDEMPOTENCY_CONFLICT
  ) {
    return res.status(409).json({
      error:
        error.code === CERTOPS_EXECUTOR_EVENT_IDEMPOTENCY_CONFLICT
          ? "Executor event conflicts with a previously accepted event"
          : "Executor event conflicts with the current certificate job status",
      code: error.code,
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

async function executorEventsHandler(req, res) {
  try {
    const workspaceId = req.apiToken.workspaceId;
    const event = normalizeExecutorEventBody(req.body, req.apiToken);
    const result = await ingestExecutorEvent({
      workspaceId,
      jobId: event.jobId,
      eventId: event.eventId,
      request: event,
      apiTokenId: req.apiToken.id,
      process: async (client) => {
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
          metadata: event.metadata,
          createdByApiTokenId: req.apiToken.id,
        });

        const evidence = await persistEvidenceItems({
          client,
          body: req.body,
          event,
          workspaceId,
          apiToken: req.apiToken,
        });

        const response = {
          ok: true,
          eventId: log.id,
          jobId: event.jobId,
          status: updatedJob.status,
        };
        if (evidence[0]?.id) response.evidenceId = evidence[0].id;
        return response;
      },
    });

    return res.status(202).json({
      ...result.response,
      ...(result.duplicate ? { duplicate: true } : {}),
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

function requestCarriesEvidence(req) {
  const body = req.body;
  return Boolean(
    body &&
      typeof body === "object" &&
      (body.eventType === "evidence.attached" ||
        (Array.isArray(body.evidence) && body.evidence.length > 0)),
  );
}

function requireExecutorEvidenceScope(req, res, next) {
  if (
    !requestCarriesEvidence(req) ||
    req.apiToken?.scopes?.includes(EXECUTOR_EVIDENCE_SCOPE)
  ) {
    return next();
  }

  return res.status(403).json({
    error: "CertOps API token scope denied",
    code: CERTOPS_API_TOKEN_SCOPE_DENIED,
  });
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
  const rateLimitMiddleware =
    options.rateLimitMiddleware ||
    createCertOpsMachineTokenRateLimit(options.rateLimitOptions || {});

  certOpsExecutorRouter.post(
    "/api/v1/certops/executor/events",
    preAuthRateLimitMiddleware,
    certOpsEnabledMiddleware,
    authMiddleware,
    rateLimitMiddleware,
    requireExecutorEvidenceScope,
    executorEventsHandler,
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
  assertEventStatusMatch,
  evidenceMetadataFromItem,
  evidenceSubjectFromItem,
  handleExecutorEventError,
  metadataEntriesToObject,
  normalizeExecutorEventBody,
  requestCarriesEvidence,
};

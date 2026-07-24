"use strict";

const router = require("express").Router();

const { pool } = require("../db/database");
const { getApiLimiter } = require("../middleware/rateLimit");
const {
  PRIVATE_KEY_MATERIAL_REJECTED,
  rejectKeyMaterial,
} = require("../middleware/reject-key-material");
const {
  CERTOPS_DISABLED,
  NOT_FOUND_RESPONSE,
  requireCertOpsEnabled,
} = require("../middleware/require-certops-enabled");
const {
  requireWorkspaceCertOpsActive,
} = require("../middleware/require-workspace-certops-active");
const { authorize, hasAtLeastRole } = require("../services/rbac");
const {
  CERTOPS_CERTIFICATE_NOT_FOUND,
  CERTOPS_CERTIFICATE_PARSE_FAILED,
  CERTOPS_CERTIFICATE_RETIRE_REASON_INVALID,
  CERTOPS_CERTIFICATE_RETIRE_STATUS_INVALID,
  CERTOPS_KEY_MODE_INVALID,
  CERTOPS_KEY_REFERENCE_INVALID,
  getManagedCertificate,
  importPublicCertificates,
  listCertificateInstances,
  listManagedCertificates,
  retireManagedCertificate,
} = require("../services/certops/inventory");
const { CERTOPS_CERTIFICATE_TOO_LARGE } = require("../services/certops/parser");
const {
  CERTOPS_API_TOKEN_INVALID,
  CERTOPS_API_TOKEN_NAME_INVALID,
  CERTOPS_API_TOKEN_SCOPE_INVALID,
  CERTOPS_API_TOKEN_CONTROLLER_CLUSTER_INVALID,
  createApiToken,
  listApiTokens,
  revokeApiTokenWithResult,
} = require("../services/certops/apiTokens");
const {
  CERTOPS_AGENT_BOOTSTRAP_TOKEN_EXPIRY_INVALID,
  CERTOPS_AGENT_BOOTSTRAP_TOKEN_INVALID,
  CERTOPS_AGENT_BOOTSTRAP_TOKEN_NAME_INVALID,
  createBootstrapToken,
  getBootstrapTokenById,
  listBootstrapTokens,
  revokeBootstrapToken,
} = require("../services/certops/agentCredentials");
const {
  CERTOPS_AGENT_INVALID,
  CERTOPS_AGENT_RETIRE_REASON_INVALID,
  countActivelyLeasedJobs,
  getAgentById,
  listAgents,
  normalizeRequiredRetireReason,
  retireAgent,
} = require("../services/certops/agentRegistry");
const {
  CERTOPS_JOB_EXECUTION_FIELD_INVALID,
  CERTOPS_JOB_IDEMPOTENCY_CONFLICT,
  CERTOPS_JOB_INVALID,
  CERTOPS_JOB_LOG_EVENT_TYPE_INVALID,
  CERTOPS_JOB_METADATA_INVALID,
  CERTOPS_JOB_NOT_FOUND,
  CERTOPS_JOB_OPERATION_INVALID,
  CERTOPS_JOB_SOURCE_INVALID,
  CERTOPS_JOB_STATUS_INVALID,
  CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED,
  findActiveJobForSubject,
  getCertificateJobById,
  listCertificateJobLog,
  listCertificateJobs,
  validateJobPayloadForOperation,
} = require("../services/certops/jobs");
const {
  NON_RENEWABLE_CERTIFICATE_STATUSES,
} = require("../services/certops/renewalScheduler");
const {
  CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
  CERTOPS_RENEWAL_PROFILE_INVALID,
} = require("../services/certops/renewalProfile");
const {
  CERTOPS_EVIDENCE_INVALID,
  CERTOPS_EVIDENCE_TYPE_INVALID,
  listCertificateEvidence,
} = require("../services/certops/evidence");
const {
  CERTOPS_WORKSPACE_NOT_FOUND,
  CERTOPS_WORKSPACE_PAUSED,
  CERTOPS_WORKSPACE_PAUSE_REASON_INVALID,
  CERTOPS_WORKSPACE_PAUSE_STATE_INVALID,
  createManualCertificateJob,
  getWorkspaceCertOpsPauseState,
  setWorkspaceCertOpsPauseState,
} = require("../services/certops/workspaceKillSwitch");
const {
  CERTOPS_CONTROLLER_PROVISIONING_INVALID,
  CERTOPS_CONTROLLER_PROVISIONING_TERMINAL_IDENTITY,
  createControllerProvisionIntent,
} = require("../services/certops/controllerProvisioning");
const {
  CERTOPS_APPROVAL_APPROVER_REQUIRED,
  CERTOPS_APPROVAL_JOB_NOT_PENDING_APPROVAL,
  CERTOPS_APPROVAL_REASON_INVALID,
  CERTOPS_APPROVAL_SELF_APPROVAL_FORBIDDEN,
  approveJob,
  rejectJob,
} = require("../services/certops/jobApprovals");
const { writeAudit } = require("../services/audit");
const { logger } = require("../utils/logger");
const Token = require("../db/models/Token");

const CERTOPS_API_TOKEN_NOT_FOUND = "CERTOPS_API_TOKEN_NOT_FOUND";
const CERTOPS_AGENT_BOOTSTRAP_TOKEN_NOT_FOUND =
  "CERTOPS_AGENT_BOOTSTRAP_TOKEN_NOT_FOUND";
const CERTOPS_AGENT_NOT_FOUND = "CERTOPS_AGENT_NOT_FOUND";
const CERTOPS_AGENT_RETIRE_BLOCKED = "CERTOPS_AGENT_RETIRE_BLOCKED";
const CERTOPS_CERTIFICATE_NOT_RENEWABLE = "CERTOPS_CERTIFICATE_NOT_RENEWABLE";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function requireCertOpsWriteRole(req, res, next) {
  if (req.isWorkerCall) return next();

  if (!hasAtLeastRole(req.authz?.workspaceRole, "workspace_manager")) {
    return res.status(403).json({
      error: "Forbidden: insufficient role",
      code: "INSUFFICIENT_ROLE",
    });
  }

  return next();
}

function requireCertOpsTokenManager(req, res, next) {
  if (req.isWorkerCall || !req.user?.id) {
    return res.status(403).json({
      error: "Forbidden: session user required",
      code: "INSUFFICIENT_ROLE",
    });
  }

  if (!hasAtLeastRole(req.authz?.workspaceRole, "workspace_manager")) {
    return res.status(403).json({
      error: "Forbidden: insufficient role",
      code: "INSUFFICIENT_ROLE",
    });
  }

  return next();
}

// The workspace kill switch is an attributable human-admin incident control.
// Shared workspace middleware intentionally grants internal workers an
// effective admin role for unrelated machine work, so this route-local guard
// must reject them rather than trusting that derived role.
function requireCertOpsSessionUser(req, res, next) {
  if (req.isWorkerCall || !req.user?.id) {
    return res.status(403).json({
      error: "Forbidden: session user required",
      code: "INSUFFICIENT_ROLE",
    });
  }
  return next();
}

function certificatePemFromBody(body) {
  if (typeof body === "string") return body;
  if (!body || typeof body !== "object") return null;

  for (const field of ["certificatePem", "pem", "certificate", "chainPem"]) {
    if (typeof body[field] === "string") return body[field];
  }

  if (
    Array.isArray(body.certificates) &&
    body.certificates.every((item) => typeof item === "string")
  ) {
    return body.certificates.join("\n");
  }

  return null;
}

function optionalTrimmedString(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed || null;
}

function writeOptionsFromRequest(req, source) {
  return {
    workspaceId: req.workspace.id,
    certificatePem: certificatePemFromBody(req.body),
    source,
    sourceRef: optionalTrimmedString(req.body?.sourceRef),
    name: optionalTrimmedString(req.body?.name),
    keyMode: optionalTrimmedString(req.body?.keyMode),
    keyReference: optionalTrimmedString(req.body?.keyReference),
    createdBy: req.user?.id || null,
  };
}

function handleCertOpsError(res, err) {
  if (err?.code === CERTOPS_DISABLED) {
    return res.status(404).json(NOT_FOUND_RESPONSE);
  }

  if (err?.code === PRIVATE_KEY_MATERIAL_REJECTED) {
    return res.status(422).json({
      error: "Private key material is not accepted in CertOps requests",
      code: PRIVATE_KEY_MATERIAL_REJECTED,
    });
  }

  if (err?.code === CERTOPS_CERTIFICATE_PARSE_FAILED) {
    return res.status(400).json({
      error: "Certificate input could not be parsed",
      code: CERTOPS_CERTIFICATE_PARSE_FAILED,
    });
  }

  if (err?.code === CERTOPS_CERTIFICATE_NOT_FOUND) {
    return res.status(404).json({
      error: "Certificate not found",
      code: CERTOPS_CERTIFICATE_NOT_FOUND,
    });
  }

  if (err?.code === CERTOPS_CERTIFICATE_RETIRE_STATUS_INVALID) {
    return res.status(400).json({
      error: "Invalid certificate retire status",
      code: CERTOPS_CERTIFICATE_RETIRE_STATUS_INVALID,
    });
  }

  if (err?.code === CERTOPS_CERTIFICATE_RETIRE_REASON_INVALID) {
    return res.status(400).json({
      error: "Invalid certificate retire reason",
      code: CERTOPS_CERTIFICATE_RETIRE_REASON_INVALID,
    });
  }

  if (err?.code === CERTOPS_KEY_MODE_INVALID) {
    return res.status(400).json({
      error: "Invalid CertOps key mode",
      code: CERTOPS_KEY_MODE_INVALID,
    });
  }

  if (err?.code === CERTOPS_KEY_REFERENCE_INVALID) {
    return res.status(400).json({
      error: "keyReference must be a non-secret reference",
      code: CERTOPS_KEY_REFERENCE_INVALID,
    });
  }

  if (err?.code === CERTOPS_API_TOKEN_NOT_FOUND) {
    return res.status(404).json({
      error: "CertOps API token not found",
      code: CERTOPS_API_TOKEN_NOT_FOUND,
    });
  }

  if (
    err?.code === CERTOPS_API_TOKEN_INVALID ||
    err?.code === CERTOPS_API_TOKEN_NAME_INVALID ||
    err?.code === CERTOPS_API_TOKEN_SCOPE_INVALID ||
    err?.code === CERTOPS_API_TOKEN_CONTROLLER_CLUSTER_INVALID
  ) {
    return res.status(400).json({
      error: "CertOps API token request is invalid",
      code: err.code,
    });
  }

  if (
    err?.code === CERTOPS_AGENT_BOOTSTRAP_TOKEN_INVALID ||
    err?.code === CERTOPS_AGENT_BOOTSTRAP_TOKEN_NAME_INVALID ||
    err?.code === CERTOPS_AGENT_BOOTSTRAP_TOKEN_EXPIRY_INVALID
  ) {
    return res.status(400).json({
      error: "CertOps agent bootstrap token request is invalid",
      code: err.code,
    });
  }

  if (
    err?.code === CERTOPS_AGENT_INVALID ||
    err?.code === CERTOPS_AGENT_RETIRE_REASON_INVALID
  ) {
    return res.status(400).json({
      error: "CertOps agent request is invalid",
      code: err.code,
    });
  }

  if (err?.code === CERTOPS_AGENT_NOT_FOUND) {
    return res.status(404).json({
      error: "CertOps agent not found",
      code: CERTOPS_AGENT_NOT_FOUND,
    });
  }

  if (err?.code === CERTOPS_JOB_NOT_FOUND) {
    return res.status(404).json({
      error: "Certificate job not found",
      code: CERTOPS_JOB_NOT_FOUND,
    });
  }

  if (err?.code === CERTOPS_WORKSPACE_PAUSED) {
    return res.status(409).json({
      error: "CertOps is paused for this workspace",
      code: CERTOPS_WORKSPACE_PAUSED,
    });
  }

  if (err?.code === CERTOPS_APPROVAL_SELF_APPROVAL_FORBIDDEN) {
    return res.status(403).json({
      error: "The user who requested a CertOps job cannot approve it",
      code: CERTOPS_APPROVAL_SELF_APPROVAL_FORBIDDEN,
    });
  }

  if (err?.code === CERTOPS_APPROVAL_JOB_NOT_PENDING_APPROVAL) {
    return res.status(409).json({
      error: "Certificate job is not awaiting approval",
      code: CERTOPS_APPROVAL_JOB_NOT_PENDING_APPROVAL,
    });
  }

  if (
    err?.code === CERTOPS_APPROVAL_APPROVER_REQUIRED ||
    err?.code === CERTOPS_APPROVAL_REASON_INVALID
  ) {
    return res.status(400).json({
      error: "CertOps approval request is invalid",
      code: err.code,
    });
  }

  const certOpsJobBadRequestCodes = new Set([
    CERTOPS_JOB_INVALID,
    CERTOPS_JOB_OPERATION_INVALID,
    CERTOPS_JOB_SOURCE_INVALID,
    CERTOPS_JOB_STATUS_INVALID,
    CERTOPS_JOB_LOG_EVENT_TYPE_INVALID,
    CERTOPS_JOB_METADATA_INVALID,
    CERTOPS_JOB_EXECUTION_FIELD_INVALID,
    CERTOPS_EVIDENCE_INVALID,
    CERTOPS_EVIDENCE_TYPE_INVALID,
  ]);
  if (certOpsJobBadRequestCodes.has(err?.code)) {
    return res.status(400).json({
      error: "CertOps job request is invalid",
      code: err.code,
    });
  }

  if (
    err?.code === CERTOPS_RENEWAL_PROFILE_INVALID ||
    err?.code === CERTOPS_RENEWAL_PROFILE_INCOMPLETE
  ) {
    return res.status(400).json({
      error: "Certificate renewal profile is missing or invalid",
      code: err.code,
    });
  }

  if (err?.code === CERTOPS_CERTIFICATE_TOO_LARGE) {
    return res.status(400).json({
      error: "Certificate input exceeds the public certificate size limit",
      code: CERTOPS_CERTIFICATE_TOO_LARGE,
    });
  }

  if (err?.code === CERTOPS_JOB_IDEMPOTENCY_CONFLICT) {
    return res.status(409).json({
      error: "Idempotency key was already used with a different CertOps job request",
      code: CERTOPS_JOB_IDEMPOTENCY_CONFLICT,
    });
  }

  if (err?.code === CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED) {
    return res.status(409).json({
      error: err.message || "Per-CA renewal capacity exceeded",
      code: CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED,
    });
  }

  if (
    err?.code === CERTOPS_WORKSPACE_PAUSE_STATE_INVALID ||
    err?.code === CERTOPS_WORKSPACE_PAUSE_REASON_INVALID
  ) {
    return res.status(400).json({
      error: "CertOps workspace pause request is invalid",
      code: err.code,
    });
  }

  if (err?.code === CERTOPS_WORKSPACE_NOT_FOUND) {
    return res.status(404).json({
      error: "Workspace not found",
      code: "WORKSPACE_NOT_FOUND",
    });
  }

  return null;
}

function jobIdFromParams(req, res) {
  const jobId = String(req.params.jobId || "");
  if (!UUID_PATTERN.test(jobId)) {
    res.status(400).json({
      error: "CertOps job identifier is invalid",
      code: CERTOPS_JOB_INVALID,
    });
    return null;
  }
  return jobId;
}

function tokenIdFromParams(req, res) {
  const tokenId = String(req.params.tokenId || "");
  if (!UUID_PATTERN.test(tokenId)) {
    res.status(400).json({
      error: "CertOps API token identifier is invalid",
      code: CERTOPS_API_TOKEN_INVALID,
    });
    return null;
  }
  return tokenId;
}

function bootstrapTokenIdFromParams(req, res) {
  const tokenId = String(req.params.tokenId || "");
  if (!UUID_PATTERN.test(tokenId)) {
    res.status(400).json({
      error: "CertOps agent bootstrap token identifier is invalid",
      code: CERTOPS_AGENT_BOOTSTRAP_TOKEN_INVALID,
    });
    return null;
  }
  return tokenId;
}

function agentIdFromParams(req, res) {
  const agentId = String(req.params.agentId || "");
  if (!UUID_PATTERN.test(agentId)) {
    res.status(400).json({
      error: "CertOps agent identifier is invalid",
      code: CERTOPS_AGENT_INVALID,
    });
    return null;
  }
  return agentId;
}

function jobListOptionsFromRequest(req) {
  return {
    workspaceId: req.workspace.id,
    limit: req.query.limit,
    offset: req.query.offset,
    status: req.query.status,
    subjectType: req.query.subjectType,
    subjectId: req.query.subjectId,
    operation: req.query.operation,
    source: req.query.source,
  };
}

function jobCreateOptionsFromRequest(req) {
  return {
    workspaceId: req.workspace.id,
    operation: req.body?.operation,
    subjectType: req.body?.subjectType,
    subjectId: req.body?.subjectId,
    payload: req.body?.payload,
    idempotencyKey: req.body?.idempotencyKey,
    // Per-job approval gate: an explicitly requested boolean true makes
    // the job start at pending_approval; anything else defaults to false.
    requiresApproval: req.body?.requiresApproval === true,
    // Manual jobs are always created through this session-authenticated
    // route: source is always "api" (the same value the certificate-import
    // route uses for session-initiated writes), never taken from the
    // request body, so a caller cannot spoof an executor- or system-sourced
    // job through the manual-create surface.
    source: "api",
    requestedByUserId: req.user?.id || null,
  };
}

function createManualCertificateJobHandler({
  manualJobCreator = createManualCertificateJob,
} = {}) {
  return async function createManualCertificateJobHandler(req, res) {
    try {
      const { job } = await manualJobCreator({
        ...jobCreateOptionsFromRequest(req),
        actorUserId: req.user?.id || null,
        subjectUserId: req.user?.id || null,
      });
      return res.status(201).json({ job: jobDetail(job) });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps manual job creation failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to create CertOps job",
        code: "INTERNAL_ERROR",
      });
    }
  };
}

const BULK_RENEW_MAX_CERTIFICATES = 100;
const BULK_RENEW_ALLOWED_BODY_FIELDS = Object.freeze([
  "certificateIds",
  "dryRun",
  "idempotencyKey",
  "requiresApproval",
  "payload",
]);
// Per-item keys are "bulk-renew:<client key>:<certificate uuid>". Bound the
// client part so the composed key stays under the service's 128-char
// short-text limit with room to spare.
const BULK_RENEW_IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;

function bulkRenewItemIdempotencyKey(idempotencyKey, certificateId) {
  // Non-dry-run bulk creates must always carry a stable per-certificate key
  // so client retries cannot enqueue duplicate renew jobs. When the caller
  // omits a request key, derive one from the certificate id alone (scoped
  // by the workspace-scoped unique index on the jobs table's idempotency key).
  if (idempotencyKey) {
    return `bulk-renew:${idempotencyKey}:${certificateId}`;
  }
  return `bulk-renew:auto:${certificateId}`;
}

/**
 * Validates the whole bulk-renew request shape. Shape problems (missing or
 * oversized id list, non-UUID or duplicate ids, wrong field types, unknown
 * fields) fail the entire request with 400; per-certificate problems are
 * reported in the response envelope instead.
 */
function parseBulkRenewRequest(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { error: "Request body must be a JSON object" };
  }

  const unknownField = Object.keys(body).find(
    (key) => !BULK_RENEW_ALLOWED_BODY_FIELDS.includes(key),
  );
  if (unknownField) {
    return { error: `Unknown field: ${unknownField}` };
  }

  const { certificateIds } = body;
  if (!Array.isArray(certificateIds) || certificateIds.length < 1) {
    return { error: "certificateIds must be a non-empty array" };
  }
  if (certificateIds.length > BULK_RENEW_MAX_CERTIFICATES) {
    return {
      error: `certificateIds accepts at most ${BULK_RENEW_MAX_CERTIFICATES} ids per request`,
    };
  }

  const normalized = [];
  const seen = new Set();
  for (const value of certificateIds) {
    if (typeof value !== "string" || !UUID_PATTERN.test(value.trim())) {
      return { error: "certificateIds must contain only UUID strings" };
    }
    const id = value.trim().toLowerCase();
    if (seen.has(id)) {
      return { error: "certificateIds must not contain duplicates" };
    }
    seen.add(id);
    normalized.push(id);
  }

  if (body.dryRun !== undefined && typeof body.dryRun !== "boolean") {
    return { error: "dryRun must be a boolean" };
  }
  if (body.idempotencyKey !== undefined) {
    if (
      typeof body.idempotencyKey !== "string" ||
      !BULK_RENEW_IDEMPOTENCY_KEY_PATTERN.test(body.idempotencyKey)
    ) {
      return {
        error:
          "idempotencyKey must be 1-64 characters of letters, digits, '.', '_' or '-'",
      };
    }
  }
  if (
    body.requiresApproval !== undefined &&
    typeof body.requiresApproval !== "boolean"
  ) {
    return { error: "requiresApproval must be a boolean" };
  }
  if (
    body.payload !== undefined &&
    (body.payload === null ||
      typeof body.payload !== "object" ||
      Array.isArray(body.payload))
  ) {
    return { error: "payload must be an object" };
  }

  return {
    certificateIds: normalized,
    dryRun: body.dryRun === true,
    idempotencyKey: body.idempotencyKey || null,
    requiresApproval: body.requiresApproval === true,
    payload: body.payload || {},
  };
}

/**
 * Bulk renewal with a partial-failure envelope. Each certificate id goes
 * through the same manual-creation service path as POST /jobs (kill switch,
 * approval gate, payload validation), so per-certificate behavior matches a
 * single renew job exactly. Item failures never abort the batch; the
 * response is always 200 with per-item outcomes, except whole-request shape
 * problems (400) and the disabled-rollout 404.
 *
 * An optional request-level idempotencyKey makes retries safe: each item is
 * created with a derived "bulk-renew:<key>:<certificateId>" job key, so a
 * replayed batch returns the already-created jobs (marked replayed: true)
 * instead of enqueueing duplicates.
 *
 * Dry run preflights each certificate without writing: existence, renewable
 * inventory status, the same payload validation the real run applies, and
 * whether a non-terminal renew job is already in flight (reported as
 * activeJobId so callers can spot double-renewals before committing).
 */
function bulkRenewCertificatesHandler({
  manualJobCreator = createManualCertificateJob,
  certificateLoader = getManagedCertificate,
  activeJobFinder = findActiveJobForSubject,
} = {}) {
  return async function bulkRenewCertificatesHandler(req, res) {
    const parsed = parseBulkRenewRequest(req.body);
    if (parsed.error) {
      return res.status(400).json({
        error: parsed.error,
        code: CERTOPS_JOB_INVALID,
      });
    }

    // The payload is a whole-request field; validate it once up front (with
    // a representative certificateId stamped in, as each item's payload
    // will be) so a bad payload is a 400 instead of N identical item errors.
    try {
      validateJobPayloadForOperation(
        { ...parsed.payload, certificateId: parsed.certificateIds[0] },
        "renew",
      );
    } catch (err) {
      if (typeof err?.code === "string" && err.code) {
        return res.status(400).json({
          error: err.message || "payload is invalid",
          code: err.code,
        });
      }
      throw err;
    }

    const results = [];
    let succeeded = 0;

    for (const certificateId of parsed.certificateIds) {
      try {
        const certificate = await certificateLoader({
          workspaceId: req.workspace.id,
          certId: certificateId,
        });
        if (!certificate) {
          results.push({
            certificateId,
            ok: false,
            errorCode: CERTOPS_CERTIFICATE_NOT_FOUND,
            message: "Certificate not found",
          });
          continue;
        }

        if (NON_RENEWABLE_CERTIFICATE_STATUSES.includes(certificate.status)) {
          results.push({
            certificateId,
            ok: false,
            errorCode: CERTOPS_CERTIFICATE_NOT_RENEWABLE,
            message: `Certificate status '${certificate.status}' is not renewable`,
          });
          continue;
        }

        if (parsed.dryRun) {
          const activeJob = await activeJobFinder({
            workspaceId: req.workspace.id,
            subjectType: "managed_certificate",
            subjectId: certificateId,
            operation: "renew",
          });
          succeeded += 1;
          results.push({
            certificateId,
            ok: true,
            ...(activeJob ? { activeJobId: activeJob.id } : {}),
          });
          continue;
        }

        const { job, created } = await manualJobCreator({
          workspaceId: req.workspace.id,
          operation: "renew",
          subjectType: "managed_certificate",
          subjectId: certificateId,
          payload: { ...parsed.payload, certificateId },
          requiresApproval: parsed.requiresApproval,
          idempotencyKey: bulkRenewItemIdempotencyKey(
            parsed.idempotencyKey,
            certificateId,
          ),
          // Same session-write source posture as single manual job creation.
          source: "api",
          requestedByUserId: req.user?.id || null,
          actorUserId: req.user?.id || null,
          subjectUserId: req.user?.id || null,
        });
        succeeded += 1;
        results.push({
          certificateId,
          ok: true,
          jobId: job.id,
          ...(created === false ? { replayed: true } : {}),
        });
      } catch (err) {
        // A disabled rollout is a whole-surface condition, not a
        // per-certificate one: keep the same 404 posture as the middleware.
        if (err?.code === CERTOPS_DISABLED) {
          return res.status(404).json(NOT_FOUND_RESPONSE);
        }
        if (typeof err?.code === "string" && err.code) {
          results.push({
            certificateId,
            ok: false,
            errorCode: err.code,
            message: err.message || "CertOps job creation failed",
          });
          continue;
        }
        logger.error("CertOps bulk renew item failed", {
          error: err?.message,
          workspaceId: req.workspace?.id,
          certificateId,
          userId: req.user?.id,
        });
        results.push({
          certificateId,
          ok: false,
          errorCode: "INTERNAL_ERROR",
          message: "Failed to create CertOps job",
        });
      }
    }

    return res.status(200).json({
      summary: {
        requested: parsed.certificateIds.length,
        succeeded,
        failed: parsed.certificateIds.length - succeeded,
      },
      ...(parsed.dryRun ? { dryRun: true } : {}),
      results,
    });
  };
}

function jobApprovalDecisionHandler(decision, {
  approver = approveJob,
  rejecter = rejectJob,
} = {}) {
  const decide = decision === "approve" ? approver : rejecter;
  return async function jobApprovalDecisionHandler(req, res) {
    const jobId = jobIdFromParams(req, res);
    if (!jobId) return null;

    try {
      const result = await decide({
        workspaceId: req.workspace.id,
        jobId,
        approverUserId: req.user?.id || null,
        reason: req.body?.reason,
      });

      // Audit is written inside the approval transaction (jobApprovals.js).
      return res.json(result);
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps job approval decision failed", {
        error: err.message,
        code: err.code || null,
        decision,
        workspaceId: req.workspace?.id,
        jobId,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to record CertOps approval decision",
        code: "INTERNAL_ERROR",
      });
    }
  };
}

function controllerProvisioningIdempotencyKey(req) {
  const value = typeof req.get === "function"
    ? req.get("Idempotency-Key")
    : req.headers?.["idempotency-key"];
  return typeof value === "string" ? value : null;
}

function createControllerProvisionIntentHandler({
  provisionIntentCreator = createControllerProvisionIntent,
} = {}) {
  return async function createControllerProvisionIntentHandler(req, res) {
    try {
      const result = await provisionIntentCreator({
        request: req.body,
        workspaceId: req.workspace.id,
        idempotencyKey: controllerProvisioningIdempotencyKey(req),
        actorUserId: req.user?.id || null,
      });
      return res.status(result.duplicate ? 200 : 201).json({
        job: jobDetail(result.job),
        managedCertificateId: result.managedCertificateId,
        targetId: result.targetId,
        duplicate: Boolean(result.duplicate),
      });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;
      if (err?.code === CERTOPS_CONTROLLER_PROVISIONING_TERMINAL_IDENTITY) {
        return res.status(409).json({
          error: "Provisioning cannot reactivate a terminal managed certificate",
          code: err.code,
        });
      }
      if (err?.code === CERTOPS_CONTROLLER_PROVISIONING_INVALID) {
        return res.status(400).json({
          error: "CertOps provision request is invalid",
          code: err.code,
        });
      }
      logger.error("CertOps controller provision intent creation failed", {
        code: err?.code || null,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to create CertOps provision intent",
        code: "CERTOPS_CONTROLLER_PROVISIONING_CREATE_FAILED",
      });
    }
  };
}

function workspacePauseStateResponse(state) {
  return {
    workspaceId: state.workspaceId,
    certOpsPaused: state.certOpsPaused,
    certOpsEnabled: state.certOpsEnabled,
    certOpsActive: state.certOpsActive,
    ...(typeof state.changed === "boolean" ? { changed: state.changed } : {}),
  };
}

function jobSummary(job) {
  return {
    id: job.id,
    workspaceId: job.workspaceId,
    operation: job.operation,
    status: job.status,
    source: job.source,
    subjectType: job.subjectType,
    subjectId: job.subjectId,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
    queuedAt: job.queuedAt,
    startedAt: job.startedAt,
    completedAt: job.completedAt,
    cancelledAt: job.cancelledAt,
    requestedByUserId: job.requestedByUserId,
    requestedByApiTokenId: job.requestedByApiTokenId,
  };
}

function jobDetail(job) {
  return {
    ...jobSummary(job),
    payload: job.payload || {},
    resultMetadata: job.resultMetadata || {},
    errorCode: job.errorCode,
    errorMessage: job.errorMessage,
  };
}

function jobLogEntry(entry) {
  return {
    id: entry.id,
    workspaceId: entry.workspaceId,
    jobId: entry.jobId,
    eventType: entry.eventType,
    status: entry.status,
    message: entry.message,
    metadata: entry.metadata || {},
    createdByUserId: entry.createdByUserId,
    createdByApiTokenId: entry.createdByApiTokenId,
    createdAt: entry.createdAt,
  };
}

function evidenceItem(item) {
  return {
    id: item.id,
    workspaceId: item.workspaceId,
    jobId: item.jobId,
    evidenceType: item.evidenceType,
    subjectType: item.subjectType,
    subjectId: item.subjectId,
    metadata: item.metadata || {},
    observedAt: item.observedAt,
    createdByUserId: item.createdByUserId,
    createdByApiTokenId: item.createdByApiTokenId,
    createdAt: item.createdAt,
  };
}

function apiTokenMetadata(token) {
  return {
    id: token.id,
    workspaceId: token.workspaceId,
    name: token.name,
    tokenPrefix: token.tokenPrefix,
    scopes: Array.isArray(token.scopes) ? [...token.scopes] : [],
    status: token.status,
    expiresAt: token.expiresAt,
    lastUsedAt: token.lastUsedAt,
    revokedAt: token.revokedAt,
    revokedByUserId: token.revokedBy ?? null,
    createdByUserId: token.createdBy ?? null,
    createdAt: token.createdAt,
    updatedAt: token.updatedAt,
  };
}

function apiTokenAuditMetadata(token, { includeRevocation = false } = {}) {
  const metadata = {
    api_token_id: token.id,
    token_prefix: token.tokenPrefix,
    name: token.name,
    scopes: Array.isArray(token.scopes) ? [...token.scopes] : [],
    status: token.status,
  };

  if (includeRevocation) {
    metadata.revoked_at = token.revokedAt;
  } else {
    metadata.expires_at = token.expiresAt;
  }

  return metadata;
}

async function withCertOpsTransaction(work) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await work(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (_rollbackError) {
      // Preserve the original mutation or audit error for the safe route handler.
    }
    throw error;
  } finally {
    client.release();
  }
}

// Alias kept for callers that still name the helper after API-token routes.
const withCertOpsTokenTransaction = withCertOpsTransaction;

async function recordApiTokenAudit({
  client,
  req,
  action,
  token,
  includeRevocation,
}) {
  const actorUserId = req.user.id;
  await writeAudit({
    client,
    actorUserId,
    subjectUserId: actorUserId,
    action,
    targetType: "certops_api_token",
    targetId: null,
    workspaceId: req.workspace.id,
    metadata: apiTokenAuditMetadata(token, { includeRevocation }),
  });
}

function bootstrapTokenAuditMetadata(token, { includeRevocation = false } = {}) {
  const metadata = {
    bootstrap_token_id: token.id,
    token_prefix: token.tokenPrefix,
    name: token.name,
    status: token.status,
  };

  if (includeRevocation) {
    metadata.revoked_at = token.revokedAt;
  } else {
    metadata.expires_at = token.expiresAt;
  }

  return metadata;
}

async function recordBootstrapTokenAudit({
  client,
  req,
  action,
  token,
  includeRevocation,
}) {
  const actorUserId = req.user.id;
  await writeAudit({
    client,
    actorUserId,
    subjectUserId: actorUserId,
    action,
    targetType: "certops_agent_bootstrap_token",
    targetId: null,
    workspaceId: req.workspace.id,
    metadata: bootstrapTokenAuditMetadata(token, { includeRevocation }),
  });
}

async function recordAgentRetiredAudit({
  client,
  req,
  agent,
  force,
  reason,
  leasedJobs,
  fenced = null,
}) {
  const actorUserId = req.user.id;
  await writeAudit({
    client,
    actorUserId,
    subjectUserId: actorUserId,
    action: "CERTOPS_AGENT_RETIRED",
    targetType: "certops_agent",
    targetId: null,
    workspaceId: req.workspace.id,
    metadata: {
      agentId: agent.agentId,
      force,
      reason,
      leasedJobs,
      ...(fenced
        ? {
            cancelledJobIds: fenced.cancelledJobIds || [],
            orphanedJobIds: fenced.orphanedJobIds || [],
          }
        : {}),
    },
  });
}

async function recordInventoryAudit(req, source, certificates, client = null) {
  const actorUserId = req.user?.id || null;
  await writeAudit({
    client,
    actorUserId,
    subjectUserId: actorUserId,
    action:
      source === "api"
        ? "CERTOPS_CERTIFICATE_REGISTERED"
        : "CERTOPS_CERTIFICATE_IMPORTED",
    targetType: "managed_certificate",
    targetId: null,
    workspaceId: req.workspace.id,
    metadata: {
      source,
      count: certificates.length,
      certificate_ids: certificates.map((certificate) => certificate.id),
      fingerprints_sha256: certificates.map(
        (certificate) => certificate.fingerprintSha256,
      ),
    },
  });
}

router.get(
  "/api/v1/workspaces/:id/certops/tokens",
  getApiLimiter(),
  requireCertOpsEnabled,
  // Token metadata enumeration is manager-only, same as create/revoke:
  // viewers must not see machine-token names, prefixes, or scopes.
  requireCertOpsWriteRole,
  async (req, res) => {
    try {
      const tokens = await listApiTokens({
        workspaceId: req.workspace.id,
      });
      return res.json({ items: tokens.map(apiTokenMetadata) });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps API token list failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to list CertOps API tokens",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/tokens",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  requireCertOpsTokenManager,
  async (req, res) => {
    try {
      // Reject already-expired expiry up front: the service layer also
      // accepts past dates for internal test fixtures that seed expired
      // tokens directly, so the future-only rule belongs on this
      // user-facing create path instead of createApiToken() itself.
      if (req.body?.expiresAt) {
        const requestedExpiry = new Date(req.body.expiresAt);
        if (
          !Number.isNaN(requestedExpiry.getTime()) &&
          requestedExpiry.getTime() <= Date.now()
        ) {
          return res.status(400).json({
            error: "API token expiry must be in the future",
            code: CERTOPS_API_TOKEN_INVALID,
          });
        }
      }

      const created = await withCertOpsTokenTransaction(async (client) => {
        const tokenResult = await createApiToken({
          client,
          workspaceId: req.workspace.id,
          name: req.body?.name,
          scopes: req.body?.scopes,
          controllerClusterId: req.body?.controllerClusterId,
          expiresAt: req.body?.expiresAt,
          createdBy: req.user.id,
        });
        await recordApiTokenAudit({
          client,
          req,
          action: "CERTOPS_API_TOKEN_CREATED",
          token: tokenResult.token,
          includeRevocation: false,
        });
        return tokenResult;
      });

      return res.status(201).json({
        token: apiTokenMetadata(created.token),
        plaintextToken: created.plaintextToken,
      });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps API token create failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to create CertOps API token",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/tokens/:tokenId/revoke",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  requireCertOpsTokenManager,
  async (req, res) => {
    const tokenId = tokenIdFromParams(req, res);
    if (!tokenId) return null;

    try {
      const revoked = await withCertOpsTokenTransaction(async (client) => {
        const result = await revokeApiTokenWithResult({
          client,
          workspaceId: req.workspace.id,
          tokenId,
          revokedBy: req.user.id,
        });
        if (result.token && result.revokedNow) {
          await recordApiTokenAudit({
            client,
            req,
            action: "CERTOPS_API_TOKEN_REVOKED",
            token: result.token,
            includeRevocation: true,
          });
          // The user may have opted in to monitor this machine token's
          // expiration in TokenTimer when it was created; a revoked token
          // is dead, so keep TokenTimer from tracking (and alerting on) a
          // credential that no longer works.
          const deletedMonitoringToken = await Token.deleteByCertOpsApiTokenId(
            tokenId,
            { client },
          );
          if (deletedMonitoringToken) {
            await writeAudit({
              client,
              actorUserId: req.user.id,
              subjectUserId: req.user.id,
              action: "TOKEN_DELETED",
              targetType: "token",
              targetId: deletedMonitoringToken.id,
              channel: null,
              workspaceId: req.workspace.id,
              metadata: {
                name: deletedMonitoringToken.name,
                reason: "certops_api_token_revoked",
              },
            });
          }
        }
        return result;
      });

      if (!revoked.token) {
        return res.status(404).json({
          error: "CertOps API token not found",
          code: CERTOPS_API_TOKEN_NOT_FOUND,
        });
      }

      return res.json({ token: apiTokenMetadata(revoked.token) });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps API token revoke failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        tokenId,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to revoke CertOps API token",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.get(
  "/api/v1/workspaces/:id/certops/agent-bootstrap-tokens",
  getApiLimiter(),
  requireCertOpsEnabled,
  // Bootstrap-token metadata enumeration is manager-only, same as
  // create/revoke: viewers must not see agent onboarding token names,
  // prefixes, or expiry windows.
  requireCertOpsWriteRole,
  async (req, res) => {
    try {
      const tokens = await listBootstrapTokens({
        workspaceId: req.workspace.id,
      });
      return res.json({ items: tokens });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps agent bootstrap token list failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to list CertOps agent bootstrap tokens",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/agent-bootstrap-tokens",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  requireCertOpsTokenManager,
  async (req, res) => {
    try {
      const created = await withCertOpsTokenTransaction(async (client) => {
        // createBootstrapToken enforces required future expiry and the
        // max-TTL window, so this route relies on service-layer validation.
        const tokenResult = await createBootstrapToken({
          client,
          workspaceId: req.workspace.id,
          name: req.body?.name,
          expiresAt: req.body?.expiresAt,
          createdBy: req.user.id,
        });
        await recordBootstrapTokenAudit({
          client,
          req,
          action: "CERTOPS_AGENT_BOOTSTRAP_TOKEN_CREATED",
          token: tokenResult.token,
          includeRevocation: false,
        });
        return tokenResult;
      });

      // The raw ttboot_ token is returned exactly once; only the hash is
      // persisted, so it can never be shown again.
      return res.status(201).json({
        token: created.token,
        plaintextToken: created.plaintextToken,
      });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps agent bootstrap token create failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to create CertOps agent bootstrap token",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/agent-bootstrap-tokens/:tokenId/revoke",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  requireCertOpsTokenManager,
  async (req, res) => {
    const tokenId = bootstrapTokenIdFromParams(req, res);
    if (!tokenId) return null;

    try {
      const revoked = await withCertOpsTokenTransaction(async (client) => {
        const before = await getBootstrapTokenById({
          client,
          workspaceId: req.workspace.id,
          tokenId,
        });
        const token = await revokeBootstrapToken({
          client,
          workspaceId: req.workspace.id,
          tokenId,
          revokedBy: req.user.id,
        });
        const revokedNow =
          Boolean(token) &&
          token.status === "revoked" &&
          before?.status !== "revoked";
        if (token && revokedNow) {
          await recordBootstrapTokenAudit({
            client,
            req,
            action: "CERTOPS_AGENT_BOOTSTRAP_TOKEN_REVOKED",
            token,
            includeRevocation: true,
          });
        }
        return token;
      });

      if (!revoked) {
        return res.status(404).json({
          error: "CertOps agent bootstrap token not found",
          code: CERTOPS_AGENT_BOOTSTRAP_TOKEN_NOT_FOUND,
        });
      }

      return res.json({ token: revoked });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps agent bootstrap token revoke failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        tokenId,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to revoke CertOps agent bootstrap token",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.get(
  "/api/v1/workspaces/:id/certops/agents",
  getApiLimiter(),
  requireCertOpsEnabled,
  // Agent fleet metadata (hostnames, versions, liveness) is manager-only,
  // matching the authorization posture of the token routes.
  requireCertOpsWriteRole,
  async (req, res) => {
    try {
      const agents = await listAgents({ workspaceId: req.workspace.id });
      return res.json({ items: agents });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps agent list failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to list CertOps agents",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/agents/:agentId/retire",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  requireCertOpsTokenManager,
  async (req, res) => {
    const agentId = agentIdFromParams(req, res);
    if (!agentId) return null;

    const force = req.body?.force === true;

    try {
      // Force requires an attributable justification before any DB work.
      const reason = force
        ? normalizeRequiredRetireReason(req.body?.reason)
        : null;

      const outcome = await withCertOpsTransaction(async (client) => {
        const existing = await getAgentById({
          client,
          workspaceId: req.workspace.id,
          agentId,
        });
        if (!existing) return { notFound: true };

        // Idempotent: an already-retired agent returns its current state
        // without a duplicate audit event.
        if (existing.status === "retired") {
          return { agent: existing, retiredNow: false };
        }

        const leasedJobs = await countActivelyLeasedJobs({
          client,
          agentId,
        });
        if (leasedJobs > 0 && !force) {
          return { blocked: true, leasedJobs };
        }

        // Force-retire immediately fences in-flight leases (H12): claimed
        // jobs are cancelled; running jobs become orphaned_unknown_effect
        // for operator reconciliation rather than waiting for the reaper.
        const result = await retireAgent({
          client,
          workspaceId: req.workspace.id,
          agentId,
          retiredBy: req.user.id,
          reason,
          force,
        });
        if (result.agent && result.retiredNow) {
          await recordAgentRetiredAudit({
            client,
            req,
            agent: result.agent,
            force,
            reason,
            leasedJobs,
            fenced: result.fenced || null,
          });
        }
        return result;
      });

      if (outcome.blocked) {
        return res.status(409).json({
          error: "CertOps agent has actively leased jobs",
          code: CERTOPS_AGENT_RETIRE_BLOCKED,
          dependencies: { leasedJobs: outcome.leasedJobs },
        });
      }

      if (outcome.notFound || !outcome.agent) {
        return res.status(404).json({
          error: "CertOps agent not found",
          code: CERTOPS_AGENT_NOT_FOUND,
        });
      }

      return res.json({
        agent: outcome.agent,
        ...(outcome.fenced
          ? {
              fenced: {
                cancelledJobIds: outcome.fenced.cancelledJobIds || [],
                orphanedJobIds: outcome.fenced.orphanedJobIds || [],
              },
            }
          : {}),
      });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps agent retire failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        agentId,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to retire CertOps agent",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.get(
  "/api/v1/workspaces/:id/certops/jobs",
  getApiLimiter(),
  requireCertOpsEnabled,
  async (req, res) => {
    try {
      const result = await listCertificateJobs(jobListOptionsFromRequest(req));
      return res.json({
        items: result.items.map(jobSummary),
        pagination: result.pagination,
      });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps job list failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to list CertOps jobs",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

// The kill-switch setting is intentionally small and workspace-local. It stays
// available while rollout is disabled so incident controls can be inspected or
// staged; its response composes the independent global and workspace state.
router.get(
  "/api/v1/workspaces/:id/certops/settings",
  getApiLimiter(),
  requireCertOpsSessionUser,
  async (req, res) => {
    try {
      const state = await getWorkspaceCertOpsPauseState({
        workspaceId: req.workspace.id,
      });
      return res.json(workspacePauseStateResponse(state));
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps workspace settings fetch failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to fetch CertOps workspace settings",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.put(
  "/api/v1/workspaces/:id/certops/settings",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsSessionUser,
  authorize("certops.kill_switch.manage"),
  async (req, res) => {
    try {
      const state = await setWorkspaceCertOpsPauseState({
        workspaceId: req.workspace.id,
        certOpsPaused: req.body?.certOpsPaused,
        reason: req.body?.reason,
        actorUserId: req.user?.id || null,
        subjectUserId: req.user?.id || null,
      });
      return res.json(workspacePauseStateResponse(state));
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps workspace settings update failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to update CertOps workspace settings",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/jobs",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  // Manual job creation is a write action that mutates workspace state
  // (queues an executor job), so it uses the same manager-only gate as
  // token issuance/revocation rather than the read-only jobs-list route.
  requireCertOpsWriteRole,
  // Keep this after key-material rejection, rollout, and role checks. It
  // blocks only new work; reads and existing machine event/evidence ingestion
  // remain available while a workspace is paused.
  requireWorkspaceCertOpsActive,
  createManualCertificateJobHandler(),
);

// Bulk renewal shares the exact middleware posture of single manual job
// creation: each certificate id is queued through the same manual-creation
// service path, and per-certificate outcomes are reported in a
// partial-failure envelope instead of aborting the batch.
router.post(
  "/api/v1/workspaces/:id/certops/jobs/bulk-renew",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  requireCertOpsWriteRole,
  requireWorkspaceCertOpsActive,
  bulkRenewCertificatesHandler(),
);

router.post(
  "/api/v1/workspaces/:id/certops/provision-intents",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  requireCertOpsSessionUser,
  requireCertOpsWriteRole,
  requireWorkspaceCertOpsActive,
  createControllerProvisionIntentHandler(),
);

// Approval gates. Approval/rejection is an attributable human decision:
// internal worker credentials are rejected (requireCertOpsSessionUser) and
// the decision needs the same manager role as manual job creation. The
// workspace pause gate is intentionally absent: deciding an approval while
// paused is safe because the agent claim path is itself blocked by the
// kill switch, and a rejection is exactly the kind of action an operator
// may need during an incident.
router.post(
  "/api/v1/workspaces/:id/certops/jobs/:jobId/approve",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  requireCertOpsSessionUser,
  requireCertOpsWriteRole,
  jobApprovalDecisionHandler("approve"),
);

router.post(
  "/api/v1/workspaces/:id/certops/jobs/:jobId/reject",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  requireCertOpsSessionUser,
  requireCertOpsWriteRole,
  jobApprovalDecisionHandler("reject"),
);

router.get(
  "/api/v1/workspaces/:id/certops/jobs/:jobId/log",
  getApiLimiter(),
  requireCertOpsEnabled,
  async (req, res) => {
    const jobId = jobIdFromParams(req, res);
    if (!jobId) return null;

    try {
      const result = await listCertificateJobLog({
        workspaceId: req.workspace.id,
        jobId,
        limit: req.query.limit,
        offset: req.query.offset,
      });
      return res.json({
        items: result.items.map(jobLogEntry),
        pagination: result.pagination,
      });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps job log list failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        jobId,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to list CertOps job log",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.get(
  "/api/v1/workspaces/:id/certops/jobs/:jobId/evidence",
  getApiLimiter(),
  requireCertOpsEnabled,
  async (req, res) => {
    const jobId = jobIdFromParams(req, res);
    if (!jobId) return null;

    try {
      const result = await listCertificateEvidence({
        workspaceId: req.workspace.id,
        jobId,
        limit: req.query.limit,
        offset: req.query.offset,
      });
      return res.json({
        items: result.items.map(evidenceItem),
        pagination: result.pagination,
      });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps job evidence list failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        jobId,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to list CertOps job evidence",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.get(
  "/api/v1/workspaces/:id/certops/jobs/:jobId",
  getApiLimiter(),
  requireCertOpsEnabled,
  async (req, res) => {
    const jobId = jobIdFromParams(req, res);
    if (!jobId) return null;

    try {
      const job = await getCertificateJobById({
        workspaceId: req.workspace.id,
        jobId,
      });

      if (!job) {
        return res.status(404).json({
          error: "Certificate job not found",
          code: CERTOPS_JOB_NOT_FOUND,
        });
      }

      return res.json({ job: jobDetail(job) });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps job detail failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        jobId,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to load CertOps job",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

async function retireCertificateHandler(req, res) {
  if (!UUID_PATTERN.test(String(req.params.certId || ""))) {
    return res.status(404).json({
      error: "Certificate not found",
      code: CERTOPS_CERTIFICATE_NOT_FOUND,
    });
  }

  try {
    const certificate = await retireManagedCertificate({
      workspaceId: req.workspace.id,
      certificateId: req.params.certId,
      status: req.body?.status,
      reason: req.body?.reason,
      actorUserId: req.user?.id || null,
      createdBy: req.user?.id || null,
    });

    return res.json({ certificate });
  } catch (err) {
    const handled = handleCertOpsError(res, err);
    if (handled) return handled;

    logger.error("CertOps certificate retire failed", {
      error: err.message,
      code: err.code || null,
      workspaceId: req.workspace?.id,
      certId: req.params?.certId,
      userId: req.user?.id,
    });
    return res.status(500).json({
      error: "Failed to retire certificate",
      code: "INTERNAL_ERROR",
    });
  }
}

async function importCertificatesHandler(req, res, source, statusCode) {
  try {
    const options = writeOptionsFromRequest(req, source);
    if (!options.certificatePem) {
      return res.status(400).json({
        error: "certificatePem is required",
        code: "CERTOPS_CERTIFICATE_PEM_REQUIRED",
      });
    }

    const certificates = await withCertOpsTransaction(async (client) => {
      const imported = await importPublicCertificates({
        ...options,
        client,
      });
      await recordInventoryAudit(req, source, imported, client);
      return imported;
    });
    return res.status(statusCode).json({
      items: certificates,
      count: certificates.length,
    });
  } catch (err) {
    const handled = handleCertOpsError(res, err);
    if (handled) return handled;

    logger.error("CertOps certificate import failed", {
      error: err.message,
      code: err.code || null,
      workspaceId: req.workspace?.id,
      userId: req.user?.id,
    });
    return res.status(500).json({
      error: "Failed to import certificate",
      code: "INTERNAL_ERROR",
    });
  }
}

router.get(
  "/api/v1/workspaces/:id/certops/certificates",
  getApiLimiter(),
  requireCertOpsEnabled,
  async (req, res) => {
    try {
      const result = await listManagedCertificates({
        workspaceId: req.workspace.id,
        limit: req.query.limit,
        offset: req.query.offset,
      });
      return res.json(result);
    } catch (err) {
      logger.error("CertOps certificate list failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to list certificates",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/certificates",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  requireCertOpsWriteRole,
  (req, res) => importCertificatesHandler(req, res, "api", 201),
);

router.get(
  "/api/v1/workspaces/:id/certops/certificates/:certId/instances",
  getApiLimiter(),
  requireCertOpsEnabled,
  async (req, res) => {
    if (!UUID_PATTERN.test(String(req.params.certId || ""))) {
      return res.status(404).json({
        error: "Certificate not found",
        code: "CERTOPS_CERTIFICATE_NOT_FOUND",
      });
    }

    try {
      const result = await listCertificateInstances({
        workspaceId: req.workspace.id,
        certId: req.params.certId,
        limit: req.query.limit,
        offset: req.query.offset,
      });

      if (!result) {
        return res.status(404).json({
          error: "Certificate not found",
          code: "CERTOPS_CERTIFICATE_NOT_FOUND",
        });
      }

      return res.json(result);
    } catch (err) {
      logger.error("CertOps certificate instances list failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        certId: req.params?.certId,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to list certificate instances",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/certificates/:certId/retire",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  requireCertOpsWriteRole,
  retireCertificateHandler,
);

router.get(
  "/api/v1/workspaces/:id/certops/certificates/:certId",
  getApiLimiter(),
  requireCertOpsEnabled,
  async (req, res) => {
    if (!UUID_PATTERN.test(String(req.params.certId || ""))) {
      return res.status(404).json({
        error: "Certificate not found",
        code: "CERTOPS_CERTIFICATE_NOT_FOUND",
      });
    }

    try {
      const certificate = await getManagedCertificate({
        workspaceId: req.workspace.id,
        certId: req.params.certId,
      });

      if (!certificate) {
        return res.status(404).json({
          error: "Certificate not found",
          code: "CERTOPS_CERTIFICATE_NOT_FOUND",
        });
      }

      return res.json({ certificate });
    } catch (err) {
      logger.error("CertOps certificate detail failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        certId: req.params?.certId,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to load certificate",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/imports",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  requireCertOpsWriteRole,
  (req, res) => importCertificatesHandler(req, res, "import", 202),
);

module.exports = router;
module.exports._test = {
  createManualCertificateJobHandler,
  bulkRenewCertificatesHandler,
  bulkRenewItemIdempotencyKey,
  parseBulkRenewRequest,
  createControllerProvisionIntentHandler,
  requireCertOpsSessionUser,
  handleCertOpsError,
};

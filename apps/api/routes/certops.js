"use strict";

const router = require("express").Router();

const { pool } = require("../db/database");
const {
  getApiLimiter,
  getDiagnosticBootstrapLimiter,
} = require("../middleware/rateLimit");
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
const { authorize, can, hasAtLeastRole } = require("../services/rbac");
const {
  CERTOPS_LIST_SORT_INVALID,
} = require("../services/certops/listSorting");
const {
  CERTOPS_CERTIFICATE_FILTER_INVALID,
  CERTOPS_CERTIFICATE_NOT_FOUND,
  CERTOPS_CERTIFICATE_PARSE_FAILED,
  CERTOPS_CERTIFICATE_RETIRE_REASON_INVALID,
  CERTOPS_CERTIFICATE_RETIRE_STATUS_INVALID,
  CERTOPS_CERTIFICATE_SOURCE_INVALID,
  CERTOPS_CERTIFICATE_STATUS_INVALID,
  CERTOPS_KEY_MODE_INVALID,
  CERTOPS_KEY_REFERENCE_INVALID,
  CERTOPS_SOURCE_REF_INVALID,
  getManagedCertificate,
  importPublicCertificates,
  listCertificateInstances,
  listCertificateTargets,
  listManagedCertificates,
  listWorkspaceCertificateInstances,
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
  CERTOPS_AGENT_ALERTS_ENABLED_INVALID,
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
  getAgentsByAgentIdStrings,
  listAgents,
  normalizeRequiredRetireReason,
  retireAgent,
  updateAgentAlertSettings,
} = require("../services/certops/agentRegistry");
const {
  countCertificatesDependentPerAgent,
  resolveRenewalPathsForCertificateIds,
} = require("../services/certops/renewalPathHealth");
const {
  CERTOPS_DIAGNOSTIC_BOOTSTRAP_ALREADY_CONSUMED,
  CERTOPS_DIAGNOSTIC_BOOTSTRAP_REQUEST_ID_INVALID,
  createDiagnosticBootstrap,
} = require("../services/certops/diagnosticBootstrap");
const {
  CERTOPS_CERTIFICATE_NOT_AGENT_DEPLOYABLE,
  CERTOPS_RENEWAL_AUTO_RENEW_DISABLED,
  CERTOPS_JOB_EXECUTION_FIELD_INVALID,
  CERTOPS_JOB_EXECUTION_FIELD_REQUIRED,
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
  isAgentDeployableKeyMode,
  isTrustAnchorOperation,
  listCertificateJobLog,
  listCertificateJobs,
  manualRenewalJobCreator,
  preflightManualRenewalJob,
} = require("../services/certops/jobs");
const {
  AUTO_RENEW_DISABLED_PROFILE_STATUSES,
  NON_RENEWABLE_CERTIFICATE_STATUSES,
  resolveRenewalThresholdDays,
} = require("../services/certops/renewalScheduler");
const {
  CERTOPS_RENEWAL_OVERRIDE_INVALID,
  CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
  CERTOPS_RENEWAL_PROFILE_INVALID,
  resolveRenewalProfileSnapshot,
  validateRenewalManualOverrides,
} = require("../services/certops/renewalProfile");
const {
  CERTOPS_PROFILE_FIELD_IMMUTABLE,
  CERTOPS_PROFILE_INVALID,
  CERTOPS_PROFILE_NOT_FOUND,
  CERTOPS_PROFILE_NO_CHANGES,
  getRenewalProfile,
  listRenewalProfiles,
  listUpcomingRenewals,
  updateRenewalProfile,
} = require("../services/certops/renewalProfileAdmin");
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
  CERTOPS_WORKSPACE_APPROVAL_POLICY_STATE_INVALID,
  createManualCertificateJob,
  getWorkspaceCertOpsPauseState,
  setWorkspaceCertOpsSettings,
} = require("../services/certops/workspaceKillSwitch");
const {
  CERTOPS_TRUST_ANCHOR_INVALID,
  CERTOPS_TRUST_ANCHOR_NOT_ACTIVE,
  CERTOPS_TRUST_ANCHOR_NOT_FOUND,
  CERTOPS_TRUST_ANCHOR_PEM_INVALID,
  CERTOPS_TRUST_ANCHOR_TYPE_IMMUTABLE,
  CERTOPS_TRUST_INSTALLATION_NOT_FOUND,
  CERTOPS_TRUST_JOB_IDEMPOTENCY_KEY_REQUIRED,
  CERTOPS_TRUST_JOB_IDEMPOTENCY_CONFLICT,
  CERTOPS_TRUST_JOB_OPERATION_INVALID,
  CERTOPS_TRUST_RESULT_INVALID,
  CERTOPS_TRUST_RESULT_MISMATCH,
  CERTOPS_TRUST_RESULT_STALE_GENERATION,
  CERTOPS_TARGET_AGENT_INVALID,
  CERTOPS_TARGET_AGENT_NOT_FOUND,
  CERTOPS_TARGET_AGENT_INELIGIBLE,
  createTrustAnchor,
  listTrustAnchors,
  listInstallationsForAnchor,
  manualTrustJobCreator,
  retireTrustAnchor,
} = require("../services/certops/trustAnchors");
const {
  CERTOPS_CERTIFICATE_NOT_PROFILED,
  CERTOPS_RENEWAL_SETUP_ALREADY_CONFIGURED,
  CERTOPS_RENEWAL_SETUP_MULTI_LOCATION,
  CERTOPS_RENEWAL_SETUP_NO_DEPLOYED_PATH,
  CERTOPS_RENEWAL_SETUP_NO_COMMON_NAME,
  CERTOPS_RENEWAL_SETUP_WINDOWS_TOPOLOGY_INCOMPLETE,
  detachRenewalProfile,
  loadRenewalSetupIntents,
  loadResumablePreflights,
  projectRenewalPreflight,
  projectRenewalSetupState,
  renewalSetupJobCreator,
  retryRenewalSetupIntent,
} = require("../services/certops/renewalAdoption");
const {
  CERTOPS_OUTBOX_EVENT_NOT_FOUND,
  CERTOPS_OUTBOX_EVENT_NOT_RETRYABLE,
} = require("../services/certops/outbox");
const {
  CERTOPS_CONTROLLER_PROVISIONING_INVALID,
  CERTOPS_CONTROLLER_PROVISIONING_TERMINAL_IDENTITY,
  createControllerProvisionIntent,
} = require("../services/certops/controllerProvisioning");
const {
  createCertificateIssuanceJob,
} = require("../services/certops/issuance");
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

/**
 * Strips `deployedCertPath` from certificate records before they reach a
 * viewer.
 *
 * The certificate list and single-certificate GET routes are intentionally
 * not manager-gated (a viewer can see the inventory), but a deployment
 * filesystem path is host reconnaissance, the same reasoning that keeps the
 * renewal-profile routes manager-only (see the comment above those routes
 * below). This keeps that line even though the two projections share
 * `toInventoryRecord`, rather than forking the projection itself.
 */
function redactDeploymentPathForViewers(req, certificateOrList) {
  if (req.isWorkerCall || hasAtLeastRole(req.authz?.workspaceRole, "workspace_manager")) {
    return certificateOrList;
  }
  const strip = (certificate) =>
    certificate ? { ...certificate, deployedCertPath: undefined } : certificate;
  return Array.isArray(certificateOrList)
    ? certificateOrList.map(strip)
    : strip(certificateOrList);
}

/**
 * Strips `claimId` from a job-detail projection before it reaches anyone
 * below admin/owner.
 *
 * claimId is the lease token an agent must reprove on every renew/report
 * call before it can act on a host (see the agent claim/renew/report
 * routes and lease_renewed_at handling in services/certops/jobs.js) - closer
 * to a credential than to ordinary job metadata like status or timestamps.
 * The job-detail read route is intentionally not manager-gated (any
 * workspace member can follow a job's timeline), so this keeps the same
 * viewer-can-read / value-can-be-sensitive split that
 * `redactDeploymentPathForViewers` uses for deployment paths, but at the
 * stricter admin threshold: unlike a filesystem path, this value is
 * reusable proof of lease ownership for as long as the lease is open, so a
 * manager who can create jobs still isn't the right audience for it.
 */
function redactClaimIdForNonAdmins(req, jobDetailProjection) {
  if (!jobDetailProjection || !jobDetailProjection.claimId) {
    return jobDetailProjection;
  }
  if (req.isWorkerCall || hasAtLeastRole(req.authz?.workspaceRole, "admin")) {
    return jobDetailProjection;
  }
  return { ...jobDetailProjection, claimId: undefined };
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
  if (err?.code === CERTOPS_LIST_SORT_INVALID) {
    return res.status(400).json({
      error: err.message,
      code: CERTOPS_LIST_SORT_INVALID,
    });
  }

  if (err?.code === CERTOPS_DISABLED) {
    return res.status(404).json(NOT_FOUND_RESPONSE);
  }

  if (err?.code === CERTOPS_PROFILE_NOT_FOUND) {
    return res.status(404).json({
      error: "Renewal profile not found",
      code: CERTOPS_PROFILE_NOT_FOUND,
    });
  }

  // 422 rather than 400: the request is well-formed, it asks for a change the
  // profile contract does not permit. The offending field names are returned so
  // the caller is never left guessing which one was refused.
  if (err?.code === CERTOPS_PROFILE_FIELD_IMMUTABLE) {
    return res.status(422).json({
      error: err.message,
      code: CERTOPS_PROFILE_FIELD_IMMUTABLE,
      fields: err.details?.fields || [],
    });
  }

  if (err?.code === CERTOPS_PROFILE_INVALID) {
    return res.status(422).json({
      error: err.message,
      code: CERTOPS_PROFILE_INVALID,
      fields: err.details?.fields || [],
    });
  }

  if (err?.code === CERTOPS_PROFILE_NO_CHANGES) {
    return res.status(400).json({
      error: err.message,
      code: CERTOPS_PROFILE_NO_CHANGES,
    });
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

  if (err?.code === CERTOPS_SOURCE_REF_INVALID) {
    return res.status(400).json({
      error: "sourceRef must be a non-secret reference",
      code: CERTOPS_SOURCE_REF_INVALID,
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
    err?.code === CERTOPS_AGENT_BOOTSTRAP_TOKEN_EXPIRY_INVALID ||
    err?.code === CERTOPS_AGENT_ALERTS_ENABLED_INVALID ||
    err?.code === "CERTOPS_AGENT_CONTACT_GROUP_INVALID"
  ) {
    return res.status(err.statusCode || 400).json({
      error: err.code === "CERTOPS_AGENT_CONTACT_GROUP_INVALID"
        ? err.message
        : "CertOps agent bootstrap token request is invalid",
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

  if (err?.code === CERTOPS_DIAGNOSTIC_BOOTSTRAP_REQUEST_ID_INVALID) {
    return res.status(400).json({
      error: "requestId is required and must be at most 128 characters",
      code: CERTOPS_DIAGNOSTIC_BOOTSTRAP_REQUEST_ID_INVALID,
    });
  }

  // Deliberately not a 409/replay body: a retried bootstrap must never
  // resemble a state the caller can recover from by retrying again, and it
  // must never suggest the original {agentId, credential, job} might still
  // be recoverable from the server (see ADR-0012 decision 7 and the
  // diagnosticBootstrap.js module comment).
  if (err?.code === CERTOPS_DIAGNOSTIC_BOOTSTRAP_ALREADY_CONSUMED) {
    return res.status(409).json({
      error: "This diagnostic bootstrap request was already consumed",
      code: CERTOPS_DIAGNOSTIC_BOOTSTRAP_ALREADY_CONSUMED,
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
    CERTOPS_JOB_EXECUTION_FIELD_REQUIRED,
    CERTOPS_EVIDENCE_INVALID,
    CERTOPS_EVIDENCE_TYPE_INVALID,
  ]);
  if (certOpsJobBadRequestCodes.has(err?.code)) {
    return res.status(400).json({
      error: "CertOps job request is invalid",
      code: err.code,
    });
  }

  // Trust-anchor CRUD/job creation errors (services/certops/trustAnchors.js).
  // err.message already names the specific field/reason, so it's surfaced
  // verbatim rather than replaced with a generic string.
  if (err?.code === CERTOPS_TRUST_ANCHOR_NOT_FOUND) {
    return res.status(404).json({
      error: err.message || "Trust anchor not found",
      code: CERTOPS_TRUST_ANCHOR_NOT_FOUND,
    });
  }
  if (err?.code === CERTOPS_TRUST_INSTALLATION_NOT_FOUND) {
    return res.status(404).json({
      error: err.message || "Trust anchor installation not found",
      code: CERTOPS_TRUST_INSTALLATION_NOT_FOUND,
    });
  }
  if (
    err?.code === CERTOPS_TRUST_ANCHOR_INVALID ||
    err?.code === CERTOPS_TRUST_ANCHOR_PEM_INVALID ||
    err?.code === CERTOPS_TRUST_JOB_IDEMPOTENCY_KEY_REQUIRED ||
    err?.code === CERTOPS_TRUST_JOB_OPERATION_INVALID
  ) {
    return res.status(400).json({
      error: err.message || "Trust anchor request is invalid",
      code: err.code,
    });
  }
  // 409, not 400: well-formed request, but distribute-trust was requested
  // against an anchor that isn't currently active.
  if (err?.code === CERTOPS_TRUST_ANCHOR_NOT_ACTIVE) {
    return res.status(409).json({
      error: err.message || "Trust anchor is not active",
      code: CERTOPS_TRUST_ANCHOR_NOT_ACTIVE,
    });
  }
  // 409: well-formed request, but the caller tried to change anchor_type
  // while a live (non-removed) installation still depends on the current
  // value (see createTrustAnchor's anchor_type-immutability check).
  if (err?.code === CERTOPS_TRUST_ANCHOR_TYPE_IMMUTABLE) {
    return res.status(409).json({
      error: err.message || "Trust anchor type cannot be changed while installations are live",
      code: CERTOPS_TRUST_ANCHOR_TYPE_IMMUTABLE,
    });
  }
  // 409: mirrors CERTOPS_JOB_IDEMPOTENCY_CONFLICT below, for the
  // no-job reference-release idempotency ledger (see
  // certops_trust_reference_release_idempotency in trustAnchors.js).
  if (err?.code === CERTOPS_TRUST_JOB_IDEMPOTENCY_CONFLICT) {
    return res.status(409).json({
      error:
        "Idempotency key was already used with a different CertOps trust-reference-release request",
      code: CERTOPS_TRUST_JOB_IDEMPOTENCY_CONFLICT,
    });
  }
  // Target-agent validation for distribute-trust/revoke-trust
  // (trustAnchors.js's assertTargetAgentRegistered): malformed id is a 400,
  // well-formed-but-unregistered is a 404, mirroring the anchor-lookup
  // split just above.
  if (err?.code === CERTOPS_TARGET_AGENT_INVALID) {
    return res.status(400).json({
      error: err.message || "agentId is invalid",
      code: CERTOPS_TARGET_AGENT_INVALID,
    });
  }
  if (err?.code === CERTOPS_TARGET_AGENT_NOT_FOUND) {
    return res.status(404).json({
      error: err.message || "Target agent not found",
      code: CERTOPS_TARGET_AGENT_NOT_FOUND,
    });
  }
  // 409: the agent can never claim this job (retired or version-blocked),
  // same convention as CERTOPS_TRUST_ANCHOR_NOT_ACTIVE below.
  if (err?.code === CERTOPS_TARGET_AGENT_INELIGIBLE) {
    return res.status(409).json({
      error: err.message || "Target agent cannot currently claim this job",
      code: CERTOPS_TARGET_AGENT_INELIGIBLE,
    });
  }
  // Result-ingestion codes (agentDispatch.ingestResult) mapped here too for
  // a consistent response shape across callers.
  if (err?.code === CERTOPS_TRUST_RESULT_INVALID) {
    return res.status(400).json({
      error: err.message || "Trust job result is invalid",
      code: CERTOPS_TRUST_RESULT_INVALID,
    });
  }
  if (
    err?.code === CERTOPS_TRUST_RESULT_MISMATCH ||
    err?.code === CERTOPS_TRUST_RESULT_STALE_GENERATION
  ) {
    return res.status(409).json({
      error: err.message || "Trust job result does not match the job",
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

  // Names exactly which field was rejected and why, so it's surfaced
  // verbatim (see validateRenewalManualOverrides in renewalProfile.js).
  if (err?.code === CERTOPS_RENEWAL_OVERRIDE_INVALID) {
    return res.status(400).json({
      error: err.message || "Renewal override is invalid",
      code: CERTOPS_RENEWAL_OVERRIDE_INVALID,
    });
  }

  if (err?.code === CERTOPS_CERTIFICATE_NOT_AGENT_DEPLOYABLE) {
    return res.status(409).json({
      error: err.message,
      code: CERTOPS_CERTIFICATE_NOT_AGENT_DEPLOYABLE,
    });
  }

  if (err?.code === CERTOPS_RENEWAL_AUTO_RENEW_DISABLED) {
    return res.status(409).json({
      error: err.message,
      code: CERTOPS_RENEWAL_AUTO_RENEW_DISABLED,
    });
  }

  if (
    err?.code === CERTOPS_RENEWAL_SETUP_ALREADY_CONFIGURED ||
    err?.code === CERTOPS_RENEWAL_SETUP_MULTI_LOCATION
  ) {
    return res.status(409).json({
      error: err.message,
      code: err.code,
    });
  }

  if (
    err?.code === CERTOPS_RENEWAL_SETUP_NO_DEPLOYED_PATH ||
    err?.code === CERTOPS_RENEWAL_SETUP_NO_COMMON_NAME ||
    err?.code === CERTOPS_RENEWAL_SETUP_WINDOWS_TOPOLOGY_INCOMPLETE
  ) {
    return res.status(422).json({
      error: err.message,
      code: err.code,
    });
  }

  if (err?.code === CERTOPS_CERTIFICATE_NOT_PROFILED) {
    return res.status(422).json({
      error: err.message,
      code: CERTOPS_CERTIFICATE_NOT_PROFILED,
    });
  }

  if (err?.code === CERTOPS_OUTBOX_EVENT_NOT_FOUND) {
    return res.status(404).json({
      error: "Outbox event not found",
      code: CERTOPS_OUTBOX_EVENT_NOT_FOUND,
    });
  }

  if (err?.code === CERTOPS_OUTBOX_EVENT_NOT_RETRYABLE) {
    return res.status(422).json({
      error: err.message,
      code: CERTOPS_OUTBOX_EVENT_NOT_RETRYABLE,
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

  if (err?.code === CERTOPS_WORKSPACE_APPROVAL_POLICY_STATE_INVALID) {
    return res.status(400).json({
      error: "CertOps workspace approval policy request is invalid",
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
    // Optional pin to a specific agent (jobs.js: explicit assignment always
    // wins over auto-assignment from the certificate's discovery agent).
    // Lets an operator route a manual job to a known-good host instead of
    // whichever eligible agent happens to poll first.
    assignedAgentId: req.body?.assignedAgentId,
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
      // Trust-anchor operations change what every certificate on a host is
      // trusted against, not just one certificate's lifecycle (ADR-0012
      // decisions 4-6), so they require certops.trust_anchor.manage (admin)
      // rather than the workspace_manager level ordinary job creation
      // (requireCertOpsWriteRole, above this handler in the route chain)
      // uses. Checked here, not as a static route-level authorize(), because
      // this one route handles every operation and only two of them need the
      // higher bar.
      if (
        isTrustAnchorOperation(req.body?.operation) &&
        !can(req.authz?.workspaceRole, "certops.trust_anchor.manage")
      ) {
        return res.status(403).json({
          error: "Forbidden: insufficient role",
          code: "INSUFFICIENT_ROLE",
        });
      }

      // An issue job creates the certificate identity before the job that
      // references it, so it swaps in a different creator. A renew job
      // swaps in one too: it materializes the payload from the
      // certificate's stored renewal profile instead of trusting the
      // request payload, so a manual renew can't diverge from an automatic
      // one (see manualRenewalJobCreator in jobs.js for the override
      // allowlist). A trust-anchor operation swaps in a third creator for
      // the same reason: trustAnchors.createTrustJob is the only path
      // allowed to create that job, since its installation-row state
      // machine must advance in the same transaction as the job insert.
      // Everything else (workspace lock, kill switch, audit row) is shared.
      const jobCreator =
        req.body?.operation === "issue"
          ? createCertificateIssuanceJob
          : req.body?.operation === "renew"
            ? manualRenewalJobCreator({ certificateId: req.body?.subjectId })
            : isTrustAnchorOperation(req.body?.operation)
              ? manualTrustJobCreator({
                  trustAnchorId: req.body?.subjectId,
                  agentId: req.body?.agentId,
                  owner: req.body?.owner,
                })
              : undefined;
      const { job, skippedOsMutation, installation } = await manualJobCreator({
        ...jobCreateOptionsFromRequest(req),
        ...(jobCreator ? { jobCreator } : {}),
        actorUserId: req.user?.id || null,
        subjectUserId: req.user?.id || null,
      });
      // revoke-trust for an owner whose reference isn't the last live one
      // creates no job (the OS store must not be touched while another
      // owner still references the same fingerprint).
      if (skippedOsMutation) {
        return res.status(200).json({ ownershipReleased: true, installation });
      }
      return res
        .status(201)
        .json({ job: redactClaimIdForNonAdmins(req, jobDetail(job)) });
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
  // No auto-derived fallback: the jobs table's (workspace_id,
  // idempotency_key) uniqueness has no time component, so a key derived from
  // the certificate id alone would make that certificate renewable exactly
  // once, forever. Retry safety is opt-in instead, via a caller-supplied key.
  if (idempotencyKey) {
    return `bulk-renew:${idempotencyKey}:${certificateId}`;
  }
  return null;
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
 * instead of enqueueing duplicates. Omitting the key leaves items without
 * one, so a replayed POST enqueues fresh jobs.
 *
 * Dry run preflights each certificate without writing: existence, renewable
 * inventory status, resolution of that certificate's stored renewal profile
 * into the payload the real run would insert (so an incomplete or invalid
 * profile fails the item here rather than at real-run time), and whether a
 * non-terminal renew job is already in flight (reported as activeJobId so
 * callers can spot double-renewals before committing). Capacity is not
 * checked: a dry run must not reserve per-CA capacity.
 */
function bulkRenewCertificatesHandler({
  manualJobCreator = createManualCertificateJob,
  certificateLoader = getManagedCertificate,
  activeJobFinder = findActiveJobForSubject,
  renewalPreflight = preflightManualRenewalJob,
} = {}) {
  return async function bulkRenewCertificatesHandler(req, res) {
    const parsed = parseBulkRenewRequest(req.body);
    if (parsed.error) {
      return res.status(400).json({
        error: parsed.error,
        code: CERTOPS_JOB_INVALID,
      });
    }

    // The payload is a whole-request field shared as an override on top of
    // each certificate's stored renewal profile; validate it once up front
    // rather than surfacing N identical item errors.
    try {
      validateRenewalManualOverrides(parsed.payload);
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
          await renewalPreflight({
            workspaceId: req.workspace.id,
            certificateId,
            payload: parsed.payload,
          });
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
          payload: parsed.payload,
          jobCreator: manualRenewalJobCreator({ certificateId }),
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
        job: redactClaimIdForNonAdmins(req, jobDetail(result.job)),
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
    certOpsRequireApprovalAlways: state.certOpsRequireApprovalAlways === true,
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
    approvedByUserId: job.approvedByUserId,
    approvedAt: job.approvedAt,
    assignedAgentId: job.assignedAgentId ?? null,
    claimedByAgentId: job.claimedByAgentId ?? null,
    needsOperatorReconciliation: job.needsOperatorReconciliation === true,
    reconciliationReason: job.reconciliationReason ?? null,
    errorMessage: job.errorMessage ?? null,
    pendingReason: job.pendingReason ?? null,
  };
}

function jobDetail(job) {
  return {
    ...jobSummary(job),
    payload: job.payload || {},
    resultMetadata: job.resultMetadata || {},
    errorCode: job.errorCode,
    errorMessage: job.errorMessage,
    // Claim/lease/attempt metadata: already computed by the service layer
    // (mapJobRow in services/certops/jobs.js) but previously dropped at this
    // projection boundary, so a human reviewing the job timeline had no
    // visibility into which agent held the job, how long its lease was valid
    // for, or which attempt this was. There is no per-attempt signing-key id
    // anywhere in the schema or agent protocol (pinned_signing_key_id lives
    // on certops_agents, not on a job/attempt), so that piece isn't included
    // here - it would need new schema, not just a projection fix. The
    // job-detail route below best-effort-resolves the claiming agent's
    // current pinned key as the closest honest proxy.
    claimId: job.claimId,
    claimedByAgentId: job.claimedByAgentId,
    claimedByControllerClusterId: job.claimedByControllerClusterId,
    leaseExpiresAt: job.leaseExpiresAt,
    leaseRenewedAt: job.leaseRenewedAt,
    attemptCount: job.attemptCount,
    maxAttempts: job.maxAttempts,
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
    // A controller token is unusable without this: the executor that claims a
    // provisioning job authenticates with a token bound to the same
    // clusterId, so a token list that omitted it could not show which
    // cluster (if any) a token is bound to.
    controllerClusterId: token.controllerClusterId ?? null,
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
        limit: req.query.limit,
        offset: req.query.offset,
      });
      return res.json({
        items: tokens.items.map(apiTokenMetadata),
        pagination: tokens.pagination,
      });
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
  // Minting a machine token is new capability granted to a workspace, not
  // a read or a recovery action, so it uses the same workspace-active gate
  // as manual job creation. Without this, a paused workspace (the operator
  // believes it is frozen from new work) could still mint a live, usable
  // credential server-side even though the dashboard's create button is
  // already disabled while paused - the UI's own intent was never enforced
  // here.
  requireWorkspaceCertOpsActive,
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
        limit: req.query.limit,
        offset: req.query.offset,
      });
      return res.json({
        items: tokens.items,
        pagination: tokens.pagination,
      });
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
  // Same posture as API token creation immediately above (see that route's
  // comment): minting a bootstrap credential is new capability, not a read
  // or a recovery action, so it is blocked while the workspace is paused.
  // Found alongside the token-create gap this route mirrors; both were
  // missing the workspace-active gate for the same reason.
  requireWorkspaceCertOpsActive,
  async (req, res) => {
    try {
      const created = await withCertOpsTokenTransaction(async (client) => {
        // Validate contact_group_id belongs to the workspace up front (same
        // check as tokens.js), so a bad id fails the create instead of
        // silently resolving to "no group" at send time much later.
        let contactGroupId = null;
        if (
          req.body?.contactGroupId !== undefined &&
          req.body?.contactGroupId !== null &&
          String(req.body.contactGroupId).trim() !== ""
        ) {
          const cgId = String(req.body.contactGroupId).trim();
          const cgRes = await client.query(
            "SELECT 1 FROM workspace_settings WHERE workspace_id = $1 AND EXISTS (SELECT 1 FROM jsonb_array_elements(contact_groups) AS g WHERE (g->>'id') = $2)",
            [req.workspace.id, cgId],
          );
          if (cgRes.rowCount === 0) {
            const error = new Error("Invalid contactGroupId for workspace");
            error.code = "CERTOPS_AGENT_CONTACT_GROUP_INVALID";
            error.statusCode = 400;
            throw error;
          }
          contactGroupId = cgId;
        }

        // createBootstrapToken enforces required future expiry and the
        // max-TTL window, so this route relies on service-layer validation.
        const tokenResult = await createBootstrapToken({
          client,
          workspaceId: req.workspace.id,
          name: req.body?.name,
          expiresAt: req.body?.expiresAt,
          createdBy: req.user.id,
          downtimeAlertsEnabled: req.body?.downtimeAlertsEnabled,
          contactGroupId,
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

router.post(
  "/api/v1/workspaces/:id/certops/agents/diagnostic-bootstrap",
  getDiagnosticBootstrapLimiter(),
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  requireCertOpsSessionUser,
  authorize("certops.agents.diagnose"),
  async (req, res) => {
    try {
      const result = await createDiagnosticBootstrap({
        workspaceId: req.workspace.id,
        requestId: req.body?.requestId,
        requestedByUserId: req.user.id,
        env: process.env,
      });
      return res.status(201).json(result);
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps diagnostic agent bootstrap failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to bootstrap CertOps diagnostic agent",
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
      const agents = await listAgents({
        workspaceId: req.workspace.id,
        limit: req.query.limit,
        offset: req.query.offset,
        sort: req.query.sort,
        direction: req.query.direction,
      });
      let impactCounts = new Map();
      try {
        impactCounts = await countCertificatesDependentPerAgent({
          workspaceId: req.workspace.id,
        });
      } catch (impactErr) {
        // Impact counts are an enrichment, not core fleet data; a failure
        // here (e.g. a workspace with malformed profile metadata) must not
        // take down the whole agent list.
        logger.warn("CertOps agent renewal-impact count failed", {
          error: impactErr.message,
          workspaceId: req.workspace?.id,
        });
      }
      const items = agents.items.map((agent) => ({
        ...agent,
        dependentAutoRenewCertificateCount: impactCounts.get(String(agent.id)) || 0,
      }));
      return res.json({
        items,
        pagination: agents.pagination,
      });
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

router.patch(
  "/api/v1/workspaces/:id/certops/agents/:agentId/alert-settings",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  requireCertOpsTokenManager,
  async (req, res) => {
    const agentId = agentIdFromParams(req, res);
    if (!agentId) return null;

    if (
      req.body?.downtimeAlertsEnabled === undefined &&
      req.body?.contactGroupId === undefined
    ) {
      return res.status(400).json({
        error: "At least one of downtimeAlertsEnabled or contactGroupId is required",
        code: "CERTOPS_AGENT_ALERT_SETTINGS_EMPTY",
      });
    }

    try {
      const outcome = await withCertOpsTransaction(async (client) => {
        const existing = await getAgentById({
          client,
          workspaceId: req.workspace.id,
          agentId,
        });
        if (!existing) return { notFound: true };

        let contactGroupId;
        if (req.body?.contactGroupId !== undefined) {
          if (req.body.contactGroupId === null || String(req.body.contactGroupId).trim() === "") {
            contactGroupId = null;
          } else {
            const cgId = String(req.body.contactGroupId).trim();
            const cgRes = await client.query(
              "SELECT 1 FROM workspace_settings WHERE workspace_id = $1 AND EXISTS (SELECT 1 FROM jsonb_array_elements(contact_groups) AS g WHERE (g->>'id') = $2)",
              [req.workspace.id, cgId],
            );
            if (cgRes.rowCount === 0) {
              return { invalidContactGroup: true };
            }
            contactGroupId = cgId;
          }
        }

        const agent = await updateAgentAlertSettings({
          client,
          workspaceId: req.workspace.id,
          agentId,
          downtimeAlertsEnabled: req.body?.downtimeAlertsEnabled,
          contactGroupId,
        });

        await writeAudit({
          client,
          actorUserId: req.user.id,
          subjectUserId: req.user.id,
          action: "CERTOPS_AGENT_ALERT_SETTINGS_UPDATED",
          targetType: "certops_agent",
          targetId: null,
          workspaceId: req.workspace.id,
          metadata: {
            agentId: agent.agentId,
            downtimeAlertsEnabled: agent.downtimeAlertsEnabled,
            contactGroupId: agent.contactGroupId,
          },
        });

        return { agent };
      });

      if (outcome.notFound) {
        return res.status(404).json({
          error: "CertOps agent not found",
          code: CERTOPS_AGENT_NOT_FOUND,
        });
      }
      if (outcome.invalidContactGroup) {
        return res.status(400).json({
          error: "Invalid contactGroupId for workspace",
          code: "CERTOPS_AGENT_CONTACT_GROUP_INVALID",
        });
      }

      return res.json({ agent: outcome.agent });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps agent alert settings update failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        agentId,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to update CertOps agent alert settings",
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
      const hasPauseField = req.body?.certOpsPaused !== undefined;
      const hasApprovalField =
        req.body?.certOpsRequireApprovalAlways !== undefined;
      if (!hasPauseField && !hasApprovalField) {
        return res.status(400).json({
          error:
            "certOpsPaused or certOpsRequireApprovalAlways is required",
          code: CERTOPS_WORKSPACE_PAUSE_STATE_INVALID,
        });
      }

      // Both fields (when present) are written in one transaction so a
      // failure partway through never leaves one setting applied and the
      // other not; see setWorkspaceCertOpsSettings.
      const state = await setWorkspaceCertOpsSettings({
        workspaceId: req.workspace.id,
        certOpsPaused: hasPauseField ? req.body.certOpsPaused : undefined,
        requireApprovalAlways: hasApprovalField
          ? req.body.certOpsRequireApprovalAlways
          : undefined,
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

// Trust-anchor CRUD (ADR-0012 decisions 6/20). Every route here is gated by
// certops.trust_anchor.manage (admin), above the workspace_manager bar the
// rest of this file's write routes use, since a trust anchor changes what
// every certificate on a host is trusted against. "retire" (not "revoke")
// is the anchor-level verb here; see trustAnchors.js's TERMINOLOGY comment.
function trustAnchorIdFromParams(req, res) {
  const anchorId = String(req.params.anchorId || "");
  if (!UUID_PATTERN.test(anchorId)) {
    res.status(400).json({
      error: "Trust anchor identifier is invalid",
      code: CERTOPS_TRUST_ANCHOR_INVALID,
    });
    return null;
  }
  return anchorId;
}

router.get(
  "/api/v1/workspaces/:id/certops/trust-anchors",
  getApiLimiter(),
  requireCertOpsEnabled,
  authorize("certops.trust_anchor.manage"),
  async (req, res) => {
    try {
      const anchors = await listTrustAnchors({
        workspaceId: req.workspace.id,
        status: req.query.status,
      });
      return res.json({ items: anchors });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps trust anchor list failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to list trust anchors",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/trust-anchors",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  authorize("certops.trust_anchor.manage"),
  requireWorkspaceCertOpsActive,
  async (req, res) => {
    try {
      const anchor = await withCertOpsTransaction((client) =>
        createTrustAnchor({
          client,
          workspaceId: req.workspace.id,
          name: req.body?.name,
          anchorType: req.body?.anchorType,
          pem: req.body?.pem,
          source: "api",
          publicMetadata: req.body?.metadata,
          createdByUserId: req.user?.id || null,
        }),
      );
      return res.status(201).json({ trustAnchor: anchor });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps trust anchor creation failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to create trust anchor",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/trust-anchors/:anchorId/retire",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  authorize("certops.trust_anchor.manage"),
  requireWorkspaceCertOpsActive,
  async (req, res) => {
    const anchorId = trustAnchorIdFromParams(req, res);
    if (!anchorId) return null;

    try {
      const result = await retireTrustAnchor({
        workspaceId: req.workspace.id,
        anchorId,
        reason: req.body?.reason,
        retiredByUserId: req.user?.id || null,
      });
      return res.json({
        trustAnchor: result.anchor,
        retiredNow: result.retiredNow,
      });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps trust anchor retire failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        anchorId,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to retire trust anchor",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

// Read-only: intentionally omits requireWorkspaceCertOpsActive (unlike the
// two mutating trust-anchor routes above) so an operator diagnosing a
// frozen/deactivated workspace can still see where a trust anchor landed.
router.get(
  "/api/v1/workspaces/:id/certops/trust-anchors/:anchorId/installations",
  getApiLimiter(),
  requireCertOpsEnabled,
  authorize("certops.trust_anchor.manage"),
  async (req, res) => {
    const anchorId = trustAnchorIdFromParams(req, res);
    if (!anchorId) return null;

    try {
      const items = await listInstallationsForAnchor({
        workspaceId: req.workspace.id,
        trustAnchorId: anchorId,
      });
      return res.json({ items });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps trust anchor installations list failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        anchorId,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to list trust anchor installations",
        code: "INTERNAL_ERROR",
      });
    }
  },
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

      // There is no per-attempt signing-key id anywhere in the schema, so
      // the closest honest proxy for "which signing key backed this
      // dispatch" is the claiming agent's own currently-pinned key. Best
      // effort only: a lookup failure must not fail the job-detail response.
      let claimedByAgentSigningKeyId = null;
      if (job.claimedByAgentId) {
        try {
          const claimingAgent = await getAgentById({
            workspaceId: req.workspace.id,
            agentId: job.claimedByAgentId,
          });
          claimedByAgentSigningKeyId =
            claimingAgent?.pinnedSigningKeyId ?? null;
        } catch (lookupErr) {
          logger.warn("CertOps job-detail signing-key lookup failed", {
            error: lookupErr.message,
            workspaceId: req.workspace?.id,
            jobId,
          });
        }
      }

      return res.json({
        job: redactClaimIdForNonAdmins(req, {
          ...jobDetail(job),
          claimedByAgentSigningKeyId,
        }),
      });
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

/**
 * Renewal-automation state exposed with every inventory row.
 *
 * The renewal scheduler only creates automatic renew jobs for certificates
 * with agent-deployable key custody AND a linked certificate_profiles row
 * whose public_metadata.renewalProfile resolves to a complete, executable
 * contract; everything else is counted as skippedIncompleteProfile and never
 * renews. Without this projection an `active` certificate that will silently
 * expire looked identical to one that renews itself, so the decision is
 * derived here from the scheduler's own inputs instead of being guessed by
 * the client.
 */
const CERTOPS_RENEWAL_STATE_AUTO = "auto";
const CERTOPS_RENEWAL_STATE_DISABLED = "disabled";
const CERTOPS_RENEWAL_STATE_NOT_CONFIGURED = "not-configured";
const CERTOPS_RENEWAL_STATE_NOT_ELIGIBLE = "not-eligible";
const CERTOPS_RENEWAL_STATE_NOT_APPLICABLE = "not-applicable";

// Lifecycle states where renewal is moot rather than missing: the scheduler
// refuses NON_RENEWABLE_CERTIFICATE_STATUSES outright, and a provisioning
// certificate has no issued lifetime to renew yet.
const RENEWAL_MOOT_CERTIFICATE_STATUSES = new Set([
  ...NON_RENEWABLE_CERTIFICATE_STATUSES,
  "provisioning",
]);

const MS_PER_DAY = 24 * 60 * 60 * 1000;

/**
 * Effective renewal lead time: the per-profile override when it is a usable
 * positive integer, else the deployment-wide threshold. Matches the
 * COALESCE(cp.renew_before_days, threshold) the scheduler scans with.
 */
function effectiveRenewBeforeDays(profileRenewBeforeDays, env) {
  const parsed = Number.parseInt(profileRenewBeforeDays, 10);
  if (Number.isSafeInteger(parsed) && parsed > 0) return parsed;
  return resolveRenewalThresholdDays(env);
}

function renewalWindowStart(notAfter, renewBeforeDays) {
  if (!notAfter) return null;
  const expiry = new Date(notAfter);
  if (Number.isNaN(expiry.getTime())) return null;
  return new Date(
    expiry.getTime() - renewBeforeDays * MS_PER_DAY,
  ).toISOString();
}

/**
 * Derives the renewal state for one managed_certificates row joined with its
 * certificate_profiles row (same column names the scheduler selects).
 *
 * Profile completeness is answered by resolveRenewalProfileSnapshot, the
 * function the scheduler itself admits on, so the badge can never claim
 * "auto" for a certificate the sweep would refuse. `renewsFrom` is when the
 * sweep starts picking the certificate up (not_after minus the effective lead
 * time), not a promise of the exact renewal moment.
 *
 * `workspacePaused` answers a different question than `state`: `state` is
 * "is this profile switched on", `workspacePaused` is "will this workspace's
 * scheduler actually act right now". A paused workspace still derives `auto`
 * here (the profile itself is not disabled), but with `workspacePaused: true`
 * so the badge can say so instead of promising a renewal that will not run
 * until the workspace is resumed.
 */
function deriveCertificateRenewalState(
  row,
  { env = process.env, workspacePaused = false } = {},
) {
  const keyMode = row?.key_mode || null;
  const base = {
    schemaVersion: 1,
    keyMode,
    profileId: row?.profile_id ? String(row.profile_id) : null,
    profileName:
      typeof row?.profile_name === "string" ? row.profile_name : null,
    renewBeforeDays: null,
    renewsFrom: null,
    workspacePaused: workspacePaused === true,
  };

  const status = String(row?.status || "").toLowerCase();
  if (RENEWAL_MOOT_CERTIFICATE_STATUSES.has(status)) {
    return {
      ...base,
      state: CERTOPS_RENEWAL_STATE_NOT_APPLICABLE,
      detail: `Automatic renewal does not apply while this certificate is ${status}.`,
    };
  }

  if (!isAgentDeployableKeyMode(keyMode)) {
    return {
      ...base,
      state: CERTOPS_RENEWAL_STATE_NOT_ELIGIBLE,
      detail:
        "TokenTimer does not hold this certificate's key, so it is monitored only and cannot be renewed by an agent.",
    };
  }

  const renewBeforeDays = effectiveRenewBeforeDays(
    row?.profile_renew_before_days,
    env,
  );

  // Deliberate operator intent, so it is reported before profile completeness:
  // a switched-off certificate is not misconfigured and telling the operator to
  // go fix its profile would be wrong. Mirrors
  // AUTO_RENEW_DISABLED_PROFILE_STATUSES in the scheduler, which excludes these
  // rows from the scan entirely.
  const profileStatus = String(row?.profile_status || "").toLowerCase();
  if (
    row?.profile_id &&
    AUTO_RENEW_DISABLED_PROFILE_STATUSES.includes(profileStatus)
  ) {
    return {
      ...base,
      state: CERTOPS_RENEWAL_STATE_DISABLED,
      renewBeforeDays,
      detail: `Automatic renewal is switched off for this certificate because its renewal profile is ${profileStatus}. It will expire unless it is renewed manually or the profile is re-enabled.`,
    };
  }

  let incompleteReason = null;
  try {
    resolveRenewalProfileSnapshot(row);
  } catch (error) {
    if (
      error?.code !== CERTOPS_RENEWAL_PROFILE_INCOMPLETE &&
      error?.code !== CERTOPS_RENEWAL_PROFILE_INVALID
    ) {
      throw error;
    }
    incompleteReason = error.message || "renewal profile is incomplete";
  }

  if (incompleteReason) {
    return {
      ...base,
      state: CERTOPS_RENEWAL_STATE_NOT_CONFIGURED,
      renewBeforeDays,
      detail: `This certificate will not renew automatically: ${incompleteReason}.`,
    };
  }

  const renewsFrom = renewalWindowStart(row?.not_after, renewBeforeDays);
  if (!renewsFrom) {
    // The scheduler only scans rows with a not_after, so a complete profile
    // still never produces a job without a recorded expiry.
    return {
      ...base,
      state: CERTOPS_RENEWAL_STATE_NOT_CONFIGURED,
      renewBeforeDays,
      detail:
        "This certificate will not renew automatically: no expiry date is recorded, so no renewal window can be computed.",
    };
  }

  return {
    ...base,
    state: CERTOPS_RENEWAL_STATE_AUTO,
    renewBeforeDays,
    renewsFrom,
    detail: `Renewal is attempted automatically from ${renewBeforeDays} days before expiry.`,
  };
}

/**
 * Renewal inputs for the listed certificates, joined to their profile exactly
 * the way findCertificatesDueForRenewal joins it. Read here rather than in the
 * inventory projection so the public-only inventory record keeps its shape and
 * profile metadata never leaks into it verbatim.
 */
async function loadCertificateRenewalRows({
  db = pool,
  workspaceId,
  certificateIds,
}) {
  const result = await db.query(
    `SELECT mc.id,
            mc.status,
            mc.key_mode,
            mc.not_after,
            mc.common_name,
            mc.subject_alt_names,
            mc.profile_id,
            cp.name AS profile_name,
            cp.status AS profile_status,
            cp.key_mode AS profile_key_mode,
            cp.public_metadata AS profile_public_metadata,
            cp.renew_before_days AS profile_renew_before_days
       FROM managed_certificates mc
       LEFT JOIN certificate_profiles cp
         ON cp.workspace_id = mc.workspace_id AND cp.id = mc.profile_id
      WHERE mc.workspace_id = $1
        AND mc.id = ANY($2::uuid[])`,
    [workspaceId, certificateIds],
  );
  return result.rows;
}

/**
 * Snake_case view of an inventory record, used when the renewal join returned
 * no row for it (retired between the two reads). It carries no profile
 * metadata, so the fallback can only ever resolve to a non-auto state: the UI
 * degrades to "not configured", never to a false "auto".
 */
function renewalRowFromInventoryRecord(certificate) {
  return {
    id: certificate?.id,
    status: certificate?.status,
    key_mode: certificate?.keyMode,
    not_after: certificate?.notAfter,
    common_name: certificate?.commonName,
    subject_alt_names: certificate?.subjectAltNames,
    profile_id: certificate?.profileId,
  };
}

/**
 * Observed Locations UI needs a connectivity fact per row ("Reachable" /
 * "Agent offline" / no responsible agent) that is deliberately NOT the same
 * axis as certificate_instances.status (that answers "is the certificate
 * still present there", per an actual scan -- see inventory.js#toInstanceRecord
 * and the product note that agent connectivity must never overload it).
 * `responsibleAgentId` is already derived server-side from source/sourceRef
 * (inventory.js); this only attaches the live liveness read for that agent,
 * reusing the exact same 10-minute threshold as the fleet table and the
 * down/recovery alert trigger (agentLiveness.js via agentRegistry.js).
 */
async function withInstanceAgentConnectivity({ workspaceId, items }) {
  const list = Array.isArray(items) ? items : [];
  const agentIds = list
    .map((item) => item?.responsibleAgentId)
    .filter((value) => typeof value === "string" && value);
  if (agentIds.length === 0) {
    return list.map((item) => ({ ...item, agent: null }));
  }
  let agentsByAgentId = new Map();
  try {
    agentsByAgentId = await getAgentsByAgentIdStrings({
      workspaceId,
      agentIds,
    });
  } catch (err) {
    // Connectivity is an enrichment on top of the persisted location row;
    // a lookup failure must still render the location itself.
    logger.warn("CertOps instance agent-connectivity lookup failed", {
      error: err.message,
      workspaceId,
    });
  }
  return list.map((item) => {
    const agent = item?.responsibleAgentId
      ? agentsByAgentId.get(item.responsibleAgentId) || null
      : null;
    return {
      ...item,
      agent: agent
        ? {
            agentId: agent.agentId,
            name: agent.name,
            hostname: agent.hostname,
            platform: agent.platform,
            livenessState: agent.livenessState,
            lastSeenAt: agent.lastSeenAt,
          }
        : null,
    };
  });
}

async function withRenewalState({
  db = pool,
  env = process.env,
  workspaceId,
  certificates,
  // Off for lists: resumability is a per-certificate action offered on the
  // detail page, and the query behind it is an anti-join over the job table
  // that a paged list has no use for.
  includePreflight = false,
}) {
  const items = Array.isArray(certificates) ? certificates : [];
  const certificateIds = items
    .map((certificate) => certificate?.id)
    .filter(Boolean)
    .map(String);
  if (certificateIds.length === 0) return items;

  const [rows, setupIntentsById, preflightsById, workspaceRow, renewalPathById] =
    await Promise.all([
      loadCertificateRenewalRows({ db, workspaceId, certificateIds }),
      loadRenewalSetupIntents({ db, workspaceId, certificateIds }),
      includePreflight
        ? loadResumablePreflights({ db, workspaceId, certificateIds })
        : Promise.resolve(new Map()),
      // Answers "will this workspace's scheduler act right now", a different
      // question from the per-profile state above (a paused workspace still
      // reported `auto` because the profile itself is genuinely switched
      // on). Read directly rather than through
      // getWorkspaceCertOpsPauseState/isCertOpsEnabled to avoid a
      // second, redundant check of the global rollout flag this route is
      // already gated on by requireCertOpsEnabled - advisory display only,
      // never a gate, so a stale or failed read just falls back to "not
      // paused" rather than failing the request.
      db
        .query(`SELECT certops_paused FROM workspaces WHERE id = $1`, [
          workspaceId,
        ])
        .catch(() => null),
      // Renewal-path health (Healthy/Degraded/Renewal path unavailable/
      // Unknown) is a distinct axis from the lifecycle `renewal` state
      // above; a failure here must not take down certificate list/detail
      // rendering, so fall back to an empty projection per certificate.
      resolveRenewalPathsForCertificateIds({
        db,
        workspaceId,
        certificateIds,
        env,
      }).catch(() => new Map()),
    ]);
  const rowsById = new Map(rows.map((row) => [String(row.id), row]));
  const workspacePaused = workspaceRow?.rows?.[0]?.certops_paused === true;

  return items.map((certificate) => ({
    ...certificate,
    renewal: deriveCertificateRenewalState(
      rowsById.get(String(certificate.id)) ||
        renewalRowFromInventoryRecord(certificate),
      { env, workspacePaused },
    ),
    renewalSetup: projectRenewalSetupState(
      setupIntentsById.get(String(certificate.id)) || null,
    ),
    ...(renewalPathById.get(String(certificate.id)) || {
      renewalPathState: null,
      renewalPathReason: null,
      renewalPathSummary: null,
      dependencies: [],
    }),
    ...(includePreflight
      ? {
          renewalPreflight: projectRenewalPreflight(
            preflightsById.get(String(certificate.id)) || null,
          ),
        }
      : {}),
  }));
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
        status: req.query.status,
        source: req.query.source,
        // Three separate renewal facts rather than one "will not auto-renew"
        // switch: a certificate whose profile fails validation also never
        // renews, and that verdict comes from a JavaScript validator over the
        // profile body with no SQL equivalent. A combined filter would promise
        // a complete answer and stop an operator looking further.
        noRenewalProfile: req.query.noRenewalProfile,
        renewalDisabled: req.query.renewalDisabled,
        keyNotAgentDeployable: req.query.keyNotAgentDeployable,
        excludeRetired: req.query.excludeRetired,
        sort: req.query.sort,
        direction: req.query.direction,
      });
      return res.json({
        ...result,
        items: redactDeploymentPathForViewers(
          req,
          await withRenewalState({
            workspaceId: req.workspace.id,
            certificates: result.items,
          })
        ),
      });
    } catch (err) {
      if (
        err?.code === CERTOPS_CERTIFICATE_STATUS_INVALID ||
        err?.code === CERTOPS_CERTIFICATE_SOURCE_INVALID ||
        err?.code === CERTOPS_CERTIFICATE_FILTER_INVALID ||
        err?.code === CERTOPS_LIST_SORT_INVALID
      ) {
        return res.status(400).json({ error: err.message, code: err.code });
      }

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

// Renewal-profile administration. Reads are manager-gated, matching the
// agent and machine-token routes rather than the certificates inventory: a
// profile body carries deployment topology (certPath, keyPath, reloadService,
// deployment owner/group, ACME command refs, CA account refs, DNS zone), which
// is host reconnaissance rather than expiry metadata. A viewer who can see the
// certificate inventory has no reason to learn where its key sits on disk or
// which privileged unit reloads it. The dashboard route guard for /certops/* is
// manager-scoped too, so this keeps the API and the UI enforcing the same line
// instead of relying on the client to hide the surface.
//
// The single mutating route is admin-gated via
// authorize("certops.renewal_profile.manage") because a profile edit changes
// what a host-privileged agent executes at the next renewal; see
// services/certops/renewalProfileAdmin.js for the editable-field boundary.
router.get(
  "/api/v1/workspaces/:id/certops/profiles",
  getApiLimiter(),
  requireCertOpsEnabled,
  requireCertOpsWriteRole,
  async (req, res) => {
    try {
      const result = await listRenewalProfiles({
        workspaceId: req.workspace.id,
        limit: req.query.limit,
        offset: req.query.offset,
        sort: req.query.sort,
        direction: req.query.direction,
      });
      return res.json(result);
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps renewal profile list failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to list renewal profiles",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.get(
  "/api/v1/workspaces/:id/certops/renewals/upcoming",
  getApiLimiter(),
  requireCertOpsEnabled,
  requireCertOpsWriteRole,
  async (req, res) => {
    try {
      const result = await listUpcomingRenewals({
        workspaceId: req.workspace.id,
        limit: req.query.limit,
        offset: req.query.offset,
        sort: req.query.sort,
        direction: req.query.direction,
        thresholdDays: resolveRenewalThresholdDays(process.env),
      });
      return res.json(result);
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps upcoming renewals list failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to list upcoming renewals",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.get(
  "/api/v1/workspaces/:id/certops/profiles/:profileId",
  getApiLimiter(),
  requireCertOpsEnabled,
  requireCertOpsWriteRole,
  async (req, res) => {
    if (!UUID_PATTERN.test(String(req.params.profileId || ""))) {
      return res.status(404).json({
        error: "Renewal profile not found",
        code: CERTOPS_PROFILE_NOT_FOUND,
      });
    }
    try {
      const profile = await getRenewalProfile({
        workspaceId: req.workspace.id,
        profileId: req.params.profileId,
      });
      return res.json(profile);
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps renewal profile fetch failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to fetch renewal profile",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.patch(
  "/api/v1/workspaces/:id/certops/profiles/:profileId",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  // A session user specifically: a profile edit is an attributable human
  // decision, so internal worker credentials must not reach it.
  requireCertOpsSessionUser,
  authorize("certops.renewal_profile.manage"),
  async (req, res) => {
    if (!UUID_PATTERN.test(String(req.params.profileId || ""))) {
      return res.status(404).json({
        error: "Renewal profile not found",
        code: CERTOPS_PROFILE_NOT_FOUND,
      });
    }
    try {
      const profile = await updateRenewalProfile({
        workspaceId: req.workspace.id,
        profileId: req.params.profileId,
        autoRenewEnabled: req.body?.autoRenewEnabled,
        renewBeforeDays: req.body?.renewBeforeDays,
        renewalProfile: req.body?.renewalProfile,
        description: req.body?.description,
        actorUserId: req.user?.id || null,
      });
      return res.json(profile);
    } catch (err) {
      // Mapped here rather than in handleCertOpsError: these two codes already
      // have an established 400 meaning on the job-creation routes ("this
      // certificate's stored profile is unusable"), and on this route they mean
      // something different ("the patch you sent would produce an unusable
      // profile"). Keeping the mapping local avoids changing the existing
      // contract for every other caller.
      if (
        err?.code === CERTOPS_RENEWAL_PROFILE_INVALID ||
        err?.code === CERTOPS_RENEWAL_PROFILE_INCOMPLETE
      ) {
        return res.status(422).json({
          error: err.message,
          code: err.code,
        });
      }

      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps renewal profile update failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to update renewal profile",
        code: "INTERNAL_ERROR",
      });
    }
  },
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

      return res.json({
        ...result,
        items: await withInstanceAgentConnectivity({
          workspaceId: req.workspace.id,
          items: result.items,
        }),
      });
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
  "/api/v1/workspaces/:id/certops/instances",
  getApiLimiter(),
  requireCertOpsEnabled,
  async (req, res) => {
    try {
      const result = await listWorkspaceCertificateInstances({
        workspaceId: req.workspace.id,
        limit: req.query.limit,
        offset: req.query.offset,
      });
      return res.json({
        ...result,
        items: await withInstanceAgentConnectivity({
          workspaceId: req.workspace.id,
          items: result.items,
        }),
      });
    } catch (err) {
      logger.error("CertOps certificate instances list failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to list certificate instances",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.get(
  "/api/v1/workspaces/:id/certops/targets",
  getApiLimiter(),
  requireCertOpsEnabled,
  async (req, res) => {
    try {
      const result = await listCertificateTargets({
        workspaceId: req.workspace.id,
        limit: req.query.limit,
        offset: req.query.offset,
      });
      return res.json(result);
    } catch (err) {
      logger.error("CertOps certificate targets list failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to list certificate targets",
        code: "INTERNAL_ERROR",
      });
    }
  },
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

      const [enriched] = await withRenewalState({
        workspaceId: req.workspace.id,
        certificates: [certificate],
        includePreflight: true,
      });
      return res.json({
        certificate: redactDeploymentPathForViewers(req, enriched || certificate),
      });
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
  "/api/v1/workspaces/:id/certops/certificates/:certId/renewal-setup",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  // Same posture as manual job creation: this creates a renew job (and, on a
  // real run, an adoption intent), so it needs the write role and the
  // workspace-active gate. A session user specifically, because arming
  // automatic renewal is an attributable human decision and the audit row
  // names an actor: the role check alone would let internal worker
  // credentials through.
  requireCertOpsSessionUser,
  requireCertOpsWriteRole,
  requireWorkspaceCertOpsActive,
  async (req, res) => {
    if (!UUID_PATTERN.test(String(req.params.certId || ""))) {
      return res.status(404).json({
        error: "Certificate not found",
        code: "CERTOPS_CERTIFICATE_NOT_FOUND",
      });
    }
    try {
      const dryRun = req.body?.dryRun === true;
      const { job } = await createManualCertificateJob({
        workspaceId: req.workspace.id,
        jobCreator: renewalSetupJobCreator({
          certificateId: req.params.certId,
        }),
        // A resumable dry_run job rather than a payload checkbox. The
        // jobCreator only enqueues the adoption intent for a real run, so a
        // preflight arms nothing even when the job itself succeeds.
        ...(dryRun ? { mode: "dry_run" } : {}),
        payload: req.body?.payload,
        assignedAgentId: req.body?.assignedAgentId,
        idempotencyKey: req.body?.idempotencyKey,
        requiresApproval: req.body?.requiresApproval === true,
        requestedByUserId: req.user?.id || null,
        actorUserId: req.user?.id || null,
        subjectUserId: req.user?.id || null,
      });
      return res
        .status(201)
        .json({ job: redactClaimIdForNonAdmins(req, jobDetail(job)) });
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps renewal setup failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        certId: req.params?.certId,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to set up automatic renewal",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/certops/renewal-setup-intents/:outboxId/retry",
  getApiLimiter(),
  rejectKeyMaterial,
  requireCertOpsEnabled,
  // Session-user, like approve/reject: this decides the fate of a parked
  // outbox row, not agent-claimed work, so the workspace-active gate is
  // deliberately absent, matching the approval routes' reasoning.
  requireCertOpsSessionUser,
  requireCertOpsWriteRole,
  async (req, res) => {
    if (!UUID_PATTERN.test(String(req.params.outboxId || ""))) {
      return res.status(404).json({
        error: "Outbox event not found",
        code: CERTOPS_OUTBOX_EVENT_NOT_FOUND,
      });
    }
    try {
      const result = await retryRenewalSetupIntent({
        workspaceId: req.workspace.id,
        outboxId: req.params.outboxId,
      });
      return res.json(result);
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps renewal setup retry failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        outboxId: req.params?.outboxId,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to retry automatic renewal setup",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

// Detach: unlink the certificate from its renewal profile without deleting the
// profile row, since one profile can cover several certificates. Same gate as
// the profile PATCH (session user, certops.renewal_profile.manage): both change
// what an agent will run on a host, and neither is agent-claimed work, so the
// workspace-active gate that blocks new job creation does not apply here.
router.delete(
  "/api/v1/workspaces/:id/certops/certificates/:certId/profile",
  getApiLimiter(),
  requireCertOpsEnabled,
  requireCertOpsSessionUser,
  authorize("certops.renewal_profile.manage"),
  async (req, res) => {
    if (!UUID_PATTERN.test(String(req.params.certId || ""))) {
      return res.status(404).json({
        error: "Certificate not found",
        code: "CERTOPS_CERTIFICATE_NOT_FOUND",
      });
    }
    try {
      const result = await detachRenewalProfile({
        workspaceId: req.workspace.id,
        certificateId: req.params.certId,
        actorUserId: req.user?.id || null,
      });
      return res.json(result);
    } catch (err) {
      const handled = handleCertOpsError(res, err);
      if (handled) return handled;

      logger.error("CertOps renewal profile detach failed", {
        error: err.message,
        code: err.code || null,
        workspaceId: req.workspace?.id,
        certId: req.params?.certId,
        userId: req.user?.id,
      });
      return res.status(500).json({
        error: "Failed to detach renewal profile",
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
  createControllerProvisionIntentHandler,
  deriveCertificateRenewalState,
  parseBulkRenewRequest,
  requireCertOpsSessionUser,
  handleCertOpsError,
  withRenewalState,
  withInstanceAgentConnectivity,
  loadRenewalSetupIntents,
  projectRenewalSetupState,
  apiTokenMetadata,
  jobSummary,
  jobDetail,
  redactClaimIdForNonAdmins,
};

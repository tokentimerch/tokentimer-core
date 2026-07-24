"use strict";

const crypto = require("node:crypto");
const { pool } = require("../../db/database");
const {
  assertNoUnredactedGenericSecretMaterial,
  containsPrivateKeyMaterial,
  fieldNameLooksGenericSecret,
  fieldNameLooksPrivateKeyMaterial,
} = require("../../utils/secretMaterial");
const {
  CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
  CERTOPS_RENEWAL_PROFILE_INVALID,
  validateRenewalProfile,
} = require("./renewalProfile");

const CERTOPS_JOB_INVALID = "CERTOPS_JOB_INVALID";
const CERTOPS_JOB_NOT_FOUND = "CERTOPS_JOB_NOT_FOUND";
const CERTOPS_JOB_OPERATION_INVALID = "CERTOPS_JOB_OPERATION_INVALID";
const CERTOPS_JOB_SOURCE_INVALID = "CERTOPS_JOB_SOURCE_INVALID";
const CERTOPS_JOB_STATUS_INVALID = "CERTOPS_JOB_STATUS_INVALID";
const CERTOPS_JOB_STATUS_TRANSITION_INVALID =
  "CERTOPS_JOB_STATUS_TRANSITION_INVALID";
const CERTOPS_JOB_IDEMPOTENCY_CONFLICT =
  "CERTOPS_JOB_IDEMPOTENCY_CONFLICT";
const CERTOPS_JOB_LOG_EVENT_TYPE_INVALID =
  "CERTOPS_JOB_LOG_EVENT_TYPE_INVALID";
const CERTOPS_JOB_METADATA_INVALID = "CERTOPS_JOB_METADATA_INVALID";
const CERTOPS_JOB_WORKSPACE_REQUIRED = "CERTOPS_JOB_WORKSPACE_REQUIRED";
const CERTOPS_JOB_EXECUTION_FIELD_INVALID =
  "CERTOPS_JOB_EXECUTION_FIELD_INVALID";
const CERTOPS_JOB_MODE_INVALID = "CERTOPS_JOB_MODE_INVALID";
const CERTOPS_JOB_MODE_TERMINAL_INVALID =
  "CERTOPS_JOB_MODE_TERMINAL_INVALID";
const PRIVATE_KEY_MATERIAL_REJECTED = "PRIVATE_KEY_MATERIAL_REJECTED";

// Job execution mode. Persisted on certificate_jobs.mode and included in the
// signed dispatch payload. Required at creation; immutable afterwards.
// "dry_run" must NEVER terminate as "succeeded" — use "dry_run_complete".
// See COORDINATION-B4.md at the worktree root.
const JOB_MODES = Object.freeze(["real", "dry_run"]);
const JOB_MODE_SET = new Set(JOB_MODES);
const DEFAULT_JOB_MODE = "real";

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
  // Terminal outcome for mode === "dry_run" only. Never use "succeeded" for
  // dry-run jobs (no keygen/renew/deploy/reload/verify actually ran).
  "dry_run_complete",
  // Terminal outcome when a lease was renewed (a side effect may have
  // occurred) but the agent never reported a result. Requires manual
  // operator reconciliation instead of a silent retry or success/failure.
  "orphaned_unknown_effect",
]);
const JOB_STATUS_SET = new Set(JOB_STATUSES);

const LOG_STATUSES = JOB_STATUSES;
const LOG_STATUS_SET = new Set(LOG_STATUSES);

const TERMINAL_JOB_STATUSES = new Set([
  "rejected",
  "succeeded",
  "failed",
  "blocked",
  "cancelled",
  "dry_run_complete",
  "orphaned_unknown_effect",
]);
const ACTIVE_JOB_STATUSES = new Set(
  JOB_STATUSES.filter((status) => !TERMINAL_JOB_STATUSES.has(status)),
);
const ACTIVE_JOB_STATUS_ORDER = Object.freeze([
  "pending_approval",
  "approved",
  "pending",
  "claimed",
  "running",
]);
const ACTIVE_JOB_STATUS_RANK = new Map(
  ACTIVE_JOB_STATUS_ORDER.map((status, index) => [status, index]),
);
// A fresh job (pending) or a claimed one can reach a terminal outcome from a
// single executor event, not just via an intermediate "running" event. The
// documented minimal executor flow (docs/certops/executor-api.md, section 6)
// posts exactly one job.completed event against a job that has never been
// reported as started; requiring job.accepted/job.started first would break
// that flow for executors that do not report intermediate progress.
const JOB_STATUS_TRANSITIONS = Object.freeze({
  pending_approval: new Set(["approved", "rejected", "cancelled"]),
  approved: new Set(["pending", "rejected", "cancelled"]),
  pending: new Set([
    "claimed",
    "running",
    "succeeded",
    "failed",
    "rejected",
    "blocked",
    "cancelled",
    "dry_run_complete",
  ]),
  claimed: new Set([
    "running",
    "succeeded",
    "failed",
    "rejected",
    "blocked",
    "cancelled",
    "dry_run_complete",
    "orphaned_unknown_effect",
  ]),
  running: new Set([
    "succeeded",
    "failed",
    "rejected",
    "blocked",
    "cancelled",
    "dry_run_complete",
    "orphaned_unknown_effect",
  ]),
  rejected: new Set(),
  succeeded: new Set(),
  failed: new Set(),
  blocked: new Set(),
  cancelled: new Set(),
  dry_run_complete: new Set(),
  orphaned_unknown_effect: new Set(),
});

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
  // This provenance is assigned only by the human provision-intent service.
  // It distinguishes narrow controller commands from generic deploy jobs.
  "controller_provisioning",
]);
const JOB_SOURCE_SET = new Set(JOB_SOURCES);

// Immutable at insert: agent claim path only sees 'agent'; controller
// provisioning delivery only sees 'controller' (B2).
const JOB_EXECUTOR_KINDS = Object.freeze(["agent", "controller"]);
const JOB_EXECUTOR_KIND_SET = new Set(JOB_EXECUTOR_KINDS);
const CONTROLLER_PROVISIONING_JOB_SOURCE = "controller_provisioning";

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
  // Approval gate lifecycle (kept in sync with the migration-25 CHECK
  // constraint on certificate_job_log.event_type).
  "approval.granted",
  "approval.rejected",
  "approval.invalidated",
]);
const JOB_LOG_EVENT_TYPE_SET = new Set(JOB_LOG_EVENT_TYPES);

const SAFE_JOB_SELECT_FIELDS = `
  id,
  workspace_id,
  operation,
  status,
  mode,
  source,
  executor_kind,
  requested_by_user_id,
  requested_by_api_token_id,
  idempotency_key,
  creation_request_hash,
  subject_type,
  subject_id,
  payload,
  result_metadata,
  error_code,
  error_message,
  claimed_by_agent_id,
  claimed_by_controller_cluster_id,
  claim_id,
  lease_expires_at,
  lease_renewed_at,
  attempt_count,
  max_attempts,
  next_attempt_at,
  scheduled_for,
  assigned_agent_id,
  required_target_selector,
  required_dns_provider,
  required_command_profile,
  approved_by_user_id,
  approved_at,
  approved_payload_hash,
  approved_canonical_intent_hash,
  needs_operator_reconciliation,
  reconciliation_reason,
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

const FORBIDDEN_KEY_BEARING_FIELD_FRAGMENTS = Object.freeze(["pem"]);

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

function normalizeRequesterIdentity(value, fieldName) {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw serviceError(`${fieldName} is invalid`, CERTOPS_JOB_INVALID);
    }
    return String(value);
  }
  if (typeof value !== "string") {
    throw serviceError(`${fieldName} is invalid`, CERTOPS_JOB_INVALID);
  }
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > MAX_SHORT_TEXT_LENGTH) {
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
  return (
    fieldNameLooksPrivateKeyMaterial(fieldName) ||
    fieldNameLooksGenericSecret(fieldName) ||
    FORBIDDEN_KEY_BEARING_FIELD_FRAGMENTS.some((fragment) =>
      normalized.includes(fragment),
    )
  );
}

function assertSafePublicValue(value, depth = 0, seen = new WeakSet()) {
  if (depth > MAX_SCAN_DEPTH) throw privateMaterialError();
  if (containsPrivateKeyMaterial(value)) throw privateMaterialError();

  if (value === null || value === undefined) return;

  if (typeof value === "string") {
    // Direct persistence callers receive a strict public-metadata boundary.
    // Executor ingestion redacts first; all other callers must supply content
    // that is already redacted rather than persisting raw generic secrets.
    assertNoUnredactedGenericSecretMaterial(value);
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

// --- Execution-field validation (job-payload.schema.json bounds) ---
//
// The stored certificate_jobs payload may carry the execution fields the
// agent consumes for renew/deploy/reload (blessed execution fields). This
// validator mirrors the schema constraints so a malformed field is rejected
// at creation instead of at dispatch. certificatePem is deliberately NOT in
// this list: the persistence boundary (fieldNameLooksForbidden's "pem" ban)
// rejects it, because certificate PEM is attached only at signed dispatch
// time and never stored in the payload column.

const ACME_KINDS = Object.freeze(["certbot", "acme.sh"]);
const ACME_KIND_SET = new Set(ACME_KINDS);
const COMMAND_REF_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;
const RELOAD_SERVICE_PATTERN = /^[A-Za-z0-9_.:@-]{1,128}$/;
const DNS_PROVIDER_PATTERN = /^[A-Za-z0-9_.:-]{1,64}$/;

function executionFieldError(fieldName) {
  return serviceError(
    `CertOps job payload field ${fieldName} is invalid`,
    CERTOPS_JOB_EXECUTION_FIELD_INVALID,
  );
}

const EXECUTION_FIELD_VALIDATORS = Object.freeze({
  commandRef(value) {
    if (typeof value !== "string" || !COMMAND_REF_PATTERN.test(value)) {
      throw executionFieldError("commandRef");
    }
  },
  caEndpoint(value) {
    if (typeof value !== "string" || value.length > 512) {
      throw executionFieldError("caEndpoint");
    }
    let parsed;
    try {
      parsed = new URL(value);
    } catch (_error) {
      throw executionFieldError("caEndpoint");
    }
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      throw executionFieldError("caEndpoint");
    }
  },
  acmeKind(value) {
    if (typeof value !== "string" || !ACME_KIND_SET.has(value)) {
      throw executionFieldError("acmeKind");
    }
  },
  keyRotation(value) {
    if (typeof value !== "boolean") {
      throw executionFieldError("keyRotation");
    }
  },
  certPath(value) {
    if (typeof value !== "string" || value.length < 1 || value.length > 512) {
      throw executionFieldError("certPath");
    }
  },
  reloadService(value) {
    if (typeof value !== "string" || !RELOAD_SERVICE_PATTERN.test(value)) {
      throw executionFieldError("reloadService");
    }
  },
  verifyHost(value) {
    if (typeof value !== "string" || value.length < 1 || value.length > 255) {
      throw executionFieldError("verifyHost");
    }
  },
  verifyPort(value) {
    if (!Number.isInteger(value) || value < 1 || value > 65535) {
      throw executionFieldError("verifyPort");
    }
  },
  dnsZone(value) {
    if (typeof value !== "string" || value.length < 1 || value.length > 255) {
      throw executionFieldError("dnsZone");
    }
  },
  dnsProvider(value) {
    if (typeof value !== "string" || !DNS_PROVIDER_PATTERN.test(value)) {
      throw executionFieldError("dnsProvider");
    }
  },
});

const EXECUTION_FIELD_NAMES = Object.freeze(
  Object.keys(EXECUTION_FIELD_VALIDATORS),
);

// Which execution fields make sense on which operation. Execution fields on
// operations that never execute them (noop/revoke) indicate a caller bug and
// are rejected rather than silently dispatched to the agent.
const EXECUTION_FIELDS_BY_OPERATION = Object.freeze({
  renew: new Set([
    "commandRef",
    "caEndpoint",
    "acmeKind",
    "keyRotation",
    "certPath",
    "reloadService",
    "verifyHost",
    "verifyPort",
    "dnsZone",
    "dnsProvider",
  ]),
  deploy: new Set([
    "certPath",
    "reloadService",
    "verifyHost",
    "verifyPort",
  ]),
  reload: new Set(["reloadService", "verifyHost", "verifyPort"]),
  revoke: new Set(),
  noop: new Set(),
});

function validateExecutionFields(payload, operation) {
  const allowedForOperation =
    EXECUTION_FIELDS_BY_OPERATION[operation] || new Set();
  for (const fieldName of EXECUTION_FIELD_NAMES) {
    if (!Object.prototype.hasOwnProperty.call(payload, fieldName)) continue;
    const value = payload[fieldName];
    if (value === null || value === undefined) continue;
    if (!allowedForOperation.has(fieldName)) {
      throw serviceError(
        `CertOps job payload field ${fieldName} is not valid for the ` +
          `${operation} operation`,
        CERTOPS_JOB_EXECUTION_FIELD_INVALID,
      );
    }
    EXECUTION_FIELD_VALIDATORS[fieldName](value);
  }
}

/**
 * Renew jobs carry an immutable renewalProfile snapshot so approval and
 * dispatch bind against a complete execution contract. Automation-created
 * renew jobs (scheduler) always require it. Manual/API renew jobs may omit
 * it at create time but approveJob will refuse to approve without one.
 */
function validateRenewalProfileOnPayload(
  payload,
  operation,
  { required = false } = {},
) {
  if (operation !== "renew") {
    if (
      payload &&
      Object.prototype.hasOwnProperty.call(payload, "renewalProfile")
    ) {
      throw serviceError(
        "renewalProfile is only valid on renew jobs",
        CERTOPS_RENEWAL_PROFILE_INVALID,
      );
    }
    return null;
  }
  const hasProfile =
    payload &&
    Object.prototype.hasOwnProperty.call(payload, "renewalProfile");
  if (!hasProfile && !required) return null;
  try {
    return validateRenewalProfile(payload?.renewalProfile);
  } catch (error) {
    if (
      error?.code === CERTOPS_RENEWAL_PROFILE_INVALID ||
      error?.code === CERTOPS_RENEWAL_PROFILE_INCOMPLETE
    ) {
      throw error;
    }
    throw serviceError(
      error?.message || "renewalProfile is invalid",
      CERTOPS_RENEWAL_PROFILE_INVALID,
    );
  }
}

function normalizeJobMode(value) {
  // Omitted mode defaults to "real". Dry-run is never an ambient default:
  // callers must pass mode: "dry_run" explicitly at creation time.
  if (value === undefined || value === null || value === "") {
    return DEFAULT_JOB_MODE;
  }
  return normalizeEnum(value, JOB_MODE_SET, CERTOPS_JOB_MODE_INVALID, "mode");
}

function assertModeAllowsTerminalStatus(mode, status) {
  if (mode === "dry_run" && status === "succeeded") {
    throw serviceError(
      'dry_run jobs must terminate as dry_run_complete, never succeeded',
      CERTOPS_JOB_MODE_TERMINAL_INVALID,
    );
  }
  if (mode === "real" && status === "dry_run_complete") {
    throw serviceError(
      "dry_run_complete is only valid for dry_run jobs",
      CERTOPS_JOB_MODE_TERMINAL_INVALID,
    );
  }
}

function normalizeOptionalEnum(value, allowedSet, code, fieldName) {
  if (value === undefined || value === null || value === "") return null;
  return normalizeEnum(value, allowedSet, code, fieldName);
}

function assertJobStatusTransition(fromStatus, toStatus) {
  if (fromStatus === toStatus) return;
  if (JOB_STATUS_TRANSITIONS[fromStatus]?.has(toStatus)) return;
  throw serviceError(
    "CertOps job status transition is invalid",
    CERTOPS_JOB_STATUS_TRANSITION_INVALID,
  );
}

function isTerminalJobStatus(status) {
  return TERMINAL_JOB_STATUSES.has(status);
}

function jobStatusTransitionDecision(fromStatus, toStatus) {
  if (fromStatus === toStatus) {
    return {
      applied: false,
      ignored: true,
      ignoredReason: isTerminalJobStatus(fromStatus)
        ? "terminal_replay"
        : "active_replay",
    };
  }

  if (isTerminalJobStatus(fromStatus)) {
    return {
      applied: false,
      ignored: true,
      ignoredReason: "terminal_regression",
    };
  }

  if (JOB_STATUS_TRANSITIONS[fromStatus]?.has(toStatus)) {
    return { applied: true, ignored: false, ignoredReason: null };
  }

  // Executor delivery is at-least-once and can be out of order. A stale
  // active lifecycle event must remain observable in the job log without
  // rolling the persisted state backward or aborting the event transaction.
  if (
    ACTIVE_JOB_STATUSES.has(toStatus) &&
    ACTIVE_JOB_STATUS_RANK.get(toStatus) < ACTIVE_JOB_STATUS_RANK.get(fromStatus)
  ) {
    return {
      applied: false,
      ignored: true,
      ignoredReason: "active_regression",
    };
  }

  assertJobStatusTransition(fromStatus, toStatus);
  return { applied: true, ignored: false, ignoredReason: null };
}

function withStatusTransitionOutcome(job, decision) {
  return {
    ...job,
    statusTransitionApplied: decision.applied,
    statusTransitionIgnored: !decision.applied,
    statusTransitionIgnoredReason: decision.ignoredReason,
  };
}

function initialLifecycleTimestamps(options, status) {
  const now = new Date();
  const queuedAt =
    options.queuedAt ||
    (ACTIVE_JOB_STATUSES.has(status) ? now : null);
  const startedAt =
    options.startedAt ||
    (status === "running" ? now : null);
  const completedAt =
    options.completedAt ||
    (["succeeded", "failed", "blocked", "dry_run_complete"].includes(status)
      ? now
      : null);
  // The database column retains the American spelling for compatibility. The
  // public job state and service option use the plan's canonical "cancelled".
  const cancelledAt =
    options.cancelledAt ||
    (status === "cancelled" ? now : null);

  return { queuedAt, startedAt, completedAt, cancelledAt };
}

function normalizeExplicitLifecycleTimestamps(options) {
  return {
    queuedAt: normalizeOptionalDate(options.queuedAt, "queuedAt"),
    startedAt: normalizeOptionalDate(options.startedAt, "startedAt"),
    completedAt: normalizeOptionalDate(options.completedAt, "completedAt"),
    cancelledAt: normalizeOptionalDate(options.cancelledAt, "cancelledAt"),
  };
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

/**
 * Resolve the immutable executor lane and the optional B5 routing selectors
 * for a new job. Controller provisioning source always forces the controller
 * lane; any other source defaults to agent unless the caller overrides.
 */
function resolveExecutorKindAndRouting(options, source, payload) {
  const inferredKind =
    source === CONTROLLER_PROVISIONING_JOB_SOURCE ? "controller" : "agent";
  const executorKind = normalizeEnum(
    options.executorKind,
    JOB_EXECUTOR_KIND_SET,
    CERTOPS_JOB_INVALID,
    "executorKind",
    inferredKind,
  );
  if (
    source === CONTROLLER_PROVISIONING_JOB_SOURCE &&
    executorKind !== "controller"
  ) {
    throw serviceError(
      "controller_provisioning jobs must use executor_kind=controller",
      CERTOPS_JOB_INVALID,
    );
  }
  if (
    source !== CONTROLLER_PROVISIONING_JOB_SOURCE &&
    executorKind === "controller"
  ) {
    throw serviceError(
      "executor_kind=controller is reserved for controller_provisioning jobs",
      CERTOPS_JOB_INVALID,
    );
  }

  const assignedAgentId =
    normalizeOptionalShortText(
      options.assignedAgentId ?? payload.assignedAgentId,
      "assignedAgentId",
    ) || null;

  const requiredTargetSelector =
    normalizeOptionalPublicText(
      options.requiredTargetSelector ??
        payload.targetSelector ??
        (payload.target && typeof payload.target === "object"
          ? payload.target.reference
          : null),
      "requiredTargetSelector",
      512,
    ) || null;

  const requiredDnsProvider =
    normalizeOptionalShortText(
      options.requiredDnsProvider ?? payload.dnsProvider,
      "requiredDnsProvider",
    ) || null;
  if (
    requiredDnsProvider &&
    !DNS_PROVIDER_PATTERN.test(requiredDnsProvider)
  ) {
    throw executionFieldError("dnsProvider");
  }

  const requiredCommandProfile =
    normalizeOptionalShortText(
      options.requiredCommandProfile ?? payload.commandRef,
      "requiredCommandProfile",
    ) || null;
  if (
    requiredCommandProfile &&
    !COMMAND_REF_PATTERN.test(requiredCommandProfile)
  ) {
    throw executionFieldError("commandRef");
  }

  return {
    executorKind,
    assignedAgentId,
    requiredTargetSelector,
    requiredDnsProvider,
    requiredCommandProfile,
  };
}

function jobFromRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    workspaceId: row.workspace_id,
    operation: row.operation,
    status: row.status,
    // Rows created before migration 26 have NULL mode; treat as real.
    mode: row.mode || DEFAULT_JOB_MODE,
    source: row.source,
    executorKind: row.executor_kind ?? "agent",
    requestedByUserId: row.requested_by_user_id,
    requestedByApiTokenId: row.requested_by_api_token_id,
    idempotencyKey: row.idempotency_key,
    creationRequestHash: row.creation_request_hash,
    subjectType: row.subject_type,
    subjectId: row.subject_id,
    payload: parseJsonb(row.payload),
    resultMetadata: parseJsonb(row.result_metadata),
    errorCode: row.error_code,
    errorMessage: row.error_message,
    claimedByAgentId: row.claimed_by_agent_id ?? null,
    claimedByControllerClusterId:
      row.claimed_by_controller_cluster_id ?? null,
    claimId: row.claim_id ?? null,
    leaseExpiresAt: dateToIso(row.lease_expires_at),
    leaseRenewedAt: dateToIso(row.lease_renewed_at),
    attemptCount: row.attempt_count ?? 0,
    maxAttempts: row.max_attempts ?? 3,
    nextAttemptAt: dateToIso(row.next_attempt_at),
    scheduledFor: dateToIso(row.scheduled_for),
    assignedAgentId: row.assigned_agent_id ?? null,
    requiredTargetSelector: row.required_target_selector ?? null,
    requiredDnsProvider: row.required_dns_provider ?? null,
    requiredCommandProfile: row.required_command_profile ?? null,
    approvedByUserId: row.approved_by_user_id ?? null,
    approvedAt: dateToIso(row.approved_at),
    approvedPayloadHash: row.approved_payload_hash ?? null,
    approvedCanonicalIntentHash: row.approved_canonical_intent_hash ?? null,
    needsOperatorReconciliation: Boolean(row.needs_operator_reconciliation),
    reconciliationReason: row.reconciliation_reason ?? null,
    createdAt: dateToIso(row.created_at),
    updatedAt: dateToIso(row.updated_at),
    queuedAt: dateToIso(row.queued_at),
    startedAt: dateToIso(row.started_at),
    completedAt: dateToIso(row.completed_at),
    cancelledAt: dateToIso(row.canceled_at),
  };
}

function canonicalizeJson(value) {
  if (Array.isArray(value)) return value.map(canonicalizeJson);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, canonicalizeJson(value[key])]),
  );
}

function legacyJobCreationIdentity(value) {
  return JSON.stringify(
    canonicalizeJson({
      operation: value.operation,
      source: value.source,
      mode: value.mode || DEFAULT_JOB_MODE,
      requestedByUserId: normalizeRequesterIdentity(
        value.requestedByUserId,
        "requestedByUserId",
      ),
      requestedByApiTokenId: normalizeRequesterIdentity(
        value.requestedByApiTokenId,
        "requestedByApiTokenId",
      ),
      subjectType: value.subjectType || null,
      subjectId: value.subjectId || null,
      payload: value.payload || {},
    }),
  );
}

function jobCreationRequestFingerprint(value) {
  // Hash only normalized public creation inputs. This immutable record is
  // intentionally separate from a job's mutable lifecycle state so an exact
  // replay remains valid after executor transitions.
  const canonicalRequest = canonicalizeJson({
    operation: value.operation,
    status: value.status,
    mode: value.mode || DEFAULT_JOB_MODE,
    source: value.source,
    requestedByUserId: value.requestedByUserId ?? null,
    requestedByApiTokenId: value.requestedByApiTokenId ?? null,
    subjectType: value.subjectType ?? null,
    subjectId: value.subjectId ?? null,
    payload: value.payload ?? {},
    resultMetadata: value.resultMetadata ?? {},
    errorCode: value.errorCode ?? null,
    errorMessage: value.errorMessage ?? null,
    queuedAt: value.queuedAt ?? null,
    startedAt: value.startedAt ?? null,
    completedAt: value.completedAt ?? null,
    cancelledAt: value.cancelledAt ?? null,
  });
  return crypto
    .createHash("sha256")
    .update(JSON.stringify(canonicalRequest), "utf8")
    .digest("hex");
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
  // Per-job approval gate: a job that requires human approval starts at
  // pending_approval and only reaches the claimable 'pending' status through
  // services/certops/jobApprovals.approveJob. The flag only chooses the
  // default initial status; an explicit conflicting status is rejected so a
  // caller cannot both request a gate and bypass it.
  const requiresApproval = options.requiresApproval === true;
  if (
    requiresApproval &&
    options.status !== undefined &&
    options.status !== null &&
    options.status !== "pending_approval"
  ) {
    throw serviceError(
      "A CertOps job that requires approval must start at pending_approval",
      CERTOPS_JOB_STATUS_INVALID,
    );
  }
  const status = normalizeEnum(
    options.status,
    JOB_STATUS_SET,
    CERTOPS_JOB_STATUS_INVALID,
    "status",
    requiresApproval ? "pending_approval" : "pending",
  );
  const mode = normalizeJobMode(options.mode);
  const source = normalizeEnum(
    options.source,
    JOB_SOURCE_SET,
    CERTOPS_JOB_SOURCE_INVALID,
    "source",
    "api",
  );
  const { subjectType, subjectId } = normalizeSubject(options);
  const requestedByUserId = normalizeRequesterIdentity(
    options.requestedByUserId,
    "requestedByUserId",
  );
  const requestedByApiTokenId = normalizeRequesterIdentity(
    options.requestedByApiTokenId,
    "requestedByApiTokenId",
  );
  const idempotencyKey = normalizeOptionalShortText(
    options.idempotencyKey,
    "idempotencyKey",
  );
  const payload = normalizePublicObject(options.payload, "payload");
  // Persist mode on the payload as well so signed dispatch (which spreads
  // certificate_jobs.payload) always carries the immutable mode contract
  // even when a caller forgets to select the column. The row column remains
  // the source of truth and is never updated after insert.
  payload.mode = mode;
  validateExecutionFields(payload, operation);
  validateRenewalProfileOnPayload(payload, operation, {
    required:
      source === "automation" || options.requireRenewalProfile === true,
  });
  assertModeAllowsTerminalStatus(mode, status);
  const {
    executorKind,
    assignedAgentId,
    requiredTargetSelector,
    requiredDnsProvider,
    requiredCommandProfile,
  } = resolveExecutorKindAndRouting(options, source, payload);
  const resultMetadata = normalizePublicObject(
    options.resultMetadata,
    "resultMetadata",
  );
  const errorCode = normalizeOptionalShortText(options.errorCode, "errorCode");
  const errorMessage = normalizeOptionalPublicText(
    options.errorMessage,
    "errorMessage",
  );
  const explicitLifecycleTimestamps = normalizeExplicitLifecycleTimestamps(options);
  const { queuedAt, startedAt, completedAt, cancelledAt } =
    initialLifecycleTimestamps(explicitLifecycleTimestamps, status);
  const creationRequestHash = jobCreationRequestFingerprint({
    operation,
    status,
    mode,
    source,
    executorKind,
    requestedByUserId,
    requestedByApiTokenId,
    subjectType,
    subjectId,
    payload,
    resultMetadata,
    errorCode,
    errorMessage,
    assignedAgentId,
    requiredTargetSelector,
    requiredDnsProvider,
    requiredCommandProfile,
    queuedAt: dateToIso(explicitLifecycleTimestamps.queuedAt),
    startedAt: dateToIso(explicitLifecycleTimestamps.startedAt),
    completedAt: dateToIso(explicitLifecycleTimestamps.completedAt),
    cancelledAt: dateToIso(explicitLifecycleTimestamps.cancelledAt),
  });

  try {
    const result = await db.query(
      `INSERT INTO certificate_jobs (
         workspace_id,
         operation,
         status,
         mode,
         source,
         executor_kind,
         requested_by_user_id,
         requested_by_api_token_id,
         idempotency_key,
         subject_type,
         subject_id,
         payload,
         result_metadata,
         error_code,
         error_message,
         assigned_agent_id,
         required_target_selector,
         required_dns_provider,
         required_command_profile,
         queued_at,
         started_at,
         completed_at,
        canceled_at,
        creation_request_hash
       )
       VALUES (
         $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
         $12::jsonb, $13::jsonb, $14, $15, $16, $17, $18, $19,
         $20, $21, $22, $23, $24
       )
       ON CONFLICT (workspace_id, idempotency_key)
         WHERE idempotency_key IS NOT NULL
       DO NOTHING
       RETURNING ${SAFE_JOB_SELECT_FIELDS}`,
      [
        workspaceId,
        operation,
        status,
        mode,
        source,
        executorKind,
        requestedByUserId,
        requestedByApiTokenId,
        idempotencyKey,
        subjectType,
        subjectId,
        JSON.stringify(payload),
        JSON.stringify(resultMetadata),
        errorCode,
        errorMessage,
        assignedAgentId,
        requiredTargetSelector,
        requiredDnsProvider,
        requiredCommandProfile,
        queuedAt,
        startedAt,
        completedAt,
        cancelledAt,
        creationRequestHash,
      ],
    );

    const job = jobFromRow(result.rows[0]);
    if (job) {
      return options.returnOutcome === true ? { job, created: true } : job;
    }

    // ON CONFLICT DO NOTHING keeps the transaction usable for an idempotent
    // replay, which is essential when the caller also persists an audit in the
    // same transaction.
    if (idempotencyKey) {
      const existing = await getJobByIdempotencyKey(
        db,
        workspaceId,
        idempotencyKey,
      );
      if (existing) {
        // Rows created before migration 20 have no immutable request hash.
        // Their original lifecycle inputs cannot be reconstructed from mutable
        // state, so replay falls back to the historic immutable-subset check
        // and deliberately leaves the legacy NULL value untouched.
        const isMatchingReplay = existing.creationRequestHash
          ? existing.creationRequestHash === creationRequestHash
          : legacyJobCreationIdentity(existing) ===
            legacyJobCreationIdentity({
              operation,
              source,
              mode,
              requestedByUserId,
              requestedByApiTokenId,
              subjectType,
              subjectId,
              payload,
            });
        if (isMatchingReplay) {
          return options.returnOutcome === true
            ? { job: existing, created: false }
            : existing;
        }
        throw serviceError(
          "Idempotency key was already used with a different CertOps job request",
          CERTOPS_JOB_IDEMPOTENCY_CONFLICT,
        );
      }
    }

    throw serviceError("Certificate job insert did not return a job", CERTOPS_JOB_INVALID);
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
      if (existing) {
        const isMatchingReplay = existing.creationRequestHash
          ? existing.creationRequestHash === creationRequestHash
          : legacyJobCreationIdentity(existing) ===
            legacyJobCreationIdentity({
              operation,
              source,
              mode,
              requestedByUserId,
              requestedByApiTokenId,
              subjectType,
              subjectId,
              payload,
            });
        if (isMatchingReplay) {
          return options.returnOutcome === true
            ? { job: existing, created: false }
            : existing;
        }
        throw serviceError(
          "Idempotency key was already used with a different CertOps job request",
          CERTOPS_JOB_IDEMPOTENCY_CONFLICT,
        );
      }
    }
    throw error;
  }
}

function getCertificateJobById(options) {
  const db = options.client || pool;
  return getJobById(
    db,
    normalizeWorkspaceId(options.workspaceId),
    normalizeRequiredId(options.jobId),
  );
}

/**
 * Runs the exact payload normalization and per-operation execution-field
 * validation that createCertificateJob applies, without touching the
 * database. Dry-run preflight uses this so a dry run rejects the same
 * payloads the real run would.
 */
function validateJobPayloadForOperation(payload, operation) {
  const normalizedOperation = normalizeEnum(
    operation,
    JOB_OPERATION_SET,
    CERTOPS_JOB_OPERATION_INVALID,
    "operation",
  );
  const normalizedPayload = normalizePublicObject(payload, "payload");
  validateExecutionFields(normalizedPayload, normalizedOperation);
  // Preflight validates a profile when one is supplied; incomplete profiles
  // are rejected the same way a real create would reject them.
  validateRenewalProfileOnPayload(normalizedPayload, normalizedOperation, {
    required: false,
  });
  return normalizedPayload;
}

/**
 * Returns the newest non-terminal job for a subject (optionally scoped to
 * one operation), or null. Lets preflight surface an in-flight renewal that
 * a new job would race against.
 */
async function findActiveJobForSubject(options) {
  const db = options.client || pool;
  const workspaceId = normalizeWorkspaceId(options.workspaceId);
  const { subjectType, subjectId } = normalizeSubject(options);
  const params = [workspaceId, subjectType, subjectId, [...ACTIVE_JOB_STATUSES]];
  const conditions = [
    "workspace_id = $1",
    "subject_type = $2",
    "subject_id = $3",
    "status = ANY($4)",
  ];

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

  const result = await db.query(
    `SELECT ${SAFE_JOB_SELECT_FIELDS}
       FROM certificate_jobs
      WHERE ${conditions.join(" AND ")}
      ORDER BY created_at DESC, id ASC
      LIMIT 1`,
    params,
  );

  return result.rows[0] ? jobFromRow(result.rows[0]) : null;
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
  const hasErrorCode = Object.prototype.hasOwnProperty.call(
    options,
    "errorCode",
  );
  const hasErrorMessage = Object.prototype.hasOwnProperty.call(
    options,
    "errorMessage",
  );
  const errorCode = hasErrorCode
    ? normalizeOptionalShortText(options.errorCode, "errorCode")
    : null;
  const errorMessage = hasErrorMessage
    ? normalizeOptionalPublicText(options.errorMessage, "errorMessage")
    : null;

  // Compare-and-swap on the current state makes every transition atomic. It
  // prevents concurrent writers from overwriting a terminal state without
  // requiring a transaction-capable client in the unit-test service harness.
  let current = await getJobById(db, workspaceId, jobId);
  if (!current) {
    throw serviceError("Certificate job not found", CERTOPS_JOB_NOT_FOUND);
  }

  for (let attempt = 0; attempt < 2; attempt += 1) {
    assertModeAllowsTerminalStatus(current.mode, status);
    const decision = jobStatusTransitionDecision(current.status, status);
    if (!decision.applied) {
      return withStatusTransitionOutcome(current, decision);
    }

    const result = await db.query(
      `UPDATE certificate_jobs
          SET status = $3,
              result_metadata = CASE WHEN $4 THEN $5::jsonb ELSE result_metadata END,
              error_code = CASE WHEN $6 THEN $7 ELSE error_code END,
              error_message = CASE WHEN $8 THEN $9 ELSE error_message END,
              updated_at = NOW(),
              queued_at = CASE
                WHEN $3 IN ('pending_approval', 'approved', 'pending', 'claimed', 'running')
                  THEN COALESCE(queued_at, NOW())
                ELSE queued_at
              END,
              started_at = CASE
                WHEN $3 = 'running' THEN COALESCE(started_at, NOW())
                ELSE started_at
              END,
              completed_at = CASE
                WHEN $3 IN ('succeeded', 'failed', 'blocked', 'dry_run_complete')
                  THEN COALESCE(completed_at, NOW())
                ELSE completed_at
              END,
              -- Keep the legacy column name only as storage compatibility for
              -- the canonical British-spelled cancelled job state.
              canceled_at = CASE
                WHEN $3 = 'cancelled' THEN COALESCE(canceled_at, NOW())
                ELSE canceled_at
              END
        WHERE workspace_id = $1
          AND id = $2
          AND status = $10
        RETURNING ${SAFE_JOB_SELECT_FIELDS}`,
      [
        workspaceId,
        jobId,
        status,
        hasResultMetadata,
        JSON.stringify(resultMetadata),
        hasErrorCode,
        errorCode,
        hasErrorMessage,
        errorMessage,
        current.status,
      ],
    );

    if (result.rows[0]) {
      return withStatusTransitionOutcome(jobFromRow(result.rows[0]), decision);
    }

    current = await getJobById(db, workspaceId, jobId);
    if (!current) {
      throw serviceError("Certificate job not found", CERTOPS_JOB_NOT_FOUND);
    }
  }

  throw serviceError(
    "CertOps job status transition is invalid",
    CERTOPS_JOB_STATUS_TRANSITION_INVALID,
  );
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
  CERTOPS_JOB_IDEMPOTENCY_CONFLICT,
  CERTOPS_JOB_LOG_EVENT_TYPE_INVALID,
  CERTOPS_JOB_METADATA_INVALID,
  CERTOPS_JOB_NOT_FOUND,
  CERTOPS_JOB_OPERATION_INVALID,
  CERTOPS_JOB_SOURCE_INVALID,
  CERTOPS_JOB_STATUS_INVALID,
  CERTOPS_JOB_STATUS_TRANSITION_INVALID,
  CERTOPS_JOB_WORKSPACE_REQUIRED,
  CERTOPS_JOB_EXECUTION_FIELD_INVALID,
  CERTOPS_JOB_MODE_INVALID,
  CERTOPS_JOB_MODE_TERMINAL_INVALID,
  CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
  CERTOPS_RENEWAL_PROFILE_INVALID,
  DEFAULT_JOB_MODE,
  JOB_LOG_EVENT_TYPES,
  JOB_MODES,
  JOB_OPERATIONS,
  JOB_EXECUTOR_KINDS,
  JOB_SOURCES,
  JOB_STATUSES,
  JOB_STATUS_TRANSITIONS,
  LOG_STATUSES,
  PRIVATE_KEY_MATERIAL_REJECTED,
  SUBJECT_TYPES,
  appendCertificateJobLog,
  assertModeAllowsTerminalStatus,
  assertSafePublicValue,
  createCertificateJob,
  dateToIso,
  fieldNameLooksForbidden,
  findActiveJobForSubject,
  getCertificateJobById,
  isTerminalJobStatus,
  jobCreationRequestFingerprint,
  jobFromRow,
  jobLogFromRow,
  listCertificateJobLog,
  listCertificateJobs,
  normalizeJobMode,
  normalizeLimit,
  normalizeOffset,
  normalizePublicObject,
  normalizeRequiredId,
  normalizeWorkspaceId,
  serviceError,
  updateCertificateJobStatus,
  validateJobPayloadForOperation,
  validateRenewalProfileOnPayload,
  _test: {
    assertSafePublicValue,
    fieldNameLooksForbidden,
    normalizePublicObject,
    parseJsonb,
    validateExecutionFields,
    EXECUTION_FIELDS_BY_OPERATION,
  },
};

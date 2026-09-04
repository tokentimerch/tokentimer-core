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
  AUTO_RENEW_DISABLED_PROFILE_STATUSES,
  buildManualRenewalJobPayload,
  validateRenewalProfile,
} = require("./renewalProfile");
const {
  CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED,
  assertRenewalPerCaCapacityAvailable,
} = require("./renewalCapacity");
const {
  resolveAgentJobRoutingRequirements,
} = require("./agentJobEligibility");
const { attachJobPendingReasons } = require("./jobPendingReason");
const { attachUserDisplayNames } = require("./userDisplayNames");

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
const CERTOPS_JOB_EXECUTION_FIELD_REQUIRED =
  "CERTOPS_JOB_EXECUTION_FIELD_REQUIRED";
const CERTOPS_JOB_MODE_INVALID = "CERTOPS_JOB_MODE_INVALID";
const CERTOPS_JOB_MODE_TERMINAL_INVALID =
  "CERTOPS_JOB_MODE_TERMINAL_INVALID";
const CERTOPS_CERTIFICATE_NOT_AGENT_DEPLOYABLE =
  "CERTOPS_CERTIFICATE_NOT_AGENT_DEPLOYABLE";
const CERTOPS_RENEWAL_AUTO_RENEW_DISABLED = "CERTOPS_RENEWAL_AUTO_RENEW_DISABLED";
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

// "issue" requests a brand-new certificate that TokenTimer does not track
// yet. It is a control-plane-only operation: the agent never sees it, because
// signed dispatch translates it to the wire-level action "renew" (identical
// execution). See docs/adr/0008-certops-upfront-issuance.md.
// "protocol_smoke" is a diagnostic-only operation (ADR-0012 decisions 2 and
// 7): it never touches certificate material, is only ever assigned to an
// agent whose server-assigned agent_kind is 'diagnostic' (see
// agentDispatch.js claimJobs), and can only be created by the dedicated
// diagnostic-bootstrap service (createCertificateJob refuses it below), so
// it is excluded from certificate quotas, per-CA limits, approval flows,
// and renewal alerts by construction rather than by an operation-name
// exclusion list scattered across those subsystems.
//
// "distribute-trust"/"revoke-trust" (ADR-0012 decisions 4-6 and 14) install
// or remove a root/intermediate CA in a machine trust store. A trust anchor
// has no private key and no renewal, so these two operations are a distinct
// family from every certificate operation above: TRUST_ANCHOR_OPERATIONS
// below is the routing key every trust-exclusion guard in this file (and in
// renewalScheduler.js / renewalProfileDerivation.js) checks against, rather
// than each guard re-deriving "is this a trust op" ad hoc.
const JOB_OPERATIONS = Object.freeze([
  "issue",
  "renew",
  "deploy",
  "reload",
  "revoke",
  "noop",
  "protocol_smoke",
  "distribute-trust",
  "revoke-trust",
]);
const JOB_OPERATION_SET = new Set(JOB_OPERATIONS);

const TRUST_ANCHOR_OPERATIONS = Object.freeze([
  "distribute-trust",
  "revoke-trust",
]);
const TRUST_ANCHOR_OPERATION_SET = new Set(TRUST_ANCHOR_OPERATIONS);

/**
 * True when operation is one of the trust-anchor operations. The single
 * predicate every by-construction exclusion guard (renewal scheduler,
 * ADR-0010 derivation, the automation-source guard below) calls, so the
 * definition of "trust operation" cannot drift between call sites.
 */
function isTrustAnchorOperation(operation) {
  return TRUST_ANCHOR_OPERATION_SET.has(operation);
}

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
  // A trust anchor (root/intermediate CA distributed to machine trust
  // stores, ADR-0012 decision 6) has no private key and no
  // managed_certificates row, so it is a subject in its own right rather
  // than a certificate.
  "trust_anchor",
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
// Mirrors job-payload.schema.json's top-level keyMode enum: the non-secret
// custody signal the agent's dispatch check reads directly off the job (e.g.
// executeJob's `job.keyMode === "os-store-managed"` gate for the windows-iis
// CNG-native executor, packages/agent/src/index.js). Distinct from the
// per-deploymentTargets-entry keyMode (a POSIX file-permission octal, see
// job-payload.schema.json's deploymentTargets items) despite the shared name.
const JOB_KEY_MODES = Object.freeze([
  "agent-local",
  "proxy-agent-local",
  "cert-manager-managed",
  "appliance-managed",
  "hsm-managed",
  "vault-managed",
  "os-store-managed",
  "external-unknown",
]);
const JOB_KEY_MODE_SET = new Set(JOB_KEY_MODES);

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
  keyMode(value) {
    if (typeof value !== "string" || !JOB_KEY_MODE_SET.has(value)) {
      throw executionFieldError("keyMode");
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
  // An issue job runs the exact same agent pipeline as a renew (ACME order,
  // deploy, optional reload, verify), so it accepts the same execution fields.
  issue: new Set([
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
    "keyMode",
  ]),
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
    "keyMode",
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
  // Adds nothing certificate-shaped (packages/contracts/certops/
  // protocol-smoke-payload.schema.json): a smoke job can never be mistaken
  // for, or grown into, a certificate job.
  protocol_smoke: new Set(),
  // A trust job carries no certificate execution fields at all (ADR-0012
  // decision 4): its own typed fields (trustAnchorId, anchorType, pem,
  // fingerprintSha256) live in trust-job-payload.schema.json, a sibling
  // contract, not in this certificate-shaped execution-field vocabulary.
  "distribute-trust": new Set(),
  "revoke-trust": new Set(),
});

// Fields an operation cannot function without. Only `issue` is covered today:
// it is the one operation with no renewalProfile to fall back on (only
// renew jobs get one, via validateRenewalProfileOnPayload / dispatch-time
// merge), and DNS-01 is the only challenge mechanism this agent supports
// (docs/certops/CONTEXT.md), so every field the agent needs to actually run
// the ACME order must be present on the payload at creation time. Without
// this, validateExecutionFields only validated fields that were present,
// so an issue request missing commandRef/caEndpoint/dnsZone/dnsProvider was
// accepted, a provisioning certificate row and job were created, and the
// gap surfaced only later on the execution plane -- potentially after a
// real, rate-limited ACME order had already been placed.
//
// certPath and keyMode are mutually exclusive rather than both-required: a
// windows-iis target has no filesystem deploy path (issuance.js's
// normalizeWindowsIssuanceTarget refuses one), it identifies its deploy
// destination via target.store/target.binding instead, and the agent's
// executeJob dispatch reads job.keyMode === "os-store-managed" to route to
// the CNG-native executor (packages/agent/src/index.js). Every other target
// type deploys to a filesystem path and has no keyMode on the payload today.
const REQUIRED_EXECUTION_FIELDS_BY_OPERATION = Object.freeze({
  issue: new Set(["commandRef", "caEndpoint", "dnsZone", "dnsProvider"]),
});

function requiredExecutionFieldsForOperation(payload, operation) {
  const base = REQUIRED_EXECUTION_FIELDS_BY_OPERATION[operation];
  if (!base) return base;
  if (operation !== "issue") return base;
  const required = new Set(base);
  required.add(payload?.target?.type === "windows-iis" ? "keyMode" : "certPath");
  return required;
}

// Multi-destination deployment is a real agent capability, but only through a
// renewalProfile.deploymentTargets array on a renew job. An `issue` payload has
// no profile: its renewal configuration is DERIVED from the payload after the
// certificate exists, and the derivation reads deploymentTargets[0] and nothing
// else. So an issue request carrying several targets was accepted, deployed to
// all of them, and then produced a renewal profile describing only the first,
// meaning every later renewal quietly stopped maintaining the rest. Refuse the
// shape instead: failing the request is recoverable, a certificate that renews
// on one host out of three is not, and it fails silently months later.
const MAX_ISSUE_DEPLOYMENT_TARGETS = 1;

function validateIssueDeploymentTargets(payload, operation) {
  if (operation !== "issue") return;
  const targets = payload?.deploymentTargets;
  if (targets === null || targets === undefined) return;
  if (!Array.isArray(targets)) {
    throw serviceError(
      "CertOps job payload field deploymentTargets must be an array",
      CERTOPS_JOB_EXECUTION_FIELD_INVALID,
    );
  }
  if (targets.length > MAX_ISSUE_DEPLOYMENT_TARGETS) {
    throw serviceError(
      "CertOps issue jobs accept at most one deploymentTargets entry, because " +
        "the renewal profile derived from the issuance describes a single " +
        "target; issue once per destination, or renew with an explicit " +
        "multi-target renewalProfile",
      CERTOPS_JOB_EXECUTION_FIELD_INVALID,
    );
  }
}

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

  validateIssueDeploymentTargets(payload, operation);

  const requiredForOperation = requiredExecutionFieldsForOperation(
    payload,
    operation,
  );
  if (!requiredForOperation) return;
  for (const fieldName of requiredForOperation) {
    const present =
      Object.prototype.hasOwnProperty.call(payload, fieldName) &&
      payload[fieldName] !== null &&
      payload[fieldName] !== undefined;
    if (!present) {
      throw serviceError(
        `CertOps job payload field ${fieldName} is required for the ` +
          `${operation} operation`,
        CERTOPS_JOB_EXECUTION_FIELD_REQUIRED,
      );
    }
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
    ([
      "succeeded",
      "failed",
      "blocked",
      "dry_run_complete",
      "orphaned_unknown_effect",
    ].includes(status)
      ? now
      : null);
  // The database column retains the American spelling for compatibility. The
  // public job state and service option use the canonical "cancelled".
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

// renew/deploy/reload/revoke always act on something that must already
// exist (a certificate, domain, endpoint, etc.), so a subject reference is
// mandatory, though its type may be "managed_certificate" (agent-executable,
// dashboard-linked) or a free-text type like "domain"/"endpoint"/"external"
// (an audit-trail job for something an external executor already handles,
// not yet adopted as a managed certificate). "issue" forbids a subject
// (issuance.js: it creates the certificate identity itself). "noop" is a
// pure heartbeat/connectivity check with nothing to reference.
// distribute-trust/revoke-trust always act on an existing certops_trust_
// anchors row (ADR-0012 decision 6), referenced the same way every other
// subject-bearing operation is: subject_type = 'trust_anchor',
// subject_id = the anchor's id.
const SUBJECT_REQUIRED_OPERATIONS = new Set([
  "renew",
  "deploy",
  "reload",
  "revoke",
  "distribute-trust",
  "revoke-trust",
]);

function normalizeSubject(options, operation) {
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
  if (!subjectType && SUBJECT_REQUIRED_OPERATIONS.has(operation)) {
    throw serviceError(
      `subjectType and subjectId are required for the ${operation} operation`,
      CERTOPS_JOB_INVALID,
    );
  }
  // A trust_anchor subject only ever makes sense under a trust-anchor
  // operation, and vice versa: this is the by-construction half of keeping
  // trust jobs and certificate jobs from ever crossing over, matching the
  // exclusion enforced in the renewal scheduler and ADR-0010 derivation
  // (see isTrustAnchorOperation).
  if (isTrustAnchorOperation(operation) && subjectType !== "trust_anchor") {
    throw serviceError(
      `subjectType must be trust_anchor for the ${operation} operation`,
      CERTOPS_JOB_INVALID,
    );
  }
  if (!isTrustAnchorOperation(operation) && subjectType === "trust_anchor") {
    throw serviceError(
      "subjectType trust_anchor is only valid for distribute-trust/revoke-trust jobs",
      CERTOPS_JOB_INVALID,
    );
  }
  return { subjectType, subjectId };
}

/**
 * Resolve the immutable executor lane and the optional B5 routing selectors
 * for a new job. Controller provisioning source always forces the controller
 * lane; any other source defaults to agent unless the caller overrides.
 */
function resolveExecutorKindAndRouting(options, source, payload, autoAssignedAgentId = null) {
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

  // Derive the same raw requirements consumed by dispatch and renewal-path
  // health, then apply this write path's validation and normalization.
  const rawRouting = resolveAgentJobRoutingRequirements({
    executorKind,
    assignedAgentId:
      options.assignedAgentId ?? payload.assignedAgentId ?? autoAssignedAgentId,
    requiredTargetSelector: options.requiredTargetSelector,
    requiredDnsProvider: options.requiredDnsProvider,
    requiredCommandProfile: options.requiredCommandProfile,
    payload,
  });

  const assignedAgentId =
    normalizeOptionalShortText(
      rawRouting.assignedAgentId,
      "assignedAgentId",
    ) || null;

  const requiredTargetSelector =
    normalizeOptionalPublicText(
      rawRouting.requiredTargetSelector,
      "requiredTargetSelector",
      512,
    ) || null;

  const requiredDnsProvider =
    normalizeOptionalShortText(
      rawRouting.requiredDnsProvider,
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
      rawRouting.requiredCommandProfile,
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

const AGENT_MUTATING_OPERATIONS = new Set([
  "renew",
  "deploy",
  "reload",
  "revoke",
]);
// os-store-managed (ADR-0012 decision 9) is a CNG-native or PFX-imported key
// held in the OS certificate store rather than on the agent filesystem.
// Custody-wise, the agent (not an external appliance, HSM, or vault) is the
// thing that would rotate it, which is why it is tempting to list it here
// alongside agent-local and proxy-agent-local. It IS included as of the
// windows-iis executor landing in packages/agent/src/index.js
// (executeWindowsIisRenewJob / runWindowsIisDeployTail): a renew job whose
// target.type is windows-iis now has a real execution path (CNG CSR ->
// ACME order -> certreq -accept -> netsh http add sslcert -> TLS-verify ->
// retention-ledger row), so os-store-managed is no longer dispatchable to a
// path that cannot execute it. This predicate still means "a job for this
// key mode can actually be executed", not merely "the agent owns this
// key" -- the executor exists specifically (and only) for target.type
// windows-iis; a job with keyMode os-store-managed and any other target
// type is rejected by resolveJobDeployTargets/executeJob's preflight in
// the agent itself, not by this set.
const AGENT_DEPLOYABLE_KEY_MODES = new Set([
  "agent-local",
  "proxy-agent-local",
  "os-store-managed",
]);

/**
 * Can an agent actually deploy to this certificate's key?
 *
 * The single source of truth for that question. Job creation refuses a
 * renew/deploy/reload/revoke against anything else, and the renewal scheduler
 * counts the refusal as skipped_not_agent_deployable, so any other view that
 * predicts whether a certificate will renew has to ask the same question here
 * rather than restate the key-mode list. A second copy of this list is a second
 * place for the answer to drift, and the drift is silent: a view that says a
 * certificate is covered while the scheduler refuses it is worse than no view.
 *
 * A NULL key_mode means the certificate was only ever observed (an endpoint or
 * domain monitor), so there is no key anywhere for an agent to rotate.
 *
 * @param {{ key_mode?: string|null }|string|null} certificateOrKeyMode
 * @returns {boolean}
 */
function isAgentDeployableKeyMode(certificateOrKeyMode) {
  const keyMode =
    certificateOrKeyMode && typeof certificateOrKeyMode === "object"
      ? certificateOrKeyMode.key_mode
      : certificateOrKeyMode;
  return AGENT_DEPLOYABLE_KEY_MODES.has(keyMode);
}
const SUBJECT_ID_UUID_PATTERN =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/**
 * Resolve certificate-ownership defaults for renew/deploy/reload/revoke jobs
 * against a managed_certificate subject, and reject the ones that have no
 * agent-manageable key custody at all. Two related problems this closes:
 *
 * 1. Without the key_mode check, a renew job could be created for a
 *    certificate that was only ever observed (e.g. via an endpoint/domain
 *    monitor: key_mode NULL, no agent target). Nothing can ever deploy to
 *    it, so whichever agent later claims it fails immediately, surfacing as
 *    a false cert_renewal_failed alert instead of a clear creation-time
 *    error.
 * 2. Without the auto-assign, a job with no requiredTargetSelector/
 *    assignedAgentId is claimable by *any* online agent that declares
 *    support for the operation (see agentDispatch.js claimJobs'
 *    "assigned_agent_id IS NULL OR ..." matcher) -- including one with zero
 *    relationship to the certificate. For a certificate discovered by a
 *    specific agent (source = agent_filesystem), that agent's id is already
 *    stored in public_metadata.controllerObservation.agentId; defaulting
 *    assignedAgentId from it pins the job to that exact agent instead of
 *    relying on every fleet agent's self-declared target-selector policy to
 *    avoid overlap (which does not scale safely to hundreds of agents).
 *
 * Skipped entirely for subject ids that are not a real managed_certificates
 * UUID: free-text subjects and most job-lifecycle test fixtures are not
 * DB-backed rows here, so there is nothing to look up.
 *
 * "issue" is deliberately NOT in AGENT_MUTATING_OPERATIONS. Its subject row
 * was created moments earlier by this same request (status 'provisioning',
 * source 'agent_issuance'), so there is no prior discovery agent to inherit
 * and the key_mode check would only be re-reading the value the issuance
 * service just wrote. Issue jobs use open-claim routing, matched on the
 * declared command profile and DNS provider like an unassigned renew.
 */
async function resolveManagedCertificateJobDefaults({
  db,
  workspaceId,
  source,
  operation,
  subjectType,
  subjectId,
}) {
  if (source === CONTROLLER_PROVISIONING_JOB_SOURCE) {
    return { autoAssignedAgentId: null };
  }
  if (!AGENT_MUTATING_OPERATIONS.has(operation)) {
    return { autoAssignedAgentId: null };
  }
  if (subjectType !== "managed_certificate" || !subjectId) {
    return { autoAssignedAgentId: null };
  }
  if (!SUBJECT_ID_UUID_PATTERN.test(subjectId)) {
    return { autoAssignedAgentId: null };
  }

  const result = await db.query(
    `SELECT mc.key_mode,
            mc.source,
            mc.deployed_agent_id,
            mc.public_metadata->'controllerObservation'->>'agentId'
              AS discovery_agent_id,
            cp.status AS profile_status
       FROM managed_certificates mc
       LEFT JOIN certificate_profiles cp
         ON cp.workspace_id = mc.workspace_id AND cp.id = mc.profile_id
      WHERE mc.workspace_id = $1
        AND mc.id = $2::uuid
      LIMIT 1`,
    [workspaceId, subjectId],
  );
  const row = result.rows[0];
  if (!row) return { autoAssignedAgentId: null };

  if (!isAgentDeployableKeyMode(row)) {
    throw serviceError(
      "This certificate has no agent-manageable key custody (it was only " +
        "observed, e.g. via an endpoint or domain monitor) and cannot be " +
        `assigned an agent-executed ${operation} job`,
      CERTOPS_CERTIFICATE_NOT_AGENT_DEPLOYABLE,
    );
  }

  // The renewal scheduler's own scan query already excludes certificates
  // whose linked profile is 'disabled'/'archived' (renewalScheduler.js,
  // AUTO_RENEW_DISABLED_PROFILE_STATUSES) - but that guarantee lives in the
  // sweep's SQL, not here, so any *other* code path that creates an
  // automation-sourced renew job directly (an alternate scheduler entry, a
  // future batch job) would not be stopped by it. Re-checked here rather
  // than left to the caller so the guarantee holds regardless of how job
  // creation is reached. Scoped to source === "automation" only: a manager
  // manually renewing (or bulk-renewing) a certificate whose profile has
  // auto-renew switched off is the documented, intended way to still renew
  // it yourself (see "Switching automatic renewal off" in automation.mdx) -
  // only the *scheduler's automatic* pickup is supposed to skip it.
  if (
    source === "automation" &&
    operation === "renew" &&
    AUTO_RENEW_DISABLED_PROFILE_STATUSES.includes(row.profile_status)
  ) {
    throw serviceError(
      "This certificate's renewal profile has automatic renewal switched " +
        `off (status: ${row.profile_status}); an automation-sourced renew ` +
        "job cannot be created for it",
      CERTOPS_RENEWAL_AUTO_RENEW_DISABLED,
    );
  }

  // Windows store/IIS observations already persist the reporting agent's row
  // id. The store and binding are host-local, so every later scheduler job
  // must stay pinned to that same executor just like filesystem discovery.
  if (row.source === "agent_windows" && row.deployed_agent_id) {
    return { autoAssignedAgentId: row.deployed_agent_id };
  }
  if (row.source !== "agent_filesystem" || !row.discovery_agent_id) {
    return { autoAssignedAgentId: null };
  }
  const agentResult = await db.query(
    `SELECT id FROM certops_agents WHERE workspace_id = $1 AND agent_id = $2 LIMIT 1`,
    [workspaceId, row.discovery_agent_id],
  );
  return { autoAssignedAgentId: agentResult.rows[0]?.id || null };
}

const CERTOPS_CERTIFICATE_NOT_FOUND = "CERTOPS_CERTIFICATE_NOT_FOUND";

// buildRenewalJobPayload requires a reason; "manual" distinguishes this
// path in the job log/audit trail from the scheduler's "expiry-threshold".
const MANUAL_RENEWAL_DEFAULT_REASON = "manual";

/**
 * Loads the managed_certificates + certificate_profiles row shape
 * resolveRenewalProfileSnapshot needs, for exactly one certificate. Selects
 * the same columns renewalScheduler.js's findCertificatesDueForRenewal
 * selects, so a manual/bulk renewal resolves the profile snapshot the same
 * way the scheduler would for the same certificate.
 */
async function loadManagedCertificateForRenewal({ db, workspaceId, certificateId }) {
  if (!SUBJECT_ID_UUID_PATTERN.test(String(certificateId || ""))) return null;
  const result = await db.query(
    `SELECT mc.id,
            mc.common_name,
            mc.subject_alt_names,
            mc.not_after,
            mc.key_mode,
            mc.profile_id,
            cp.name AS profile_name,
            cp.key_mode AS profile_key_mode,
            cp.public_metadata AS profile_public_metadata
       FROM managed_certificates mc
       LEFT JOIN certificate_profiles cp
         ON cp.workspace_id = mc.workspace_id AND cp.id = mc.profile_id
      WHERE mc.workspace_id = $1
        AND mc.id = $2::uuid
      LIMIT 1`,
    [workspaceId, certificateId],
  );
  return result.rows[0] || null;
}

/**
 * Single materializer for a manual/bulk renew payload: reads the certificate
 * with its linked profile and resolves the stored renewal profile into the
 * same payload the scheduler would build. Read-only. Shared by the real
 * creation path and its dry-run preflight so the two cannot drift.
 */
async function materializeManualRenewalPayload({
  db,
  workspaceId,
  certificateId,
  overrides,
  loadCertificate = loadManagedCertificateForRenewal,
}) {
  const certificate = await loadCertificate({
    db,
    workspaceId,
    certificateId,
  });
  if (!certificate) {
    throw serviceError("Certificate not found", CERTOPS_CERTIFICATE_NOT_FOUND);
  }
  return buildManualRenewalJobPayload({
    certificate,
    defaultReason: MANUAL_RENEWAL_DEFAULT_REASON,
    overrides,
  });
}

/**
 * jobCreator swapped in (by routes/certops.js) for a renew job whose
 * subject is an existing managed certificate, for both single manual and
 * bulk creation. Materializes the payload the same way the scheduler does
 * (buildManualRenewalJobPayload), so a manual/bulk renewal can never
 * diverge from an automatic one. options.payload may only carry the fields
 * RENEWAL_MANUAL_OVERRIDE_FIELDS names; anything else is rejected
 * (CERTOPS_RENEWAL_OVERRIDE_INVALID). A missing/incomplete stored renewal
 * profile also fails here, before any row is inserted.
 */
function manualRenewalJobCreator({
  certificateId,
  createJob = createCertificateJob,
  loadCertificate = loadManagedCertificateForRenewal,
} = {}) {
  return async function manualRenewalJobCreator(options) {
    const { client, workspaceId } = options;
    const payload = await materializeManualRenewalPayload({
      db: client,
      workspaceId,
      certificateId,
      overrides: options.payload,
      loadCertificate,
    });

    return createJob({
      ...options,
      operation: "renew",
      subjectType: "managed_certificate",
      subjectId: certificateId,
      payload,
    });
  };
}

/**
 * Read-only twin of manualRenewalJobCreator's materialization step: resolves
 * the certificate's stored renewal profile, builds the renew payload from it
 * and runs the same payload validation createCertificateJob runs. Writes
 * nothing, takes no lock and reserves no per-CA capacity, so a bulk dry run
 * can reject the certificates a real run would reject (notably
 * CERTOPS_RENEWAL_PROFILE_INCOMPLETE / CERTOPS_RENEWAL_PROFILE_INVALID)
 * without side effects. Returns the payload the real run would insert.
 */
async function preflightManualRenewalJob({
  client,
  workspaceId,
  certificateId,
  payload,
  loadCertificate = loadManagedCertificateForRenewal,
} = {}) {
  const materialized = await materializeManualRenewalPayload({
    db: client || pool,
    workspaceId,
    certificateId,
    overrides: payload,
    loadCertificate,
  });
  return validateJobPayloadForOperation(materialized, "renew");
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

/**
 * Authoritative read of workspaces.certops_require_approval_always.
 * DB true always wins; an explicit caller hint of true is OR'd for
 * transitional callers/tests that already resolved the column under a lock.
 * An explicit false cannot override a true DB value.
 */
async function resolveWorkspaceRequiresApprovalAlways(
  db,
  workspaceId,
  explicitOption,
) {
  const result = await db.query(
    `SELECT certops_require_approval_always
       FROM workspaces
      WHERE id = $1`,
    [workspaceId],
  );
  const fromDb = result.rows[0]?.certops_require_approval_always === true;
  return fromDb || explicitOption === true;
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
  // protocol_smoke is diagnostic-only and must never enter through the
  // general-purpose job-creation path: allowing it here would let a
  // protocol_smoke job pick up an approval gate, a per-CA cap check, a
  // renewal-profile requirement, or a managed-certificate default the way
  // any other operation can, defeating the exclusion this operation exists
  // to have by construction. Only the diagnostic-bootstrap service
  // (services/certops/diagnosticBootstrap.js) creates these jobs, via its
  // own dedicated insert, and passes this flag explicitly.
  if (operation === "protocol_smoke" && options.allowDiagnosticOperation !== true) {
    throw serviceError(
      "protocol_smoke jobs can only be created by the CertOps diagnostic-bootstrap service",
      CERTOPS_JOB_OPERATION_INVALID,
    );
  }
  // protocol_smoke is always dispatched dry-run (ADR-0012 decision 7): this
  // is what makes assertModeAllowsTerminalStatus below reject a later
  // "succeeded" report for this job, the same guard that already stops any
  // other dry_run job from terminating that way. A caller cannot opt a
  // smoke job into mode: "real" and reach a code path that never runs a
  // real ACME order or filesystem write anyway.
  if (
    operation === "protocol_smoke" &&
    options.mode !== undefined &&
    options.mode !== null &&
    options.mode !== "dry_run"
  ) {
    throw serviceError(
      "protocol_smoke jobs must use mode: dry_run",
      CERTOPS_JOB_MODE_INVALID,
    );
  }
  if (operation === "protocol_smoke") {
    options = { ...options, mode: "dry_run" };
  }
  // Per-job approval gate: a job that requires human approval starts at
  // pending_approval and only reaches the claimable 'pending' status through
  // services/certops/jobApprovals.approveJob. The flag only chooses the
  // default initial status; an explicit conflicting status is rejected so a
  // caller cannot both request a gate and bypass it.
  const perJobRequiresApproval = options.requiresApproval === true;
  // Workspace-wide override (certops_require_approval_always) is read here,
  // not trusted from the caller alone: omitting workspaceRequiresApprovalAlways
  // must not bypass a policy that is on. Callers that already hold the
  // workspace lock may still pass the column value as a hint; an explicit
  // true is OR'd in, but an explicit false cannot override a true DB value.
  // protocol_smoke is exempt by the same by-construction exclusion as every
  // other approval-flow concept.
  const workspaceForcesApproval =
    operation !== "protocol_smoke" &&
    (await resolveWorkspaceRequiresApprovalAlways(
      db,
      workspaceId,
      options.workspaceRequiresApprovalAlways,
    ));
  const requiresApproval = perJobRequiresApproval || workspaceForcesApproval;
  if (
    perJobRequiresApproval &&
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
    workspaceForcesApproval ? "pending_approval" : options.status,
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
  // Trust-anchor operations are excluded from the unattended renewal
  // scheduler BY CONSTRUCTION, not by convention: "automation" is the one
  // source value the scheduler (and only the scheduler) uses, so refusing
  // that combination here makes "the scheduler can never create a trust
  // job" a property of job creation itself, holding even if a future change
  // to the scheduler tried to parameterize its hardcoded operation: "renew".
  // Distributing or revoking a CA trust anchor is always an explicit human
  // or API-token decision.
  if (source === "automation" && isTrustAnchorOperation(operation)) {
    throw serviceError(
      "Trust-anchor operations cannot be created by automation; " +
        "distribute-trust and revoke-trust require an explicit human or " +
        "API request",
      CERTOPS_JOB_OPERATION_INVALID,
    );
  }
  const { subjectType, subjectId } = normalizeSubject(options, operation);
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
  const { autoAssignedAgentId } = await resolveManagedCertificateJobDefaults({
    db,
    workspaceId,
    source,
    operation,
    subjectType,
    subjectId,
  });
  const {
    executorKind,
    assignedAgentId,
    requiredTargetSelector,
    requiredDnsProvider,
    requiredCommandProfile,
  } = resolveExecutorKindAndRouting(options, source, payload, autoAssignedAgentId);
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

  // Idempotent replays must not be rejected by the per-CA cap: a retry of an
  // already-created renew job is not a new capacity reservation.
  if (idempotencyKey) {
    const existingBeforeInsert = await getJobByIdempotencyKey(
      db,
      workspaceId,
      idempotencyKey,
    );
    if (existingBeforeInsert) {
      const isMatchingReplay = existingBeforeInsert.creationRequestHash
        ? existingBeforeInsert.creationRequestHash === creationRequestHash
        : legacyJobCreationIdentity(existingBeforeInsert) ===
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
          ? { job: existingBeforeInsert, created: false }
          : existingBeforeInsert;
      }
      throw serviceError(
        "Idempotency key was already used with a different CertOps job request",
        CERTOPS_JOB_IDEMPOTENCY_CONFLICT,
      );
    }
  }

  // Authoritative per-(workspace, CA) capacity. Scheduler pre-filters are
  // best-effort; bulk/manual paths share this transactional gate. issue and
  // renew share the bucket: both place a real ACME order.
  if (operation === "renew" || operation === "issue") {
    await assertRenewalPerCaCapacityAvailable({
      client: db,
      workspaceId,
      payload,
      terminalStatuses: [...TERMINAL_JOB_STATUSES],
      env: options.env || process.env,
      perCaCap: options.perCaCap,
    });
  }

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

async function getCertificateJobById(options) {
  const db = options.client || pool;
  const job = await getJobById(
    db,
    normalizeWorkspaceId(options.workspaceId),
    normalizeRequiredId(options.jobId),
  );
  if (!job) return null;
  const [withPending] = await attachJobPendingReasons({
    db,
    workspaceId: job.workspaceId,
    jobs: [job],
    env: options.env,
  });
  const [decorated] = await attachUserDisplayNames({
    db,
    records: [withPending],
    idKey: "approvedByUserId",
    nameKey: "approvedByDisplayName",
  });
  return decorated;
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

  // Counted over the filter predicate the page itself uses, before LIMIT and
  // OFFSET are appended. A total taken over a wider predicate would advertise
  // pages that hold none of the rows the caller asked for.
  const totalResult = await db.query(
    `SELECT COUNT(*)::int AS total
       FROM certificate_jobs
      WHERE ${conditions.join(" AND ")}`,
    params,
  );

  params.push(limit, offset);
  const result = await db.query(
    `SELECT ${SAFE_JOB_SELECT_FIELDS}
       FROM certificate_jobs
      WHERE ${conditions.join(" AND ")}
      ORDER BY created_at DESC, id ASC
      LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params,
  );

  const withPending = await attachJobPendingReasons({
    db,
    workspaceId,
    jobs: result.rows.map(jobFromRow),
    env: options.env,
  });
  const items = await attachUserDisplayNames({
    db,
    records: withPending,
    idKey: "approvedByUserId",
    nameKey: "approvedByDisplayName",
  });

  return {
    items,
    pagination: {
      limit,
      offset,
      total: Number(totalResult.rows[0]?.total || 0),
    },
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
                WHEN $3 IN (
                  'succeeded',
                  'failed',
                  'blocked',
                  'dry_run_complete',
                  'orphaned_unknown_effect'
                )
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

  const items = await attachUserDisplayNames({
    db,
    records: result.rows.map(jobLogFromRow),
    idKey: "createdByUserId",
    nameKey: "createdByDisplayName",
  });

  return {
    items,
    pagination: { limit, offset },
  };
}

module.exports = {
  CERTOPS_JOB_INVALID,
  CERTOPS_CERTIFICATE_NOT_AGENT_DEPLOYABLE,
  CERTOPS_CERTIFICATE_NOT_FOUND,
  CERTOPS_RENEWAL_AUTO_RENEW_DISABLED,
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
  CERTOPS_JOB_EXECUTION_FIELD_REQUIRED,
  CERTOPS_JOB_MODE_INVALID,
  CERTOPS_JOB_MODE_TERMINAL_INVALID,
  CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED,
  CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
  CERTOPS_RENEWAL_PROFILE_INVALID,
  DEFAULT_JOB_MODE,
  MANUAL_RENEWAL_DEFAULT_REASON,
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
  TRUST_ANCHOR_OPERATIONS,
  appendCertificateJobLog,
  assertModeAllowsTerminalStatus,
  assertSafePublicValue,
  createCertificateJob,
  dateToIso,
  fieldNameLooksForbidden,
  findActiveJobForSubject,
  getCertificateJobById,
  isAgentDeployableKeyMode,
  isTerminalJobStatus,
  isTrustAnchorOperation,
  jobCreationRequestFingerprint,
  jobFromRow,
  jobLogFromRow,
  listCertificateJobLog,
  listCertificateJobs,
  loadManagedCertificateForRenewal,
  manualRenewalJobCreator,
  normalizeJobMode,
  normalizeLimit,
  normalizeOffset,
  normalizePublicObject,
  normalizeRequiredId,
  normalizeWorkspaceId,
  preflightManualRenewalJob,
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

"use strict";

// Read projections for the operator namespace (ADR-0015 section 4).
//
// Every function builds its result from a fixed list of named fields. Nothing
// is produced by deleting fields from a richer record, so a field added to an
// internal record later cannot reach a connection by accident. Outputs are
// validated against packages/contracts/mcp/mcp-read-tools.schema.json in the
// unit tests.

const { classifyAgentLiveness } = require("../certops/agentLiveness");
const {
  isoOrNull,
  snakeCodeOrNull,
  untrustedText,
} = require("./projections");

const DAY_MS = 24 * 60 * 60 * 1000;
const DEFAULT_LIMIT = 25;
const MAX_LIMIT = 50;
const MAX_SANS = 25;
const MAX_PERIODS = 20;
const MAX_MESSAGE = 300;
const CURSOR_INVALID = "OPERATOR_CURSOR_INVALID";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/;

const DISPLAY_STATUSES = new Set([
  "discovered",
  "provisioning",
  "active",
  "renewing",
  "expiring",
  "expired",
  "revoked",
  "decommissioned",
]);
const LIFECYCLE_STATUSES = new Set(["active", "revoked", "decommissioned"]);
const RENEWAL_PATH_STATES = new Set(["healthy", "degraded", "unavailable", "unknown"]);
const PRESENCE_STATES = new Set(["confirmed_present", "confirmed_absent", "unknown"]);
const EVIDENCE_KINDS = new Set(["service_binding", "stored_copy", "unknown"]);
const AGENT_STATUSES = new Set(["active", "offline", "retired"]);
const PLATFORMS = new Set(["linux", "darwin", "win32"]);
const CAPABILITY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,63}$/;
const JOB_OPERATIONS = new Set([
  "issue",
  "renew",
  "deploy",
  "deploy-from-store",
  "reload",
  "revoke",
  "noop",
  "protocol_smoke",
  "distribute-trust",
  "revoke-trust",
  "continue-enrollment",
  "adcs-preflight",
]);

class CursorError extends Error {
  constructor() {
    super("Cursor is invalid");
    this.code = CURSOR_INVALID;
  }
}

function isUuid(value) {
  return typeof value === "string" && UUID_PATTERN.test(value);
}

// Pagination cursors are opaque to the client. Today they wrap an offset,
// because the underlying services page by offset.
function encodeCursor(offset) {
  return Buffer.from(`o:${offset}`, "utf8").toString("base64url");
}

function decodeCursor(cursor) {
  if (cursor === undefined || cursor === null || cursor === "") return 0;
  if (typeof cursor !== "string" || cursor.length > 512 || !/^[A-Za-z0-9_=.-]+$/.test(cursor)) {
    throw new CursorError();
  }
  const text = Buffer.from(cursor, "base64url").toString("utf8");
  const match = /^o:(\d{1,9})$/.exec(text);
  if (!match) throw new CursorError();
  return Number.parseInt(match[1], 10);
}

function clampLimit(value) {
  if (value === undefined || value === null || value === "") return DEFAULT_LIMIT;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || String(parsed) !== String(value).trim()) return null;
  if (parsed < 1 || parsed > MAX_LIMIT) return null;
  return parsed;
}

// "No matches" must be distinguishable from "first page only".
function completeness({ offset, returned, total, hardCap = null }) {
  const reachable = hardCap === null ? total : Math.min(total, hardCap);
  const consumed = offset + returned;
  return {
    returned,
    truncated: consumed < total,
    nextCursor: consumed < reachable ? encodeCursor(consumed) : null,
    totalKnown: true,
    total,
  };
}

function daysUntilExpiry(notAfter, now = Date.now()) {
  const iso = isoOrNull(notAfter);
  if (!iso) return null;
  return Math.floor((new Date(iso).getTime() - now) / DAY_MS);
}

function fingerprintOrNull(value) {
  return typeof value === "string" && FINGERPRINT_PATTERN.test(value) ? value : null;
}

function projectCertificateSummary(record, { renewalPathState = null, now = Date.now() } = {}) {
  const fingerprint = fingerprintOrNull(record.fingerprintSha256);
  const lifecycle = LIFECYCLE_STATUSES.has(record.lifecycleStatus) ? record.lifecycleStatus : null;
  return {
    // The identity id is the handle every other tool takes. The record's own
    // id is the managed-certificate id when one exists, which no operator
    // route accepts.
    id: record.identityId || record.id,
    kind: fingerprint ? "identity" : "provisional",
    fingerprintSha256: fingerprint,
    commonName: untrustedText(record.commonName || record.name),
    issuer: untrustedText(record.issuer),
    notAfter: isoOrNull(record.notAfter),
    daysUntilExpiry: daysUntilExpiry(record.notAfter, now),
    displayStatus: DISPLAY_STATUSES.has(record.status) ? record.status : "discovered",
    lifecycleStatus: lifecycle,
    renewalPathState: RENEWAL_PATH_STATES.has(renewalPathState) ? renewalPathState : null,
    stillObserved: record.stillObserved === true,
  };
}

function projectManagementPeriods(sources) {
  const list = Array.isArray(sources) ? sources : [];
  const items = list
    .filter((source) => isUuid(source?.periodId))
    .slice(0, MAX_PERIODS)
    .map((source) => ({
      periodId: source.periodId,
      sourceKind: snakeCodeOrNull(source.source) || "unknown",
      startedAt: isoOrNull(source.startedAt) || isoOrNull(source.periodStartedAt) || new Date(0).toISOString(),
      endedAt: isoOrNull(source.endedAt),
      endedReason: snakeCodeOrNull(source.endedReason),
    }));
  return { items, truncated: list.length > MAX_PERIODS };
}

function projectCertificateDetail(record, { renewalPath = null, workspacePaused = false, now = Date.now() } = {}) {
  const snapshot = record.certificateSnapshot && typeof record.certificateSnapshot === "object"
    ? record.certificateSnapshot
    : {};
  const rawSans = Array.isArray(snapshot.subjectAltNames) ? snapshot.subjectAltNames : [];
  const sans = rawSans.map((san) => untrustedText(san)).filter(Boolean);
  const periods = projectManagementPeriods(record.sources);
  const locations = Array.isArray(record.locations) ? record.locations : [];
  const observedTimes = locations
    .map((location) => isoOrNull(location?.capturedAt))
    .filter(Boolean)
    .sort();
  const lifecycle = LIFECYCLE_STATUSES.has(record.lifecycleStatus) ? record.lifecycleStatus : "active";
  return {
    summary: projectCertificateSummary(record, {
      renewalPathState: renewalPath?.renewalPathState ?? null,
      now,
    }),
    details: {
      notBefore: isoOrNull(snapshot.notBefore),
      sans: sans.slice(0, MAX_SANS),
      sansTruncated: sans.length > MAX_SANS,
    },
    lifecycle: { status: lifecycle, reason: untrustedText(record.lifecycleReason) },
    managementPeriods: periods.items,
    managementPeriodsTruncated: periods.truncated,
    renewal: {
      pathState: RENEWAL_PATH_STATES.has(renewalPath?.renewalPathState) ? renewalPath.renewalPathState : null,
      pathReason: snakeCodeOrNull(renewalPath?.renewalPathReason),
      profileId: isUuid(record.profileId) ? record.profileId : null,
      workspacePaused: workspacePaused === true,
    },
    observation: {
      lastObservedAt: observedTimes.length ? observedTimes[observedTimes.length - 1] : null,
      locationCount: Number(record.locationCount || 0),
      visibilityUnknown: record.visibilityUnknown === true,
    },
  };
}

function projectObservation(location) {
  const evidence = EVIDENCE_KINDS.has(location.evidenceKind) ? location.evidenceKind : null;
  return {
    id: location.id,
    source: snakeCodeOrNull(location.source) || "unknown",
    locationKind: snakeCodeOrNull(location.locationKind),
    presenceState: PRESENCE_STATES.has(location.presenceState) ? location.presenceState : "unknown",
    evidenceKind: evidence,
    observedAt: isoOrNull(location.capturedAt),
    monitoringEnded: location.monitoringEnded === true,
    observationReason: snakeCodeOrNull(location.observationReason),
    previousObservationCount: Number(location.previousObservationCount || 0),
  };
}

function projectObservations(record, { offset = 0, limit = DEFAULT_LIMIT } = {}) {
  const all = (Array.isArray(record.locations) ? record.locations : []).filter((l) => isUuid(l?.id));
  const total = Number(record.locationCount || all.length);
  const page = all.slice(offset, offset + limit);
  return {
    identityId: record.identityId,
    visibilityUnknown: record.visibilityUnknown === true,
    items: page.map(projectObservation),
    // The source returns at most 20 locations per certificate, so a longer
    // list is reported as truncated with no cursor to follow.
    completeness: completeness({ offset, returned: page.length, total, hardCap: all.length }),
  };
}

function projectAgent(agent, { now = Date.now() } = {}) {
  const status = AGENT_STATUSES.has(agent.status) ? agent.status : "offline";
  const liveness =
    status === "retired"
      ? "retired"
      : classifyAgentLiveness({ lastSeenAt: agent.lastSeenAt, createdAt: agent.createdAt, now }) || "stale";
  return {
    id: agent.id,
    hostname: untrustedText(agent.hostname),
    platform: PLATFORMS.has(agent.platform) ? agent.platform : null,
    status,
    liveness,
    agentKind: agent.agentKind === "diagnostic" ? "diagnostic" : "normal",
    lastSeenAt: isoOrNull(agent.lastSeenAt),
    agentVersion: String(agent.agentVersion || "").slice(0, 32),
    protocolVersion: /^\d+\.\d+\.\d+$/.test(String(agent.protocolVersion || "")) ? agent.protocolVersion : "0.0.0",
    compatibilityState: snakeCodeOrNull(agent.compatibilityState) || "unknown",
    clockDriftState: snakeCodeOrNull(agent.clockDriftState),
    supportedOperations: (agent.supportedOperations || []).filter((op) => JOB_OPERATIONS.has(op)).slice(0, 32),
    declaredCapabilities: (agent.declaredCapabilities || [])
      .filter((capability) => typeof capability === "string" && CAPABILITY_PATTERN.test(capability))
      .slice(0, 64),
  };
}

// Error codes are stored in whatever case the writer used; the contract is
// lower snake case, so normalize deterministically and drop anything else.
function errorCodeOrNull(value) {
  if (typeof value !== "string") return null;
  return snakeCodeOrNull(value.trim().toLowerCase());
}

function requestedByKind(job) {
  if (job.requestedByUserId !== null && job.requestedByUserId !== undefined) return "user";
  if (job.requestedByApiTokenId) return "api_token";
  return "system";
}

function projectJobSummary(job) {
  return {
    id: job.id,
    operation: JOB_OPERATIONS.has(job.operation) ? job.operation : "noop",
    status: job.status,
    subjectType: snakeCodeOrNull(job.subjectType),
    subjectId: isUuid(job.subjectId) ? job.subjectId : null,
    createdAt: isoOrNull(job.createdAt),
    startedAt: isoOrNull(job.startedAt),
    completedAt: isoOrNull(job.completedAt),
    requestedByKind: requestedByKind(job),
    needsOperatorReconciliation: job.needsOperatorReconciliation === true,
  };
}

// An approved job later refused by an agent also reports "rejected", so a
// decision timestamp wins over the status when both are present.
function approvalState(job) {
  if (job.status === "pending_approval") return "pending";
  if (job.approvedAt) return "approved";
  if (job.status === "rejected") return "rejected";
  return "not_required";
}

function projectJobDetail(job) {
  const state = approvalState(job);
  const pending = job.pendingReason;
  return {
    summary: projectJobSummary(job),
    updatedAt: isoOrNull(job.updatedAt),
    attemptCount: Number(job.attemptCount || 0),
    errorCode: errorCodeOrNull(job.errorCode),
    approval: {
      required: state !== "not_required",
      state,
      decidedAt: isoOrNull(job.approvedAt),
    },
    pendingReason:
      pending && snakeCodeOrNull(pending.code)
        ? { code: pending.code, message: String(pending.message || "").slice(0, MAX_MESSAGE) }
        : null,
  };
}

module.exports = {
  CURSOR_INVALID,
  CursorError,
  DEFAULT_LIMIT,
  MAX_LIMIT,
  MAX_MESSAGE,
  clampLimit,
  completeness,
  decodeCursor,
  encodeCursor,
  errorCodeOrNull,
  isUuid,
  projectAgent,
  projectCertificateDetail,
  projectCertificateSummary,
  projectJobDetail,
  projectJobSummary,
  projectObservations,
};

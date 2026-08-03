"use strict";

const crypto = require("node:crypto");
const { pool } = require("../../db/database");
const { redactGenericSecrets } = require("../../utils/secretMaterial");
const {
  TRANSITION_ORIGINS,
  classifyTerminalTransition,
} = require("./renewalAlertPolicy");
const { OUTBOX_EVENT_TYPES, enqueueOutboxEvent } = require("./outbox");

const CERTOPS_AGENT_NOT_FOUND = "CERTOPS_AGENT_NOT_FOUND";
const CERTOPS_AGENT_INVALID = "CERTOPS_AGENT_INVALID";
const CERTOPS_AGENT_RETIRE_REASON_INVALID =
  "CERTOPS_AGENT_RETIRE_REASON_INVALID";
const CERTOPS_AGENT_WORKSPACE_REQUIRED = "CERTOPS_AGENT_WORKSPACE_REQUIRED";

const MAX_RETIRE_REASON_LENGTH = 500;

const FORCE_RETIRED_CODE = "CERTOPS_AGENT_FORCE_RETIRED";
const FORCE_RETIRED_UNKNOWN_EFFECT_CODE =
  "CERTOPS_AGENT_FORCE_RETIRED_UNKNOWN_EFFECT";

// H8: config-driven protocol/agent compatibility and clock-drift thresholds.
const DEFAULT_MIN_PROTOCOL_VERSION = "1.0.0";
const DEFAULT_MAX_PROTOCOL_VERSION = "1.999.999";
const DEFAULT_MIN_AGENT_VERSION = "0.1.0";
// Intentionally unbounded: this is a reject-ceiling, not a "latest version"
// reference, so the control plane never blocks an agent purely for being
// newer than this server happens to know about. Do not reuse this constant
// to decide what counts as "outdated" (see DEFAULT_LATEST_KNOWN_AGENT_VERSION).
const DEFAULT_MAX_AGENT_VERSION = "99.999.999";
// The "outdated" heuristic below needs a real latest-version reference, not
// the unbounded reject-ceiling above. Default it to the agent package this
// server actually ships, so it tracks every release automatically without
// an operator having to remember to bump an env var each time. Falls back to
// the reject-ceiling (old behavior) only if that package.json can't be read.
let DEFAULT_LATEST_KNOWN_AGENT_VERSION = null;
try {
  DEFAULT_LATEST_KNOWN_AGENT_VERSION =
    require("../../../../packages/agent/package.json").version || null;
} catch {
  DEFAULT_LATEST_KNOWN_AGENT_VERSION = null;
}
const DEFAULT_CLOCK_DRIFT_WARN_MS = 5_000;
const DEFAULT_CLOCK_DRIFT_ALERT_MS = 30_000;
// Kept in sync with apps/worker/src/certops-worker.js's
// DEFAULT_AGENT_OFFLINE_AFTER_MS / CERTOPS_AGENT_OFFLINE_AFTER_MS: the
// stale-agent sweep is the eventual source of truth for the persisted
// `status` column, but it only runs periodically, so this read path
// independently derives a `livenessState` from the same threshold to avoid
// showing a crashed/unresponsive agent as "active" between sweeps.
const DEFAULT_AGENT_OFFLINE_AFTER_MS = 10 * 60 * 1000;

// ADR-0012 decision 7. agent_kind is server-assigned exactly once, at row
// creation (registerAgent for 'normal', createDiagnosticBootstrap for
// 'diagnostic'), and there is deliberately no code path that updates it on
// an existing row.
const AGENT_KIND_NORMAL = "normal";
const AGENT_KIND_DIAGNOSTIC = "diagnostic";
const AGENT_KINDS = Object.freeze([AGENT_KIND_NORMAL, AGENT_KIND_DIAGNOSTIC]);

// ADR-0012 decision 7: a diagnostic agent that never heartbeats again (the
// common case: an operator ran the reference client once to test
// connectivity and closed it) must not linger in the fleet forever. Distinct
// from DEFAULT_AGENT_OFFLINE_AFTER_MS, which only ever flips status to
// 'offline' and never retires anything.
const DEFAULT_DIAGNOSTIC_AGENT_INACTIVITY_TTL_MS = 24 * 60 * 60 * 1000;

function diagnosticAgentInactivityTtlMs(env = process.env) {
  const raw = Number.parseInt(
    env.CERTOPS_DIAGNOSTIC_AGENT_INACTIVITY_TTL_MS,
    10,
  );
  if (Number.isSafeInteger(raw) && raw > 0) return raw;
  return DEFAULT_DIAGNOSTIC_AGENT_INACTIVITY_TTL_MS;
}

// ADR-0012 decision 17: capability-gated claim selection at
// agentDispatch.js's claimJobs needs a freshness bound for
// certops_agents.capabilities_updated_at. The bound is not an independently
// invented number - it reuses this file's own existing agent-liveness SLO
// (DEFAULT_AGENT_OFFLINE_AFTER_MS above), on the reasoning that an agent
// whose last capability assertion is stale by more than the threshold that
// would already mark it `livenessState: "stale"` has no business being
// offered a capability-gated job. It is deliberately its OWN named constant
// (not a direct reference to DEFAULT_AGENT_OFFLINE_AFTER_MS) so the two can
// be tuned independently later; they simply start equal. This is NOT "3x
// the 30-second heartbeat interval" - that arithmetic was considered and is
// explicitly rejected by ADR-0012 decision 17.
const DEFAULT_CERTOPS_CAPABILITY_FRESHNESS_MS = 10 * 60 * 1000;

function certopsCapabilityFreshnessMs(env = process.env) {
  return Number.parseInt(
    env.CERTOPS_CAPABILITY_FRESHNESS_MS ||
      String(DEFAULT_CERTOPS_CAPABILITY_FRESHNESS_MS),
    10,
  );
}

// The workspace admin surface must never see credential_prefix or
// credential_hash; only these columns leave the service layer.
const AGENT_SAFE_SELECT_FIELDS = `
  id,
  workspace_id,
  agent_id,
  name,
  hostname,
  platform,
  agent_version,
  protocol_version,
  status,
  agent_kind,
  last_seen_at,
  clock_offset_ms,
  ntp_synced,
  pinned_signing_key_id,
  created_at,
  retired_at,
  retire_reason
`;

// Idempotent revocation guard for retireAgent below. Generates a fresh
// cryptographically random value in Node (not SQL): gen_random_bytes()
// needs the pgcrypto extension, which nothing in this schema's migrations
// installs, whereas Node's own crypto module has no such dependency and the
// value never needs to be derived from anything the database holds.
function randomCredentialRevocationHash() {
  return crypto.randomBytes(32).toString("hex");
}

function serviceError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function dateToIso(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function normalizeWorkspaceId(value) {
  const workspaceId = typeof value === "string" ? value.trim() : "";
  if (!workspaceId) {
    throw serviceError(
      "Workspace id is required",
      CERTOPS_AGENT_WORKSPACE_REQUIRED,
    );
  }
  return workspaceId;
}

// Same shape as workspaceKillSwitch.normalizeReason, but mandatory: the
// force-retire path requires an attributable justification.
function normalizeRequiredRetireReason(value) {
  if (typeof value !== "string") {
    throw serviceError(
      "reason must be a string",
      CERTOPS_AGENT_RETIRE_REASON_INVALID,
    );
  }
  const reason = value.trim();
  if (reason.length === 0) {
    throw serviceError(
      "reason is required",
      CERTOPS_AGENT_RETIRE_REASON_INVALID,
    );
  }
  if (reason.length > MAX_RETIRE_REASON_LENGTH) {
    throw serviceError(
      `reason must not exceed ${MAX_RETIRE_REASON_LENGTH} characters`,
      CERTOPS_AGENT_RETIRE_REASON_INVALID,
    );
  }
  if (/[\u0000-\u001F\u007F]/.test(reason)) {
    throw serviceError(
      "reason contains control characters",
      CERTOPS_AGENT_RETIRE_REASON_INVALID,
    );
  }
  // Retire reasons land in audit metadata; keep generic secrets out of it.
  return redactGenericSecrets(reason);
}

function parseSemverParts(value) {
  if (typeof value !== "string") return null;
  const match = /^(\d+)\.(\d+)\.(\d+)/.exec(value.trim());
  if (!match) return null;
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

function compareSemver(a, b) {
  const left = parseSemverParts(a);
  const right = parseSemverParts(b);
  if (!left || !right) return null;
  for (let i = 0; i < 3; i += 1) {
    if (left[i] < right[i]) return -1;
    if (left[i] > right[i]) return 1;
  }
  return 0;
}

function readCompatibilityConfig(env = process.env) {
  return {
    minProtocolVersion:
      env.CERTOPS_AGENT_MIN_PROTOCOL_VERSION || DEFAULT_MIN_PROTOCOL_VERSION,
    maxProtocolVersion:
      env.CERTOPS_AGENT_MAX_PROTOCOL_VERSION || DEFAULT_MAX_PROTOCOL_VERSION,
    minAgentVersion:
      env.CERTOPS_AGENT_MIN_AGENT_VERSION || DEFAULT_MIN_AGENT_VERSION,
    maxAgentVersion:
      env.CERTOPS_AGENT_MAX_AGENT_VERSION || DEFAULT_MAX_AGENT_VERSION,
    // Reference point for the "outdated" heuristic only; kept distinct from
    // maxAgentVersion's reject-ceiling (see comment on the constants above).
    latestKnownAgentVersion:
      env.CERTOPS_AGENT_LATEST_KNOWN_VERSION ||
      DEFAULT_LATEST_KNOWN_AGENT_VERSION ||
      env.CERTOPS_AGENT_MAX_AGENT_VERSION ||
      DEFAULT_MAX_AGENT_VERSION,
    clockDriftWarnMs: Number.parseInt(
      env.CERTOPS_AGENT_CLOCK_DRIFT_WARN_MS || String(DEFAULT_CLOCK_DRIFT_WARN_MS),
      10,
    ),
    clockDriftAlertMs: Number.parseInt(
      env.CERTOPS_AGENT_CLOCK_DRIFT_ALERT_MS ||
        String(DEFAULT_CLOCK_DRIFT_ALERT_MS),
      10,
    ),
    agentOfflineAfterMs: Number.parseInt(
      env.CERTOPS_AGENT_OFFLINE_AFTER_MS ||
        String(DEFAULT_AGENT_OFFLINE_AFTER_MS),
      10,
    ),
  };
}

/**
 * Compute fleet compatibility for an agent (H8).
 * @returns {{ compatibilityState: 'compatible'|'outdated'|'blocked', clockDriftState: 'ok'|'warn'|'alert'|null, clockDriftMs: number|null }}
 */
function computeAgentCompatibility(agent, env = process.env) {
  const config = readCompatibilityConfig(env);
  const protocolCmpMin = compareSemver(
    agent.protocolVersion,
    config.minProtocolVersion,
  );
  const protocolCmpMax = compareSemver(
    agent.protocolVersion,
    config.maxProtocolVersion,
  );
  const agentCmpMin = compareSemver(agent.agentVersion, config.minAgentVersion);
  const agentCmpMax = compareSemver(agent.agentVersion, config.maxAgentVersion);

  let compatibilityState = "compatible";
  if (
    protocolCmpMin === null ||
    protocolCmpMax === null ||
    agentCmpMin === null ||
    agentCmpMax === null ||
    protocolCmpMin < 0 ||
    protocolCmpMax > 0 ||
    agentCmpMin < 0 ||
    agentCmpMax > 0
  ) {
    compatibilityState = "blocked";
  } else {
    // Within supported bounds but more than one minor behind the latest
    // known agent build: surface as outdated so operators can plan upgrades.
    const agentParts = parseSemverParts(agent.agentVersion);
    const maxParts = parseSemverParts(config.latestKnownAgentVersion);
    if (
      agentParts &&
      maxParts &&
      (maxParts[0] > agentParts[0] ||
        (maxParts[0] === agentParts[0] && maxParts[1] > agentParts[1] + 1))
    ) {
      compatibilityState = "outdated";
    }
  }

  const clockDriftMs =
    agent.clockOffsetMs === null || agent.clockOffsetMs === undefined
      ? null
      : Math.abs(Number(agent.clockOffsetMs));
  let clockDriftState = null;
  if (clockDriftMs !== null && Number.isFinite(clockDriftMs)) {
    if (clockDriftMs >= config.clockDriftAlertMs) clockDriftState = "alert";
    else if (clockDriftMs >= config.clockDriftWarnMs) clockDriftState = "warn";
    else clockDriftState = "ok";
  }

  // Mirrors sweepStaleAgents' own COALESCE(last_seen_at, created_at) check
  // (apps/worker/src/certops-worker.js) so an agent that registered but
  // never heartbeated, or stopped heartbeating, is flagged 'stale' here in
  // real time rather than waiting for the next periodic sweep to persist
  // status='offline'. Retired agents are never stale; they are terminal.
  let livenessState = null;
  if (agent.status === "retired") {
    livenessState = "retired";
  } else {
    const referenceAt = agent.lastSeenAt || agent.createdAt;
    const referenceMs = referenceAt ? new Date(referenceAt).getTime() : NaN;
    if (Number.isFinite(referenceMs)) {
      livenessState =
        Date.now() - referenceMs >= config.agentOfflineAfterMs
          ? "stale"
          : "live";
    }
  }

  return {
    compatibilityState,
    clockDriftState,
    clockDriftMs,
    livenessState,
    compatibilityConfig: {
      minProtocolVersion: config.minProtocolVersion,
      maxProtocolVersion: config.maxProtocolVersion,
      minAgentVersion: config.minAgentVersion,
      maxAgentVersion: config.maxAgentVersion,
      latestKnownAgentVersion: config.latestKnownAgentVersion,
      clockDriftWarnMs: config.clockDriftWarnMs,
      clockDriftAlertMs: config.clockDriftAlertMs,
      agentOfflineAfterMs: config.agentOfflineAfterMs,
    },
  };
}

function agentMetadataFromRow(row, env = process.env) {
  if (!row) return null;
  const base = {
    id: row.id,
    agentId: row.agent_id,
    name: row.name ?? null,
    hostname: row.hostname ?? null,
    platform: row.platform ?? null,
    agentVersion: row.agent_version,
    protocolVersion: row.protocol_version,
    status: row.status,
    agentKind: row.agent_kind === AGENT_KIND_DIAGNOSTIC
      ? AGENT_KIND_DIAGNOSTIC
      : AGENT_KIND_NORMAL,
    lastSeenAt: dateToIso(row.last_seen_at),
    clockOffsetMs: row.clock_offset_ms === null ? null : Number(row.clock_offset_ms),
    ntpSynced: typeof row.ntp_synced === "boolean" ? row.ntp_synced : null,
    pinnedSigningKeyId: row.pinned_signing_key_id ?? null,
    createdAt: dateToIso(row.created_at),
    retiredAt: dateToIso(row.retired_at),
    retireReason: row.retire_reason ?? null,
  };
  const compatibility = computeAgentCompatibility(base, env);
  return {
    ...base,
    compatibilityState: compatibility.compatibilityState,
    clockDriftState: compatibility.clockDriftState,
    clockDriftMs: compatibility.clockDriftMs,
    livenessState: compatibility.livenessState,
  };
}

// Pagination here is opt-in. The agent fleet list is unbounded today and the
// dashboard has no page control for it, so an omitted limit must keep returning
// every row: a silent default page would truncate a fleet audit with nothing on
// screen to say so. The default is switched on with the control that reveals it.
function normalizeOptionalLimit(value) {
  if (value === undefined || value === null || value === "") return null;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return null;
  return Math.max(1, Math.min(100, parsed));
}

function normalizeOffset(value) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return 0;
  return Math.max(0, parsed);
}

async function listAgents(options) {
  const db = options.client || pool;
  const workspaceId = normalizeWorkspaceId(options.workspaceId);
  const limit = normalizeOptionalLimit(options.limit);
  const offset = normalizeOffset(options.offset);
  const params = [workspaceId];
  let pageClause = "";
  if (limit !== null) {
    params.push(limit, offset);
    pageClause = `
      LIMIT $${params.length - 1} OFFSET $${params.length}`;
  } else if (offset > 0) {
    params.push(offset);
    pageClause = `
      OFFSET $${params.length}`;
  }

  const totalResult = await db.query(
    `SELECT COUNT(*)::int AS total
       FROM certops_agents
      WHERE workspace_id = $1`,
    [workspaceId],
  );
  const result = await db.query(
    `SELECT ${AGENT_SAFE_SELECT_FIELDS}
       FROM certops_agents
      WHERE workspace_id = $1
      ORDER BY created_at DESC, id ASC${pageClause}`,
    params,
  );

  return {
    items: result.rows.map((row) => agentMetadataFromRow(row, options.env)),
    pagination: {
      limit,
      offset,
      total: Number(totalResult.rows[0]?.total || 0),
    },
  };
}

async function getAgentById(options) {
  const result = await (options.client || pool).query(
    `SELECT ${AGENT_SAFE_SELECT_FIELDS}
       FROM certops_agents
      WHERE workspace_id = $1
        AND id = $2
      LIMIT 1`,
    [normalizeWorkspaceId(options.workspaceId), options.agentId],
  );
  return agentMetadataFromRow(result.rows[0] || null, options.env);
}

// Leased jobs actively claimed by this agent block a non-forced retire.
// The lease reaper worker, not this service, handles lease expiry.
async function countActivelyLeasedJobs(options) {
  const result = await (options.client || pool).query(
    `SELECT COUNT(*)::int AS leased_jobs
       FROM certificate_jobs
      WHERE claimed_by_agent_id = $1
        AND status IN ('claimed', 'running')
        AND lease_expires_at > NOW()`,
    [options.agentId],
  );
  return result.rows[0] ? Number(result.rows[0].leased_jobs) : 0;
}

/**
 * H12: fence in-flight work for a force-retired agent.
 * - claimed (no execution start evidence): cancel cleanly
 * - running: orphaned_unknown_effect + needs_operator_reconciliation
 *
 * Forced retirement is a terminal-failure path like any other, so it owes the
 * same alert. It did not pay it: the two UPDATEs below ended renewals with no
 * outbox intent, so retiring an agent that held a renewal lease produced a
 * failed renewal that emailed nobody, which is indistinguishable from no
 * renewal having failed. `TRANSITION_ORIGINS.FORCED_RETIREMENT` and its policy
 * test already existed, so only the call was missing.
 *
 * The intent is enqueued on the caller's client so it commits with the status
 * change; `enqueueOutboxEvent` refuses a non-transactional caller outright,
 * which is why the retire route wraps this in `withCertOpsTransaction`. The
 * dedupe key is the job id, matching the agent-result and lease-reaper paths, so
 * a job already alerted for cannot be alerted for twice by a different origin.
 */
async function fenceAgentInFlightWork(options) {
  const db = options.client || pool;
  const reason =
    options.reason ||
    "Agent force-retired while holding an active lease; operator reconciliation required";

  const cancelled = await db.query(
    `UPDATE certificate_jobs
        SET status = 'cancelled',
            lease_expires_at = NOW(),
            error_code = 'CERTOPS_AGENT_FORCE_RETIRED',
            error_message = $2,
            completed_at = COALESCE(completed_at, NOW()),
            canceled_at = COALESCE(canceled_at, NOW()),
            updated_at = NOW()
      WHERE claimed_by_agent_id = $1
        AND status = 'claimed'
        AND lease_expires_at > NOW()
      RETURNING id, workspace_id, operation, subject_type, subject_id`,
    [options.agentId, reason],
  );

  const orphaned = await db.query(
    `UPDATE certificate_jobs
        SET status = 'orphaned_unknown_effect',
            needs_operator_reconciliation = TRUE,
            reconciliation_reason = $2,
            lease_expires_at = NOW(),
            error_code = 'CERTOPS_AGENT_FORCE_RETIRED_UNKNOWN_EFFECT',
            error_message = $2,
            completed_at = COALESCE(completed_at, NOW()),
            updated_at = NOW()
      WHERE claimed_by_agent_id = $1
        AND status = 'running'
        AND lease_expires_at > NOW()
      RETURNING id, workspace_id, operation, subject_type, subject_id`,
    [options.agentId, reason],
  );

  const fencedGroups = [
    { rows: cancelled.rows, status: "cancelled", errorCode: FORCE_RETIRED_CODE },
    {
      rows: orphaned.rows,
      status: "orphaned_unknown_effect",
      errorCode: FORCE_RETIRED_UNKNOWN_EFFECT_CODE,
    },
  ];
  for (const group of fencedGroups) {
    for (const row of group.rows) {
      const classification = classifyTerminalTransition({
        operation: row.operation,
        status: group.status,
        origin: TRANSITION_ORIGINS.FORCED_RETIREMENT,
      });
      if (!classification.alertWorthy) continue;
      await enqueueOutboxEvent({
        client: db,
        workspaceId: row.workspace_id,
        eventType: OUTBOX_EVENT_TYPES.RENEWAL_ALERT_REQUESTED,
        dedupeKey: String(row.id),
        payload: {
          jobId: String(row.id),
          operation: row.operation,
          jobStatus: group.status,
          origin: TRANSITION_ORIGINS.FORCED_RETIREMENT,
          classificationReason: classification.reason,
          priority: classification.priority || null,
          errorCode: group.errorCode,
          subjectType: row.subject_type || null,
          subjectId: row.subject_id ? String(row.subject_id) : null,
        },
      });
    }
  }

  return {
    cancelledJobIds: cancelled.rows.map((row) => row.id),
    orphanedJobIds: orphaned.rows.map((row) => row.id),
  };
}

// Retire is idempotent: an already-retired agent is returned as-is with
// retiredNow=false so the route can skip duplicate audit writes.
async function retireAgent(options) {
  const db = options.client || pool;
  const workspaceId = normalizeWorkspaceId(options.workspaceId);
  const force = options.force === true;

  let fenced = { cancelledJobIds: [], orphanedJobIds: [] };
  if (force) {
    fenced = await fenceAgentInFlightWork({
      client: db,
      agentId: options.agentId,
      reason: options.reason || null,
    });
  }

  const result = await db.query(
    `UPDATE certops_agents
        SET status = 'retired',
            retired_at = NOW(),
            retired_by_user_id = $3,
            retire_reason = $4,
            -- ADR-0012 decision 7: a retired diagnostic agent must fail at
            -- authentication, not merely at authorization on individual
            -- routes afterward - unlike the frozen-retired rule that
            -- deliberately still lets a retired *normal* agent authenticate
            -- so the route layer can answer 410 (see agent-auth.js).
            -- credential_hash is NOT NULL + unique, so revocation overwrites
            -- it with a fresh cryptographically random value rather than
            -- NULL: validateAgentCredential's timingSafeEqual comparison
            -- against a candidate hash derived from the agent's real
            -- (unrecoverable, sha256-hashed-at-source) plaintext credential
            -- can then never match. Both the status flip and the hash
            -- overwrite are written by this one UPDATE, so there is no row
            -- state, and no window, where status already reads 'retired'
            -- but credential_hash still matches the live credential.
            credential_hash = CASE
              WHEN agent_kind = 'diagnostic' THEN $5
              ELSE credential_hash
            END,
            updated_at = NOW()
      WHERE workspace_id = $1
        AND id = $2
        AND status <> 'retired'
      RETURNING ${AGENT_SAFE_SELECT_FIELDS}`,
    [
      workspaceId,
      options.agentId,
      options.retiredBy || null,
      options.reason || null,
      randomCredentialRevocationHash(),
    ],
  );

  if (result.rows[0]) {
    return {
      agent: agentMetadataFromRow(result.rows[0], options.env),
      retiredNow: true,
      fenced,
    };
  }

  const existing = await getAgentById({
    client: db,
    workspaceId,
    agentId: options.agentId,
    env: options.env,
  });
  return { agent: existing, retiredNow: false, fenced };
}

// ADR-0012 decision 7's four orphan-retirement branches, keyed on the
// diagnostic agent's single protocol_smoke job. A lost registration
// response, or an operator who ran the reference client once and never
// heartbeated again, must not leave a permanently-active fleet row; but a
// job that is genuinely mid-execution must not be yanked out from under a
// live claim either. Exactly one of these four is safe to act on for any
// given (agent, job) pair at the moment this function is called:
//   pending_unclaimed  - nothing was ever leased: cancel the job and retire
//                        the agent atomically, no claim to race.
//   active_unexpired   - a client may be executing right now: defer.
//   active_expired     - the lease reaper's terminalization, inlined here
//                        instead of waited-for, then retire the agent.
//   terminal           - the job already reached a terminal status (or the
//                        transaction that would have created one never
//                        happened): retire the agent normally.
const DIAGNOSTIC_ORPHAN_BRANCH = Object.freeze({
  PENDING_UNCLAIMED: "pending_unclaimed",
  ACTIVE_UNEXPIRED: "active_unexpired",
  ACTIVE_EXPIRED: "active_expired",
  TERMINAL: "terminal",
});

const DIAGNOSTIC_AGENT_RETIRED_JOB_ERROR_CODE = "CERTOPS_DIAGNOSTIC_AGENT_RETIRED";

function classifyDiagnosticOrphanBranch(job) {
  if (!job) return DIAGNOSTIC_ORPHAN_BRANCH.TERMINAL;
  if (job.status === "pending") {
    return DIAGNOSTIC_ORPHAN_BRANCH.PENDING_UNCLAIMED;
  }
  if (job.status === "claimed" || job.status === "running") {
    const leaseExpiresAt = job.lease_expires_at ? new Date(job.lease_expires_at) : null;
    const leaseExpired = !leaseExpiresAt || leaseExpiresAt.getTime() <= Date.now();
    return leaseExpired
      ? DIAGNOSTIC_ORPHAN_BRANCH.ACTIVE_EXPIRED
      : DIAGNOSTIC_ORPHAN_BRANCH.ACTIVE_UNEXPIRED;
  }
  return DIAGNOSTIC_ORPHAN_BRANCH.TERMINAL;
}

// Finds the one protocol_smoke job this diagnostic agent's bootstrap created.
// FOR UPDATE so a concurrent claim (agentDispatch.js claimJobs) and this
// reconciliation can never both believe they hold the deciding vote on the
// same job row.
async function loadAssignedProtocolSmokeJobForUpdate(db, workspaceId, agentId) {
  const result = await db.query(
    `SELECT id, status, lease_expires_at
       FROM certificate_jobs
      WHERE workspace_id = $1
        AND assigned_agent_id = $2
        AND operation = 'protocol_smoke'
      ORDER BY created_at DESC
      LIMIT 1
      FOR UPDATE`,
    [workspaceId, agentId],
  );
  return result.rows[0] || null;
}

/**
 * Reconciles exactly one diagnostic agent against the four-branch state
 * machine above, then retires it unless the branch is active_unexpired.
 * Callers (the inactivity sweep, or a test) are expected to have already
 * decided *that* this agent is a retirement candidate (e.g. past the 24-hour
 * inactivity TTL); this function only decides *how* to retire it safely.
 *
 * Runs inside options.client's transaction when provided; the inactivity
 * sweep runs it inside its own per-agent transaction so one agent's
 * reconciliation can never block or partially apply another's.
 */
async function reconcileDiagnosticAgentOrphan(options) {
  const db = options.client || pool;
  const workspaceId = normalizeWorkspaceId(options.workspaceId);

  const agentResult = await db.query(
    `SELECT id, agent_kind, status
       FROM certops_agents
      WHERE workspace_id = $1
        AND id = $2
      FOR UPDATE`,
    [workspaceId, options.agentId],
  );
  const agentRow = agentResult.rows[0];
  if (!agentRow) return { notFound: true };
  if (agentRow.agent_kind !== AGENT_KIND_DIAGNOSTIC) {
    return { notApplicable: true, reason: "agent_kind is not diagnostic" };
  }
  if (agentRow.status === "retired") {
    return { alreadyRetired: true };
  }

  const job = await loadAssignedProtocolSmokeJobForUpdate(
    db,
    workspaceId,
    options.agentId,
  );
  const branch = classifyDiagnosticOrphanBranch(job);

  if (branch === DIAGNOSTIC_ORPHAN_BRANCH.ACTIVE_UNEXPIRED) {
    return { deferred: true, branch, jobId: job ? job.id : null };
  }

  const reason =
    options.reason ||
    "Diagnostic agent retired by the inactivity sweep (ADR-0012 decision 7)";

  if (branch === DIAGNOSTIC_ORPHAN_BRANCH.PENDING_UNCLAIMED) {
    // Nothing was ever leased, so there is no in-flight claim to race:
    // cancel-and-retire is safe to do unconditionally in this transaction.
    await db.query(
      `UPDATE certificate_jobs
          SET status = 'cancelled',
              lease_expires_at = NOW(),
              error_code = $2,
              error_message = $3,
              completed_at = COALESCE(completed_at, NOW()),
              canceled_at = COALESCE(canceled_at, NOW()),
              updated_at = NOW()
        WHERE id = $1`,
      [job.id, DIAGNOSTIC_AGENT_RETIRED_JOB_ERROR_CODE, reason],
    );
  } else if (branch === DIAGNOSTIC_ORPHAN_BRANCH.ACTIVE_EXPIRED) {
    // Same terminalization the lease reaper applies to any expired lease
    // (claimed -> cancelled, running -> orphaned_unknown_effect), inlined
    // here rather than waited-for so retirement is not blocked on the next
    // reaper pass. protocol_smoke is excluded from renewal alerting
    // (RENEWAL_ALERTING_OPERATIONS), so no outbox alert is owed here.
    const terminalStatus =
      job.status === "running" ? "orphaned_unknown_effect" : "cancelled";
    await db.query(
      `UPDATE certificate_jobs
          SET status = $2,
              needs_operator_reconciliation = ($2 = 'orphaned_unknown_effect'),
              reconciliation_reason = CASE WHEN $2 = 'orphaned_unknown_effect' THEN $3 ELSE NULL END,
              lease_expires_at = NOW(),
              error_code = $4,
              error_message = $3,
              completed_at = COALESCE(completed_at, NOW()),
              canceled_at = CASE WHEN $2 = 'cancelled' THEN COALESCE(canceled_at, NOW()) ELSE canceled_at END,
              updated_at = NOW()
        WHERE id = $1`,
      [
        job.id,
        terminalStatus,
        reason,
        terminalStatus === "orphaned_unknown_effect"
          ? "CERTOPS_DIAGNOSTIC_AGENT_RETIRED_UNKNOWN_EFFECT"
          : DIAGNOSTIC_AGENT_RETIRED_JOB_ERROR_CODE,
      ],
    );
  }
  // TERMINAL: the job (if any) is already in a terminal status; nothing to
  // do to it before retiring the agent.

  const retireResult = await retireAgent({
    client: db,
    workspaceId,
    agentId: options.agentId,
    retiredBy: options.retiredBy ?? null,
    reason,
  });

  return {
    retired: true,
    branch,
    jobId: job ? job.id : null,
    agent: retireResult.agent,
  };
}

/**
 * The 24-hour inactivity sweep itself: finds every non-retired diagnostic
 * agent whose last_seen_at is older than the TTL and reconciles each one in
 * its own transaction via reconcileDiagnosticAgentOrphan. A freshly
 * registered diagnostic agent that has never heartbeated has last_seen_at
 * set at INSERT time (see diagnosticBootstrap.js), so it is timed from
 * registration, not left permanently exempt for lack of a heartbeat.
 */
async function sweepInactiveDiagnosticAgents(options = {}) {
  const dbPool = options.dbPool || pool;
  const ttlMs = diagnosticAgentInactivityTtlMs(options.env);
  const batchSize = Number.isSafeInteger(options.batchSize) && options.batchSize > 0
    ? options.batchSize
    : 200;

  const candidates = await dbPool.query(
    `SELECT id, workspace_id
       FROM certops_agents
      WHERE agent_kind = 'diagnostic'
        AND status <> 'retired'
        AND last_seen_at < NOW() - make_interval(secs => $1)
      ORDER BY last_seen_at ASC
      LIMIT $2`,
    [Math.floor(ttlMs / 1000), batchSize],
  );

  const results = [];
  for (const row of candidates.rows) {
    const client = await dbPool.connect();
    try {
      await client.query("BEGIN");
      const outcome = await reconcileDiagnosticAgentOrphan({
        client,
        workspaceId: row.workspace_id,
        agentId: row.id,
        reason:
          "Diagnostic agent exceeded its 24-hour inactivity TTL (ADR-0012 decision 7)",
      });
      await client.query("COMMIT");
      results.push({ agentId: row.id, workspaceId: row.workspace_id, ...outcome });
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch (_rollbackError) {
        // The original error is more useful to the caller.
      }
      results.push({
        agentId: row.id,
        workspaceId: row.workspace_id,
        error: error.message,
      });
    } finally {
      client.release();
    }
  }
  return results;
}

module.exports = {
  AGENT_KIND_DIAGNOSTIC,
  AGENT_KIND_NORMAL,
  AGENT_KINDS,
  CERTOPS_AGENT_INVALID,
  CERTOPS_AGENT_NOT_FOUND,
  CERTOPS_AGENT_RETIRE_REASON_INVALID,
  CERTOPS_AGENT_WORKSPACE_REQUIRED,
  DEFAULT_CERTOPS_CAPABILITY_FRESHNESS_MS,
  DEFAULT_DIAGNOSTIC_AGENT_INACTIVITY_TTL_MS,
  DIAGNOSTIC_ORPHAN_BRANCH,
  certopsCapabilityFreshnessMs,
  computeAgentCompatibility,
  countActivelyLeasedJobs,
  diagnosticAgentInactivityTtlMs,
  fenceAgentInFlightWork,
  getAgentById,
  listAgents,
  normalizeRequiredRetireReason,
  readCompatibilityConfig,
  reconcileDiagnosticAgentOrphan,
  retireAgent,
  sweepInactiveDiagnosticAgents,
};

module.exports._test = {
  agentMetadataFromRow,
  classifyDiagnosticOrphanBranch,
  compareSemver,
  computeAgentCompatibility,
  normalizeRequiredRetireReason,
  parseSemverParts,
  readCompatibilityConfig,
};

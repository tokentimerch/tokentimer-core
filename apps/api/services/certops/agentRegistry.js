"use strict";

const { pool } = require("../../db/database");
const { redactGenericSecrets } = require("../../utils/secretMaterial");

const CERTOPS_AGENT_NOT_FOUND = "CERTOPS_AGENT_NOT_FOUND";
const CERTOPS_AGENT_INVALID = "CERTOPS_AGENT_INVALID";
const CERTOPS_AGENT_RETIRE_REASON_INVALID =
  "CERTOPS_AGENT_RETIRE_REASON_INVALID";
const CERTOPS_AGENT_WORKSPACE_REQUIRED = "CERTOPS_AGENT_WORKSPACE_REQUIRED";

const MAX_RETIRE_REASON_LENGTH = 500;

// H8: config-driven protocol/agent compatibility and clock-drift thresholds.
const DEFAULT_MIN_PROTOCOL_VERSION = "1.0.0";
const DEFAULT_MAX_PROTOCOL_VERSION = "1.999.999";
const DEFAULT_MIN_AGENT_VERSION = "0.1.0";
const DEFAULT_MAX_AGENT_VERSION = "99.999.999";
const DEFAULT_CLOCK_DRIFT_WARN_MS = 5_000;
const DEFAULT_CLOCK_DRIFT_ALERT_MS = 30_000;

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
  last_seen_at,
  clock_offset_ms,
  ntp_synced,
  pinned_signing_key_id,
  created_at,
  retired_at,
  retire_reason
`;

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
    clockDriftWarnMs: Number.parseInt(
      env.CERTOPS_AGENT_CLOCK_DRIFT_WARN_MS || String(DEFAULT_CLOCK_DRIFT_WARN_MS),
      10,
    ),
    clockDriftAlertMs: Number.parseInt(
      env.CERTOPS_AGENT_CLOCK_DRIFT_ALERT_MS ||
        String(DEFAULT_CLOCK_DRIFT_ALERT_MS),
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
    // Within supported bounds but more than one minor behind the configured
    // maximum: surface as outdated so operators can plan upgrades.
    const agentParts = parseSemverParts(agent.agentVersion);
    const maxParts = parseSemverParts(config.maxAgentVersion);
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

  return {
    compatibilityState,
    clockDriftState,
    clockDriftMs,
    compatibilityConfig: {
      minProtocolVersion: config.minProtocolVersion,
      maxProtocolVersion: config.maxProtocolVersion,
      minAgentVersion: config.minAgentVersion,
      maxAgentVersion: config.maxAgentVersion,
      clockDriftWarnMs: config.clockDriftWarnMs,
      clockDriftAlertMs: config.clockDriftAlertMs,
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
  };
}

async function listAgents(options) {
  const result = await (options.client || pool).query(
    `SELECT ${AGENT_SAFE_SELECT_FIELDS}
       FROM certops_agents
      WHERE workspace_id = $1
      ORDER BY created_at DESC, id ASC`,
    [normalizeWorkspaceId(options.workspaceId)],
  );
  return result.rows.map((row) => agentMetadataFromRow(row, options.env));
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
      RETURNING id`,
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
      RETURNING id`,
    [options.agentId, reason],
  );

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

module.exports = {
  CERTOPS_AGENT_INVALID,
  CERTOPS_AGENT_NOT_FOUND,
  CERTOPS_AGENT_RETIRE_REASON_INVALID,
  CERTOPS_AGENT_WORKSPACE_REQUIRED,
  computeAgentCompatibility,
  countActivelyLeasedJobs,
  fenceAgentInFlightWork,
  getAgentById,
  listAgents,
  normalizeRequiredRetireReason,
  readCompatibilityConfig,
  retireAgent,
};

module.exports._test = {
  agentMetadataFromRow,
  compareSemver,
  computeAgentCompatibility,
  normalizeRequiredRetireReason,
  parseSemverParts,
  readCompatibilityConfig,
};

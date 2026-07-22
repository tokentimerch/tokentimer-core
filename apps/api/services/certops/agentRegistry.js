"use strict";

const { pool } = require("../../db/database");
const { redactGenericSecrets } = require("../../utils/secretMaterial");

const CERTOPS_AGENT_NOT_FOUND = "CERTOPS_AGENT_NOT_FOUND";
const CERTOPS_AGENT_INVALID = "CERTOPS_AGENT_INVALID";
const CERTOPS_AGENT_RETIRE_REASON_INVALID =
  "CERTOPS_AGENT_RETIRE_REASON_INVALID";
const CERTOPS_AGENT_WORKSPACE_REQUIRED = "CERTOPS_AGENT_WORKSPACE_REQUIRED";

const MAX_RETIRE_REASON_LENGTH = 500;

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

function agentMetadataFromRow(row) {
  if (!row) return null;
  return {
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
    createdAt: dateToIso(row.created_at),
    retiredAt: dateToIso(row.retired_at),
    retireReason: row.retire_reason ?? null,
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
  return result.rows.map(agentMetadataFromRow);
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
  return agentMetadataFromRow(result.rows[0] || null);
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

// Retire is idempotent: an already-retired agent is returned as-is with
// retiredNow=false so the route can skip duplicate audit writes.
async function retireAgent(options) {
  const db = options.client || pool;
  const workspaceId = normalizeWorkspaceId(options.workspaceId);
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
    return { agent: agentMetadataFromRow(result.rows[0]), retiredNow: true };
  }

  const existing = await getAgentById({
    client: db,
    workspaceId,
    agentId: options.agentId,
  });
  return { agent: existing, retiredNow: false };
}

module.exports = {
  CERTOPS_AGENT_INVALID,
  CERTOPS_AGENT_NOT_FOUND,
  CERTOPS_AGENT_RETIRE_REASON_INVALID,
  CERTOPS_AGENT_WORKSPACE_REQUIRED,
  countActivelyLeasedJobs,
  getAgentById,
  listAgents,
  normalizeRequiredRetireReason,
  retireAgent,
};

module.exports._test = {
  agentMetadataFromRow,
  normalizeRequiredRetireReason,
};

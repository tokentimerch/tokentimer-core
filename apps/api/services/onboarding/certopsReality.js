"use strict";

// CertOps part of the verified onboarding summary. Reads the same agent
// metadata the fleet panel shows so the wizard and the Agents page cannot
// disagree. Returns null when the caller cannot see it or CertOps is off, and
// callers must treat null as "unknown", never as "nothing installed".

const { listAgents } = require("../certops/agentRegistry");

// Operations that only exist once execution is switched on in the agent.
const EXECUTION_OPERATIONS = new Set([
  "issue",
  "renew",
  "deploy",
  "reload",
  "revoke",
]);

function summarizeAgents(items, { now = Date.now(), since = null } = {}) {
  const agents = (items || []).filter(
    (a) => a.status !== "retired" && a.agentKind !== "diagnostic",
  );
  const sinceMs = since ? new Date(since).getTime() : null;
  const live = agents.filter((a) => a.livenessState === "live");
  const recent =
    sinceMs === null
      ? []
      : agents.filter((a) => new Date(a.createdAt).getTime() >= sinceMs);
  return {
    total: agents.length,
    live: live.length,
    registeredSinceToken: recent.length,
    executionEnabled: live.some((a) =>
      (a.supportedOperations || []).some((op) => EXECUTION_OPERATIONS.has(op)),
    ),
    items: agents.slice(0, 10).map((a) => ({
      id: a.id,
      wireAgentId: a.agentId,
      name: a.name,
      hostname: a.hostname,
      platform: a.platform,
      agentVersion: a.agentVersion,
      livenessState: a.livenessState,
      lastSeenAt: a.lastSeenAt,
      compatibilityState: a.compatibilityState,
      clockDriftState: a.clockDriftState,
      ntpSynced: a.ntpSynced,
      declaredCapabilities: a.declaredCapabilities || [],
      supportedOperations: a.supportedOperations || [],
      targetSelectors: a.targetSelectors || [],
      commandProfiles: a.commandProfiles || [],
    })),
    nowIso: new Date(now).toISOString(),
  };
}

/**
 * Distribution is verified only when a rollout reached the verified state,
 * which requires consumer evidence. Existing groups alone prove nothing.
 */
async function loadDistributionReality(pool, workspaceId) {
  const { rows } = await pool.query(
    `SELECT (SELECT COUNT(*)::int FROM certops_distribution_groups WHERE workspace_id = $1) AS groups,
            (SELECT COUNT(*)::int FROM certops_consumer_bindings WHERE workspace_id = $1) AS bindings,
            (SELECT COUNT(*)::int FROM certops_distribution_rollouts
              WHERE workspace_id = $1 AND state = 'verified' AND verification_only = false) AS verified_rollouts`,
    [workspaceId],
  );
  const row = rows[0] || {};
  return {
    groups: row.groups || 0,
    bindings: row.bindings || 0,
    verified: (row.verified_rollouts || 0) > 0,
  };
}

/**
 * Status of a job the wizard created, scoped to this workspace. Reading it
 * from the database means a dry run only counts when it really ended as
 * dry_run_complete.
 */
async function loadJobStatus(pool, workspaceId, jobId) {
  if (typeof jobId !== "string" || !/^[0-9a-f-]{36}$/i.test(jobId)) return null;
  const { rows } = await pool.query(
    `SELECT id, operation, status FROM certificate_jobs WHERE workspace_id = $1 AND id = $2`,
    [workspaceId, jobId],
  );
  return rows[0] ? { id: rows[0].id, operation: rows[0].operation, status: rows[0].status } : null;
}

async function loadCertopsReality(pool, { workspaceId, role, enabled, since, dryRunJobId }) {
  if (enabled !== true) return null;
  if (role !== "admin" && role !== "workspace_manager") return null;
  const agents = await listAgents({ workspaceId, client: pool });
  const certs = await pool.query(
    `SELECT COUNT(*)::int AS total,
            COUNT(*) FILTER (WHERE status = 'active')::int AS active
       FROM managed_certificates
      WHERE workspace_id = $1 AND status NOT IN ('decommissioned')`,
    [workspaceId],
  );
  const distribution = await loadDistributionReality(pool, workspaceId);
  const dryRun = await loadJobStatus(pool, workspaceId, dryRunJobId);
  return {
    agents: summarizeAgents(agents.items, { since }),
    distribution,
    dryRun,
    certificates: {
      total: certs.rows[0]?.total || 0,
      active: certs.rows[0]?.active || 0,
    },
  };
}

module.exports = {
  summarizeAgents,
  loadCertopsReality,
  loadDistributionReality,
  loadJobStatus,
  EXECUTION_OPERATIONS,
};

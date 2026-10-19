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
    `SELECT j.id, j.operation, j.status, j.mode, j.error_code, j.error_message,
            mc.status AS certificate_status
       FROM certificate_jobs j
       LEFT JOIN managed_certificates mc
         ON j.subject_type = 'managed_certificate' AND mc.id::text = j.subject_id
      WHERE j.workspace_id = $1 AND j.id = $2`,
    [workspaceId, jobId],
  );
  const row = rows[0];
  if (!row) return null;
  return {
    id: row.id,
    operation: row.operation,
    status: row.status,
    mode: row.mode,
    errorCode: row.error_code || null,
    // Shown in the wizard, so bounded; the full text stays in the job log.
    errorMessage: row.error_message ? String(row.error_message).slice(0, 300) : null,
    certificateStatus: row.certificate_status || null,
  };
}

/**
 * AD CS issuers and profiles, by name and state only. An issuer counts as
 * confirmed once its current version has a pinned CA certificate, and as safe
 * once the last check found both the template and the CA safe.
 */
async function loadAdcsReality(pool, workspaceId) {
  const issuers = await pool.query(
    `SELECT i.id, i.name, i.last_preflight,
            (v.confirmed_at IS NOT NULL AND v.ca_key_sha256 IS NOT NULL) AS confirmed
       FROM certificate_issuers i
       LEFT JOIN certificate_issuer_versions v
         ON v.issuer_id = i.id AND v.version = i.current_version
      WHERE i.workspace_id = $1 AND i.kind = 'adcs'
      ORDER BY i.created_at DESC
      LIMIT 20`,
    [workspaceId],
  );
  const profiles = await pool.query(
    `SELECT COUNT(*)::int AS n
       FROM certificate_profiles p
       JOIN certificate_issuers i ON i.id = p.issuer_id
      WHERE p.workspace_id = $1 AND i.kind = 'adcs'`,
    [workspaceId],
  );
  return {
    issuers: issuers.rows.map((row) => ({
      id: row.id,
      name: row.name,
      confirmed: row.confirmed === true,
      safe:
        row.last_preflight?.templateCheck?.verdict === "safe" &&
        row.last_preflight?.caCheck?.verdict === "safe",
    })),
    profiles: profiles.rows[0]?.n || 0,
  };
}

async function loadCertopsReality(
  pool,
  { workspaceId, role, enabled, since, dryRunJobId, issueJobId },
) {
  if (enabled !== true) return null;
  if (role !== "admin" && role !== "workspace_manager") return null;
  const agents = await listAgents({ workspaceId, client: pool });
  // A row in "provisioning" only means an order was requested. It becomes an
  // observed certificate once it holds real material.
  const certs = await pool.query(
    `SELECT COUNT(*)::int AS total,
            COUNT(*) FILTER (WHERE status = 'active')::int AS active,
            COUNT(*) FILTER (
              WHERE status IN ('discovered', 'active', 'renewing', 'expiring', 'expired')
            )::int AS observed
       FROM managed_certificates
      WHERE workspace_id = $1 AND status NOT IN ('decommissioned')`,
    [workspaceId],
  );
  const distribution = await loadDistributionReality(pool, workspaceId);
  const dryRun = await loadJobStatus(pool, workspaceId, dryRunJobId);
  const issueJob = await loadJobStatus(pool, workspaceId, issueJobId);
  const adcs = await loadAdcsReality(pool, workspaceId);
  return {
    adcs,
    agents: summarizeAgents(agents.items, { since }),
    distribution,
    dryRun,
    issueJob,
    certificates: {
      total: certs.rows[0]?.total || 0,
      active: certs.rows[0]?.active || 0,
      observed: certs.rows[0]?.observed || 0,
    },
  };
}

module.exports = {
  summarizeAgents,
  loadCertopsReality,
  loadAdcsReality,
  loadDistributionReality,
  loadJobStatus,
  EXECUTION_OPERATIONS,
};

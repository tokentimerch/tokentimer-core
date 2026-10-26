"use strict";

const { consumerMatrix, normalizeDistributionId } = require("./materialDistribution");

function parseIds(value) {
  if (value === undefined) return [];
  if (typeof value !== "string" || !value || value.split(",").length > 200) {
    const error = new Error("Expected up to 200 comma-separated certificate IDs");
    error.statusCode = 422;
    throw error;
  }
  return [...new Set(value.split(",").map(normalizeDistributionId))];
}

// Convergence comes exclusively from consumerMatrix, never from job success.
function consumerStatus(row) {
  if (row.binding_state !== "active") return "inactive";
  if (row.latest_deployment?.stage === "orphaned_unknown_effect") return "uncertain";
  if (row.latest_deployment?.stage === "failed") return "failed";
  if (row.converged === true) return row.verification_policy === "installed" ? "installed" : "verified";
  if (row.stale === true) return "stale";
  if (!row.desired_material_version_id) return "not_deployed";
  return "pending";
}

function summarizeConsumers(rows, active = true) {
  const counts = { total: 0, verified: 0, installed: 0, failed: 0, uncertain: 0, stale: 0, pending: 0, not_deployed: 0 };
  const expirations = [];
  const installations = [];
  for (const row of rows) {
    const status = consumerStatus(row);
    if (status === "inactive") continue;
    counts.total++;
    counts[status]++;
    if (status === "verified" || status === "installed") {
      const freshness = new Date(row.observed_at).getTime() + Number(row.freshness_seconds) * 1000;
      const expiry = new Date(row.observed_valid_to).getTime();
      if (Number.isFinite(freshness) && Number.isFinite(expiry)) (status === "installed" ? installations : expirations).push(Math.min(freshness, expiry));
    }
  }
  if (!active) return { ...counts, verified: 0, installed: 0, status: "inactive" };
  const status = counts.uncertain ? "uncertain" : counts.failed ? "failed" : counts.stale ? "stale"
    : counts.total && counts.verified === counts.total ? "verified"
      : counts.total && counts.installed === counts.total ? "installed"
        : counts.total && counts.verified + counts.installed === counts.total ? "completed"
          : counts.verified + counts.installed ? "partial"
      : !counts.total || counts.not_deployed === counts.total ? "not_deployed" : "pending";
  // Only deadlines, no consumer IDs or evidence. Allows cached counts to expire without granting convergence.
  return { ...counts, status,
    ...(expirations.length === counts.verified ? { verification_expirations: expirations.sort((a, b) => a - b) } : {}),
    ...(installations.length === counts.installed ? { installation_expirations: installations.sort((a, b) => a - b) } : {}) };
}

/** Bounded batch metadata read; two queries regardless of certificate/consumer count. */
async function listDistributionGroups({ client, workspaceId, query = {} }) {
  const evaluated_at = new Date().toISOString();
  const managedIds = parseIds(query.managedCertificateIds);
  const identityIds = parseIds(query.identityIds);
  const scoped = managedIds.length > 0 || identityIds.length > 0;
  const summaries = query.summaries === "true";
  if (summaries && !scoped) {
    const error = new Error("Certificate IDs are required for summaries");
    error.statusCode = 422;
    throw error;
  }
  const groups = (await client.query(`SELECT g.*,p.current_identity_id,p.ended_at AS period_ended_at,
    (g.state='active' AND p.ended_at IS NULL) AS active,
    latest.state AS publication_state,latest.provider_version,latest.publishing_job_id,
    latest.fingerprint_sha256,latest.valid_to,latest.published_at
    FROM certops_distribution_groups g
    JOIN certops_management_periods p ON p.workspace_id=g.workspace_id
      AND p.managed_certificate_id=g.managed_certificate_id AND p.id=g.management_period_id
    LEFT JOIN LATERAL (SELECT v.state,v.provider_version,v.publishing_job_id,v.fingerprint_sha256,v.valid_to,v.published_at
      FROM certops_material_versions v WHERE v.workspace_id=g.workspace_id AND v.group_id=g.id
      ORDER BY v.created_at DESC,v.id DESC LIMIT 1) latest ON true
    WHERE g.workspace_id=$1
      AND (NOT $4::boolean OR g.managed_certificate_id=ANY($2::uuid[]) OR p.current_identity_id=ANY($3::uuid[])
        OR (NOT $5::boolean AND EXISTS (SELECT 1 FROM certops_material_versions history
          WHERE history.workspace_id=g.workspace_id AND history.group_id=g.id AND history.certificate_identity_id=ANY($3::uuid[]))))
      AND (NOT $5::boolean OR (g.state='active' AND p.ended_at IS NULL))
    ORDER BY g.created_at DESC LIMIT 1000`, [workspaceId, managedIds, identityIds, scoped, summaries])).rows;
  if (!summaries || !groups.length) return { groups, evaluated_at };
  const consumers = await consumerMatrix({ client, workspaceId, groupIds: groups.map(group => group.id) });
  const byGroup = new Map();
  for (const row of consumers) {
    if (!byGroup.has(row.group_id)) byGroup.set(row.group_id, []);
    byGroup.get(row.group_id).push(row);
  }
  return { evaluated_at, groups: groups.map(group => ({
    id: group.id, managed_certificate_id: group.managed_certificate_id,
    current_identity_id: group.current_identity_id,
    summary: summarizeConsumers(byGroup.get(group.id) || []),
  })) };
}

module.exports = { parseIds, consumerStatus, summarizeConsumers, listDistributionGroups };

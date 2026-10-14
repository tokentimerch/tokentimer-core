"use strict";

/**
 * AD CS preflight gate. An AD CS renewal starts only when an active agent
 * holds a safe adcs-preflight for the confirmed CA, template, and pinned key,
 * taken after that confirmation and inside the freshness window. The renewal
 * scheduler and renewal health both ask this question through the functions
 * below, so they cannot disagree about whether a renewal is waiting.
 */

const {
  ADCS_PREFLIGHT_MAX_AGE_MS,
} = require("../../../../packages/contracts/certops/adcs-preflight-freshness.cjs");

// Surfaced as renewalPathReason while the scheduler is waiting on an agent.
const ADCS_PREFLIGHT_WAITING_REASON = "waiting_for_fresh_preflight";

// One row per active agent that declares the target, with that agent's latest
// adcs-preflight for this issuer. The verdict is checked in JS by
// qualifiesAdcsPreflight so both callers run identical logic.
const QUALIFYING_AGENTS_SQL = `
  SELECT a.id, a.last_seen_at, latest.status, latest.result_metadata, latest.created_at
    FROM certops_agents a
    LEFT JOIN LATERAL (
      SELECT j.status, j.result_metadata, j.created_at
        FROM certificate_jobs j
       WHERE j.workspace_id = a.workspace_id
         AND j.operation = 'adcs-preflight'
         AND j.subject_id = $3
         AND j.assigned_agent_id = a.id
       ORDER BY j.preflight_seq DESC NULLS LAST, j.created_at DESC, j.id DESC
       LIMIT 1
    ) latest ON TRUE
   WHERE a.workspace_id = $1
     AND a.status = 'active'
     AND a.declared_target_selectors @> jsonb_build_array($2::text)
   ORDER BY a.last_seen_at DESC NULLS LAST`;

async function loadCurrentAdcsIssuerVersion({ db, workspaceId, issuerId }) {
  const result = await db.query(
    `SELECT v.ca_config, v.template, v.ca_key_sha256, v.confirmed_at
       FROM certificate_issuers i
       JOIN certificate_issuer_versions v
         ON v.workspace_id = i.workspace_id
        AND v.issuer_id = i.id
        AND v.version = i.current_version
      WHERE i.workspace_id = $1 AND i.id = $2`,
    [workspaceId, issuerId],
  );
  return result.rows[0] || null;
}

function timeMs(value) {
  if (value == null) return null;
  const ms = new Date(value).getTime();
  return Number.isFinite(ms) ? ms : null;
}

// A missing version or confirmation time fails closed, as it did in SQL.
function qualifiesAdcsPreflight(evidence, version, nowMs) {
  if (!evidence || evidence.status !== "succeeded" || !version) return false;
  const verdict = evidence.result_metadata?.preflightVerdict;
  const createdMs = timeMs(evidence.created_at);
  const confirmedMs = timeMs(version.confirmed_at);
  if (createdMs == null || confirmedMs == null) return false;
  return (
    verdict?.templateCheck === "safe" &&
    verdict?.caCheck === "safe" &&
    version.ca_config != null &&
    verdict.caConfig === version.ca_config &&
    version.template != null &&
    verdict.template === version.template &&
    version.ca_key_sha256 != null &&
    Array.isArray(verdict.caKeySha256s) &&
    verdict.caKeySha256s.includes(version.ca_key_sha256) &&
    createdMs >= confirmedMs &&
    createdMs >= nowMs - ADCS_PREFLIGHT_MAX_AGE_MS
  );
}

/**
 * Active agents that declare `reference` and hold a qualifying preflight for
 * the issuer, most recently seen first. Callers that need only a yes or no
 * check the first element.
 */
async function loadQualifyingAdcsAgents({
  db,
  workspaceId,
  issuerId,
  reference,
  version,
  nowMs = Date.now(),
}) {
  const result = await db.query(QUALIFYING_AGENTS_SQL, [
    workspaceId,
    reference,
    String(issuerId),
  ]);
  return result.rows
    .filter((row) => qualifiesAdcsPreflight(row, version, nowMs))
    .map((row) => ({ id: row.id, last_seen_at: row.last_seen_at }));
}

module.exports = {
  ADCS_PREFLIGHT_MAX_AGE_MS,
  ADCS_PREFLIGHT_WAITING_REASON,
  loadCurrentAdcsIssuerVersion,
  loadQualifyingAdcsAgents,
  qualifiesAdcsPreflight,
};

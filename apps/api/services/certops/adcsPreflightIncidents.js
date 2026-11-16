"use strict";

// Read-only projection of the existing due-renewal paths. No CA calls, job
// dispatch or new scheduling loop. Both the UI and incident recovery use it.
const {
  refreshState,
  FAILURE_ACTIONS,
  comparePreflightJobs,
} = require("./adcsPreflightRefresh");
const { renewalAgentEligibility } = require("./adcsPreflightGate");
const { validateAdcsRenewalProfile } = require("./adcsRenewalRules");
const { resolveRenewalThresholdPolicy } = require("./renewalThreshold");
const { isCertOpsEnabled } = require("./settings");
const UUID =
  /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const CRITICAL_MS = 7 * 86400000;

function projectRenewalPath(certificate, agents, version, now, env) {
  const base = {
    certificateId: certificate.id,
    notAfter: certificate.not_after,
    certificateName: String(certificate.common_name || certificate.id).slice(
      0,
      253,
    ),
  };
  let profile;
  try {
    profile = validateAdcsRenewalProfile(
      certificate.profile_public_metadata?.renewalProfile,
    );
  } catch {
    return {
      ...base,
      state: "blocked",
      code: "CERTOPS_RENEWAL_PROFILE_INCOMPLETE",
      action: "Correct the assigned AD CS renewal profile.",
    };
  }
  const target = profile.target,
    binding = target.binding;
  const pinned =
    target.type === "windows-cert-store" ||
    (target.type === "windows-iis" &&
      binding?.address != null &&
      !["*", "0.0.0.0"].includes(binding.address));
  const ownerId = pinned ? certificate.deployed_agent_id : null;
  const declared = agents.filter(
    (a) =>
      (!pinned || (ownerId && String(a.id) === String(ownerId))) &&
      Array.isArray(a.declared_target_selectors) &&
      a.declared_target_selectors.includes(target.reference),
  );
  const evaluated = declared.map((agent) => ({
    agent,
    ...renewalAgentEligibility(agent, { target, ownerId, env, now }),
  }));
  const eligible = evaluated.filter((a) => a.eligible);
  if (!eligible.length) {
    const active = evaluated.find(
      (a) => (a.agent.agent_status || a.agent.status) === "active",
    );
    const code = active
      ? "CERTOPS_ADCS_AGENT_INELIGIBLE"
      : "CERTOPS_ADCS_AGENT_UNAVAILABLE";
    return {
      ...base,
      targetReference: target.reference,
      agentId: ownerId || active?.agent.id || null,
      state: active ? "agent_ineligible" : "agent_unavailable",
      code,
      eligibilityReason: active?.reason || "agent_unavailable",
      action: FAILURE_ACTIONS[code],
    };
  }
  const checked = eligible.map(({ agent }) => ({
    ...base,
    targetReference: target.reference,
    agentId: agent.id,
    ...refreshState(
      [...(agent.preflight_jobs || [])].sort(comparePreflightJobs),
      version,
      now,
    ),
  }));
  return checked.find((a) => a.state === "fresh") || checked[0];
}

function summarizeReadiness(paths, now = Date.now()) {
  const blocked = paths
    .filter((p) => p.state !== "fresh")
    .sort(
      (a, b) =>
        new Date(a.notAfter) - new Date(b.notAfter) ||
        String(a.certificateId).localeCompare(String(b.certificateId)),
    );
  const urgent = blocked[0];
  const alert = Boolean(
    urgent &&
    (new Date(urgent.notAfter).getTime() - now <= CRITICAL_MS ||
      blocked.some((p) =>
        ["blocked", "agent_unavailable", "agent_ineligible"].includes(p.state),
      )),
  );
  const seen = new Set();
  const checks = [];
  for (const path of [
    ...blocked,
    ...paths.filter((p) => p.state === "fresh"),
  ]) {
    const key = JSON.stringify([
      path.agentId,
      path.state,
      path.code,
      path.eligibilityReason,
    ]);
    if (seen.has(key)) continue;
    seen.add(key);
    if (checks.length < 20)
      checks.push({ ...path, renewalReady: path.state === "fresh" });
  }
  return {
    alert,
    affectedCount: blocked.length,
    dueCount: paths.length,
    severity:
      urgent && new Date(urgent.notAfter).getTime() - now <= CRITICAL_MS
        ? "critical"
        : "warning",
    mostUrgentCertificateId: urgent?.certificateId || null,
    earliestNotAfter: urgent ? new Date(urgent.notAfter).toISOString() : null,
    code: urgent?.code || "CERTOPS_PREFLIGHT_REQUIRED",
    failureCode: urgent?.failureCode || null,
    errorCode: urgent?.errorCode || null,
    action: urgent?.action || FAILURE_ACTIONS.CERTOPS_PREFLIGHT_REQUIRED,
    checks,
    truncated: seen.size > checks.length,
  };
}

async function loadIssuerPreflightReadiness({
  db,
  workspaceId,
  issuerId,
  env = process.env,
  now = Date.now(),
  version,
  agents,
}) {
  if (!version) {
    version = (
      await db.query(
        `SELECT v.*,i.revalidation_required,w.certops_paused
      FROM certificate_issuers i JOIN workspaces w ON w.id=i.workspace_id
      LEFT JOIN certificate_issuer_versions v ON v.workspace_id=i.workspace_id AND v.issuer_id=i.id AND v.version=i.current_version
      WHERE i.workspace_id=$1 AND i.id=$2 AND i.kind='adcs'`,
        [workspaceId, issuerId],
      )
    ).rows[0];
  }
  if (
    !version ||
    version.certops_paused ||
    !(await isCertOpsEnabled({ dbPool: db, env }))
  )
    return { ...summarizeReadiness([], now), agents: [] };
  // Keep the latest observation across versions, just like the final renewal
  // gate: a newer superseded-context result must not uncover an older safe
  // result. refreshState bounds the retry episode to the current confirmation.
  if (!agents)
    agents = (
      await db.query(
        `SELECT a.id,a.status,a.platform,a.agent_version,a.protocol_version,
    a.declared_capabilities,a.capabilities_updated_at,a.agent_kind,a.supported_operations,
    a.declared_target_selectors,a.last_seen_at,history.jobs AS preflight_jobs FROM certops_agents a
    LEFT JOIN LATERAL (SELECT jsonb_agg(j ORDER BY j.preflight_seq DESC NULLS LAST,j.created_at DESC,j.id DESC) AS jobs FROM (
      SELECT id,status,source,error_code,result_metadata,created_at,completed_at,updated_at,preflight_seq
      FROM certificate_jobs WHERE workspace_id=a.workspace_id AND assigned_agent_id=a.id AND subject_id=$2
        AND operation='adcs-preflight' ORDER BY preflight_seq DESC NULLS LAST,created_at DESC,id DESC LIMIT 6
    ) j) history ON TRUE WHERE a.workspace_id=$1 ORDER BY a.last_seen_at DESC NULLS LAST,a.id`,
        [workspaceId, String(issuerId)],
      )
    ).rows;
  // Reuse the scheduler's exact eligibility, lead-time and non-terminal-work
  // exclusions. LIMIT NULL is intentional: counts/earliest expiry must not
  // depend on the scheduler's current dispatch batch.
  const {
    findCertificatesDueForRenewal,
    RENEWAL_JOB_TERMINAL_STATUSES,
  } = require("./renewalScheduler");
  const certificates = await findCertificatesDueForRenewal({
    db,
    workspaceId,
    issuerId,
    ...resolveRenewalThresholdPolicy(env),
    batchSize: null,
    terminalStatuses: RENEWAL_JOB_TERMINAL_STATUSES,
  });
  return {
    ...summarizeReadiness(
      certificates.map((c) => projectRenewalPath(c, agents, version, now, env)),
      now,
    ),
    agents,
  };
}

async function reconcileIssuerPreflightIncident({
  db,
  workspaceId,
  issuerId,
  env = process.env,
  now = Date.now(),
  transactionOwned = false,
}) {
  if (!UUID.test(String(issuerId)) || !UUID.test(String(workspaceId)))
    return null;
  if (!transactionOwned) {
    const client =
      typeof db.connect === "function" && typeof db.idleCount === "number"
        ? await db.connect()
        : db;
    try {
      await client.query("BEGIN");
      const result = await reconcileIssuerPreflightIncident({
        db: client,
        workspaceId,
        issuerId,
        env,
        now,
        transactionOwned: true,
      });
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      if (client !== db) client.release();
    }
  }
  await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 141))", [
    `${workspaceId}:${issuerId}`,
  ]);
  const risk = await loadIssuerPreflightReadiness({
    db,
    workspaceId,
    issuerId,
    env,
    now,
  });
  const key = `adcs-preflight:${issuerId}`;
  // Replace the old per-agent/target bell rows with one bounded current issuer
  // incident. Historical rows and delivery evidence remain in the database.
  await db.query(
    `UPDATE operational_notifications SET resolved_at=NOW(),updated_at=NOW()
    WHERE workspace_id=$1 AND category='certops' AND type='adcs_preflight_blocked' AND resolved_at IS NULL
      AND metadata->>'issuerId'=$2 AND (dedupe_key<>$3 OR $4::boolean)`,
    [workspaceId, issuerId, key, !risk.alert],
  );
  if (!risk.alert) return null;
  const metadata = {
    issuerId,
    affectedCount: risk.affectedCount,
    mostUrgentCertificateId: risk.mostUrgentCertificateId,
    earliestNotAfter: risk.earliestNotAfter,
    code: risk.code,
    failureCode: risk.failureCode,
    errorCode: risk.errorCode,
    href: `/certops/adcs?workspace=${workspaceId}`,
    action: risk.action,
  };
  const result = await db.query(
    `INSERT INTO operational_notifications(workspace_id,category,type,severity,dedupe_key,title,message,metadata)
    VALUES($1,'certops','adcs_preflight_blocked',$2,$3,'AD CS automatic renewal needs attention',$4,$5::jsonb)
    ON CONFLICT(workspace_id,dedupe_key) WHERE resolved_at IS NULL DO UPDATE SET
      severity=EXCLUDED.severity,message=EXCLUDED.message,
      metadata=EXCLUDED.metadata || jsonb_build_object('emailDelivery',COALESCE(operational_notifications.metadata->'emailDelivery','{}'::jsonb)),updated_at=NOW()
    RETURNING id`,
    [
      workspaceId,
      risk.severity,
      key,
      `${risk.code}${risk.failureCode ? ` (last cause: ${risk.failureCode})` : ""}${risk.errorCode ? `; recorded job code: ${risk.errorCode}` : ""}: ${risk.affectedCount} due certificate(s) lack a safe renewal path for issuer ${issuerId}. Earliest certificate ${risk.mostUrgentCertificateId} expires ${risk.earliestNotAfter}. ${risk.action}`,
      JSON.stringify(metadata),
    ],
  );
  return result.rows[0]?.id || null;
}

async function reconcilePendingPreflightIncidents({
  db,
  env = process.env,
  limit = 50,
  certificates = [],
}) {
  const rows = await db.query(
    `SELECT workspace_id,metadata->>'issuerId' AS issuer_id
    FROM operational_notifications WHERE category='certops' AND type='adcs_preflight_blocked' AND resolved_at IS NULL
    GROUP BY workspace_id,metadata->>'issuerId' ORDER BY MIN(updated_at),workspace_id,metadata->>'issuerId' LIMIT $1`,
    [limit],
  );
  const scopes = new Map();
  for (const c of certificates)
    if (c.profile_issuer_kind === "adcs" && c.profile_issuer_id)
      scopes.set(`${c.workspace_id}:${c.profile_issuer_id}`, {
        workspaceId: c.workspace_id,
        issuerId: c.profile_issuer_id,
      });
  for (const row of rows.rows)
    scopes.set(`${row.workspace_id}:${row.issuer_id}`, {
      workspaceId: row.workspace_id,
      issuerId: row.issuer_id,
    });
  for (const scope of scopes.values())
    await reconcileIssuerPreflightIncident({ db, ...scope, env });
}

module.exports = {
  projectRenewalPath,
  summarizeReadiness,
  loadIssuerPreflightReadiness,
  reconcileIssuerPreflightIncident,
  reconcilePendingPreflightIncidents,
};

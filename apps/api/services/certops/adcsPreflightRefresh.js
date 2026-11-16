"use strict";

const crypto = require("node:crypto");
const {
  qualifiesAdcsPreflight,
  ADCS_PREFLIGHT_MAX_AGE_MS,
} = require("./adcsPreflightGate");

// One initial check and four retries. A successful check or an explicit manual
// check starts a new episode; a scheduler/worker restart does not.
const MAX_ATTEMPTS = 5;
const BACKOFF_MS = 15 * 60 * 1000;
const QUEUE_TIMEOUT_MS = 60 * 60 * 1000;
const TERMINAL = new Set([
  "succeeded",
  "failed",
  "blocked",
  "rejected",
  "cancelled",
  "orphaned_unknown_effect",
  "dry_run_complete",
  "awaiting_issuer",
]);
const POLICY_FAILURES = new Set([
  "ADCS_TEMPLATE_UNSAFE",
  "ADCS_CA_CONFIG_UNSAFE",
  "ADCS_CA_KEY_CHANGED",
  "ADCS_CA_KEY_UNPINNED",
  "issuer_not_allowlisted",
  "CERTOPS_ISSUER_REVALIDATION_REQUIRED",
  "CERTOPS_SNAPSHOT_INVALID",
]);

function classifyPreflight(job, version) {
  const verdict = job?.result_metadata?.preflightVerdict;
  const failure = job?.error_code || job?.result_metadata?.rejectionReason;
  if (POLICY_FAILURES.has(failure)) return failure;
  if (verdict?.templateCheck === "unsafe") return "ADCS_TEMPLATE_UNSAFE";
  if (verdict?.caCheck === "unsafe") return "ADCS_CA_CONFIG_UNSAFE";
  if (
    verdict &&
    (verdict.caConfig !== version.ca_config ||
      verdict.template !== version.template)
  ) {
    return "CERTOPS_ISSUER_REVALIDATION_REQUIRED";
  }
  if (
    verdict &&
    Array.isArray(verdict.caKeySha256s) &&
    verdict.caKeySha256s.length &&
    !verdict.caKeySha256s.includes(version.ca_key_sha256)
  )
    return "ADCS_CA_KEY_CHANGED";
  if (
    [
      "blocked",
      "rejected",
      "cancelled",
      "dry_run_complete",
      "awaiting_issuer",
    ].includes(job?.status)
  ) {
    return (
      job.error_code ||
      job.result_metadata?.rejectionReason ||
      "CERTOPS_PREFLIGHT_OPERATOR_ACTION_REQUIRED"
    );
  }
  return null;
}

function refreshState(jobs, version, now = Date.now()) {
  if (
    !version?.confirmed_at ||
    !version.ca_key_sha256 ||
    version.revalidation_required
  ) {
    return {
      state: "blocked",
      code: "CERTOPS_ISSUER_REVALIDATION_REQUIRED",
      attempts: 0,
    };
  }
  const latest = jobs[0];
  if (!latest) return { state: "required", attempts: 0 };
  const code = classifyPreflight(latest, version);
  if (code) return { state: "blocked", code, attempts: 0 };
  if (!TERMINAL.has(latest.status))
    return {
      state: latest.status === "pending" ? "queued" : "running",
      attempts: 0,
      jobId: latest.id,
    };
  if (qualifiesAdcsPreflight(latest, version, now))
    return {
      state: "fresh",
      attempts: 0,
      jobId: latest.id,
      checkedAt: new Date(latest.created_at).toISOString(),
      expiresAt: new Date(
        new Date(latest.created_at).getTime() + ADCS_PREFLIGHT_MAX_AGE_MS,
      ).toISOString(),
    };
  // A stale safe result needs an ordinary refresh, not another failure attempt.
  if (
    qualifiesAdcsPreflight(
      latest,
      version,
      new Date(latest.created_at).getTime(),
    )
  ) {
    return { state: "required", attempts: 0 };
  }
  let attempts = 0;
  for (const job of jobs) {
    if (
      qualifiesAdcsPreflight(job, version, new Date(job.created_at).getTime())
    )
      break;
    attempts += 1;
    if (job.source !== "automation") break;
  }
  if (attempts >= MAX_ATTEMPTS)
    return {
      state: "blocked",
      code: "CERTOPS_PREFLIGHT_RETRIES_EXHAUSTED",
      attempts,
    };
  const completed = new Date(
    latest.completed_at || latest.updated_at || latest.created_at,
  ).getTime();
  if (!Number.isFinite(completed))
    return {
      state: "blocked",
      code: "CERTOPS_PREFLIGHT_OPERATOR_ACTION_REQUIRED",
      attempts,
    };
  const retryAt = completed + BACKOFF_MS * 2 ** Math.max(0, attempts - 1);
  return {
    state: "retrying",
    code: "ADCS_CA_UNREACHABLE",
    attempts,
    nextRefreshAt: new Date(retryAt).toISOString(),
    dispatch: now >= retryAt,
  };
}

async function loadRefreshJobs(
  db,
  { workspaceId, issuerId, agentId, version },
) {
  const result = await db.query(
    `SELECT id, status, source, error_code, result_metadata, created_at, completed_at, updated_at
       FROM certificate_jobs
      WHERE workspace_id=$1 AND operation='adcs-preflight' AND subject_id=$2
        AND assigned_agent_id=$3 AND created_at >= $4
        AND (result_metadata->'preflightContext'->>'issuerVersion' IS NULL
             OR result_metadata->'preflightContext'->>'issuerVersion'=$6)
      ORDER BY preflight_seq DESC NULLS LAST, created_at DESC, id DESC LIMIT $5`,
    [
      workspaceId,
      String(issuerId),
      agentId,
      version.confirmed_at,
      MAX_ATTEMPTS + 1,
      String(version.version),
    ],
  );
  return result.rows;
}

function issuerRefreshStates(jobs, version, now = Date.now()) {
  const agents = new Map();
  for (const job of jobs || []) {
    if (!job.assigned_agent_id) continue;
    if (!agents.has(job.assigned_agent_id))
      agents.set(job.assigned_agent_id, []);
    agents.get(job.assigned_agent_id).push(job);
  }
  return [...agents].map(([agentId, history]) => ({
    agentId,
    ...refreshState(history, version, now),
  }));
}

function refreshIdempotencyKey({
  workspaceId,
  issuerId,
  agentId,
  version,
  previousId,
}) {
  return `adcs-refresh:${crypto
    .createHash("sha256")
    .update(
      JSON.stringify([
        workspaceId,
        issuerId,
        agentId,
        version.version,
        version.confirmed_at,
        version.ca_config,
        version.template,
        version.ca_key_sha256,
        previousId || null,
      ]),
    )
    .digest("hex")}`;
}

async function notifyRefreshState(
  db,
  {
    workspaceId,
    issuerId,
    agentId,
    state,
    notAfter,
    unavailableTarget = null,
    targetReference = null,
    now = Date.now(),
  },
) {
  const unavailableKey = (reference) =>
    `adcs-preflight:${issuerId}:unavailable:${crypto.createHash("sha256").update(reference).digest("hex")}`;
  const key = unavailableTarget
    ? unavailableKey(unavailableTarget)
    : `adcs-preflight:${issuerId}:${agentId}`;
  if (state.state === "fresh") {
    await db.query(
      `UPDATE operational_notifications SET resolved_at=NOW(),updated_at=NOW()
      WHERE workspace_id=$1 AND dedupe_key=ANY($2::text[]) AND resolved_at IS NULL`,
      [
        workspaceId,
        [key, ...(targetReference ? [unavailableKey(targetReference)] : [])],
      ],
    );
    return;
  }
  const expiry = notAfter == null ? Infinity : new Date(notAfter).getTime();
  const critical =
    Number.isFinite(expiry) && expiry - now <= 7 * 24 * 60 * 60 * 1000;
  if (state.state !== "blocked" && !critical) return;
  const code = state.code || "CERTOPS_PREFLIGHT_REQUIRED";
  await db.query(
    `INSERT INTO operational_notifications(workspace_id,category,type,severity,dedupe_key,title,message,metadata)
     VALUES($1,'certops','adcs_preflight_blocked',$2,$3,'AD CS automatic renewal needs attention',$4,$5::jsonb)
     ON CONFLICT(workspace_id,dedupe_key) WHERE resolved_at IS NULL
     DO UPDATE SET severity=CASE WHEN operational_notifications.severity='critical' THEN 'critical' ELSE EXCLUDED.severity END,
       message=EXCLUDED.message,metadata=EXCLUDED.metadata,updated_at=NOW()`,
    [
      workspaceId,
      critical ? "critical" : "warning",
      key,
      `${code}: Review the CA check, approved key, template security and agent enrollment rule. Restore connectivity, then run Check again if retries stopped.`,
      JSON.stringify({
        issuerId,
        agentId,
        targetReference: unavailableTarget || targetReference,
        code,
        attempts: state.attempts,
        href: `/certops/adcs?workspace=${workspaceId}`,
      }),
    ],
  );
}

module.exports = {
  MAX_ATTEMPTS,
  BACKOFF_MS,
  QUEUE_TIMEOUT_MS,
  classifyPreflight,
  refreshState,
  loadRefreshJobs,
  refreshIdempotencyKey,
  notifyRefreshState,
  issuerRefreshStates,
};

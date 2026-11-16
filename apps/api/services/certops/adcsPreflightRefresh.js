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
    ((typeof verdict.caConfig === "string" &&
      verdict.caConfig !== version.ca_config) ||
      (typeof verdict.template === "string" &&
        verdict.template !== version.template))
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

const FAILURE_ACTIONS = Object.freeze({
  ADCS_TEMPLATE_UNSAFE:
    "Review and correct the certificate template security settings, then run Check again.",
  ADCS_CA_CONFIG_UNSAFE:
    "Review and correct the CA security settings, then run Check again.",
  ADCS_CA_KEY_CHANGED:
    "Independently verify the changed CA key and explicitly approve it before checking again.",
  ADCS_CA_KEY_UNPINNED:
    "Verify the approved CA key and the agent's public CA certificate cache.",
  issuer_not_allowlisted:
    "Add the exact CA/template pair to the local enrollment rule and restart the agent.",
  CERTOPS_ISSUER_REVALIDATION_REQUIRED:
    "Review the current issuer version and explicitly confirm its CA key if required.",
  CERTOPS_PREFLIGHT_QUEUE_TIMEOUT:
    "Restore the assigned agent's connectivity and inspect its job queue.",
  CERTOPS_ADCS_AGENT_UNAVAILABLE:
    "Restore the owning Windows agent or configure an eligible renewal agent.",
  CERTOPS_ADCS_AGENT_INELIGIBLE:
    "Check the agent's version, target declaration and fresh destination/enrollment capabilities.",
  ADCS_CA_UNREACHABLE:
    "Restore connectivity from the agent to the configured CA.",
  CERTOPS_PREFLIGHT_NETWORK_TIMEOUT:
    "Check agent-to-CA networking and timeout diagnostics.",
  CERTOPS_PREFLIGHT_EXECUTION_INTERRUPTED:
    "Check the worker and agent; read-only preflight can recover after backoff.",
  CERTOPS_PREFLIGHT_RESULT_UNREADABLE:
    "Inspect the check and local permissions; unreadable evidence does not prove the CA is unreachable.",
  CERTOPS_PREFLIGHT_OPERATION_FAILED:
    "Inspect the job's recorded error and restore the execution path.",
  CERTOPS_PREFLIGHT_RETRIES_EXHAUSTED:
    "Correct the reported cause and deliberately run Check again to start a new retry episode.",
  CERTOPS_PREFLIGHT_OPERATOR_ACTION_REQUIRED:
    "Review the job and local policy before deliberately checking again.",
  CERTOPS_PREFLIGHT_REQUIRED:
    "Wait for the due-renewal check, or run Check again to verify the selected agent now.",
});

function preflightFailure(job, version) {
  const policy = classifyPreflight(job, version);
  const raw = job?.error_code || job?.result_metadata?.rejectionReason;
  const errorCode =
    typeof raw === "string" && /^[A-Za-z][A-Za-z0-9_]{0,127}$/.test(raw)
      ? raw
      : null;
  let code = policy;
  if (!code) {
    if (errorCode === "CERTOPS_PREFLIGHT_QUEUE_TIMEOUT") code = errorCode;
    else if (errorCode === "CERTOPS_ADCS_AGENT_UNAVAILABLE") code = errorCode;
    else if (errorCode === "ADCS_CA_UNREACHABLE") code = errorCode;
    else if (
      [
        "ETIMEDOUT",
        "ESOCKETTIMEDOUT",
        "NETWORK_TIMEOUT",
        "ADCS_NETWORK_TIMEOUT",
      ].includes(errorCode)
    )
      code = "CERTOPS_PREFLIGHT_NETWORK_TIMEOUT";
    else if (
      job?.status === "orphaned_unknown_effect" ||
      ["effects_unknown", "lease_expired", "max_attempts_exceeded"].includes(
        errorCode,
      )
    )
      code = "CERTOPS_PREFLIGHT_EXECUTION_INTERRUPTED";
    else if (job?.status === "succeeded")
      code = "CERTOPS_PREFLIGHT_RESULT_UNREADABLE";
    else code = "CERTOPS_PREFLIGHT_OPERATION_FAILED";
  }
  return {
    code,
    errorCode,
    retryable: !policy,
    action:
      FAILURE_ACTIONS[code] ||
      FAILURE_ACTIONS.CERTOPS_PREFLIGHT_OPERATOR_ACTION_REQUIRED,
  };
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
      action: FAILURE_ACTIONS.CERTOPS_ISSUER_REVALIDATION_REQUIRED,
      attempts: 0,
    };
  }
  const latest = jobs[0];
  if (!latest) return { state: "required", attempts: 0 };
  const context = latest.result_metadata?.preflightContext;
  if (
    new Date(latest.created_at).getTime() <
      new Date(version.confirmed_at).getTime() ||
    (context &&
      (Number(context.issuerVersion) !== Number(version.version) ||
        context.caKeySha256 !== version.ca_key_sha256 ||
        new Date(context.confirmedAt).getTime() !==
          new Date(version.confirmed_at).getTime()))
  ) {
    return {
      state: "required",
      code: "CERTOPS_PREFLIGHT_EVIDENCE_STALE",
      attempts: 0,
      action: FAILURE_ACTIONS.CERTOPS_PREFLIGHT_REQUIRED,
    };
  }
  const failure = preflightFailure(latest, version);
  if (!failure.retryable) return { state: "blocked", ...failure, attempts: 0 };
  if (!TERMINAL.has(latest.status))
    return {
      state:
        latest.status === "pending_approval"
          ? "awaiting_approval"
          : ["pending", "approved"].includes(latest.status)
            ? "queued"
            : "running",
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
    const priorContext = job.result_metadata?.preflightContext;
    if (
      new Date(job.created_at).getTime() <
        new Date(version.confirmed_at).getTime() ||
      (priorContext &&
        (Number(priorContext.issuerVersion) !== Number(version.version) ||
          priorContext.caKeySha256 !== version.ca_key_sha256 ||
          new Date(priorContext.confirmedAt).getTime() !==
            new Date(version.confirmed_at).getTime()))
    )
      break;
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
      failureCode: failure.code,
      errorCode: failure.errorCode,
      action: FAILURE_ACTIONS.CERTOPS_PREFLIGHT_RETRIES_EXHAUSTED,
      retryable: false,
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
    ...failure,
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
  for (const job of [...(jobs || [])].sort(comparePreflightJobs)) {
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

function comparePreflightJobs(a, b) {
  const sequence = (value) =>
    value != null && /^\d+$/.test(String(value)) ? BigInt(value) : null;
  const left = sequence(a.preflight_seq),
    right = sequence(b.preflight_seq);
  if (left !== right) {
    if (left == null) return 1;
    if (right == null) return -1;
    return left > right ? -1 : 1;
  }
  const time =
    new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
  if (Number.isFinite(time) && time !== 0) return time;
  return String(a.id) === String(b.id)
    ? 0
    : String(a.id) > String(b.id)
      ? -1
      : 1;
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

module.exports = {
  MAX_ATTEMPTS,
  BACKOFF_MS,
  QUEUE_TIMEOUT_MS,
  classifyPreflight,
  refreshState,
  loadRefreshJobs,
  refreshIdempotencyKey,
  FAILURE_ACTIONS,
  preflightFailure,
  comparePreflightJobs,
  issuerRefreshStates,
};

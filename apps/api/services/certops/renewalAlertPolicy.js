"use strict";

/**
 * Canonical renewal-alerting vocabulary.
 *
 * This module exists to be dependency-free. agentDispatch.js already requires
 * renewalFailureAlerts.js, so the operation set cannot live in the dispatcher
 * and be imported back by the resolver without a cycle. Both sides import it
 * from here instead, so the "does this job alert?" question has exactly one
 * answer in the codebase.
 *
 * The previous arrangement had two: the dispatcher's own set said
 * {renew, issue} while the resolver hard-rejected anything but renew, so a
 * failed issuance was dispatched to an alert path that silently discarded it.
 */

// Operations whose terminal failures notify the operator. "issue" is
// deliberately absent: an issuance failure has no certificate identity worth
// alerting on yet (no token to anchor routing, nothing in the inventory the
// operator was already relying on), and the job itself is visible in the
// dashboard and audit trail. Once an issued certificate is active, its
// subsequent renewals alert normally like any other certificate's.
const RENEWAL_ALERTING_OPERATIONS = Object.freeze(new Set(["renew"]));

/**
 * Origin of the terminal transition, which is not the same thing as
 * certificate_jobs.source (how the job was created).
 *
 * Status alone cannot decide whether to alert: RESULT_STATUS_TO_JOB_STATUS maps
 * agent-reported results onto 'rejected' and 'blocked', the same statuses the
 * human approval flow produces. An agent refusing a job on policy grounds is
 * actionable; a human rejecting it is the human's own deliberate act and
 * emailing them about it is noise. Creation source cannot tell them apart
 * either, since an API-created job can later be rejected by either.
 */
const TRANSITION_ORIGINS = Object.freeze({
  AGENT_RESULT: "agent_result",
  // Terminal status reported by a machine credential on the executor lane
  // (a bring-your-own executor, or the Kubernetes controller). Distinct
  // from AGENT_RESULT because the executor lane holds no lease and no
  // claim, so an operator reading the alert needs to know which lane
  // ended the job.
  EXECUTOR_EVENT: "executor_event",
  APPROVAL_REJECTION: "approval_rejection",
  OPERATOR_CANCEL: "operator_cancel",
  LEASE_REAPER: "lease_reaper",
  STALE_AGENT: "stale_agent",
  FORCED_RETIREMENT: "forced_retirement",
});

const TRANSITION_ORIGIN_VALUES = Object.freeze(
  new Set(Object.values(TRANSITION_ORIGINS)),
);

// Statuses that never notify regardless of origin. A dry run changes nothing on
// the host by construction, so there is no failure for an operator to act on.
const NON_ALERTING_STATUSES = Object.freeze(
  new Set(["succeeded", "dry_run_complete", "pending", "approved", "claimed", "running"]),
);

// Origins that represent a deliberate human decision. The human already knows.
const HUMAN_DECISION_ORIGINS = Object.freeze(
  new Set([
    TRANSITION_ORIGINS.APPROVAL_REJECTION,
    TRANSITION_ORIGINS.OPERATOR_CANCEL,
  ]),
);

/**
 * Decide whether a terminal transition is alert-worthy.
 *
 * Returns { alertWorthy: boolean, reason: string }. The reason is recorded
 * either way: a skip that cannot explain itself is indistinguishable from the
 * bug this replaced.
 */
function classifyTerminalTransition({
  operation = null,
  status = null,
  origin = null,
} = {}) {
  if (!RENEWAL_ALERTING_OPERATIONS.has(operation)) {
    return { alertWorthy: false, reason: "operation_not_alerting" };
  }
  if (!status || NON_ALERTING_STATUSES.has(status)) {
    return { alertWorthy: false, reason: "status_not_alerting" };
  }
  if (HUMAN_DECISION_ORIGINS.has(origin)) {
    // Reached by a person who was looking at the job at the time.
    return { alertWorthy: false, reason: `deliberate_${origin}` };
  }
  if (status === "cancelled") {
    // Cancellation without an operator origin means something else cancelled
    // it, which the operator did not ask for and should hear about.
    return origin
      ? { alertWorthy: true, reason: `cancelled_by_${origin}` }
      : { alertWorthy: false, reason: "cancelled_unknown_origin" };
  }
  if (status === "orphaned_unknown_effect") {
    // Side effects may have landed and cannot be proven either way; this is the
    // one case where inaction risks a half-deployed certificate.
    return { alertWorthy: true, reason: "orphaned_unknown_effect", priority: "high" };
  }
  if (status === "failed" || status === "blocked" || status === "rejected") {
    return { alertWorthy: true, reason: `${status}_${origin || "unknown_origin"}` };
  }
  return { alertWorthy: false, reason: "status_not_alerting" };
}

module.exports = {
  RENEWAL_ALERTING_OPERATIONS,
  TRANSITION_ORIGINS,
  TRANSITION_ORIGIN_VALUES,
  NON_ALERTING_STATUSES,
  HUMAN_DECISION_ORIGINS,
  classifyTerminalTransition,
};

/**
 * CertOps maintenance worker.
 *
 * Architecture conformance (H7): each sweep is an independently configurable
 * unit within this process. The plan calls for independently schedulable
 * scheduler/reaper workers so one slow or failing sweep cannot block the
 * others. Fully separate OS processes are not required by the existing worker
 * runner, but each sweep here has:
 *   - its own enable flag (env var, default enabled)
 *   - its own timeout (env var)
 *   - its own error isolation (failure never prevents other sweeps)
 *   - its own metrics/logging labels
 *
 * Sweeps:
 *   1. Lease reaper: requeue or fail certificate_jobs whose agent lease
 *      expired (claimed/running + lease_expires_at < now()).
 *   2. Stale-agent sweep: mark active agents offline when last_seen_at is
 *      older than CERTOPS_AGENT_OFFLINE_AFTER_MS (observational; never
 *      retires agents).
 *   3. Nonce sweep: delete expired dispatch nonces (jobSigning.js).
 *   4. Registration-replay sweep: delete expired H1 registration replay
 *      rows (registrationCredentialCrypto.js).
 *   5. Renewal scheduler: plan renew jobs for expiring certificates
 *      (apps/api/services/certops/renewalScheduler.js).
 *   6. Diagnostic-agent inactivity sweep: retire diagnostic agents past their
 *      24-hour inactivity TTL via the four-branch orphan-retirement state
 *      machine (apps/api/services/certops/agentRegistry.js, ADR-0012
 *      decision 7).
 *   7. Trust-anchor reconciliation sweep: revalidate/reschedule or report
 *      stale certops_trust_anchor_installations rows past their
 *      next_reconcile_at (apps/api/services/certops/trustAnchors.js,
 *      ADR-0012 decision 20b/20f/20h).
 *
 * Zero-custody: nothing here reads or writes private key material.
 */

import { pool, withClient } from "./db.js";
import { isNodeEntrypoint } from "./is-node-entrypoint.js";
import { warnIfNodeUseEnvProxyUnsupported } from "./proxy-compat-check.js";
import { logger } from "./logger.js";
import { pushMetrics } from "./metrics.js";
import {
  cCertopsSweep,
  gCertopsLeaseReaped,
  gCertopsStaleAgents,
  gCertopsNoncesSwept,
  gCertopsRegistrationReplaysSwept,
  gCertopsRenewalJobsCreated,
  gCertopsRenewalScheduler,
  gCertopsDiagnosticAgentsRetired,
  gCertopsAgentHealthAlerts,
  gCertopsTrustAnchorReconciliation,
} from "./certops-metrics.js";
import { safeInc } from "./shared/safeMetrics.js";
import { createRequire } from "module";
import { randomUUID } from "crypto";

const require = createRequire(import.meta.url);
const { sweepExpiredNonces } = require(
  "../../api/services/certops/jobSigning.js",
);
const { sweepExpiredRegistrationReplays } = require(
  "../../api/services/certops/registrationCredentialCrypto.js",
);
const { runRenewalSchedulerSweep } = require(
  "../../api/services/certops/renewalScheduler.js",
);
const { queueCertRenewalFailedAlert } = require(
  "../../api/services/certops/renewalFailureAlerts.js",
);
const {
  TRANSITION_ORIGINS,
  classifyTerminalTransition,
} = require("../../api/services/certops/renewalAlertPolicy.js");
const { enqueueOutboxEvent } = require(
  "../../api/services/certops/outbox.js",
);
const { ensureDerivedRenewalProfile } = require(
  "../../api/services/certops/renewalProfileDerivation.js",
);
const { writeAudit } = require("../../api/services/audit.js");
// The job status vocabulary comes from the API service, never from a local copy:
// a dry run terminates as 'dry_run_complete' rather than 'succeeded', and
// 'orphaned_unknown_effect' is terminal without being a success, so a restated
// list that drifted would make the drain derive from runs it must not.
// TERMINAL_JOB_STATUSES is not exported, so the terminal set is computed from
// the exported enum through the exported predicate instead of being copied.
const {
  JOB_STATUSES,
  isTerminalJobStatus,
} = require("../../api/services/certops/jobs.js");

const {
  sweepInactiveDiagnosticAgents,
} = require("../../api/services/certops/agentRegistry.js");

const { queueAgentHealthAlert } = require(
  "../../api/services/certops/agentHealthAlerts.js",
);
const { resolveRenewalPathsForWorkspace } = require(
  "../../api/services/certops/renewalPathHealth.js",
);

// ADR-0012 decision 20b/20f/20h: the reconciliation half of the trust-anchor
// state machine (creation/dispatch/result-ingestion live in the API
// service, not this worker).
const {
  sweepOverdueTrustInstallations,
} = require("../../api/services/certops/trustAnchors.js");

// Single source of truth for the 10-minute agent liveness threshold, shared
// with the API's live-read path (agentRegistry.js#computeAgentCompatibility)
// and the agent-health down/recovery alert transition detector
// (agentHealthAlerts.js), so this sweep's persisted `status = 'offline'`
// flip, the dashboard's `livenessState`, and the alert trigger can never
// disagree about when an agent counts as offline.
const {
  DEFAULT_AGENT_OFFLINE_AFTER_MS,
  resolveAgentOfflineAfterMs,
} = require("../../api/services/certops/agentLiveness.js");
export { DEFAULT_AGENT_OFFLINE_AFTER_MS, resolveAgentOfflineAfterMs };

const TERMINAL_JOB_STATUSES = new Set(
  JOB_STATUSES.filter((status) => isTerminalJobStatus(status)),
);

export const DEFAULT_LEASE_REAPER_BATCH_SIZE = 100;
// Hard grace and lease defaults are owned by the API leaseTiming module so
// nonce TTL (B7) and reaper deferral (B6) cannot drift apart.
const {
  DEFAULT_LEASE_HARD_GRACE_MS,
  leaseHardGraceMs,
} = require("../../api/services/certops/leaseTiming.js");
export { DEFAULT_LEASE_HARD_GRACE_MS };
// Exponential backoff for requeued attempts: attempt 1 -> 1m, 2 -> 2m,
// 3 -> 4m, capped at 30m.
const BACKOFF_BASE_MS = 60_000;
const BACKOFF_MAX_MS = 30 * 60_000;

export const DEFAULT_SWEEP_TIMEOUT_MS = 120_000;

/**
 * Per-sweep enable + timeout configuration. Defaults keep all sweeps on so
 * existing deployments behave as before; operators can disable or tighten
 * one unit without touching the others.
 */
export const CERTOPS_SWEEP_CONFIG = Object.freeze({
  "lease-reaper": Object.freeze({
    enableEnv: "CERTOPS_SWEEP_LEASE_REAPER_ENABLED",
    timeoutEnv: "CERTOPS_SWEEP_LEASE_REAPER_TIMEOUT_MS",
  }),
  "stale-agents": Object.freeze({
    enableEnv: "CERTOPS_SWEEP_STALE_AGENTS_ENABLED",
    timeoutEnv: "CERTOPS_SWEEP_STALE_AGENTS_TIMEOUT_MS",
  }),
  "nonce-sweep": Object.freeze({
    enableEnv: "CERTOPS_SWEEP_NONCE_ENABLED",
    timeoutEnv: "CERTOPS_SWEEP_NONCE_TIMEOUT_MS",
  }),
  "registration-replay-sweep": Object.freeze({
    enableEnv: "CERTOPS_SWEEP_REGISTRATION_REPLAY_ENABLED",
    timeoutEnv: "CERTOPS_SWEEP_REGISTRATION_REPLAY_TIMEOUT_MS",
  }),
  "renewal-scheduler": Object.freeze({
    enableEnv: "CERTOPS_SWEEP_RENEWAL_SCHEDULER_ENABLED",
    timeoutEnv: "CERTOPS_SWEEP_RENEWAL_SCHEDULER_TIMEOUT_MS",
  }),
  "outbox-drain": Object.freeze({
    enableEnv: "CERTOPS_SWEEP_OUTBOX_DRAIN_ENABLED",
    timeoutEnv: "CERTOPS_SWEEP_OUTBOX_DRAIN_TIMEOUT_MS",
  }),
  "diagnostic-agent-inactivity-sweep": Object.freeze({
    enableEnv: "CERTOPS_SWEEP_DIAGNOSTIC_AGENT_INACTIVITY_ENABLED",
    timeoutEnv: "CERTOPS_SWEEP_DIAGNOSTIC_AGENT_INACTIVITY_TIMEOUT_MS",
  }),
  "agent-recovery-alerts": Object.freeze({
    enableEnv: "CERTOPS_SWEEP_AGENT_RECOVERY_ALERTS_ENABLED",
    timeoutEnv: "CERTOPS_SWEEP_AGENT_RECOVERY_ALERTS_TIMEOUT_MS",
  }),
  "trust-anchor-reconciliation": Object.freeze({
    enableEnv: "CERTOPS_SWEEP_TRUST_ANCHOR_RECONCILIATION_ENABLED",
    timeoutEnv: "CERTOPS_SWEEP_TRUST_ANCHOR_RECONCILIATION_TIMEOUT_MS",
  }),
});

export const DEFAULT_OUTBOX_DRAIN_BATCH_SIZE = 50;
// Lease window for one outbox row. Long enough for contact resolution plus the
// alert_queue insert, short enough that a crashed worker's rows come back
// within one or two maintenance ticks.
const OUTBOX_LEASE_MS = 60_000;

/**
 * Drain outcomes, as the sweep summary counts them.
 *
 * DEFERRED is the one that had to be added. A row whose work is not possible yet
 * (an adoption intent whose job is still running) is not a failed attempt, and
 * counting it as one made attempt_count meaningless: it was incremented at claim
 * time and never restored, so a row that merely waited burned an attempt per
 * sweep with no backoff. attempt_count and max_attempts now count failed
 * attempts at real work; a sweep that looked and left is DEFERRED, refunds the
 * claim-time increment and sets its own next_retry_at.
 *
 * RETRIED and DEFERRED were also indistinguishable in the summary, which hid
 * exactly this defect: a backlog of transient failures looked identical to a
 * queue of rows patiently waiting.
 */
export const OUTBOX_DRAIN_OUTCOMES = Object.freeze({
  SUCCEEDED: "succeeded",
  SKIPPED: "skipped",
  DEFERRED: "deferred",
  RETRIED: "retried",
  FAILED: "failed",
});

// How long a not-yet-actionable row waits before the drain looks again. A renew
// job takes minutes, so re-examining every sweep is pure noise.
export const DEFAULT_OUTBOX_DEFER_MS = 60_000;

// Wall-clock bound on an adoption intent, independent of attempt_count. A job
// that never terminates (nothing ever claims it, an approval nobody answers)
// would otherwise leave the row cycling for the life of the workspace. Generous
// enough that a real human approval delay is not mistaken for abandonment.
export const DEFAULT_ADOPTION_WAIT_DEADLINE_MS = 72 * 60 * 60 * 1000;

export function resolveAdoptionWaitDeadlineMs(env = process.env) {
  const raw = env.CERTOPS_OUTBOX_ADOPTION_WAIT_DEADLINE_MS;
  if (raw == null || String(raw).trim() === "") {
    return DEFAULT_ADOPTION_WAIT_DEADLINE_MS;
  }
  const parsed = Number.parseInt(String(raw).trim(), 10);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    return DEFAULT_ADOPTION_WAIT_DEADLINE_MS;
  }
  return parsed;
}

/**
 * Terminal skip reasons for an adoption intent, one per decision the lifecycle
 * makes. Every one of them is a deliberate "configure nothing": the reason is
 * persisted so the operator sees which it was rather than an unexplained
 * absence of automation.
 */
export const ADOPTION_SKIP_REASONS = Object.freeze({
  ALREADY_LINKED: "already_linked",
  DETACHED: "detached",
  DRY_RUN: "dry_run",
  JOB_NEVER_TERMINATED: "job_never_terminated",
  JOB_NOT_FOUND: "job_not_found",
  CERTIFICATE_NOT_FOUND: "certificate_not_found",
  NO_CLAIM_BOUND_EVIDENCE: "no_claim_bound_verify_evidence",
  MISSING_CERTIFICATE_ID: "missing_certificate_id",
  MISSING_JOB_ID: "missing_job_id",
  PROFILE_OPERATOR_OWNED: "profile_operator_owned",
  CERTIFICATE_LINK_CONFLICT: "certificate_link_conflict",
});

// Terminal job states that are not a proven successful run. Each is a
// "configure nothing" answer, and each keeps its own reason so an operator can
// tell a rejected approval from a dry run from a run whose effects nobody could
// confirm.
const ADOPTION_NON_SUCCESS_TERMINAL_REASONS = Object.freeze({
  dry_run_complete: ADOPTION_SKIP_REASONS.DRY_RUN,
  failed: "job_failed",
  rejected: "job_rejected",
  cancelled: "job_cancelled",
  blocked: "job_blocked",
  // Its own outcome rather than being lumped with failure: the certificate may
  // in fact have been deployed with nobody able to confirm it, which is exactly
  // the run a renewal profile must not be built from.
  orphaned_unknown_effect: "orphaned_unknown_effect",
});

function deferredOutcome(reason, retryInMs) {
  return {
    deferred: true,
    reason,
    retryInMs,
  };
}

function completedOutcome(terminalStatus, reason) {
  return { completed: true, terminalStatus, reason: reason || null };
}

/**
 * Execute one adoption intent.
 *
 * Owns its own transaction, which is what makes the detach race closable. The
 * transaction begins by re-reading this worker's own outbox row FOR UPDATE and
 * aborts unless it is still pending, and it marks the row terminal before it
 * commits. A detach does the mirror image: it locks the same rows and marks them
 * skipped in the transaction that nulls profile_id. Whichever commits second
 * sees the other's decision, so the derivation happens strictly before the
 * detach or not at all, and no ordering leaves a certificate both detached and
 * profiled.
 */
export async function handleProfileDerivationIntent({
  dbPool,
  row,
  claimId,
  payload = {},
  log = logger,
  deriveProfile = ensureDerivedRenewalProfile,
  deferMs = DEFAULT_OUTBOX_DEFER_MS,
  waitDeadlineMs = DEFAULT_ADOPTION_WAIT_DEADLINE_MS,
  now = () => Date.now(),
} = {}) {
  const certificateId = payload.certificateId
    ? String(payload.certificateId)
    : null;
  if (!certificateId) {
    return {
      queued: false,
      reason: ADOPTION_SKIP_REASONS.MISSING_CERTIFICATE_ID,
    };
  }
  const jobId = payload.jobId ? String(payload.jobId) : null;
  if (!jobId) {
    return { queued: false, reason: ADOPTION_SKIP_REASONS.MISSING_JOB_ID };
  }

  const jobResult = await dbPool.query(
    `SELECT id, status, claim_id, operation, payload
       FROM certificate_jobs
      WHERE workspace_id = $1 AND id = $2::uuid`,
    [row.workspace_id, jobId],
  );
  const job = jobResult.rows[0] || null;
  if (!job) {
    return { queued: false, reason: ADOPTION_SKIP_REASONS.JOB_NOT_FOUND };
  }

  if (!TERMINAL_JOB_STATUSES.has(job.status)) {
    // Waiting, not failing. The intent is created with the job, so the drain
    // normally sees it well before the job finishes.
    const createdAtMs = row.created_at ? new Date(row.created_at).getTime() : NaN;
    const waitedTooLong =
      Number.isFinite(createdAtMs) && now() - createdAtMs > waitDeadlineMs;
    if (waitedTooLong) {
      // A wall-clock bound, not an attempt count: a job nothing ever claims
      // would otherwise leave this row cycling for the life of the workspace.
      return {
        queued: false,
        reason: ADOPTION_SKIP_REASONS.JOB_NEVER_TERMINATED,
      };
    }
    return deferredOutcome(job.status, deferMs);
  }

  const nonSuccessReason = ADOPTION_NON_SUCCESS_TERMINAL_REASONS[job.status];
  if (nonSuccessReason) {
    return { queued: false, reason: nonSuccessReason };
  }

  const client = await dbPool.connect();
  let transactionStarted = false;
  try {
    await client.query("BEGIN");
    transactionStarted = true;

    const ownRow = await client.query(
      `SELECT id, status
         FROM certops_outbox
        WHERE id = $1 AND claim_id = $2::uuid
        FOR UPDATE`,
      [row.id, claimId],
    );
    const current = ownRow.rows[0] || null;
    if (!current || current.status !== "pending") {
      // Either a detach invalidated this intent or the lease was taken over.
      // Both mean this worker no longer owns the decision.
      await client.query("ROLLBACK");
      transactionStarted = false;
      return completedOutcome(
        "skipped",
        current ? ADOPTION_SKIP_REASONS.DETACHED : null,
      );
    }

    // Locked in the same transaction as the outbox row, so a detach cannot
    // slip between reading profile_id here and writing it in derivation.
    const certResult = await client.query(
      `SELECT id, common_name, subject_alt_names, profile_id
         FROM managed_certificates
        WHERE workspace_id = $1 AND id = $2::uuid
        FOR UPDATE`,
      [row.workspace_id, certificateId],
    );
    const certificate = certResult.rows[0] || null;
    if (!certificate) {
      return await completeOwnRow(client, row.id, claimId, {
        status: "skipped",
        reason: ADOPTION_SKIP_REASONS.CERTIFICATE_NOT_FOUND,
      });
    }
    if (certificate.profile_id) {
      return await completeOwnRow(client, row.id, claimId, {
        status: "skipped",
        reason: ADOPTION_SKIP_REASONS.ALREADY_LINKED,
      });
    }

    // Derive only from a run that provably worked, bound to the attempt that
    // reported it. Evidence from an earlier attempt describes a certificate a
    // previous run deployed, so it cannot stand in for this one.
    const evidence = await client.query(
      `SELECT metadata
         FROM certificate_evidence
        WHERE workspace_id = $1
          AND job_id = $2
          AND evidence_type = 'validation.passed'
          AND claim_id = $3::uuid
          AND metadata->>'step' = 'verify'
        ORDER BY created_at DESC
        LIMIT 1`,
      [row.workspace_id, jobId, job.claim_id],
    );
    if (!evidence.rows[0]?.metadata) {
      return await completeOwnRow(client, row.id, claimId, {
        status: "skipped",
        reason: ADOPTION_SKIP_REASONS.NO_CLAIM_BOUND_EVIDENCE,
      });
    }

    const derivation = await deriveProfile({
      client,
      workspaceId: row.workspace_id,
      certificateId,
      payload: job.payload || {},
      certificate: {
        commonName: certificate.common_name,
        subjectAltNames: Array.isArray(certificate.subject_alt_names)
          ? certificate.subject_alt_names
          : [],
      },
      logger: log,
    });

    if (derivation?.profileId) {
      return await completeOwnRow(client, row.id, claimId, {
        status: "succeeded",
        reason: null,
      });
    }

    // An operator-owned profile is a decision, not a fault: retrying cannot
    // change the answer, so the row goes terminal with the reason preserved.
    if (derivation?.reason === "profile_operator_owned") {
      return await completeOwnRow(client, row.id, claimId, {
        status: "skipped",
        reason: ADOPTION_SKIP_REASONS.PROFILE_OPERATOR_OWNED,
      });
    }
    if (derivation?.reason === "already_linked") {
      return await completeOwnRow(client, row.id, claimId, {
        status: "skipped",
        reason: ADOPTION_SKIP_REASONS.ALREADY_LINKED,
      });
    }
    if (derivation?.reason === "certificate_link_conflict") {
      return await completeOwnRow(client, row.id, claimId, {
        status: "skipped",
        reason: ADOPTION_SKIP_REASONS.CERTIFICATE_LINK_CONFLICT,
      });
    }

    // Anything else is a derivation failure. Derivation never throws for one, so
    // the throw happens here: it is transient until max_attempts says otherwise,
    // and the message is what the operator eventually reads.
    await client.query("ROLLBACK");
    transactionStarted = false;
    const failure = new Error(
      derivation?.error ||
        `Renewal profile could not be derived (${derivation?.reason || "unknown"})`,
    );
    failure.code = derivation?.reason || "derivation_failed";
    throw failure;
  } catch (error) {
    if (transactionStarted) {
      try {
        await client.query("ROLLBACK");
      } catch (_) {
        // Preserve the primary failure for the drain's retry path.
      }
    }
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Mark this worker's own outbox row terminal inside the handler's transaction
 * and commit. Terminal status and side effect become one atomic fact, which the
 * loop's separate post-handler write could not provide.
 */
async function completeOwnRow(client, id, claimId, { status, reason }) {
  await client.query(
    `UPDATE certops_outbox
        SET status = $1,
            outcome_reason = $2,
            claim_id = NULL,
            claimed_until = NULL,
            updated_at = NOW()
      WHERE id = $3 AND claim_id = $4::uuid`,
    [status, reason || null, id, claimId],
  );
  await client.query("COMMIT");
  return completedOutcome(status, reason);
}

export function computeBackoffMs(attemptCount) {
  const attempt = Math.max(1, attemptCount);
  return Math.min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * 2 ** (attempt - 1));
}

function parseBoolEnv(raw, defaultValue = true) {
  if (raw == null || String(raw).trim() === "") return defaultValue;
  const normalized = String(raw).trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return defaultValue;
}

export function isSweepEnabled(sweepName, env = process.env) {
  const config = CERTOPS_SWEEP_CONFIG[sweepName];
  if (!config) return true;
  return parseBoolEnv(env[config.enableEnv], true);
}

export function resolveSweepTimeoutMs(sweepName, env = process.env) {
  const config = CERTOPS_SWEEP_CONFIG[sweepName];
  const raw = config ? env[config.timeoutEnv] : undefined;
  if (raw == null || String(raw).trim() === "") {
    return DEFAULT_SWEEP_TIMEOUT_MS;
  }
  const parsed = Number.parseInt(String(raw).trim(), 10);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    return DEFAULT_SWEEP_TIMEOUT_MS;
  }
  return parsed;
}

// appendCertificateJobLog (jobs.js) accepts a client, but it re-checks job
// existence with an extra query per row and runs API-facing normalizers.
// Inside the reaper's row-locked transaction a plain insert matching the
// certificate_job_log schema (migrate.js) is equivalent and avoids redundant
// round trips; the event types and statuses used here are legal per the
// table CHECK constraints.
async function insertJobLog(
  client,
  jobRow,
  { eventType, status, message, metadata },
) {
  await client.query(
    `INSERT INTO certificate_job_log (
       workspace_id, job_id, event_type, status, message, metadata
     )
     VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
    [
      jobRow.workspace_id,
      jobRow.id,
      eventType,
      status,
      message,
      JSON.stringify(metadata || {}),
    ],
  );
}

/**
 * Lease reaper. One guarded transaction: expired-lease rows are picked with
 * FOR UPDATE SKIP LOCKED so concurrent reapers (or the claim path) never
 * double-process a row.
 *
 * Requeue policy (B6):
 * - Never renewed (lease_renewed_at IS NULL and status still 'claimed'):
 *   no side effects proven → safe to requeue when the agent is gone or the
 *   hard grace has elapsed.
 * - Renewed (lease_renewed_at set) or status 'running': side effects may
 *   have happened → NEVER silent requeue. Defer while the agent is alive
 *   within hard grace (late result may still land); otherwise mark
 *   orphaned_unknown_effect with needs_operator_reconciliation for
 *   manual reconciliation (not an ordinary failed/policy rejection).
 * Requeue does not touch attempt_count: the claim path already counted this
 * dispatch attempt.
 *
 * Every non-requeue terminal write (orphaned_unknown_effect, or failed with
 * retry budget exhausted) also writes a CERTOPS_JOB_FAILED audit event, in
 * the same transaction as the status update. This mirrors what
 * agentDispatch.js does for agent-reported terminal failures, so the
 * reconciliation runbook's audit-log search (Step 1) finds a lease-reaped
 * job exactly the way it finds one reported by an agent - the job row itself
 * only ever keeps the latest error, so this is the only durable per-attempt
 * trail.
 */
export async function reapExpiredLeases({
  client,
  batchSize = DEFAULT_LEASE_REAPER_BATCH_SIZE,
  offlineAfterMs = DEFAULT_AGENT_OFFLINE_AFTER_MS,
  hardGraceMs = DEFAULT_LEASE_HARD_GRACE_MS,
  log = logger,
  recordOutboxEvent = enqueueOutboxEvent,
  auditWriter = writeAudit,
} = {}) {
  const summary = { scanned: 0, requeued: 0, failed: 0, deferred: 0 };

  await client.query("BEGIN");
  try {
    const expired = await client.query(
      `SELECT cj.id, cj.workspace_id, cj.status, cj.attempt_count,
              cj.max_attempts, cj.operation, cj.subject_type, cj.subject_id,
              cj.lease_renewed_at,
              (ca.id IS NOT NULL
                AND ca.status = 'active'
                AND COALESCE(ca.last_seen_at, ca.created_at)
                      >= NOW() - ($2 || ' milliseconds')::interval
              ) AS agent_alive,
              (cj.lease_expires_at
                < NOW() - ($3 || ' milliseconds')::interval
              ) AS past_hard_grace
         FROM certificate_jobs cj
         LEFT JOIN certops_agents ca ON ca.id = cj.claimed_by_agent_id
        WHERE cj.status IN ('claimed', 'running')
          AND cj.executor_kind = 'agent'
          AND cj.lease_expires_at IS NOT NULL
          AND cj.lease_expires_at < NOW()
        ORDER BY cj.lease_expires_at ASC
        LIMIT $1
        FOR UPDATE OF cj SKIP LOCKED`,
      [batchSize, String(offlineAfterMs), String(hardGraceMs)],
    );
    summary.scanned = expired.rows.length;

    for (const row of expired.rows) {
      const attemptCount = row.attempt_count ?? 0;
      const maxAttempts = row.max_attempts ?? 3;
      const sideEffectsPossible =
        row.status === "running" || row.lease_renewed_at != null;
      const hasRetryBudget =
        !sideEffectsPossible &&
        row.status === "claimed" &&
        attemptCount < maxAttempts;

      if (row.agent_alive && !row.past_hard_grace) {
        // Agent still heartbeating inside the hard grace: give it time to
        // renew the lease or report a result. Leave the row untouched.
        summary.deferred += 1;
        continue;
      }

      if (hasRetryBudget) {
        // Never renewed / no side effects proven: safe automatic requeue.
        const backoffMs = computeBackoffMs(attemptCount);
        await client.query(
          `UPDATE certificate_jobs
              SET status = 'pending',
                  claimed_by_agent_id = NULL,
                  claim_id = NULL,
                  lease_expires_at = NULL,
                  lease_renewed_at = NULL,
                  next_attempt_at = NOW() + ($2 || ' milliseconds')::interval,
                  updated_at = NOW()
            WHERE id = $1`,
          [row.id, String(backoffMs)],
        );
        await insertJobLog(client, row, {
          eventType: "job.status_updated",
          status: "pending",
          message:
            "Lease expired before any renew; job requeued by the certops " +
            "maintenance worker (no side effects proven)",
          metadata: {
            sweep: "lease-reaper",
            outcome: "requeued",
            attemptCount,
            maxAttempts,
            backoffMs,
          },
        });
        summary.requeued += 1;
      } else if (sideEffectsPossible) {
        // Renewed close to a side-effect boundary: effects unknown. Never
        // silently requeue; mark orphaned for operator reconciliation.
        const errorCode = "effects_unknown";
        const reconciliationReason =
          "lease_expired_after_side_effect_window_agent_unresponsive";
        await client.query(
          `UPDATE certificate_jobs
              SET status = 'orphaned_unknown_effect',
                  error_code = $2,
                  error_message =
                    'Lease expired after renew; side effects are unknown and require manual reconciliation',
                  needs_operator_reconciliation = TRUE,
                  reconciliation_reason = $3,
                  claimed_by_agent_id = NULL,
                  claim_id = NULL,
                  lease_expires_at = NULL,
                  completed_at = COALESCE(completed_at, NOW()),
                  updated_at = NOW()
            WHERE id = $1`,
          [row.id, errorCode, reconciliationReason],
        );
        await insertJobLog(client, row, {
          eventType: "job.failed",
          status: "orphaned_unknown_effect",
          message:
            "Lease expired after renew; job marked orphaned_unknown_effect " +
            "for manual reconciliation by the certops maintenance worker",
          metadata: {
            sweep: "lease-reaper",
            outcome: "orphaned_unknown_effect",
            errorCode,
            reconciliationReason,
            attemptCount,
            maxAttempts,
            previousStatus: row.status,
          },
        });
        summary.failed += 1;

        // The reconciliation runbook's Step 1 searches the audit log for
        // CERTOPS_JOB_FAILED with needsOperatorReconciliation=true as the
        // durable trail for this outcome (the job row itself only ever holds
        // the latest error). Written here so a lease-reaped job is just as
        // discoverable that way as one that failed via agent-reported result
        // ingestion (agentDispatch.js).
        await auditWriter({
          client,
          actorUserId: null,
          subjectUserId: null,
          action: "CERTOPS_JOB_FAILED",
          targetType: "certificate_job",
          targetId: null,
          workspaceId: row.workspace_id,
          metadata: {
            jobId: String(row.id),
            operation: row.operation || null,
            jobStatus: "orphaned_unknown_effect",
            source: "lease-reaper",
            errorCode,
            subjectType: row.subject_type || null,
            subjectId: row.subject_id ? String(row.subject_id) : null,
            needsOperatorReconciliation: true,
            reconciliationReason,
          },
        });

        // Side effects may have landed and cannot be proven either way, so this
        // is the one reaper outcome an operator must always hear about. Recorded
        // in the outbox inside the reaper's transaction: the job's terminal
        // status and the intent to notify commit together.
        const classification = classifyTerminalTransition({
          operation: row.operation,
          status: "orphaned_unknown_effect",
          origin: TRANSITION_ORIGINS.LEASE_REAPER,
        });
        if (classification.alertWorthy) {
          await recordOutboxEvent({
            client,
            workspaceId: row.workspace_id,
            eventType: "renewal_alert_requested",
            dedupeKey: String(row.id),
            payload: {
              jobId: String(row.id),
              operation: row.operation,
              jobStatus: "orphaned_unknown_effect",
              origin: TRANSITION_ORIGINS.LEASE_REAPER,
              classificationReason: classification.reason,
              priority: classification.priority || null,
              errorCode,
              subjectType: row.subject_type || null,
              subjectId: row.subject_id ? String(row.subject_id) : null,
            },
          });
        }
      } else {
        // Never renewed but retry budget exhausted (or non-claimable state).
        const errorCode = row.agent_alive ? "lease_expired" : "agent_offline";
        await client.query(
          `UPDATE certificate_jobs
              SET status = 'failed',
                  error_code = $2,
                  error_message = 'Agent lease expired and the job cannot be retried',
                  claimed_by_agent_id = NULL,
                  claim_id = NULL,
                  lease_expires_at = NULL,
                  lease_renewed_at = NULL,
                  completed_at = COALESCE(completed_at, NOW()),
                  updated_at = NOW()
            WHERE id = $1`,
          [row.id, errorCode],
        );
        await insertJobLog(client, row, {
          eventType: "job.failed",
          status: "failed",
          message:
            `Lease expired; job failed as ${errorCode} by the certops ` +
            "maintenance worker",
          metadata: {
            sweep: "lease-reaper",
            outcome: "failed",
            errorCode,
            attemptCount,
            maxAttempts,
            previousStatus: row.status,
          },
        });
        summary.failed += 1;

        await auditWriter({
          client,
          actorUserId: null,
          subjectUserId: null,
          action: "CERTOPS_JOB_FAILED",
          targetType: "certificate_job",
          targetId: null,
          workspaceId: row.workspace_id,
          metadata: {
            jobId: String(row.id),
            operation: row.operation || null,
            jobStatus: "failed",
            source: "lease-reaper",
            errorCode,
            subjectType: row.subject_type || null,
            subjectId: row.subject_id ? String(row.subject_id) : null,
            needsOperatorReconciliation: false,
            reconciliationReason: null,
          },
        });

        const classification = classifyTerminalTransition({
          operation: row.operation,
          status: "failed",
          origin: TRANSITION_ORIGINS.LEASE_REAPER,
        });
        if (classification.alertWorthy) {
          await recordOutboxEvent({
            client,
            workspaceId: row.workspace_id,
            eventType: "renewal_alert_requested",
            dedupeKey: String(row.id),
            payload: {
              jobId: String(row.id),
              operation: row.operation,
              jobStatus: "failed",
              origin: TRANSITION_ORIGINS.LEASE_REAPER,
              classificationReason: classification.reason,
              priority: classification.priority || null,
              errorCode,
              subjectType: row.subject_type || null,
              subjectId: row.subject_id ? String(row.subject_id) : null,
            },
          });
        }
      }
    }

    await client.query("COMMIT");
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (_) {
      log.debug?.("certops lease reaper rollback failed");
    }
    throw error;
  }

  return summary;
}

/**
 * Builds a per-agent impact resolver that shares ONE
 * `resolveRenewalPathsForWorkspace` call across every agent transitioning in
 * the same workspace during the same sweep tick, rather than one full
 * workspace resolve per agent (calling `listCertificatesDependentOnAgent`
 * directly, once per stale agent, would do exactly that -- O(agents)
 * workspace resolves). A
 * network partition or host-level outage can take an entire fleet segment
 * stale in one tick; without batching, N simultaneously-stale agents in one
 * workspace cost N full certificate+agent re-resolutions in that same tick,
 * which is the worst possible moment for the worker to be slow.
 *
 * The shared projection is computed once per (workspace, resolver instance)
 * on first access via a memoized promise, so concurrent callers for the same
 * workspace within one sweep tick await the same in-flight query rather than
 * issuing their own. Callers that commit an agent-status change between
 * resolutions invalidate that workspace before the next lookup; otherwise a
 * later agent would inherit a projection computed before its own transition.
 * A fresh resolver must be constructed per sweep tick
 * (see callers below) so the projection always reflects that tick's
 * just-written agent statuses, never a stale cross-tick cache.
 */
function createBatchedImpactResolver({ client, log = logger } = {}) {
  const workspaceProjections = new Map();
  const projectionFor = (workspaceId) => {
    if (!workspaceProjections.has(workspaceId)) {
      workspaceProjections.set(
        workspaceId,
        resolveRenewalPathsForWorkspace({ db: client, workspaceId }),
      );
    }
    return workspaceProjections.get(workspaceId);
  };
  const resolver = async function resolveImpactedCertificatesBatched(agent) {
    try {
      const targetAgentRowId = String(agent.id);
      const all = await projectionFor(agent.workspaceId);
      return all
        .filter(
          (entry) =>
            entry.renewalPathState != null &&
            entry.dependencies.some((dep) => dep.agentRowId === targetAgentRowId),
        )
        .map((entry) => ({
          id: entry.certificateId,
          commonName: entry.commonName,
          renewalPathState: entry.renewalPathState,
        }));
    } catch (err) {
      log.error("certops-agent-impact-resolve-failed", {
        agentId: agent.agentId,
        error: err.message,
      });
      return [];
    }
  };
  resolver.invalidateWorkspace = (workspaceId) => {
    workspaceProjections.delete(workspaceId);
  };
  return resolver;
}

/**
 * Stale-agent sweep. certops_agents statuses are 'active'/'offline'/'retired'
 * (Migration 24); 'offline' is a legal status, so stale active agents are
 * marked offline. An agent that registered but never heartbeated is judged
 * on its created_at, so it cannot stay displayed 'active' forever.
 * Recovery back to 'active' happens on the agent's next authenticated poll
 * (owned by the API heartbeat/claim paths). Retirement is never automated:
 * offline is observational fleet status only.
 */
/**
 * Marks agents offline past the liveness threshold and queues exactly one
 * agent_health down alert per agent that just crossed the edge (transition,
 * not level: only rows this UPDATE actually flips are candidates, so a
 * worker tick that finds nothing new to flip queues nothing).
 * Each candidate owns a separate transaction: its guarded offline UPDATE,
 * durable incident, and alert intent commit atomically, while a failure for
 * one agent cannot roll back an unrelated agent that already committed.
 *
 * `resolveImpactedCertificates` defaults to `createBatchedImpactResolver`,
 * which resolves each workspace's full
 * renewal-path dependency projection at most once per sweep tick (shared
 * across every agent transitioning in that workspace this tick) and embeds
 * the dependent auto-renew certificates for each agent from it. Tests that
 * don't care about enrichment can override it with a stub.
 */
export async function sweepStaleAgents({
  client,
  offlineAfterMs,
  log = logger,
  resolveImpactedCertificates = createBatchedImpactResolver({ client, log }),
  alertQueuer = queueAgentHealthAlert,
} = {}) {
  const candidatesResult = await client.query(
    `SELECT id, agent_id, workspace_id, name, hostname, platform,
            last_seen_at, downtime_alerts_enabled, contact_group_id
       FROM certops_agents
      WHERE status = 'active'
        AND COALESCE(last_seen_at, created_at)
              < NOW() - ($1 || ' milliseconds')::interval
      ORDER BY workspace_id, id`,
    [String(offlineAfterMs)],
  );
  const candidates = candidatesResult.rows.map((row) => ({
    id: row.id,
    agentId: row.agent_id,
    workspaceId: row.workspace_id,
    name: row.name,
    hostname: row.hostname,
    platform: row.platform,
    lastSeenAt: row.last_seen_at,
    downtimeAlertsEnabled: row.downtime_alerts_enabled,
    contactGroupId: row.contact_group_id,
  }));

  const staleAgents = [];
  const failures = [];
  let alertsQueued = 0;
  for (const candidate of candidates) {
    let transactionStarted = false;
    try {
      await client.query("BEGIN");
      transactionStarted = true;
      const transition = await client.query(
        `UPDATE certops_agents
            SET status = 'offline',
                updated_at = NOW()
          WHERE id = $2
            AND workspace_id = $3
            AND status = 'active'
            AND COALESCE(last_seen_at, created_at)
                  < NOW() - ($1 || ' milliseconds')::interval
          RETURNING id, agent_id, workspace_id, name, hostname, platform,
                    last_seen_at, downtime_alerts_enabled, contact_group_id`,
        [String(offlineAfterMs), candidate.id, candidate.workspaceId],
      );
      if (transition.rows.length === 0) {
        await client.query("COMMIT");
        transactionStarted = false;
        continue;
      }

      const row = transition.rows[0];
      const agent = {
        id: row.id,
        agentId: row.agent_id,
        workspaceId: row.workspace_id,
        name: row.name,
        hostname: row.hostname,
        platform: row.platform,
        lastSeenAt: row.last_seen_at,
        downtimeAlertsEnabled: row.downtime_alerts_enabled,
        contactGroupId: row.contact_group_id,
      };
      // Resolve after the guarded status flip so the shared renewal-path
      // resolver observes this agent as offline even when deployments use a
      // non-default liveness threshold. Only this agent's row is locked;
      // unrelated agents are no longer coupled to this work.
      resolveImpactedCertificates.invalidateWorkspace?.(agent.workspaceId);
      const impactedCertificates = await resolveImpactedCertificates(agent);
      // Build the alert key in JS. Embedding `$1::text` in the same statement
      // as a UUID column bind made Postgres reject the query with
      // "inconsistent types deduced for parameter $1".
      await client.query(
        `INSERT INTO certops_agent_health_incidents (
           agent_id, workspace_id, opened_at, last_seen_at, down_alert_key
         ) VALUES ($1, $2, NOW(), $3, $4)
         ON CONFLICT (agent_id) DO NOTHING`,
        [
          agent.id,
          agent.workspaceId,
          agent.lastSeenAt,
          `agent_health:${agent.id}:down`,
        ],
      );
      const outcome = await alertQueuer({
        client,
        agent,
        transitionType: "down",
        impactedCertificates,
        offlineAfterMs,
      });
      if (outcome.queued) alertsQueued += 1;
      await client.query("COMMIT");
      transactionStarted = false;
      staleAgents.push(agent);
    } catch (error) {
      if (transactionStarted) {
        try {
          await client.query("ROLLBACK");
        } catch (_rollbackError) {
          // Preserve the transition/alert failure.
        }
      }
      failures.push(error);
      log.error("certops-stale-agent-transition-failed", {
        agentId: candidate.agentId,
        error: error.message,
      });
    }
  }

  if (staleAgents.length > 0) {
    log.warn("certops-stale-agents-detected", {
      count: staleAgents.length,
      offlineAfterMs,
      agentIds: staleAgents.map((agent) => agent.agentId),
    });
  }

  if (failures.length > 0) {
    const error = new AggregateError(
      failures,
      `CertOps stale-agent sweep failed for ${failures.length} agent(s): ${failures[0].message}`,
    );
    error.code = "CERTOPS_AGENT_HEALTH_PARTIAL_FAILURE";
    throw error;
  }
  return { staleCount: staleAgents.length, staleAgents, alertsQueued };
}

/**
 * Recovery counterpart to the down alert above. Runs against
 * currently-active agents rather than a status transition the SQL layer can
 * see directly: the flip back to 'active' happens on the agent's own
 * heartbeat/claim call (agentDispatch.js), not in this worker, so recovery
 * is detected from the durable incident row created atomically with the
 * offline transition. The alert queue is delivery state, not incident state.
 * Candidate discovery is read-only; each incident is then rechecked and
 * locked in its own transaction so recovery intent/deletion remains atomic
 * without coupling unrelated agents' outcomes.
 */
export async function sweepAgentRecoveries({
  client,
  log = logger,
  resolveImpactedCertificates = createBatchedImpactResolver({ client, log }),
  alertQueuer = queueAgentHealthAlert,
} = {}) {
  const result = await client.query(
    `SELECT a.id, a.agent_id, a.workspace_id, a.name, a.hostname, a.platform,
            a.last_seen_at, a.downtime_alerts_enabled, a.contact_group_id
       FROM certops_agents a
       JOIN certops_agent_health_incidents i ON i.agent_id = a.id
      WHERE a.status = 'active'
      ORDER BY a.workspace_id, a.id`,
  );

  const candidates = result.rows.map((row) => ({
    id: row.id,
    agentId: row.agent_id,
    workspaceId: row.workspace_id,
    name: row.name,
    hostname: row.hostname,
    platform: row.platform,
    lastSeenAt: row.last_seen_at,
    downtimeAlertsEnabled: row.downtime_alerts_enabled,
    contactGroupId: row.contact_group_id,
  }));

  const failures = [];
  let alertsQueued = 0;
  for (const candidate of candidates) {
    let transactionStarted = false;
    try {
      const impactedCertificates = await resolveImpactedCertificates(candidate);
      await client.query("BEGIN");
      transactionStarted = true;
      const locked = await client.query(
        `SELECT a.id, a.agent_id, a.workspace_id, a.name, a.hostname, a.platform,
                a.last_seen_at, a.downtime_alerts_enabled, a.contact_group_id
           FROM certops_agents a
           JOIN certops_agent_health_incidents i ON i.agent_id = a.id
          WHERE a.id = $1
            AND a.workspace_id = $2
            AND a.status = 'active'
          FOR UPDATE OF i`,
        [candidate.id, candidate.workspaceId],
      );
      if (locked.rows.length === 0) {
        await client.query("COMMIT");
        transactionStarted = false;
        continue;
      }
      const row = locked.rows[0];
      const agent = {
        id: row.id,
        agentId: row.agent_id,
        workspaceId: row.workspace_id,
        name: row.name,
        hostname: row.hostname,
        platform: row.platform,
        lastSeenAt: row.last_seen_at,
        downtimeAlertsEnabled: row.downtime_alerts_enabled,
        contactGroupId: row.contact_group_id,
      };
      const outcome = await alertQueuer({
        client,
        agent,
        transitionType: "recovered",
        impactedCertificates,
      });
      if (outcome.queued) alertsQueued += 1;
      if (outcome.retry !== true) {
        await client.query(
          `DELETE FROM certops_agent_health_incidents
            WHERE agent_id = $1 AND workspace_id = $2`,
          [agent.id, agent.workspaceId],
        );
      }
      await client.query("COMMIT");
      transactionStarted = false;
    } catch (error) {
      if (transactionStarted) {
        try {
          await client.query("ROLLBACK");
        } catch (_rollbackError) {
          // Preserve the transition/alert failure.
        }
      }
      failures.push(error);
      log.error("certops-agent-recovery-transition-failed", {
        agentId: candidate.agentId,
        error: error.message,
      });
    }
  }

  if (failures.length > 0) {
    const error = new AggregateError(
      failures,
      `CertOps agent-recovery sweep failed for ${failures.length} agent(s): ${failures[0].message}`,
    );
    error.code = "CERTOPS_AGENT_HEALTH_PARTIAL_FAILURE";
    throw error;
  }
  return { candidateCount: candidates.length, alertsQueued };
}

async function withTimeout(promise, timeoutMs, sweepName) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          const error = new Error(
            `CertOps sweep ${sweepName} timed out after ${timeoutMs}ms`,
          );
          error.code = "CERTOPS_SWEEP_TIMEOUT";
          reject(error);
        }, timeoutMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function runIsolated(name, log, fn, { enabled = true, timeoutMs } = {}) {
  if (!enabled) {
    safeInc(cCertopsSweep, { sweep: name, status: "skipped" });
    log.info?.("certops-sweep-skipped", { sweep: name, reason: "disabled" });
    return { name, status: "skipped", result: null };
  }

  const startedAt = Date.now();
  try {
    const result = await withTimeout(fn(), timeoutMs, name);
    safeInc(cCertopsSweep, { sweep: name, status: "success" });
    log.info?.("certops-sweep-complete", {
      sweep: name,
      status: "success",
      durationMs: Date.now() - startedAt,
      timeoutMs,
    });
    return { name, status: "success", result };
  } catch (error) {
    safeInc(cCertopsSweep, { sweep: name, status: "failure" });
    log.error("certops-sweep-failure", {
      sweep: name,
      error: error?.message,
      stack: error?.stack,
      code: error?.code,
      durationMs: Date.now() - startedAt,
      timeoutMs,
    });
    return { name, status: "failed", error };
  }
}

/**
 * Outbox drain. Executes intents recorded by the transactions that decided
 * them (terminal job transitions, successful reconciliations, operator adoption
 * requests).
 *
 * Each row is claimed under an owner-scoped lease and every terminal write is
 * conditional on that claim id, so a second worker taking over an expired lease
 * turns the first worker's late writes into no-ops. Claim-then-commit applies:
 * the claim commits before any resolution work, so row locks are never held
 * across the alert pipeline.
 *
 * Retry policy distinguishes three outcomes that look similar but are not:
 * - A resolver that returns "not queued" for a structural reason (no linked
 *   token, no contacts configured) is DONE. Retrying cannot change the answer,
 *   so the row goes terminal as 'skipped' with the reason preserved.
 * - A resolver that reports the work is not possible YET has not attempted
 *   anything. The row stays pending with its own next_retry_at and the
 *   claim-time attempt increment refunded, so waiting never consumes the retry
 *   budget that exists for failures.
 * - A thrown error is transient until proven otherwise, so the row is retried
 *   with backoff until max_attempts, then parked as 'failed' for an operator.
 *
 * A handler may also own its transaction and complete its own row inside it, in
 * which case the loop records the outcome and writes nothing. Marking a row
 * terminal in a separate statement after the handler returned leaves a window
 * where the side effect is committed and the row is not; the alert handler
 * tolerates that, an adoption intent cannot.
 */
export async function drainCertOpsOutbox({
  dbPool = pool,
  batchSize = DEFAULT_OUTBOX_DRAIN_BATCH_SIZE,
  log = logger,
  env = process.env,
  alertResolver = queueCertRenewalFailedAlert,
  derivationResolver = handleProfileDerivationIntent,
} = {}) {
  const summary = {
    scanned: 0,
    [OUTBOX_DRAIN_OUTCOMES.SUCCEEDED]: 0,
    [OUTBOX_DRAIN_OUTCOMES.SKIPPED]: 0,
    [OUTBOX_DRAIN_OUTCOMES.DEFERRED]: 0,
    [OUTBOX_DRAIN_OUTCOMES.RETRIED]: 0,
    [OUTBOX_DRAIN_OUTCOMES.FAILED]: 0,
  };
  const claimId = randomUUID();
  const waitDeadlineMs = resolveAdoptionWaitDeadlineMs(env);

  const claimed = await dbPool.query(
    `WITH due AS (
       SELECT id
         FROM certops_outbox
        WHERE status = 'pending'
          AND next_retry_at <= NOW()
          AND (claimed_until IS NULL OR claimed_until < NOW())
        ORDER BY next_retry_at ASC
        LIMIT $1
        FOR UPDATE SKIP LOCKED
     )
     UPDATE certops_outbox o
        SET claim_id = $2::uuid,
            claimed_until = NOW() + ($3 || ' milliseconds')::interval,
            attempt_count = o.attempt_count + 1,
            updated_at = NOW()
       FROM due
      WHERE o.id = due.id
      RETURNING o.id, o.workspace_id, o.event_type, o.dedupe_key, o.payload,
                o.attempt_count, o.max_attempts, o.created_at`,
    [batchSize, claimId, String(OUTBOX_LEASE_MS)],
  );
  summary.scanned = claimed.rows.length;

  for (const row of claimed.rows) {
    const payload =
      row.payload && typeof row.payload === "object" ? row.payload : {};
    try {
      let outcome = { queued: false, reason: "unsupported_event_type" };

      if (row.event_type === "renewal_alert_requested") {
        outcome = await alertResolver({
          client: dbPool,
          jobId: payload.jobId || row.dedupe_key,
          workspaceId: row.workspace_id,
          errorCode: payload.errorCode || null,
        });
      } else if (row.event_type === "profile_derivation_requested") {
        outcome = await derivationResolver({
          dbPool,
          row,
          claimId,
          payload,
          log,
          waitDeadlineMs,
        });
      }

      if (outcome?.deferred) {
        await deferOutboxRow(dbPool, row.id, claimId, outcome.retryInMs);
        summary.deferred += 1;
        log.debug?.("certops-outbox-event-deferred", {
          outboxId: String(row.id),
          eventType: row.event_type,
          reason: outcome.reason || null,
        });
        continue;
      }

      if (outcome?.completed) {
        // The handler already wrote the terminal status inside its own
        // transaction; a second write here could only contradict it.
        if (outcome.terminalStatus === "succeeded") summary.succeeded += 1;
        else summary.skipped += 1;
        continue;
      }

      const terminalStatus = outcome?.queued ? "succeeded" : "skipped";
      await dbPool.query(
        `UPDATE certops_outbox
            SET status = $1,
                outcome_reason = $2,
                claim_id = NULL,
                claimed_until = NULL,
                updated_at = NOW()
          WHERE id = $3 AND claim_id = $4::uuid`,
        [terminalStatus, outcome?.reason || null, row.id, claimId],
      );
      if (terminalStatus === "succeeded") summary.succeeded += 1;
      else summary.skipped += 1;
    } catch (error) {
      const exhausted = row.attempt_count >= row.max_attempts;
      await dbPool.query(
        `UPDATE certops_outbox
            SET status = CASE WHEN $1 THEN 'failed' ELSE 'pending' END,
                last_error = $2,
                next_retry_at = NOW() + ($3 || ' milliseconds')::interval,
                claim_id = NULL,
                claimed_until = NULL,
                updated_at = NOW()
          WHERE id = $4 AND claim_id = $5::uuid`,
        [
          exhausted,
          String(error?.message || "unknown").slice(0, 2048),
          String(computeBackoffMs(row.attempt_count)),
          row.id,
          claimId,
        ],
      );
      if (exhausted) {
        summary.failed += 1;
        log.error?.("certops-outbox-event-exhausted", {
          outboxId: String(row.id),
          eventType: row.event_type,
          dedupeKey: row.dedupe_key,
          attemptCount: row.attempt_count,
          error: error?.message,
        });
      } else {
        summary.retried += 1;
        log.warn?.("certops-outbox-event-retry", {
          outboxId: String(row.id),
          eventType: row.event_type,
          attemptCount: row.attempt_count,
          error: error?.message,
        });
      }
    }
  }

  return summary;
}

/**
 * Reschedule a row whose work is not possible yet.
 *
 * Three things, all required. The lease is released so another sweep can pick
 * the row up; next_retry_at is moved forward, without which the row is
 * re-claimed on the very next tick; and the claim-time attempt increment is
 * refunded, without which a row that merely waited would burn its whole retry
 * budget and eventually be parked as failed for never having failed at
 * anything.
 */
async function deferOutboxRow(dbPool, id, claimId, retryInMs) {
  const delayMs =
    Number.isSafeInteger(retryInMs) && retryInMs > 0
      ? retryInMs
      : DEFAULT_OUTBOX_DEFER_MS;
  await dbPool.query(
    `UPDATE certops_outbox
        SET claim_id = NULL,
            claimed_until = NULL,
            attempt_count = GREATEST(0, attempt_count - 1),
            next_retry_at = NOW() + ($3 || ' milliseconds')::interval,
            updated_at = NOW()
      WHERE id = $1 AND claim_id = $2::uuid`,
    [id, claimId, String(delayMs)],
  );
}

function safeGaugeSet(gauge, labelsOrValue, maybeValue) {
  try {
    if (maybeValue === undefined) gauge.set(labelsOrValue);
    else gauge.set(labelsOrValue, maybeValue);
  } catch (_) {
    logger.debug("Metrics recording failed", { metric: gauge?.name });
  }
}

export async function runCertOpsMaintenance({
  env = process.env,
  log = logger,
  withClientFn = withClient,
  dbPool = pool,
  nonceSweeper = sweepExpiredNonces,
  registrationReplaySweeper = sweepExpiredRegistrationReplays,
  renewalSweeper = runRenewalSchedulerSweep,
  outboxDrainer = drainCertOpsOutbox,
  diagnosticAgentSweeper = sweepInactiveDiagnosticAgents,
  pushMetricsFn = pushMetrics,
} = {}) {
  log.info("CertOps maintenance worker started");
  const offlineAfterMs = resolveAgentOfflineAfterMs(env);

  const results = {};

  results.leaseReaper = await runIsolated(
    "lease-reaper",
    log,
    () =>
      withClientFn((client) =>
        reapExpiredLeases({
          client,
          offlineAfterMs,
          hardGraceMs: leaseHardGraceMs(env),
          log,
        }),
      ),
    {
      enabled: isSweepEnabled("lease-reaper", env),
      timeoutMs: resolveSweepTimeoutMs("lease-reaper", env),
    },
  );
  if (results.leaseReaper.status === "success") {
    const { requeued, failed } = results.leaseReaper.result;
    safeGaugeSet(gCertopsLeaseReaped, { outcome: "requeued" }, requeued);
    safeGaugeSet(gCertopsLeaseReaped, { outcome: "failed" }, failed);
  }

  results.staleAgents = await runIsolated(
    "stale-agents",
    log,
    () =>
      withClientFn((client) =>
        sweepStaleAgents({ client, offlineAfterMs, log }),
      ),
    {
      enabled: isSweepEnabled("stale-agents", env),
      timeoutMs: resolveSweepTimeoutMs("stale-agents", env),
    },
  );
  if (results.staleAgents.status === "success") {
    safeGaugeSet(gCertopsStaleAgents, results.staleAgents.result.staleCount);
    safeGaugeSet(
      gCertopsAgentHealthAlerts,
      { transition: "down" },
      results.staleAgents.result.alertsQueued,
    );
  }

  results.agentRecoveryAlerts = await runIsolated(
    "agent-recovery-alerts",
    log,
    () => withClientFn((client) => sweepAgentRecoveries({ client, log })),
    {
      enabled: isSweepEnabled("agent-recovery-alerts", env),
      timeoutMs: resolveSweepTimeoutMs("agent-recovery-alerts", env),
    },
  );
  if (results.agentRecoveryAlerts.status === "success") {
    safeGaugeSet(
      gCertopsAgentHealthAlerts,
      { transition: "recovered" },
      results.agentRecoveryAlerts.result.alertsQueued,
    );
  }

  results.nonceSweep = await runIsolated(
    "nonce-sweep",
    log,
    async () => {
      const deleted = await nonceSweeper({ client: dbPool });
      return { deleted };
    },
    {
      enabled: isSweepEnabled("nonce-sweep", env),
      timeoutMs: resolveSweepTimeoutMs("nonce-sweep", env),
    },
  );
  if (results.nonceSweep.status === "success") {
    safeGaugeSet(gCertopsNoncesSwept, results.nonceSweep.result.deleted);
  }

  results.registrationReplaySweep = await runIsolated(
    "registration-replay-sweep",
    log,
    async () => {
      const deleted = await registrationReplaySweeper({ client: dbPool });
      return { deleted };
    },
    {
      enabled: isSweepEnabled("registration-replay-sweep", env),
      timeoutMs: resolveSweepTimeoutMs("registration-replay-sweep", env),
    },
  );
  if (results.registrationReplaySweep.status === "success") {
    safeGaugeSet(
      gCertopsRegistrationReplaysSwept,
      results.registrationReplaySweep.result.deleted,
    );
  }

  results.renewalScheduler = await runIsolated(
    "renewal-scheduler",
    log,
    () => renewalSweeper({ dbPool, env, logger: log }),
    {
      enabled: isSweepEnabled("renewal-scheduler", env),
      timeoutMs: resolveSweepTimeoutMs("renewal-scheduler", env),
    },
  );
  if (results.renewalScheduler.status === "success") {
    const summary = results.renewalScheduler.result;
    safeGaugeSet(gCertopsRenewalJobsCreated, summary.created);
    // Export the skip reasons too, not just the successes. Without these a
    // fleet whose certificates all lack a renewal profile looks identical to an
    // idle one, which is exactly the failure mode that lets certificates expire
    // unnoticed.
    for (const [outcome, value] of [
      ["scanned", summary.scanned],
      ["created", summary.created],
      ["replayed", summary.replayed],
      ["skipped_paused", summary.skippedPaused],
      ["skipped_ca_cap", summary.skippedByCaCap],
      ["skipped_incomplete_profile", summary.skippedIncompleteProfile],
      ["skipped_not_agent_deployable", summary.skippedNotAgentDeployable],
      ["skipped_auto_renew_disabled", summary.skippedAutoRenewDisabled],
      ["errors", summary.errors?.length ?? 0],
    ]) {
      safeGaugeSet(gCertopsRenewalScheduler, { outcome }, value ?? 0);
    }
  }

  results.outboxDrain = await runIsolated(
    "outbox-drain",
    log,
    () => outboxDrainer({ dbPool, log, env }),
    {
      enabled: isSweepEnabled("outbox-drain", env),
      timeoutMs: resolveSweepTimeoutMs("outbox-drain", env),
    },
  );

  // ADR-0012 decision 7: this sweep is the only path that retires a
  // diagnostic agent past its 24-hour inactivity TTL. It is deliberately
  // separate from the stale-agents sweep above: that one only ever flips
  // status to 'offline' and never retires anything, for any agent kind.
  results.diagnosticAgentInactivitySweep = await runIsolated(
    "diagnostic-agent-inactivity-sweep",
    log,
    async () => {
      const outcomes = await diagnosticAgentSweeper({ dbPool, env });
      const retired = outcomes.filter((o) => o.retired).length;
      const deferred = outcomes.filter((o) => o.deferred).length;
      const errors = outcomes.filter((o) => o.error).length;
      return { candidates: outcomes.length, retired, deferred, errors };
    },
    {
      enabled: isSweepEnabled("diagnostic-agent-inactivity-sweep", env),
      timeoutMs: resolveSweepTimeoutMs(
        "diagnostic-agent-inactivity-sweep",
        env,
      ),
    },
  );
  if (results.diagnosticAgentInactivitySweep.status === "success") {
    const { retired, deferred, errors } =
      results.diagnosticAgentInactivitySweep.result;
    safeGaugeSet(gCertopsDiagnosticAgentsRetired, { outcome: "retired" }, retired);
    safeGaugeSet(gCertopsDiagnosticAgentsRetired, { outcome: "deferred" }, deferred);
    safeGaugeSet(gCertopsDiagnosticAgentsRetired, { outcome: "error" }, errors);
  }

  // ADR-0012 decision 20b/20f/20h: revalidates/reschedules or marks stale a
  // pending certops_trust_anchor_installations row; never signs or
  // dispatches a job itself (that's agentDispatch.claimJobs's job).
  results.trustAnchorReconciliation = await runIsolated(
    "trust-anchor-reconciliation",
    log,
    () => sweepOverdueTrustInstallations({ dbPool }),
    {
      enabled: isSweepEnabled("trust-anchor-reconciliation", env),
      timeoutMs: resolveSweepTimeoutMs("trust-anchor-reconciliation", env),
    },
  );
  if (results.trustAnchorReconciliation.status === "success") {
    const { unwound, rescheduled, markedStale } =
      results.trustAnchorReconciliation.result;
    safeGaugeSet(
      gCertopsTrustAnchorReconciliation,
      { outcome: "unwound" },
      unwound,
    );
    safeGaugeSet(
      gCertopsTrustAnchorReconciliation,
      { outcome: "rescheduled" },
      rescheduled,
    );
    safeGaugeSet(
      gCertopsTrustAnchorReconciliation,
      { outcome: "marked_stale" },
      markedStale,
    );
  }

  log.info("CertOps maintenance worker finished", {
    leaseReaper:
      results.leaseReaper.status === "success"
        ? results.leaseReaper.result
        : results.leaseReaper.status,
    staleAgents:
      results.staleAgents.status === "success"
        ? results.staleAgents.result.staleCount
        : results.staleAgents.status,
    noncesSwept:
      results.nonceSweep.status === "success"
        ? results.nonceSweep.result.deleted
        : results.nonceSweep.status,
    registrationReplaysSwept:
      results.registrationReplaySweep.status === "success"
        ? results.registrationReplaySweep.result.deleted
        : results.registrationReplaySweep.status,
    renewalScheduler:
      results.renewalScheduler.status === "success"
        ? results.renewalScheduler.result
        : results.renewalScheduler.status,
    outboxDrain:
      results.outboxDrain.status === "success"
        ? results.outboxDrain.result
        : results.outboxDrain.status,
    diagnosticAgentInactivitySweep:
      results.diagnosticAgentInactivitySweep.status === "success"
        ? results.diagnosticAgentInactivitySweep.result
        : results.diagnosticAgentInactivitySweep.status,
    agentRecoveryAlerts:
      results.agentRecoveryAlerts.status === "success"
        ? results.agentRecoveryAlerts.result
        : results.agentRecoveryAlerts.status,
    trustAnchorReconciliation:
      results.trustAnchorReconciliation.status === "success"
        ? results.trustAnchorReconciliation.result
        : results.trustAnchorReconciliation.status,
  });

  await pushMetricsFn("certops").catch((e) =>
    log.warn("Failed to push metrics", { error: e.message }),
  );

  return results;
}

if (isNodeEntrypoint(import.meta.url)) {
  warnIfNodeUseEnvProxyUnsupported();
  void (async () => {
    try {
      await runCertOpsMaintenance();
      await pool.end();
      process.exit(0);
    } catch (error) {
      logger.error("CertOps maintenance worker fatal error", {
        error: error.message,
        stack: error.stack,
      });
      try {
        await pool.end();
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }
      process.exit(1);
    }
  })();
}

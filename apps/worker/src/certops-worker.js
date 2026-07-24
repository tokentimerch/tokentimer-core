/**
 * CertOps maintenance worker.
 *
 * One scheduled run executes three isolated sweeps plus the renewal
 * scheduler; a failure in one sweep never prevents the others:
 *   1. Lease reaper: requeue or fail certificate_jobs whose agent lease
 *      expired (claimed/running + lease_expires_at < now()).
 *   2. Stale-agent sweep: mark active agents offline when last_seen_at is
 *      older than CERTOPS_AGENT_OFFLINE_AFTER_MS (observational; never
 *      retires agents).
 *   3. Nonce sweep: delete expired dispatch nonces (jobSigning.js).
 *   4. Renewal scheduler: plan renew jobs for expiring certificates
 *      (apps/api/services/certops/renewalScheduler.js).
 *
 * Zero-custody: nothing here reads or writes private key material.
 */

import { pool, withClient } from "./db.js";
import { isNodeEntrypoint } from "./is-node-entrypoint.js";
import { logger } from "./logger.js";
import { pushMetrics } from "./metrics.js";
import {
  cCertopsSweep,
  gCertopsLeaseReaped,
  gCertopsStaleAgents,
  gCertopsNoncesSwept,
  gCertopsRenewalJobsCreated,
} from "./certops-metrics.js";
import { safeInc } from "./shared/safeMetrics.js";
import { createRequire } from "module";

const require = createRequire(import.meta.url);
const { sweepExpiredNonces } = require(
  "../../api/services/certops/jobSigning.js",
);
const { runRenewalSchedulerSweep } = require(
  "../../api/services/certops/renewalScheduler.js",
);
const { queueCertRenewalFailedAlert } = require(
  "../../api/services/certops/renewalFailureAlerts.js",
);

export const DEFAULT_AGENT_OFFLINE_AFTER_MS = 10 * 60 * 1000;
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

export function resolveAgentOfflineAfterMs(env = process.env) {
  const raw = env.CERTOPS_AGENT_OFFLINE_AFTER_MS;
  if (raw == null || String(raw).trim() === "") {
    return DEFAULT_AGENT_OFFLINE_AFTER_MS;
  }
  const parsed = Number.parseInt(String(raw).trim(), 10);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    return DEFAULT_AGENT_OFFLINE_AFTER_MS;
  }
  return parsed;
}

export function computeBackoffMs(attemptCount) {
  const attempt = Math.max(1, attemptCount);
  return Math.min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * 2 ** (attempt - 1));
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
 *   within hard grace (late result may still land); otherwise fail as
 *   effects_unknown for manual reconciliation.
 * Requeue does not touch attempt_count: the claim path already counted this
 * dispatch attempt.
 */
export async function reapExpiredLeases({
  client,
  batchSize = DEFAULT_LEASE_REAPER_BATCH_SIZE,
  offlineAfterMs = DEFAULT_AGENT_OFFLINE_AFTER_MS,
  hardGraceMs = DEFAULT_LEASE_HARD_GRACE_MS,
  log = logger,
  queueRenewalFailedAlert = queueCertRenewalFailedAlert,
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
        // silently requeue; leave for manual reconciliation.
        const errorCode = "effects_unknown";
        await client.query(
          `UPDATE certificate_jobs
              SET status = 'failed',
                  error_code = $2,
                  error_message =
                    'Lease expired after renew; side effects are unknown and require manual reconciliation',
                  claimed_by_agent_id = NULL,
                  claim_id = NULL,
                  lease_expires_at = NULL,
                  completed_at = COALESCE(completed_at, NOW()),
                  updated_at = NOW()
            WHERE id = $1`,
          [row.id, errorCode],
        );
        await insertJobLog(client, row, {
          eventType: "job.failed",
          status: "failed",
          message:
            "Lease expired after renew; job failed as effects_unknown for " +
            "manual reconciliation by the certops maintenance worker",
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

        if (row.operation === "renew") {
          try {
            await client.query("SAVEPOINT certops_renewal_alert");
            const alertOutcome = await queueRenewalFailedAlert({
              client,
              job: row,
              workspaceId: row.workspace_id,
              errorCode,
            });
            await client.query("RELEASE SAVEPOINT certops_renewal_alert");
            if (!alertOutcome?.queued) {
              log.warn?.("certops-renewal-failed-alert-skipped", {
                jobId: String(row.id),
                reason: alertOutcome?.reason || "unknown",
              });
            }
          } catch (alertErr) {
            try {
              await client.query(
                "ROLLBACK TO SAVEPOINT certops_renewal_alert",
              );
            } catch (_rollbackErr) {
              // Savepoint may not exist if SAVEPOINT itself failed.
            }
            log.warn?.("certops-renewal-failed-alert-error", {
              jobId: String(row.id),
              error: alertErr?.message,
            });
          }
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

        if (row.operation === "renew") {
          try {
            await client.query("SAVEPOINT certops_renewal_alert");
            const alertOutcome = await queueRenewalFailedAlert({
              client,
              job: row,
              workspaceId: row.workspace_id,
              errorCode,
            });
            await client.query("RELEASE SAVEPOINT certops_renewal_alert");
            if (!alertOutcome?.queued) {
              log.warn?.("certops-renewal-failed-alert-skipped", {
                jobId: String(row.id),
                reason: alertOutcome?.reason || "unknown",
              });
            }
          } catch (alertErr) {
            try {
              await client.query(
                "ROLLBACK TO SAVEPOINT certops_renewal_alert",
              );
            } catch (_rollbackErr) {
              // Savepoint may not exist if SAVEPOINT itself failed.
            }
            log.warn?.("certops-renewal-failed-alert-error", {
              jobId: String(row.id),
              error: alertErr?.message,
            });
          }
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
 * Stale-agent sweep. certops_agents statuses are 'active'/'offline'/'retired'
 * (Migration 24); 'offline' is a legal status, so stale active agents are
 * marked offline. An agent that registered but never heartbeated is judged
 * on its created_at, so it cannot stay displayed 'active' forever.
 * Recovery back to 'active' happens on the agent's next authenticated poll
 * (owned by the API heartbeat/claim paths). Retirement is never automated:
 * offline is observational fleet status only.
 */
export async function sweepStaleAgents({
  client,
  offlineAfterMs,
  log = logger,
} = {}) {
  const result = await client.query(
    `UPDATE certops_agents
        SET status = 'offline',
            updated_at = NOW()
      WHERE status = 'active'
        AND COALESCE(last_seen_at, created_at)
              < NOW() - ($1 || ' milliseconds')::interval
      RETURNING id, agent_id, workspace_id, last_seen_at`,
    [String(offlineAfterMs)],
  );

  const staleAgents = result.rows.map((row) => ({
    id: row.id,
    agentId: row.agent_id,
    workspaceId: row.workspace_id,
    lastSeenAt: row.last_seen_at,
  }));

  if (staleAgents.length > 0) {
    log.warn("certops-stale-agents-detected", {
      count: staleAgents.length,
      offlineAfterMs,
      agentIds: staleAgents.map((agent) => agent.agentId),
    });
  }

  return { staleCount: staleAgents.length, staleAgents };
}

async function runIsolated(name, log, fn) {
  try {
    const result = await fn();
    safeInc(cCertopsSweep, { sweep: name, status: "success" });
    return { name, status: "success", result };
  } catch (error) {
    safeInc(cCertopsSweep, { sweep: name, status: "failure" });
    log.error("certops-sweep-failure", {
      sweep: name,
      error: error?.message,
      stack: error?.stack,
    });
    return { name, status: "failed", error };
  }
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
  renewalSweeper = runRenewalSchedulerSweep,
  pushMetricsFn = pushMetrics,
} = {}) {
  log.info("CertOps maintenance worker started");
  const offlineAfterMs = resolveAgentOfflineAfterMs(env);

  const results = {};

  results.leaseReaper = await runIsolated("lease-reaper", log, () =>
    withClientFn((client) =>
      reapExpiredLeases({
        client,
        offlineAfterMs,
        hardGraceMs: leaseHardGraceMs(env),
        log,
      }),
    ),
  );
  if (results.leaseReaper.status === "success") {
    const { requeued, failed } = results.leaseReaper.result;
    safeGaugeSet(gCertopsLeaseReaped, { outcome: "requeued" }, requeued);
    safeGaugeSet(gCertopsLeaseReaped, { outcome: "failed" }, failed);
  }

  results.staleAgents = await runIsolated("stale-agents", log, () =>
    withClientFn((client) =>
      sweepStaleAgents({ client, offlineAfterMs, log }),
    ),
  );
  if (results.staleAgents.status === "success") {
    safeGaugeSet(gCertopsStaleAgents, results.staleAgents.result.staleCount);
  }

  results.nonceSweep = await runIsolated("nonce-sweep", log, async () => {
    const deleted = await nonceSweeper({ client: dbPool });
    return { deleted };
  });
  if (results.nonceSweep.status === "success") {
    safeGaugeSet(gCertopsNoncesSwept, results.nonceSweep.result.deleted);
  }

  results.renewalScheduler = await runIsolated("renewal-scheduler", log, () =>
    renewalSweeper({ dbPool, env, logger: log }),
  );
  if (results.renewalScheduler.status === "success") {
    safeGaugeSet(
      gCertopsRenewalJobsCreated,
      results.renewalScheduler.result.created,
    );
  }

  log.info("CertOps maintenance worker finished", {
    leaseReaper:
      results.leaseReaper.status === "success"
        ? results.leaseReaper.result
        : "failed",
    staleAgents:
      results.staleAgents.status === "success"
        ? results.staleAgents.result.staleCount
        : "failed",
    noncesSwept:
      results.nonceSweep.status === "success"
        ? results.nonceSweep.result.deleted
        : "failed",
    renewalScheduler:
      results.renewalScheduler.status === "success"
        ? results.renewalScheduler.result
        : "failed",
  });

  await pushMetricsFn("certops").catch((e) =>
    log.warn("Failed to push metrics", { error: e.message }),
  );

  return results;
}

if (isNodeEntrypoint(import.meta.url)) {
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

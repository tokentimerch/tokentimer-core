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
// An expired lease held by an agent that is still heartbeating is deferred
// (the agent is likely still executing and will report). After this hard
// grace past lease expiry the job is failed WITHOUT requeue, because the
// silent-but-alive agent may have executed side effects.
export const DEFAULT_LEASE_HARD_GRACE_MS = 60 * 60 * 1000;
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
  "renewal-scheduler": Object.freeze({
    enableEnv: "CERTOPS_SWEEP_RENEWAL_SCHEDULER_ENABLED",
    timeoutEnv: "CERTOPS_SWEEP_RENEWAL_SCHEDULER_TIMEOUT_MS",
  }),
});

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
 * Requeue policy: a 'claimed' job with retry budget is requeued ONLY when
 * the claiming agent is provably gone (offline/retired/deleted or silent
 * past offlineAfterMs). If the agent is still heartbeating, the job may
 * still be executing, so it is deferred until the hard grace elapses and
 * then failed WITHOUT requeue (the agent may have executed side effects;
 * replaying could double-execute them). A 'running' job is never requeued
 * for the same reason. Requeue does not touch attempt_count: the claim
 * path already counted this dispatch attempt.
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
      const hasRetryBudget =
        row.status === "claimed" && attemptCount < maxAttempts;

      if (hasRetryBudget && row.agent_alive && !row.past_hard_grace) {
        // The claiming agent is still heartbeating: it is probably still
        // executing this job and will report. Leave the row untouched;
        // the next sweep re-evaluates it against the hard grace.
        summary.deferred += 1;
        continue;
      }

      if (hasRetryBudget && !row.agent_alive) {
        const backoffMs = computeBackoffMs(attemptCount);
        await client.query(
          `UPDATE certificate_jobs
              SET status = 'pending',
                  claimed_by_agent_id = NULL,
                  claim_id = NULL,
                  lease_expires_at = NULL,
                  next_attempt_at = NOW() + ($2 || ' milliseconds')::interval,
                  updated_at = NOW()
            WHERE id = $1`,
          [row.id, String(backoffMs)],
        );
        await insertJobLog(client, row, {
          eventType: "job.status_updated",
          status: "pending",
          message:
            "Lease expired with the claiming agent gone; job requeued by " +
            "the certops maintenance worker",
          metadata: {
            sweep: "lease-reaper",
            outcome: "requeued",
            attemptCount,
            maxAttempts,
            backoffMs,
          },
        });
        summary.requeued += 1;
      } else {
        // Running jobs, exhausted retry budgets, and alive-but-silent
        // agents past the hard grace all fail without requeue.
        const errorCode = row.agent_alive ? "lease_expired" : "agent_offline";
        await client.query(
          `UPDATE certificate_jobs
              SET status = 'failed',
                  error_code = $2,
                  error_message = 'Agent lease expired and the job cannot be retried',
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

        // A terminal failure of a renew job queues a cert_renewal_failed
        // alert. Best-effort inside a savepoint so an alert failure never
        // aborts the reaper transaction.
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

  results.leaseReaper = await runIsolated(
    "lease-reaper",
    log,
    () =>
      withClientFn((client) =>
        reapExpiredLeases({ client, offlineAfterMs, log }),
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
    safeGaugeSet(
      gCertopsRenewalJobsCreated,
      results.renewalScheduler.result.created,
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
    renewalScheduler:
      results.renewalScheduler.status === "success"
        ? results.renewalScheduler.result
        : results.renewalScheduler.status,
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

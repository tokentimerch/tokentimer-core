"use strict";

/**
 * CertOps renewal scheduler.
 *
 * Scans managed_certificates approaching expiry and creates automation-source
 * renew jobs. Every job creation runs inside a transaction gated by
 * lockWorkspaceForCertOpsSideEffect, so paused workspaces and the global
 * rollout flag are respected (skipped, never errored). Reruns are idempotent:
 * the idempotency key is derived from the certificate id and its not_after
 * timestamp, and certificates that already have a non-terminal renew job for
 * the same subject are skipped before any insert is attempted.
 *
 * Zero-custody: this module only reads public inventory metadata and writes
 * public job payload fields. It never touches private key material.
 */

const { pool } = require("../../db/database");
const { createCertificateJob, isTerminalJobStatus } = require("./jobs");
const {
  CERTOPS_WORKSPACE_PAUSED,
  lockWorkspaceForCertOpsSideEffect,
} = require("./workspaceKillSwitch");
const { CERTOPS_DISABLED } = require("./settings");

const DEFAULT_RENEWAL_THRESHOLD_DAYS = 30;
const DEFAULT_BATCH_SIZE = 200;
const RENEWAL_THRESHOLD_ENV = "CERTOPS_RENEWAL_THRESHOLD_DAYS";

// Inventory statuses that never get automated renewal jobs.
const NON_RENEWABLE_CERTIFICATE_STATUSES = Object.freeze([
  "revoked",
  "decommissioned",
]);

function resolveRenewalThresholdDays(env = process.env) {
  const raw = env[RENEWAL_THRESHOLD_ENV];
  if (raw == null || String(raw).trim() === "") {
    return DEFAULT_RENEWAL_THRESHOLD_DAYS;
  }
  const parsed = Number.parseInt(String(raw).trim(), 10);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    return DEFAULT_RENEWAL_THRESHOLD_DAYS;
  }
  return parsed;
}

/**
 * Stable idempotency key: cert id + not_after epoch. A renewed certificate
 * gets a new not_after, so the next expiry window produces a new key while
 * reruns within the same window replay the same job.
 */
function renewalIdempotencyKey(certificateId, notAfter) {
  const epoch = new Date(notAfter).getTime();
  return `certops-renewal:${certificateId}:${epoch}`;
}

/**
 * Certificates due for renewal: managed, expiring within the threshold, not
 * retired, and without an existing non-terminal renew job for the same
 * subject. terminalStatuses is derived from jobs.js isTerminalJobStatus so
 * the SQL dedupe stays aligned with the service's terminal set.
 */
async function findCertificatesDueForRenewal({
  db = pool,
  thresholdDays,
  batchSize = DEFAULT_BATCH_SIZE,
  terminalStatuses,
} = {}) {
  const result = await db.query(
    `SELECT mc.id,
            mc.workspace_id,
            mc.common_name,
            mc.not_after,
            mc.key_mode,
            cp.renew_before_days AS profile_renew_before_days
       FROM managed_certificates mc
       LEFT JOIN certificate_profiles cp
         ON cp.workspace_id = mc.workspace_id AND cp.id = mc.profile_id
      WHERE mc.not_after IS NOT NULL
        AND mc.not_after <= NOW()
              + (COALESCE(cp.renew_before_days, $1) || ' days')::interval
        AND mc.status NOT IN (${NON_RENEWABLE_CERTIFICATE_STATUSES.map(
          (status) => `'${status}'`,
        ).join(", ")})
        AND NOT EXISTS (
          SELECT 1
            FROM certificate_jobs cj
           WHERE cj.workspace_id = mc.workspace_id
             AND cj.operation = 'renew'
             AND cj.subject_type = 'managed_certificate'
             AND cj.subject_id = mc.id::text
             AND NOT (cj.status = ANY($2::text[]))
        )
      ORDER BY mc.not_after ASC
      LIMIT $3`,
    [String(thresholdDays), terminalStatuses, batchSize],
  );
  return result.rows;
}

async function createRenewalJobForCertificate({
  dbPool,
  certificate,
  jobCreator,
  env,
}) {
  const client = await dbPool.connect();
  let transactionStarted = false;
  try {
    await client.query("BEGIN");
    transactionStarted = true;

    // Kill-switch gate inside the same transaction as the insert. Paused or
    // globally disabled workspaces throw here; the caller converts that into
    // a skip, never an error.
    await lockWorkspaceForCertOpsSideEffect({
      client,
      workspaceId: certificate.workspace_id,
      env,
    });

    const payload = {
      certificateId: String(certificate.id),
      notAfter: new Date(certificate.not_after).toISOString(),
      reason: "expiry-threshold",
    };
    // The inventory schema records no dedicated keyRotationPolicy column, so
    // the payload keyRotation execution field is only set when key_mode
    // policy data exists and the agent holds the key locally (the only modes
    // where the agent could rotate). Otherwise it is omitted entirely.
    if (
      certificate.key_mode === "agent-local" ||
      certificate.key_mode === "proxy-agent-local"
    ) {
      payload.keyRotation = false;
    }

    const outcome = await jobCreator({
      client,
      workspaceId: certificate.workspace_id,
      operation: "renew",
      source: "automation",
      status: "pending",
      subjectType: "managed_certificate",
      subjectId: String(certificate.id),
      idempotencyKey: renewalIdempotencyKey(
        certificate.id,
        certificate.not_after,
      ),
      payload,
      returnOutcome: true,
    });

    await client.query("COMMIT");
    transactionStarted = false;
    const job = outcome?.job || outcome;
    return { job, created: outcome?.created === true };
  } catch (error) {
    if (transactionStarted) {
      try {
        await client.query("ROLLBACK");
      } catch (_) {
        // Preserve the primary failure for the caller.
      }
    }
    throw error;
  } finally {
    client.release();
  }
}

/**
 * One renewal-planning pass. Returns a summary:
 * { thresholdDays, scanned, created, replayed, skippedPaused, errors }.
 */
async function runRenewalSchedulerSweep({
  dbPool = pool,
  env = process.env,
  jobCreator = createCertificateJob,
  batchSize = DEFAULT_BATCH_SIZE,
  logger = null,
} = {}) {
  const thresholdDays = resolveRenewalThresholdDays(env);
  const terminalStatuses = [
    "rejected",
    "succeeded",
    "failed",
    "blocked",
    "cancelled",
  ].filter(isTerminalJobStatus);

  const dueCertificates = await findCertificatesDueForRenewal({
    db: dbPool,
    thresholdDays,
    batchSize,
    terminalStatuses,
  });

  const summary = {
    thresholdDays,
    scanned: dueCertificates.length,
    created: 0,
    replayed: 0,
    skippedPaused: 0,
    errors: [],
  };

  for (const certificate of dueCertificates) {
    try {
      const { created } = await createRenewalJobForCertificate({
        dbPool,
        certificate,
        jobCreator,
        env,
      });
      if (created) summary.created += 1;
      else summary.replayed += 1;
    } catch (error) {
      if (
        error?.code === CERTOPS_WORKSPACE_PAUSED ||
        error?.code === CERTOPS_DISABLED
      ) {
        summary.skippedPaused += 1;
        continue;
      }
      summary.errors.push({
        certificateId: String(certificate.id),
        error: error?.message || String(error),
      });
      if (logger?.error) {
        logger.error("certops-renewal-scheduler-cert-failure", {
          certificateId: String(certificate.id),
          error: error?.message,
        });
      }
    }
  }

  return summary;
}

module.exports = {
  DEFAULT_RENEWAL_THRESHOLD_DAYS,
  RENEWAL_THRESHOLD_ENV,
  findCertificatesDueForRenewal,
  renewalIdempotencyKey,
  resolveRenewalThresholdDays,
  runRenewalSchedulerSweep,
};

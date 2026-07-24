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
 * B1/H6: Before creating a job the scheduler resolves a complete, validated
 * renewal-profile snapshot (target, cert path, SANs, ACME command/profile,
 * DNS provider+zone, key/CA/verification settings) from
 * certificate_profiles.public_metadata.renewalProfile. Certificates lacking
 * a complete profile are refused (logged/alerted) and never produce a job
 * an agent cannot execute. The snapshot is bound into the job payload so
 * approval and dispatch hash an immutable contract.
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
const {
  CERTOPS_RENEWAL_PROFILE_INCOMPLETE,
  CERTOPS_RENEWAL_PROFILE_INVALID,
  buildRenewalJobPayload,
} = require("./renewalProfile");

const DEFAULT_RENEWAL_THRESHOLD_DAYS = 30;
const DEFAULT_BATCH_SIZE = 200;
const RENEWAL_THRESHOLD_ENV = "CERTOPS_RENEWAL_THRESHOLD_DAYS";
const DEFAULT_RENEWAL_PER_CA_CAP = 5;
const RENEWAL_PER_CA_CAP_ENV = "CERTOPS_RENEWAL_PER_CA_CAP";

// Certificates without a resolvable caEndpoint share this bucket, so a flood
// of endpoint-less renewals is still capped instead of being unbounded.
const UNKNOWN_CA_BUCKET = "__unknown-ca__";

// Advisory lock key for the sweep (single-flight across workers). Any
// constant bigint works; this one is arbitrary but must stay stable.
const RENEWAL_SCHEDULER_ADVISORY_LOCK_KEY = 7_384_211_257_001n;

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
 * Max renewal jobs that may be in flight per CA endpoint at sweep time.
 * Same env pattern as resolveRenewalThresholdDays: blank/invalid values fall
 * back to the default.
 */
function resolveRenewalPerCaCap(env = process.env) {
  const raw = env[RENEWAL_PER_CA_CAP_ENV];
  if (raw == null || String(raw).trim() === "") {
    return DEFAULT_RENEWAL_PER_CA_CAP;
  }
  const parsed = Number.parseInt(String(raw).trim(), 10);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    return DEFAULT_RENEWAL_PER_CA_CAP;
  }
  return parsed;
}

/**
 * True when a metadata caEndpoint value would pass the execution-field
 * validation in jobs.js (http/https URL, <= 512 chars). Invalid values are
 * still used for cap bucketing but never stamped onto job payloads.
 */
function isValidCaEndpointUrl(value) {
  if (typeof value !== "string" || value.length > 512) return false;
  let parsed;
  try {
    parsed = new URL(value);
  } catch (_error) {
    return false;
  }
  return parsed.protocol === "https:" || parsed.protocol === "http:";
}

/**
 * Canonical form of a CA endpoint for cap bucketing, so the same CA never
 * lands in two buckets because of representation differences (case in the
 * scheme/host, default ports, trailing slashes, query/fragment noise).
 * Non-URL strings are lowercased+trimmed as-is; empty input maps to the
 * unknown-CA bucket. Used for BOTH sides of the cap comparison (due
 * certificates and in-flight job counts); the raw (un-normalized but valid)
 * URL is still what gets stamped on job payloads.
 */
function normalizeCaBucket(value) {
  if (typeof value !== "string") return UNKNOWN_CA_BUCKET;
  const trimmed = value.trim();
  if (trimmed === "" || trimmed === UNKNOWN_CA_BUCKET) return UNKNOWN_CA_BUCKET;
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch (_error) {
    return trimmed.toLowerCase();
  }
  const pathname = parsed.pathname.replace(/\/+$/, "");
  // URL already lowercases protocol/hostname and drops default ports.
  return `${parsed.protocol}//${parsed.host}${pathname}`;
}

/**
 * CA bucket for a due certificate: the caEndpoint recorded in the
 * certificate's public metadata, falling back to its profile's public
 * metadata / renewalProfile.ca.endpoint, else the shared unknown-CA bucket.
 * Normalized for bucketing.
 */
function certificateCaBucket(certificate) {
  const candidates = [
    certificate?.certificate_ca_endpoint,
    certificate?.profile_ca_endpoint,
  ];
  for (const candidate of candidates) {
    if (typeof candidate === "string" && candidate.trim() !== "") {
      return normalizeCaBucket(candidate);
    }
  }
  return UNKNOWN_CA_BUCKET;
}

/**
 * Raw (un-normalized) caEndpoint candidate for stamping on job payloads.
 * Kept separate from certificateCaBucket so payloads carry the operator's
 * exact URL while cap accounting uses the canonical bucket.
 */
function certificateCaEndpointRaw(certificate) {
  const candidates = [
    certificate?.certificate_ca_endpoint,
    certificate?.profile_ca_endpoint,
  ];
  for (const candidate of candidates) {
    if (typeof candidate === "string" && candidate.trim() !== "") {
      return candidate.trim();
    }
  }
  return null;
}

/**
 * Composite cap-accounting key: caps are per (workspace, CA), never global,
 * so one tenant's renewal backlog can never starve another tenant sharing
 * the same public CA.
 */
function caCapKey(workspaceId, caBucket) {
  return `${workspaceId}::${caBucket}`;
}

/**
 * Point-in-time snapshot of in-flight renewal jobs keyed by
 * (workspace, normalized CA bucket). Jobs without a payload caEndpoint land
 * in the unknown-CA bucket. Normalization happens here in JS with the SAME
 * normalizeCaBucket used for due certificates, so both sides of the cap
 * comparison agree. The sweep itself is single-flight (advisory lock in
 * runRenewalSchedulerSweep) and locally increments this map for jobs it
 * creates, so the snapshot stays consistent for the duration of a sweep; a
 * concurrent manual job at worst delays a renewal by one sweep.
 */
async function countInFlightRenewalJobsByCaEndpoint({
  db = pool,
  terminalStatuses,
} = {}) {
  const result = await db.query(
    `SELECT cj.workspace_id,
            NULLIF(BTRIM(cj.payload->>'caEndpoint'), '') AS ca_endpoint,
            COUNT(*)::int AS in_flight
       FROM certificate_jobs cj
      WHERE cj.operation = 'renew'
        AND NOT (cj.status = ANY($1::text[]))
      GROUP BY 1, 2`,
    [terminalStatuses],
  );
  const counts = new Map();
  for (const row of result.rows || []) {
    const bucket =
      row.ca_endpoint == null
        ? UNKNOWN_CA_BUCKET
        : normalizeCaBucket(row.ca_endpoint);
    const key = caCapKey(row.workspace_id, bucket);
    counts.set(key, (counts.get(key) || 0) + (Number(row.in_flight) || 0));
  }
  return counts;
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
 *
 * Also loads the linked certificate_profiles row (including
 * public_metadata.renewalProfile) needed to resolve an executable payload.
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
            mc.subject_alt_names,
            mc.not_after,
            mc.key_mode,
            mc.profile_id,
            cp.name AS profile_name,
            cp.key_mode AS profile_key_mode,
            cp.public_metadata AS profile_public_metadata,
            cp.renew_before_days AS profile_renew_before_days,
            NULLIF(BTRIM(mc.public_metadata->>'caEndpoint'), '')
              AS certificate_ca_endpoint,
            NULLIF(
              BTRIM(
                COALESCE(
                  cp.public_metadata->'renewalProfile'->'ca'->>'endpoint',
                  cp.public_metadata->>'caEndpoint'
                )
              ),
              ''
            ) AS profile_ca_endpoint
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
  mode = "real",
}) {
  // Resolve the immutable execution contract BEFORE opening the insert
  // transaction. Incomplete profiles never create a job row.
  const payload = buildRenewalJobPayload({ certificate });

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

    const outcome = await jobCreator({
      client,
      workspaceId: certificate.workspace_id,
      operation: "renew",
      source: "automation",
      status: "pending",
      mode,
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
 * { thresholdDays, perCaCap, lockAcquired, scanned, created, replayed,
 *   skippedPaused, skippedByCaCap, skippedIncompleteProfile, errors }.
 *
 * Single-flight: the whole sweep runs under a session advisory lock
 * (pg_try_advisory_lock). A second worker starting a sweep while one is in
 * progress returns immediately with lockAcquired: false and does nothing;
 * without this, two concurrent sweeps would each take a point-in-time
 * in-flight snapshot and could jointly exceed every per-CA cap.
 *
 * Per-CA cap: before creating a job the sweep checks how many renew jobs
 * are already in flight for the certificate's (workspace, normalized CA)
 * bucket (snapshot taken once per sweep, incremented locally for jobs this
 * sweep creates). Capped certificates are skipped, counted in
 * skippedByCaCap, and picked up by a later sweep once the CA's in-flight
 * jobs drain.
 *
 * Incomplete profiles: certificates whose linked renewal profile cannot be
 * resolved into a complete executable snapshot are skipped (never insert a
 * job), counted in skippedIncompleteProfile, and logged/alerted.
 */
async function runRenewalSchedulerSweep({
  dbPool = pool,
  env = process.env,
  jobCreator = createCertificateJob,
  batchSize = DEFAULT_BATCH_SIZE,
  logger = null,
  mode = "real",
} = {}) {
  const thresholdDays = resolveRenewalThresholdDays(env);
  const perCaCap = resolveRenewalPerCaCap(env);
  const terminalStatuses = [
    "rejected",
    "succeeded",
    "failed",
    "blocked",
    "cancelled",
    "dry_run_complete",
  ].filter(isTerminalJobStatus);

  const summary = {
    thresholdDays,
    perCaCap,
    lockAcquired: false,
    scanned: 0,
    created: 0,
    replayed: 0,
    skippedPaused: 0,
    skippedByCaCap: 0,
    skippedIncompleteProfile: 0,
    errors: [],
  };

  // Advisory locks are session-scoped: acquire and release on ONE dedicated
  // connection held for the whole sweep.
  const lockClient = await dbPool.connect();
  try {
    const lockResult = await lockClient.query(
      "SELECT pg_try_advisory_lock($1) AS acquired",
      [RENEWAL_SCHEDULER_ADVISORY_LOCK_KEY.toString()],
    );
    if (lockResult.rows?.[0]?.acquired !== true) {
      return summary;
    }
    summary.lockAcquired = true;

    const dueCertificates = await findCertificatesDueForRenewal({
      db: dbPool,
      thresholdDays,
      batchSize,
      terminalStatuses,
    });

    const inFlightByCa = await countInFlightRenewalJobsByCaEndpoint({
      db: dbPool,
      terminalStatuses,
    });

    summary.scanned = dueCertificates.length;

    for (const certificate of dueCertificates) {
      const capKey = caCapKey(
        certificate.workspace_id,
        certificateCaBucket(certificate),
      );
      const inFlight = inFlightByCa.get(capKey) || 0;
      if (inFlight >= perCaCap) {
        summary.skippedByCaCap += 1;
        continue;
      }
      try {
        const { created } = await createRenewalJobForCertificate({
          dbPool,
          certificate,
          jobCreator,
          env,
          mode,
        });
        if (created) {
          summary.created += 1;
          inFlightByCa.set(capKey, inFlight + 1);
        } else {
          summary.replayed += 1;
        }
      } catch (error) {
        if (
          error?.code === CERTOPS_WORKSPACE_PAUSED ||
          error?.code === CERTOPS_DISABLED
        ) {
          summary.skippedPaused += 1;
          continue;
        }
        if (
          error?.code === CERTOPS_RENEWAL_PROFILE_INCOMPLETE ||
          error?.code === CERTOPS_RENEWAL_PROFILE_INVALID
        ) {
          summary.skippedIncompleteProfile += 1;
          if (logger?.warn || logger?.error) {
            const logFn = logger.warn || logger.error;
            logFn.call(logger, "certops-renewal-scheduler-incomplete-profile", {
              certificateId: String(certificate.id),
              workspaceId: certificate.workspace_id,
              profileId: certificate.profile_id
                ? String(certificate.profile_id)
                : null,
              error: error?.message,
              code: error?.code,
            });
          }
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
  } finally {
    if (summary.lockAcquired) {
      try {
        await lockClient.query("SELECT pg_advisory_unlock($1)", [
          RENEWAL_SCHEDULER_ADVISORY_LOCK_KEY.toString(),
        ]);
      } catch (_error) {
        // The session release below frees the lock regardless.
      }
    }
    lockClient.release();
  }
}

module.exports = {
  DEFAULT_RENEWAL_PER_CA_CAP,
  DEFAULT_RENEWAL_THRESHOLD_DAYS,
  NON_RENEWABLE_CERTIFICATE_STATUSES,
  RENEWAL_PER_CA_CAP_ENV,
  RENEWAL_SCHEDULER_ADVISORY_LOCK_KEY,
  RENEWAL_THRESHOLD_ENV,
  UNKNOWN_CA_BUCKET,
  caCapKey,
  certificateCaBucket,
  certificateCaEndpointRaw,
  countInFlightRenewalJobsByCaEndpoint,
  findCertificatesDueForRenewal,
  isValidCaEndpointUrl,
  normalizeCaBucket,
  renewalIdempotencyKey,
  resolveRenewalPerCaCap,
  resolveRenewalThresholdDays,
  runRenewalSchedulerSweep,
};

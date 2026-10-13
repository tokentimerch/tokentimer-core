"use strict";

/**
 * Shared per-(workspace, CA) renewal capacity helpers.
 *
 * The scheduler sweep uses these as a fast pre-filter; createCertificateJob
 * enforces the same cap transactionally so bulk/manual creators cannot bypass
 * the scheduler's accounting.
 */

const crypto = require("node:crypto");

const DEFAULT_RENEWAL_PER_CA_CAP = 5;
const RENEWAL_PER_CA_CAP_ENV = "CERTOPS_RENEWAL_PER_CA_CAP";
const UNKNOWN_CA_BUCKET = "__unknown-ca__";
// AD CS has no CA URL. Its bucket is the issuer row, which is stable across
// CA certificate rotations and does not depend on metadata.
const ADCS_CA_BUCKET_PREFIX = "adcs-issuer:";
const CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED =
  "CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED";
// Operations that place a real ACME order and therefore consume the CA's rate
// limits. "issue" shares the bucket with "renew": both are the same ACME
// order from the CA's point of view, so counting only renews would let a
// burst of issuances blow through a CA rate limit unaccounted for.
const CA_CONSUMING_OPERATIONS = Object.freeze(["issue", "renew"]);

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
 * Canonical form of a CA endpoint for cap bucketing, so the same CA never
 * lands in two buckets because of representation differences.
 */
function normalizeCaBucket(value) {
  if (typeof value !== "string") return UNKNOWN_CA_BUCKET;
  const trimmed = value.trim();
  if (trimmed === "" || trimmed === UNKNOWN_CA_BUCKET) return UNKNOWN_CA_BUCKET;
  // Already a canonical AD CS key. Parsing it as a URL would mangle the scheme.
  if (trimmed.startsWith(ADCS_CA_BUCKET_PREFIX)) return adcsCaBucket(trimmed.slice(ADCS_CA_BUCKET_PREFIX.length));
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch (_error) {
    return trimmed.toLowerCase();
  }
  const pathname = parsed.pathname.replace(/\/+$/, "");
  return `${parsed.protocol}//${parsed.host}${pathname}`;
}

function caCapKey(workspaceId, caBucket) {
  return `${workspaceId}::${caBucket}`;
}

function caBucketFromPayload(payload) {
  const endpoint =
    payload && typeof payload === "object" ? payload.caEndpoint : null;
  if (typeof endpoint === "string" && endpoint.trim() !== "") {
    return normalizeCaBucket(endpoint);
  }
  return UNKNOWN_CA_BUCKET;
}

function adcsCaBucket(issuerId) {
  return `${ADCS_CA_BUCKET_PREFIX}${String(issuerId).trim().toLowerCase()}`;
}

// Bucket of a job row for in-flight counting. AD CS enrollment jobs have no
// caEndpoint, so they are attributed through the enrollment that owns them.
const IN_FLIGHT_BUCKET_SQL = `COALESCE(
  CASE WHEN e.issuer_id IS NOT NULL
       THEN '${ADCS_CA_BUCKET_PREFIX}' || e.issuer_id::text END,
  NULLIF(BTRIM(cj.payload->>'caEndpoint'), '')
)`;

/**
 * Stable signed bigint for pg_advisory_xact_lock, derived from the cap key.
 */
function advisoryLockKeyForCaCap(workspaceId, caBucket) {
  const digest = crypto
    .createHash("sha256")
    .update(`certops-renewal-ca-cap:${caCapKey(workspaceId, caBucket)}`)
    .digest();
  return digest.readBigInt64BE(0).toString();
}

/**
 * Transactional capacity reservation for renew job creation.
 * Serializes creators on (workspace, CA) via an xact advisory lock, then
 * counts non-terminal renew jobs in that bucket (normalized in JS so URL
 * representation differences cannot split one CA into two buckets). Callers
 * must invoke this inside the same DB transaction as the subsequent INSERT.
 */
async function assertRenewalPerCaCapacityAvailable({
  client,
  workspaceId,
  payload,
  terminalStatuses,
  env = process.env,
  perCaCap = null,
  capacityBucket = null,
} = {}) {
  const cap =
    Number.isSafeInteger(perCaCap) && perCaCap > 0
      ? perCaCap
      : resolveRenewalPerCaCap(env);
  const caBucket = capacityBucket || caBucketFromPayload(payload);
  const lockKey = advisoryLockKeyForCaCap(workspaceId, caBucket);

  await client.query("SELECT pg_advisory_xact_lock($1)", [lockKey]);

  const countResult = await client.query(
    `SELECT ${IN_FLIGHT_BUCKET_SQL} AS ca_bucket
       FROM certificate_jobs cj
       LEFT JOIN certificate_enrollments e
         ON e.workspace_id = cj.workspace_id AND e.current_job_id = cj.id
      WHERE cj.workspace_id = $1
        AND cj.operation = ANY($3::text[])
        AND NOT (cj.status = ANY($2::text[]))
      FOR UPDATE OF cj`,
    [workspaceId, terminalStatuses, [...CA_CONSUMING_OPERATIONS]],
  );

  let inFlight = 0;
  for (const row of countResult.rows || []) {
    const bucket =
      row.ca_bucket == null
        ? UNKNOWN_CA_BUCKET
        : normalizeCaBucket(row.ca_bucket);
    if (bucket === caBucket) inFlight += 1;
  }

  if (inFlight >= cap) {
    const error = new Error(
      `Per-CA renewal capacity exceeded for this workspace (cap=${cap}, inFlight=${inFlight})`,
    );
    error.code = CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED;
    error.perCaCap = cap;
    error.inFlight = inFlight;
    error.caBucket = caBucket;
    throw error;
  }

  return { perCaCap: cap, inFlight, caBucket };
}

module.exports = {
  ADCS_CA_BUCKET_PREFIX,
  CA_CONSUMING_OPERATIONS,
  CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED,
  DEFAULT_RENEWAL_PER_CA_CAP,
  IN_FLIGHT_BUCKET_SQL,
  RENEWAL_PER_CA_CAP_ENV,
  UNKNOWN_CA_BUCKET,
  adcsCaBucket,
  advisoryLockKeyForCaCap,
  assertRenewalPerCaCapacityAvailable,
  caBucketFromPayload,
  caCapKey,
  normalizeCaBucket,
  resolveRenewalPerCaCap,
};

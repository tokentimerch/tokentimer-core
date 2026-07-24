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
const CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED =
  "CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED";

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
} = {}) {
  const cap =
    Number.isSafeInteger(perCaCap) && perCaCap > 0
      ? perCaCap
      : resolveRenewalPerCaCap(env);
  const caBucket = caBucketFromPayload(payload);
  const lockKey = advisoryLockKeyForCaCap(workspaceId, caBucket);

  await client.query("SELECT pg_advisory_xact_lock($1)", [lockKey]);

  const countResult = await client.query(
    `SELECT NULLIF(BTRIM(payload->>'caEndpoint'), '') AS ca_endpoint
       FROM certificate_jobs
      WHERE workspace_id = $1
        AND operation = 'renew'
        AND NOT (status = ANY($2::text[]))
      FOR UPDATE`,
    [workspaceId, terminalStatuses],
  );

  let inFlight = 0;
  for (const row of countResult.rows || []) {
    const bucket =
      row.ca_endpoint == null
        ? UNKNOWN_CA_BUCKET
        : normalizeCaBucket(row.ca_endpoint);
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
  CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED,
  DEFAULT_RENEWAL_PER_CA_CAP,
  RENEWAL_PER_CA_CAP_ENV,
  UNKNOWN_CA_BUCKET,
  advisoryLockKeyForCaCap,
  assertRenewalPerCaCapacityAvailable,
  caBucketFromPayload,
  caCapKey,
  normalizeCaBucket,
  resolveRenewalPerCaCap,
};

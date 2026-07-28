"use strict";

/**
 * Shared CertOps lease / nonce timing (B6/B7).
 *
 * Claim leases, dispatch-nonce validity, and the lease-reaper hard grace
 * must stay coupled: a nonce that expires before the reaper's terminal
 * window makes legitimate late results permanently unreportable, and a
 * reaper that silently requeues after a renewed lease can double-execute
 * side effects. Every consumer of these windows imports from here.
 */

const DEFAULT_JOB_LEASE_SECONDS = 900;
// Extra headroom on top of the renewable lease so clock skew and a late
// result HTTP round-trip still succeed.
const NONCE_TTL_GRACE_SECONDS = 300;
// After lease expiry, the reaper may defer an alive agent for this long
// before taking a terminal action (requeue vs effects_unknown).
const DEFAULT_LEASE_HARD_GRACE_MS = 60 * 60 * 1000;
const DEFAULT_LEASE_HARD_GRACE_SECONDS = DEFAULT_LEASE_HARD_GRACE_MS / 1000;

function jobLeaseSeconds(env = process.env) {
  const raw = Number.parseInt(env.CERTOPS_JOB_LEASE_SECONDS, 10);
  if (Number.isInteger(raw) && raw > 0) return raw;
  return DEFAULT_JOB_LEASE_SECONDS;
}

function leaseHardGraceMs(env = process.env) {
  const raw = Number.parseInt(env.CERTOPS_LEASE_HARD_GRACE_MS, 10);
  if (Number.isSafeInteger(raw) && raw > 0) return raw;
  return DEFAULT_LEASE_HARD_GRACE_MS;
}

function leaseHardGraceSeconds(env = process.env) {
  return Math.ceil(leaseHardGraceMs(env) / 1000);
}

/**
 * Initial (and per-renewal) nonce TTL: covers one lease period plus the
 * reaper hard-grace defer window plus a small delivery grace. Renewing the
 * lease also extends the matching nonce row to the same absolute horizon.
 */
function dispatchNonceTtlSeconds(env = process.env) {
  return (
    jobLeaseSeconds(env) +
    leaseHardGraceSeconds(env) +
    NONCE_TTL_GRACE_SECONDS
  );
}

module.exports = {
  DEFAULT_JOB_LEASE_SECONDS,
  DEFAULT_LEASE_HARD_GRACE_MS,
  DEFAULT_LEASE_HARD_GRACE_SECONDS,
  NONCE_TTL_GRACE_SECONDS,
  dispatchNonceTtlSeconds,
  jobLeaseSeconds,
  leaseHardGraceMs,
  leaseHardGraceSeconds,
};

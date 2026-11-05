"use strict";

// A verification result is separate from inventory lifecycle and trust state.
// Inputs are public facts; missing or malformed verification never implies good.
const VERDICTS = new Set(["good", "revoked", "issuer_revoked", "unknown"]);

function revocationStatus(result, now = Date.now()) {
  const fallback = { verdict: "unknown", freshness: "unchecked", checkedAt: null, validUntil: null };
  if (!result || !VERDICTS.has(result.verdict) || !Number.isFinite(now)) return fallback;
  const checkedAt = Date.parse(result.checkedAt);
  const validUntil = Date.parse(result.validUntil);
  if (!Number.isFinite(checkedAt) || checkedAt > now) return fallback;
  if (result.verdict === "unknown") {
    return { verdict: "unknown", freshness: "unknown", checkedAt: result.checkedAt, validUntil: null };
  }
  if (!Number.isFinite(validUntil) || validUntil <= checkedAt) return fallback;
  return { verdict: result.verdict, freshness: now < validUntil ? "fresh" : "stale", checkedAt: result.checkedAt, validUntil: result.validUntil };
}

module.exports = { revocationStatus };

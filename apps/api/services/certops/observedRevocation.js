"use strict";

const VERDICTS = new Set(["good", "revoked", "issuer_revoked", "unknown"]);
const CHAIN_STATES = new Set(["valid", "invalid", "unknown"]);

// Treat malformed optional results as absent: inventory discovery must keep
// working, and invalid data must never become a healthy verification.
function normalizeObservedRevocation(metadata, serverObservedAt) {
  if (!metadata || metadata.observedRevocationVerdict === undefined) return null;
  const verdict = metadata.observedRevocationVerdict;
  const chainStatus = metadata.observedChainStatus;
  if (!VERDICTS.has(verdict) || !CHAIN_STATES.has(chainStatus)) return null;
  if (typeof metadata.observedRevocationCheckedAt !== "string") return null;
  const checked = Date.parse(metadata.observedRevocationCheckedAt);
  const server = Date.parse(serverObservedAt);
  if (!Number.isFinite(checked) || !Number.isFinite(server) || checked > server + 5 * 60 * 1000) return null;
  let validUntil = null;
  if (metadata.observedRevocationValidUntil != null && metadata.observedRevocationValidUntil !== "") {
    if (typeof metadata.observedRevocationValidUntil !== "string") return null;
    const until = Date.parse(metadata.observedRevocationValidUntil);
    if (!Number.isFinite(until) || until <= checked) return null;
    validUntil = new Date(until).toISOString();
  }
  if (verdict !== "unknown" && (chainStatus !== "valid" || !validUntil)) return null;
  const detail = typeof metadata.observedRevocationDetail === "string" ? metadata.observedRevocationDetail.slice(0, 256) : null;
  return { verdict, chainStatus, checkedAt: new Date(checked).toISOString(), validUntil, detail };
}

module.exports = { normalizeObservedRevocation };

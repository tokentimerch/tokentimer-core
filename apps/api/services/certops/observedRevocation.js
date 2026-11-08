"use strict";

const VERDICTS = new Set(["good", "revoked", "issuer_revoked", "unknown"]);
const CHAIN_STATES = new Set(["valid", "invalid", "unknown"]);

// An absent legacy result is distinct from a malformed current observation.
function normalizeObservedRevocation(metadata, serverObservedAt) {
  const recognized = metadata && Object.keys(metadata).some((key) =>
    key.startsWith("observedRevocation") || key === "observedChainStatus");
  if (!recognized) return null;
  const reported = Date.parse(serverObservedAt);
  if (!Number.isFinite(reported)) return null;
  let revision;
  const invalid = () => ({ verdict: "invalid_observation", chainStatus: "unknown", checkedAt: null, validUntil: null, detail: "Invalid revocation observation", reportedAt: new Date(reported).toISOString(), ...(revision === undefined ? {} : { revision }) });
  const rawRevision = metadata?.observedRevocationRevision;
  if (rawRevision !== undefined) {
    if (typeof rawRevision !== "string" || !/^[1-9][0-9]{0,15}$/.test(rawRevision)) return invalid();
    revision = Number(rawRevision);
    if (!Number.isSafeInteger(revision)) { revision = undefined; return invalid(); }
  }
  const revisionField = revision === undefined ? {} : { revision };
  if (["not_configured", "disabled"].includes(metadata?.observedRevocationState)) {
    const verdict = metadata.observedRevocationState;
    return { verdict, chainStatus: "unknown", checkedAt: null, validUntil: null, detail: verdict === "disabled" ? "Revocation monitoring is disabled" : "Revocation responder origins are not configured", reportedAt: new Date(reported).toISOString(), ...revisionField };
  }
  if (!metadata || metadata.observedRevocationVerdict === undefined) return invalid();
  const verdict = metadata.observedRevocationVerdict;
  const chainStatus = metadata.observedChainStatus;
  if (!VERDICTS.has(verdict) || !CHAIN_STATES.has(chainStatus)) return invalid();
  if (typeof metadata.observedRevocationCheckedAt !== "string") return invalid();
  const checked = Date.parse(metadata.observedRevocationCheckedAt);
  const server = Date.parse(serverObservedAt);
  if (!Number.isFinite(checked) || !Number.isFinite(server) || checked > server + 5 * 60 * 1000) return invalid();
  let validUntil = null;
  if (metadata.observedRevocationValidUntil != null && metadata.observedRevocationValidUntil !== "") {
    if (typeof metadata.observedRevocationValidUntil !== "string") return invalid();
    const until = Date.parse(metadata.observedRevocationValidUntil);
    if (!Number.isFinite(until) || until <= checked) return invalid();
    validUntil = new Date(until).toISOString();
  }
  if (verdict !== "unknown" && (chainStatus !== "valid" || !validUntil)) return invalid();
  const detail = typeof metadata.observedRevocationDetail === "string" ? metadata.observedRevocationDetail.slice(0, 256) : null;
  return { verdict, chainStatus, checkedAt: new Date(checked).toISOString(), validUntil, detail, ...revisionField };
}

module.exports = { normalizeObservedRevocation };

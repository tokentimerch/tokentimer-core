"use strict";
/** Read-only orchestration decisions. Azure/task/GitHub adapters must independently
 * observe custody; this module emits bounded intents, never executes shell text.
 * preparedLease must come from the independently authenticated owning GitHub
 * prepare artifact, never the guest or mutable Azure tags.
 * A missing/mismatched attestation fails before granting a long-lived lease. */
const contract = require("./certops-retention24h-contract");
function handoffIntent({ lease, preparedLease, observed, observedAt }) {
  contract.verifyOriginalLease(lease, preparedLease);
  const extended = contract.attestHandoff(lease, observed, observedAt);
  return { action: "serialized-compare-verify-owned-lease", resourceId: lease.vmResourceId, expectedPhase: "preparing", expectedExpiresAt: lease.expiresAt, lease: extended };
}
function finalizeIntent({ lease, preparedLease, githubOwner, observed, observedAt }) {
  contract.verifyOriginalLease(lease, preparedLease);
  contract.verifyOwner(lease, githubOwner);
  if (lease.phase !== "keeper-owned") throw new Error("Retention finalization requires verified keeper handoff");
  for (const key of contract.IDENTITY) if (observed[key] !== lease[key]) throw new Error("Finalizer ownership mismatch");
  if (contract.epoch(observedAt) >= contract.epoch(lease.hardExpiresAt)) throw new Error("Hard lease expired; independent cleanup takes precedence");
  return { action: "collect-owned-public-report-then-delete", resourceId: lease.vmResourceId, nonce: lease.nonce };
}
module.exports = { handoffIntent, finalizeIntent };

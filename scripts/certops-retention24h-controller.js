/*
 * Qualification notes: retention24h-controller-lifecycle
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Main-only protected prepare creates owned Server2022 domain lab,initial4h receipt then authenticated
 * immutable artifact+repeat VM/task/process/custody/TLS/source readback authorizes one original32h
 * lease. Deallocate exact CA/control VMs only after sealed facts; member stays running. On any
 * failed/cancelled prepare/upload call final abort after diagnostics; authenticate
 * run/candidate/attempt/nonce/deployment chronology,never delete by name/tag alone. Abort failure
 * emits bounded orphan receipt to workflow log before local file. Hourly finalizer independently
 * authenticates both artifacts/successful owner,original task/process/boot,real24h native
 * deletion/history/replacementTLS and verified RG absence before qualification. Prepare queue is
 * run/attempt-specific noncancelling;cleanup queues shared noncancelling/unattended least-privilege
 * identity separate from lab approval. Prepare180m<4h initial expiry. Later-main finalizer must
 * authenticate5 controller digests,sealing chronology/original candidate and exclude other candidates
 * before proof parsing. Janitor uses authenticated attempt job-start+32h if artifacts missing,never
 * mutable tag extension. Comparison/readback is not atomicAzure ETag or guaranteed billing cutoff.
 * Dynamic native snapshot executes once,private exclusive byte/hash/identity-bound retrieval/cleanup;
 * remove/restore Node preload/search env. Manual API redirects never forward auth to signed blob; read
 * one bounded ZIP member in memory,no extraction. Upload only sanitized identities/counts/hashes,never
 * credentials/CSRs/config/taskXML/rawoutput/signed URLs. Native day/cloud execution still requires
 * actual protected workflows.
 */
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

"use strict";
/** Closed evidence contract for native expiry-wins cleanup at the default and
 * maximum retention policies. This verifier performs no native operations.
 * A passing supporting test of this module does not qualify the installed
 * service timer, nor demonstrate 168 or 720 hours of elapsed retention.
 */
const assert = require("node:assert/strict");

const SCOPE = "native-retention-policy-expiry-wins";
const POLICIES = Object.freeze([168, 720]);
const FLAGS = Object.freeze([
  "actualProductionCollectorUsed",
  "preDeadlineCustodyPreserved",
  "oldCertificateAbsent",
  "oldKeyAbsent",
  "immutableHistoryPreserved",
  "replacementCustodyUnchanged",
  "replacementTrustedTlsVerified",
  "interruptedNativeDeleteRecovered",
]);
const COUNTS = Object.freeze([
  "successfulCutovers",
  "predecessorCertificatesRemoved",
  "predecessorKeysRemoved",
  "lineageRowsFinalized",
]);
const FIELDS = Object.freeze([
  "scope",
  "ownedInterruption",
  "configuredRetentionHours",
  "verifiedCutoverAt",
  "oldNotAfter",
  "cleanupDeadline",
  "preDeadlineObservedAt",
  "cleanupObservedAt",
  "waitStartedAt",
  "waitFinishedAt",
  "waitedMonotonicMs",
  "installedServiceTimerQualified",
  "fullRetentionWindowQualified",
  ...FLAGS,
  ...COUNTS,
]);

function epoch(value) {
  assert.equal(
    typeof value,
    "string",
    "A canonical public timestamp is required",
  );
  const instant = Date.parse(value);
  assert.ok(Number.isFinite(instant), "Timestamp must be finite");
  assert.equal(
    new Date(instant).toISOString(),
    value,
    "Timestamp must be canonical UTC",
  );
  return instant;
}

function publicNativeTimestamp(value) {
  // PowerShell DateTime.ToString('o') carries seven fractional digits. Only
  // the bounded public timestamp is normalized; private custody readbacks
  // retain their original bytes for exact before/after comparison.
  assert.equal(typeof value, "string");
  assert.match(value, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3,7}Z$/);
  return new Date(value).toISOString();
}

function verifyProof(proof) {
  assert.ok(proof && typeof proof === "object" && !Array.isArray(proof));
  assert.deepEqual(Object.keys(proof).sort(), [...FIELDS].sort());
  assert.equal(proof.scope, SCOPE);
  require("./retention-interrupted-process").verifyProof(
    proof.ownedInterruption,
  );
  assert.ok(POLICIES.includes(proof.configuredRetentionHours));
  assert.equal(proof.installedServiceTimerQualified, false);
  assert.equal(proof.fullRetentionWindowQualified, false);
  for (const field of FLAGS) assert.equal(proof[field], true, field);
  for (const field of COUNTS) assert.equal(proof[field], 2, field);
  const cutover = epoch(proof.verifiedCutoverAt);
  const expiry = epoch(proof.oldNotAfter);
  const deadline = epoch(proof.cleanupDeadline);
  const before = epoch(proof.preDeadlineObservedAt);
  const after = epoch(proof.cleanupObservedAt);
  const started = epoch(proof.waitStartedAt);
  const finished = epoch(proof.waitFinishedAt);
  assert.ok(
    cutover < expiry,
    "The real predecessor must remain valid at cutover",
  );
  assert.equal(
    deadline,
    expiry + 300000,
    "Actual expiry plus production grace must win",
  );
  assert.ok(deadline < cutover + proof.configuredRetentionHours * 3600000);
  assert.ok(
    before >= cutover && before < expiry,
    "Native preservation must be observed before expiry",
  );
  assert.ok(
    after > deadline,
    "Production eligibility is strictly after the deadline",
  );
  assert.ok(Number.isFinite(proof.waitedMonotonicMs));
  assert.ok(
    proof.waitedMonotonicMs >= 300000 && proof.waitedMonotonicMs < 600000,
  );
  assert.ok(before <= started && started < expiry);
  assert.ok(
    finished > deadline && after >= finished && after - finished < 180000,
  );
  // Compare clocks across the actual wait, excluding bounded native deletion
  // and TLS observations that follow it.
  assert.ok(Math.abs(finished - started - proof.waitedMonotonicMs) <= 5000);
  return true;
}

module.exports = {
  SCOPE,
  POLICIES,
  FLAGS,
  COUNTS,
  FIELDS,
  publicNativeTimestamp,
  verifyProof,
};

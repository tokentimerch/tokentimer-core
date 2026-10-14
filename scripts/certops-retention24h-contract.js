"use strict";
/** Disposable retention qualification lease, independent of guest wall-clock claims.
 * A normal four-hour environment can extend once only after independently observed
 * SYSTEM task/process custody. The immutable creation time always bounds costs.
 * Pure decisions are not native evidence and never grant Azure permissions. */
const assert = require("node:assert/strict");
const HOUR = 3600000, DAY = 24 * HOUR, INITIAL = 4 * HOUR, MAX = 32 * HOUR;
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const IDENTITY = ["candidateSha", "runId", "runAttempt", "nonce", "vmResourceId", "vmId", "taskName", "nodeSha256", "keeperSha256"];
function canonicalCreatedAt(value) { assert.equal(typeof value,"string");const parsed=Date.parse(value);assert.ok(Number.isFinite(parsed));return new Date(parsed).toISOString(); }
function epoch(value) { assert.equal(typeof value, "string"); const n = Date.parse(value); assert.ok(Number.isFinite(n)); assert.equal(new Date(n).toISOString(), value); return n; }
function identity(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.match(value.candidateSha, /^[a-f0-9]{40}$/);
  for (const key of ["runId", "runAttempt"]) assert.match(value[key], /^[1-9][0-9]{0,19}$/);
  assert.match(value.nonce, /^[a-f0-9]{64}$/); assert.match(value.vmId, UUID);
  assert.match(value.vmResourceId, /^\/subscriptions\/[a-f0-9-]{36}\/resourceGroups\/tt-certops-[1-9][0-9]*-[1-9][0-9]*\/providers\/Microsoft.Compute\/virtualMachines\/windows-agent$/);
  assert.ok(value.vmResourceId.includes(`/resourceGroups/tt-certops-${value.runId}-${value.runAttempt}/`));
  assert.equal(value.taskName, `TokenTimer-Retention24h-${value.nonce}`);
  for (const key of ["nodeSha256", "keeperSha256"]) assert.match(value[key], /^[a-f0-9]{64}$/);
}
function verifyLease(value) {
  identity(value); assert.equal(value.schemaVersion, 1); assert.equal(value.kind, "certops-native-retention24h");
  const created = epoch(value.createdAt), expires = epoch(value.expiresAt);
  assert.equal(epoch(value.hardExpiresAt), created + MAX);
  assert.ok(["preparing", "keeper-owned"].includes(value.phase));
  assert.equal(expires, created + (value.phase === "preparing" ? INITIAL : MAX));
  return value;
}
function createLease(owner, createdAt) {
  identity(owner); const created = epoch(createdAt);
  return verifyLease({ ...Object.fromEntries(IDENTITY.map(key => [key, owner[key]])), schemaVersion: 1, kind: "certops-native-retention24h", phase: "preparing", createdAt, expiresAt: new Date(created + INITIAL).toISOString(), hardExpiresAt: new Date(created + MAX).toISOString() });
}
function verifyOriginalLease(lease, preparedLease) {
  verifyLease(lease); verifyLease(preparedLease); assert.equal(preparedLease.phase, "preparing");
  for (const key of [...IDENTITY, "createdAt", "hardExpiresAt"]) assert.equal(lease[key], preparedLease[key], "Immutable prepare receipt mismatch: " + key);
  return true;
}
function verifyOwner(lease, owner) {
  verifyLease(lease); identity(owner);
  for (const key of IDENTITY) assert.equal(owner[key], lease[key], key);
  assert.equal(owner.repository, "tokentimerch/tokentimer-core");
  assert.equal(owner.event, "workflow_dispatch"); assert.equal(owner.headBranch, "main");
  assert.equal(owner.workflowPath, ".github/workflows/certops-retention24h-prepare.yml");
  assert.equal(owner.status, "completed"); assert.equal(owner.conclusion, "success");
}
function attestHandoff(lease, observed, observedAt) {
  verifyLease(lease); assert.equal(lease.phase, "preparing");
  assert.ok(epoch(observedAt) >= epoch(lease.createdAt) && epoch(observedAt) < epoch(lease.expiresAt));
  for (const key of IDENTITY) assert.equal(observed[key], lease[key], key);
  for (const key of ["taskXmlVerified", "vmIdentityVerified", "nodeHashVerified", "keeperHashVerified", "residentProcessVerified", "soleAgentStoppedAndDrained", "productionCutoverVerified", "nativeCustodyVerified", "trustedTlsVerified", "ledgerUnmodified"]) assert.equal(observed[key], true, key);
  assert.equal(observed.principalSid, "S-1-5-18"); assert.equal(observed.taskState, "Running");
  assert.ok(Number.isInteger(observed.processId) && observed.processId > 0); assert.equal(typeof observed.bootTime,"string"); assert.ok(observed.bootTime.length <= 40 && Number.isFinite(Date.parse(observed.bootTime)));
  assert.ok(Number.isInteger(observed.monotonicElapsedMs) && observed.monotonicElapsedMs >= 0 && observed.monotonicElapsedMs < INITIAL);
  const cutover = epoch(observed.verifiedCutoverAt);
  assert.ok(cutover >= epoch(lease.createdAt) && cutover <= epoch(observedAt));
  assert.ok(epoch(observed.oldNotAfter) > cutover + DAY + HOUR, "Expiry must not win the real 24-hour retention deadline");
  assert.equal(epoch(observed.cleanupDeadline), cutover + DAY);
  return { ...lease, phase: "keeper-owned", expiresAt: lease.hardExpiresAt };
}
function cleanupDecision(lease, owner, observedAt) {
  verifyLease(lease); const now = epoch(observedAt); assert.ok(now >= epoch(lease.createdAt));
  if (now >= epoch(lease.expiresAt)) return "delete-owned-expired";
  // Caller must obtain this owner status from GitHub independently; guest files
  // cannot attest cancellation or rewrite the owning workflow's identity.
  for (const key of ["runId", "runAttempt", "candidateSha"]) assert.equal(owner[key], lease[key]);
  assert.equal(owner.repository, "tokentimerch/tokentimer-core");
  assert.equal(owner.workflowPath, ".github/workflows/certops-retention24h-prepare.yml");
  if (["cancelled", "failure", "timed_out", "action_required", "stale", "startup_failure"].includes(owner.conclusion)) return "delete-owned-failed-owner";
  assert.ok([null, "success"].includes(owner.conclusion));
  return "retain-within-owned-lease";
}
module.exports = { HOUR, DAY, INITIAL, MAX, IDENTITY, canonicalCreatedAt, epoch, identity, verifyLease, createLease, verifyOriginalLease, verifyOwner, attestHandoff, cleanupDecision };

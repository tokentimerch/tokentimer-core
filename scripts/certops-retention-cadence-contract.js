"use strict";
/** Closed public protocol for an actual installed-service default timer campaign.
 * Pure validation never proves elapsed time, native custody, or Azure ownership.
 * The independent controller must authenticate the original preparation artifact.
 */
const assert = require("node:assert/strict");
const HOUR = 3600000;
const INITIAL = 4 * HOUR;
const MAX = 16 * HOUR;
const BASE_INTERVAL = 6 * HOUR;
const MIN_INTERVAL = BASE_INTERVAL * 0.8;
const MAX_INTERVAL = BASE_INTERVAL * 1.2;
const OBSERVATION_MARGIN = 5 * 60000;
const KIND = "certops-native-installed-retention-cadence";
const PREPARE_WORKFLOW =
  ".github/workflows/certops-retention-cadence-prepare.yml";
const IDENTITY = [
  "candidateSha",
  "runId",
  "runAttempt",
  "nonce",
  "vmResourceId",
  "vmId",
  "taskName",
  "nodeSha256",
  "observerSha256",
];
const LEASE_FIELDS = [
  ...IDENTITY,
  "schemaVersion",
  "kind",
  "phase",
  "createdAt",
  "expiresAt",
  "hardExpiresAt",
];
const FLAGS = [
  "taskXmlVerified",
  "vmIdentityVerified",
  "observerSourceVerified",
  "defaultsOmittedVerified",
  "soleInstalledAgentVerified",
  "soleLedgerWriterVerified",
  "noOtherActiveJobsVerified",
  "nativeCustodyVerified",
  "trustedTlsVerified",
  "immediateSweepVerified",
];
const OBSERVATION_FIELDS = [
  ...IDENTITY,
  ...FLAGS,
  "principalSid",
  "taskState",
  "processId",
  "processCreatedAt",
  "bootTime",
  "serviceHostPid",
  "serviceHostCreatedAt",
  "agentPid",
  "agentCreatedAt",
  "configSha256",
  "observerConfigSha256",
  "immutableLedgerSha256",
  "pendingLedgerFileId",
  "immediateLedgerFileId",
  "immediateObservedAt",
  "immediateMonotonicMs",
  "oldNotAfter",
  "verifiedAt",
];
function closed(value, fields) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(
    Object.keys(value).sort(),
    [...fields].sort(),
    "Unexpected public protocol fields",
  );
}
function epoch(value) {
  assert.equal(typeof value, "string");
  const n = Date.parse(value);
  assert.ok(Number.isFinite(n));
  assert.equal(new Date(n).toISOString(), value);
  return n;
}
function identity(value) {
  assert.match(value.candidateSha, /^[a-f0-9]{40}$/);
  for (const key of ["runId", "runAttempt"])
    assert.match(value[key], /^[1-9][0-9]{0,19}$/);
  assert.match(value.nonce, /^[a-f0-9]{64}$/);
  assert.match(value.vmId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  assert.match(
    value.vmResourceId,
    /^\/subscriptions\/[a-f0-9-]{36}\/resourceGroups\/tt-certops-[1-9][0-9]*-[1-9][0-9]*\/providers\/Microsoft.Compute\/virtualMachines\/windows-agent$/,
  );
  assert.ok(
    value.vmResourceId.includes(
      `/resourceGroups/tt-certops-${value.runId}-${value.runAttempt}/`,
    ),
  );
  assert.equal(value.taskName, `TokenTimer-RetentionCadence-${value.nonce}`);
  for (const key of ["nodeSha256", "observerSha256"])
    assert.match(value[key], /^[a-f0-9]{64}$/);
}
function verifyLease(value) {
  closed(value, LEASE_FIELDS);
  identity(value);
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.kind, KIND);
  assert.ok(["preparing", "observer-owned"].includes(value.phase));
  const created = epoch(value.createdAt);
  assert.equal(epoch(value.hardExpiresAt), created + MAX);
  assert.equal(
    epoch(value.expiresAt),
    created + (value.phase === "preparing" ? INITIAL : MAX),
  );
  return value;
}
function createLease(owner, createdAt) {
  identity(owner);
  const created = epoch(createdAt);
  return verifyLease({
    ...Object.fromEntries(IDENTITY.map((key) => [key, owner[key]])),
    schemaVersion: 1,
    kind: KIND,
    phase: "preparing",
    createdAt,
    expiresAt: new Date(created + INITIAL).toISOString(),
    hardExpiresAt: new Date(created + MAX).toISOString(),
  });
}
function verifyOriginalLease(value, original) {
  verifyLease(value);
  verifyLease(original);
  assert.equal(original.phase, "preparing");
  for (const key of [...IDENTITY, "createdAt", "hardExpiresAt"])
    assert.equal(value[key], original[key], "Original lease identity mismatch");
  return value;
}
function verifyObservation(value, original) {
  verifyLease(original);
  closed(value, OBSERVATION_FIELDS);
  for (const key of IDENTITY)
    assert.equal(value[key], original[key], "Observer identity mismatch");
  for (const key of FLAGS) assert.equal(value[key], true, key);
  assert.equal(value.principalSid, "S-1-5-18");
  assert.equal(value.taskState, "Running");
  for (const key of ["processId", "serviceHostPid", "agentPid"])
    assert.ok(Number.isSafeInteger(value[key]) && value[key] > 0 && value[key] <= 0xffffffff);
  for (const key of [
    "processCreatedAt",
    "serviceHostCreatedAt",
    "agentCreatedAt",
  ]) {
    assert.match(value[key], /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3,7}Z$/);
    assert.ok(Number.isFinite(Date.parse(value[key])));
  }
  epoch(value.bootTime);
  for (const key of [
    "configSha256",
    "observerConfigSha256",
    "immutableLedgerSha256",
  ])
    assert.match(value[key], /^[a-f0-9]{64}$/);
  for (const key of ["pendingLedgerFileId", "immediateLedgerFileId"])
    assert.match(value[key], /^[1-9][0-9]{0,24}:[1-9][0-9]{0,24}$/);
  assert.notEqual(value.pendingLedgerFileId, value.immediateLedgerFileId);
  const immediate = epoch(value.immediateObservedAt),
    verified = epoch(value.verifiedAt);
  assert.ok(
    immediate >= epoch(original.createdAt) &&
      verified >= immediate &&
      verified < epoch(original.expiresAt),
  );
  assert.ok(
    Number.isSafeInteger(value.immediateMonotonicMs) &&
      value.immediateMonotonicMs >= 0 &&
      value.immediateMonotonicMs < INITIAL,
  );
  assert.ok(epoch(value.oldNotAfter) > epoch(original.hardExpiresAt) + HOUR);
  return value;
}
function attestHandoff(original, observed) {
  assert.equal(original.phase, "preparing");
  verifyObservation(observed, original);
  return verifyLease({
    ...original,
    phase: "observer-owned",
    expiresAt: original.hardExpiresAt,
  });
}
function verifyTimerWindow(immediateMs, changedMs, verifiedMs) {
  for (const n of [immediateMs, changedMs, verifiedMs])
    assert.ok(Number.isSafeInteger(n) && n >= 0);
  assert.ok(
    changedMs >= immediateMs + MIN_INTERVAL - OBSERVATION_MARGIN,
    "Rewrite occurred before default jitter minimum",
  );
  assert.ok(
    changedMs <= immediateMs + MAX_INTERVAL + OBSERVATION_MARGIN,
    "Default timer rewrite not observed within bounded native/observation margin",
  );
  assert.ok(
    verifiedMs >= changedMs && verifiedMs <= changedMs + OBSERVATION_MARGIN,
  );
  return true;
}
module.exports = {
  HOUR,
  INITIAL,
  MAX,
  BASE_INTERVAL,
  MIN_INTERVAL,
  MAX_INTERVAL,
  OBSERVATION_MARGIN,
  KIND,
  PREPARE_WORKFLOW,
  IDENTITY,
  LEASE_FIELDS,
  FLAGS,
  OBSERVATION_FIELDS,
  closed,
  epoch,
  identity,
  createLease,
  verifyLease,
  verifyOriginalLease,
  verifyObservation,
  attestHandoff,
  verifyTimerWindow,
};

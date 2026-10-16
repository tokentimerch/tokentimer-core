"use strict";
/** Closed installed default timer proof. Pure receipts qualify only after the
 * independent controller authenticates original artifacts/native candidate and
 * confirms exact owned Azure absence. No full retention window is implied.
 */
const assert = require("node:assert/strict");
const c = require("./certops-retention-cadence-contract");
const SCOPE = "actual-installed-default-six-hour-retention-deferral-timer";
const SCENARIOS = [
  "windows-retention-default-timer-real-immediate-sweep",
  "windows-retention-default-timer-real-jittered-sweep",
  "windows-retention-default-timer-independent-final-and-owned-cleanup",
];
const NATIVE_FIELDS = [
  "principalSid",
  "bootTime",
  "serviceHostPid",
  "serviceHostCreatedAt",
  "agentPid",
  "agentCreatedAt",
  "nativeCustodyVerified",
  "defaultsOmittedVerified",
  "soleInstalledAgentVerified",
  "soleLedgerWriterVerified",
  "trustedTlsVerified",
  "configSha256",
];
const RESULT_FIELDS = [
  "schemaVersion",
  "scope",
  "startedAt",
  "finishedAt",
  "immediate",
  "timer",
  "native",
  "configSha256",
  "defaultIntervalMs",
  "defaultRetentionHours",
  "actualCleanupQualified",
  "full168HourRetentionQualified",
];
const COMPLETION_FIELDS = [
  "schemaVersion",
  "scope",
  "originalObservation",
  "result",
  "currentNativeVerified",
  "verifiedAt",
];
const FLAGS = [
  "originalLeaseAndSourcesBound",
  "realImmediateAtomicLedgerRewrite",
  "realDefaultJitteredAtomicLedgerRewrite",
  "sameInstalledProcessAndBoot",
  "sameUnmodifiedDefaultConfiguration",
  "sameDeferredLedgerAndCustody",
  "trustedReplacementTlsPreserved",
  "independentCurrentNativeReadback",
  "ownedAzureCleanupVerified",
];
const FALSE_FLAGS = [
  "actualCertificateCleanupQualified",
  "full168HourRetentionQualified",
  "maximum720HourRetentionQualified",
  "powerLossDurabilityQualified",
];
const FACT_FIELDS = [
  "observerProcessId",
  "observerProcessCreatedAt",
  "candidateSha",
  "prepareRunId",
  "prepareRunAttempt",
  "nonce",
  "vmId",
  "nodeSha256",
  "observerSha256",
  "agentConfigSha256",
  "observerConfigSha256",
  "immutableLedgerSha256",
  "pendingLedgerFileId",
  "immediateLedgerFileId",
  "timerLedgerFileId",
  "originalCreatedAt",
  "immediateObservedAt",
  "timerObservedAt",
  "finishedAt",
  "cleanupFinishedAt",
  "bootTime",
  "serviceHostPid",
  "serviceHostCreatedAt",
  "agentPid",
  "agentCreatedAt",
];
function verifyProof(proof) {
  c.closed(proof, [
    "scope",
    "defaultIntervalMs",
    "defaultRetentionHours",
    "actualMonotonicIntervalMs",
    ...FLAGS,
    ...FALSE_FLAGS,
    ...FACT_FIELDS,
  ]);
  assert.equal(proof.scope, SCOPE);
  assert.equal(proof.defaultIntervalMs, c.BASE_INTERVAL);
  assert.equal(proof.defaultRetentionHours, 168);
  for (const key of FLAGS) assert.equal(proof[key], true, key);
  for (const key of FALSE_FLAGS) assert.equal(proof[key], false, key);
  assert.match(proof.candidateSha, /^[a-f0-9]{40}$/);
  for (const key of ["prepareRunId", "prepareRunAttempt"])
    assert.match(proof[key], /^[1-9][0-9]{0,19}$/);
  assert.match(proof.vmId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  for (const key of [
    "nonce",
    "nodeSha256",
    "observerSha256",
    "agentConfigSha256",
    "observerConfigSha256",
    "immutableLedgerSha256",
  ])
    assert.match(proof[key], /^[a-f0-9]{64}$/);
  for (const key of [
    "pendingLedgerFileId",
    "immediateLedgerFileId",
    "timerLedgerFileId",
  ])
    assert.match(proof[key], /^[1-9][0-9]{0,24}:[1-9][0-9]{0,24}$/);
  // A filesystem may reuse the already-unlinked initial inode hours later.
  // Adjacent observed replacements must differ; historical global uniqueness
  // is not an NTFS file-identity guarantee.
  assert.notEqual(proof.pendingLedgerFileId, proof.immediateLedgerFileId);
  assert.notEqual(proof.timerLedgerFileId, proof.immediateLedgerFileId);
  for (const key of ["observerProcessId", "serviceHostPid", "agentPid"])
    assert.ok(Number.isSafeInteger(proof[key]) && proof[key] > 0 && proof[key] <= 0xffffffff);
  for (const key of [
    "observerProcessCreatedAt",
    "serviceHostCreatedAt",
    "agentCreatedAt",
  ]) {
    assert.match(proof[key], /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3,7}Z$/);
    assert.ok(Number.isFinite(Date.parse(proof[key])));
  }
  c.epoch(proof.bootTime);
  const created = c.epoch(proof.originalCreatedAt),
    immediate = c.epoch(proof.immediateObservedAt),
    timer = c.epoch(proof.timerObservedAt),
    finished = c.epoch(proof.finishedAt),
    cleanup = c.epoch(proof.cleanupFinishedAt);
  assert.ok(
    created <= immediate &&
      immediate < created + c.INITIAL &&
      timer <= finished &&
      finished <= timer + c.OBSERVATION_MARGIN &&
      finished <= cleanup &&
      cleanup < created + c.MAX,
  );
  const boot=Date.parse(proof.bootTime),observer=Date.parse(proof.observerProcessCreatedAt),host=Date.parse(proof.serviceHostCreatedAt),agent=Date.parse(proof.agentCreatedAt);
  assert.ok(boot<=observer&&observer<=host&&host<=agent&&agent<=immediate,"Installed/observer process chronology changed");
  c.verifyTimerWindow(
    0,
    proof.actualMonotonicIntervalMs,
    proof.actualMonotonicIntervalMs,
  );
  assert.ok(
    Math.abs(timer - immediate - proof.actualMonotonicIntervalMs) <= 5000,
  );
  return proof;
}
function same(actual, expected, keys) {
  for (const key of keys)
    assert.equal(
      actual[key],
      expected[key],
      "Original cadence evidence mismatch",
    );
}
function verifyCompositeProof(value, { requireCleanup = true } = {}) {
  c.closed(value, [
    "preparedLease",
    "lease",
    "preparation",
    "completion",
    "cleanup",
    "cleanupFinishedAt",
  ]);
  c.verifyOriginalLease(value.lease, value.preparedLease);
  assert.equal(value.lease.phase, "observer-owned");
  c.closed(value.preparation, [
    "schemaVersion",
    "kind",
    "preparedLease",
    "observed",
    "fixtureSources",
  ]);
  assert.equal(value.preparation.schemaVersion, 1);
  assert.equal(value.preparation.kind, c.KIND);
  c.verifyOriginalLease(value.preparation.preparedLease, value.preparedLease);
  assert.equal(value.preparation.preparedLease.phase, "preparing");
  const original = c.verifyObservation(
    value.preparation.observed,
    value.preparedLease,
  );
  const sources = value.preparation.fixtureSources;
  assert.ok(
    Array.isArray(sources) && sources.length > 5 && sources.length <= 128,
  );
  const unique = new Set();
  for (const row of sources) {
    c.closed(row, ["file", "sha256"]);
    assert.match(
      row.file,
      /^(?:scripts|tests|packages|infra|apps|\.github)\/[a-zA-Z0-9_./-]+$/,
    );
    assert.ok(!row.file.split("/").includes(".."));
    assert.ok(!unique.has(row.file));
    unique.add(row.file);
    assert.match(row.sha256, /^[a-f0-9]{64}$/);
  }
  for (const file of require("./certops-retention-cadence-sources")
    .REQUIRED_SOURCES)
    assert.ok(unique.has(file), "Missing native cadence source");
  const completion = value.completion;
  c.closed(completion, COMPLETION_FIELDS);
  assert.equal(completion.schemaVersion, 1);
  assert.equal(
    completion.scope,
    "completed-installed-default-timer-awaiting-owned-cleanup",
  );
  assert.equal(completion.currentNativeVerified, true);
  // Completed observations carry original process identities, but are not a new
  // Running/first-four-hours attestation and cannot renew that original authority.
  c.closed(completion.originalObservation, c.OBSERVATION_FIELDS);
  same(
    completion.originalObservation,
    original,
    c.OBSERVATION_FIELDS.filter((key) => key !== "verifiedAt"),
  );
  const result = completion.result;
  c.closed(result, RESULT_FIELDS);
  assert.equal(result.schemaVersion, 1);
  assert.equal(
    result.scope,
    "observed-installed-default-timer-awaiting-independent-finalization",
  );
  assert.equal(result.defaultIntervalMs, c.BASE_INTERVAL);
  assert.equal(result.defaultRetentionHours, 168);
  assert.equal(result.actualCleanupQualified, false);
  assert.equal(result.full168HourRetentionQualified, false);
  c.closed(result.native, NATIVE_FIELDS);
  same(result.native, original, [
    "principalSid",
    "bootTime",
    "serviceHostPid",
    "serviceHostCreatedAt",
    "agentPid",
    "agentCreatedAt",
    "configSha256",
  ]);
  for (const key of [
    "nativeCustodyVerified",
    "defaultsOmittedVerified",
    "soleInstalledAgentVerified",
    "soleLedgerWriterVerified",
    "trustedTlsVerified",
  ])
    assert.equal(result.native[key], true);
  for (const item of [result.immediate, result.timer]) {
    c.closed(item, ["monotonicMs", "observedAt", "fileId"]);
    c.epoch(item.observedAt);
    assert.match(item.fileId, /^[1-9][0-9]{0,24}:[1-9][0-9]{0,24}$/);
  }
  assert.equal(result.immediate.fileId, original.immediateLedgerFileId);
  assert.equal(result.immediate.observedAt, original.immediateObservedAt);
  assert.equal(result.immediate.monotonicMs, original.immediateMonotonicMs);
  assert.notEqual(result.timer.fileId, result.immediate.fileId);
  c.verifyTimerWindow(
    result.immediate.monotonicMs,
    result.timer.monotonicMs,
    result.timer.monotonicMs,
  );
  const wallElapsed =
      c.epoch(result.timer.observedAt) - c.epoch(result.immediate.observedAt),
    monoElapsed = result.timer.monotonicMs - result.immediate.monotonicMs;
  assert.ok(Math.abs(wallElapsed - monoElapsed) <= 5000);
  assert.ok(
    c.epoch(result.startedAt) >= c.epoch(value.preparedLease.createdAt) &&
      c.epoch(result.startedAt) <= c.epoch(result.immediate.observedAt),
  );
  assert.ok(
    c.epoch(result.finishedAt) >= c.epoch(result.timer.observedAt) &&
      c.epoch(result.finishedAt) <=
        c.epoch(result.timer.observedAt) + c.OBSERVATION_MARGIN,
  );
  assert.ok(
    c.epoch(completion.verifiedAt) >= c.epoch(result.finishedAt) &&
      c.epoch(completion.verifiedAt) < c.epoch(value.lease.hardExpiresAt),
  );
  assert.match(result.configSha256, /^[a-f0-9]{64}$/);
  assert.equal(result.configSha256, original.observerConfigSha256);
  if (requireCleanup) {
    assert.equal(value.cleanup, "completed");
    assert.ok(
      c.epoch(value.cleanupFinishedAt) >= c.epoch(completion.verifiedAt),
    );
  } else {
    assert.ok(["pending", "completed"].includes(value.cleanup));
    if (value.cleanup !== "completed")
      assert.equal(value.cleanupFinishedAt, null);
  }
  const facts = {
    observerProcessId: original.processId,
    observerProcessCreatedAt: original.processCreatedAt,
    candidateSha: value.preparedLease.candidateSha,
    prepareRunId: value.preparedLease.runId,
    prepareRunAttempt: value.preparedLease.runAttempt,
    nonce: value.preparedLease.nonce,
    vmId: value.preparedLease.vmId,
    nodeSha256: value.preparedLease.nodeSha256,
    observerSha256: value.preparedLease.observerSha256,
    agentConfigSha256: original.configSha256,
    observerConfigSha256: result.configSha256,
    immutableLedgerSha256: original.immutableLedgerSha256,
    pendingLedgerFileId: original.pendingLedgerFileId,
    immediateLedgerFileId: original.immediateLedgerFileId,
    timerLedgerFileId: result.timer.fileId,
    originalCreatedAt: value.preparedLease.createdAt,
    immediateObservedAt: result.immediate.observedAt,
    timerObservedAt: result.timer.observedAt,
    finishedAt: result.finishedAt,
    cleanupFinishedAt: requireCleanup
      ? value.cleanupFinishedAt
      : completion.verifiedAt,
    ...Object.fromEntries(
      [
        "bootTime",
        "serviceHostPid",
        "serviceHostCreatedAt",
        "agentPid",
        "agentCreatedAt",
      ].map((key) => [key, original[key]]),
    ),
  };
  const proof = {
    scope: SCOPE,
    defaultIntervalMs: c.BASE_INTERVAL,
    defaultRetentionHours: 168,
    actualMonotonicIntervalMs: monoElapsed,
    ...facts,
    ...Object.fromEntries(FLAGS.map((key) => [key, true])),
    ...Object.fromEntries(FALSE_FLAGS.map((key) => [key, false])),
  };
  verifyProof(proof);
  if (!requireCleanup && value.cleanup !== "completed")
    proof.ownedAzureCleanupVerified = false;
  return proof;
}
function createQualificationReport(value, provenance) {
  const proof = verifyCompositeProof(value),
    source = "scripts/certops-retention-cadence-runtime.js",
    fixtureSource = value.preparation.fixtureSources.find(
      (item) => item.file === source,
    );
  assert.ok(fixtureSource);
  const capabilities = Object.fromEntries(
    ["windows", "system", "domain", "sameVmResidentKeeper", "api"].map(
      (name) => [name, { available: true }],
    ),
  );
  const intervals = [
    [value.preparedLease.createdAt, proof.immediateObservedAt],
    [proof.immediateObservedAt, proof.finishedAt],
    [value.completion.verifiedAt, value.cleanupFinishedAt],
  ];
  return {
    schemaVersion: 1,
    suite: "windows-domain-installed-retention-default-timer",
    candidateSha: proof.candidateSha,
    strict: true,
    status: "passed",
    evidenceLevel: "real-host",
    startedAt: value.preparedLease.createdAt,
    finishedAt: value.cleanupFinishedAt,
    requiredCapabilities: Object.keys(capabilities),
    capabilities,
    missingCapabilities: [],
    requiredScenarios: SCENARIOS,
    missingScenarios: [],
    scenarios: SCENARIOS.map((id, index) => ({
      id,
      status: "passed",
      evidenceLevel: "real-host",
      startedAt: intervals[index][0],
      finishedAt: intervals[index][1],
    })),
    cleanup: { status: "passed" },
    platform: "win32",
    architecture: "x64",
    qualificationEnvironment: {
      osFamily: "windows",
      osVersion: "2022",
      nativeLanguage: "en-US",
      identity: "LocalSystem",
      architecture: "x64",
      measurement: "native",
    },
    fixtureSource,
    fixtureSources: value.preparation.fixtureSources,
    artifactQualification: "workflow-checkout-source",
    nativeRetentionCadence: proof,
    retentionCadenceProvenance: provenance,
  };
}
module.exports = {
  SCOPE,
  SCENARIOS,
  NATIVE_FIELDS,
  RESULT_FIELDS,
  COMPLETION_FIELDS,
  FLAGS,
  FALSE_FLAGS,
  FACT_FIELDS,
  verifyProof,
  verifyCompositeProof,
  createQualificationReport,
};

"use strict";
// Supporting evidence-contract tests only. These do not run a collector or
// create certificates, keys, services, bindings, or elapsed native evidence.
const assert = require("node:assert/strict");
const test = require("node:test");
const proof = require("../packages/agent/scripts/host/retention-policy-expiry-proof");
const retention = require("../packages/agent/src/windows-retention");

function fixture(hours = 168) {
  return {
    ownedInterruption: {
      scope: "owned-short-retention-native-interruption-drain",
      assignedBeforeResume: true,
      rootExit86: true,
      nativeActiveZero: true,
      nativeHandlesClosed: true,
      wrapperClosed: true,
    },
    scope: proof.SCOPE,
    configuredRetentionHours: hours,
    verifiedCutoverAt: "2026-10-15T10:00:00.000Z",
    oldNotAfter: "2026-10-15T10:02:00.000Z",
    cleanupDeadline: "2026-10-15T10:07:00.000Z",
    preDeadlineObservedAt: "2026-10-15T10:01:00.000Z",
    cleanupObservedAt: "2026-10-15T10:07:01.000Z",
    waitStartedAt: "2026-10-15T10:01:00.000Z",
    waitFinishedAt: "2026-10-15T10:07:01.000Z",
    waitedMonotonicMs: 361000,
    installedServiceTimerQualified: false,
    fullRetentionWindowQualified: false,
    ...Object.fromEntries(proof.FLAGS.map((field) => [field, true])),
    ...Object.fromEntries(proof.COUNTS.map((field) => [field, 2])),
  };
}

test("default and maximum native expiry contracts match the actual production deadline rule", () => {
  for (const hours of proof.POLICIES) {
    const value = fixture(hours);
    assert.equal(proof.verifyProof(value), true);
    assert.equal(
      retention
        .computeCleanupDeadline({
          verifiedCutoverAt: value.verifiedCutoverAt,
          oldNotAfter: value.oldNotAfter,
          retentionHours: hours,
        })
        .toISOString(),
      value.cleanupDeadline,
    );
  }
});

test("actual PowerShell seven-digit native expiry is canonicalized only at the public proof boundary", () => {
  const raw = "2026-10-15T10:02:00.0000000Z";
  const privateCustody = { expiry: raw };
  const value = {
    ...fixture(),
    oldNotAfter: proof.publicNativeTimestamp(privateCustody.expiry),
  };
  assert.equal(proof.verifyProof(value), true);
  assert.equal(privateCustody.expiry, raw);
  assert.throws(() => proof.verifyProof({ ...value, oldNotAfter: raw }));
  for (const input of [null, "not-a-date", "2026-10-15T10:02:00Z"]) {
    assert.throws(() => proof.publicNativeTimestamp(input));
  }
});

test("every native fact is mandatory and private or timer-promotion fields are refused", () => {
  const value = fixture();
  for (const field of proof.FIELDS) {
    const missing = { ...value };
    delete missing[field];
    assert.throws(() => proof.verifyProof(missing));
  }
  for (const field of proof.FLAGS) {
    for (const invalid of [false, 1, "true", null]) {
      assert.throws(() => proof.verifyProof({ ...value, [field]: invalid }));
    }
  }
  for (const field of proof.COUNTS) {
    for (const invalid of [0, 1, 3, "2", null]) {
      assert.throws(() => proof.verifyProof({ ...value, [field]: invalid }));
    }
  }
  for (const field of [
    "installedServiceTimerQualified",
    "fullRetentionWindowQualified",
  ]) {
    assert.throws(() => proof.verifyProof({ ...value, [field]: true }));
  }
  assert.throws(() =>
    proof.verifyProof({ ...value, rawCngContainer: "private" }),
  );
});

test("unsupported native policy parameters fail before creating fixture ownership state", async () => {
  const {
    qualifyElapsedRetention,
  } = require("../packages/agent/scripts/host/retention-elapsed-fixture");
  for (const retentionHours of [0, 23, 169, 721, "168", null]) {
    await assert.rejects(qualifyElapsedRetention({ retentionHours }));
  }
});

test("wrong policies, premature cleanup, changed grace, and wall-clock-only waits cannot qualify", () => {
  for (const change of [
    { configuredRetentionHours: 24 },
    { configuredRetentionHours: "168" },
    { configuredRetentionHours: 721 },
    { cleanupObservedAt: fixture().cleanupDeadline },
    { cleanupDeadline: "2026-10-15T10:06:59.000Z" },
    { preDeadlineObservedAt: fixture().oldNotAfter },
    { waitedMonotonicMs: 299999 },
    { waitedMonotonicMs: 600000 },
    { waitedMonotonicMs: 320000 },
    { oldNotAfter: "2026-10-15T10:00:00.000Z" },
    { cleanupObservedAt: "2026-10-15T10:07:01Z" },
  ])
    assert.throws(() => proof.verifyProof({ ...fixture(), ...change }));
});

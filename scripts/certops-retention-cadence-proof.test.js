"use strict";
// Offline receipt adversaries; these synthetic objects are never native reports.
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const p = require("./certops-retention-cadence-proof");
const { fixture } = require("./fixtures/certops-retention-cadence.cjs");

test("separate timer proof requires native chronology and actual owned cleanup", () => {
  const value = fixture(),
    proof = p.verifyCompositeProof(value);
  assert.equal(proof.sameInstalledProcessAndBoot, true);
  assert.equal(proof.full168HourRetentionQualified, false);
  assert.equal(p.createQualificationReport(value).requiredScenarios.length, 3);
  value.cleanup = "pending";
  value.cleanupFinishedAt = null;
  assert.throws(() => p.createQualificationReport(value));
  assert.equal(
    p.verifyCompositeProof(value, { requireCleanup: false })
      .ownedAzureCleanupVerified,
    false,
  );
});
test("no receipt splice, missing source, timing fabrication or broader promotion is accepted", () => {
  for (const mutate of [
    (v) => {
      v.completion.result.native.agentPid++;
    },
    (v) => {
      v.completion.originalObservation.configSha256 = "0".repeat(64);
    },
    (v) => {
      v.completion.result.timer.fileId = v.completion.result.immediate.fileId;
    },
    (v) => {
      v.completion.result.timer.monotonicMs = 1000;
    },
    (v) => {
      v.completion.result.full168HourRetentionQualified = true;
    },
    (v) => {
      v.completion.result.actualCleanupQualified = true;
    },
    (v) => {
      v.preparation.fixtureSources.pop();
    },
    (v) => {
      v.completion.currentNativeVerified = false;
    },
    (v) => {
      v.lease.hardExpiresAt = "2026-10-16T00:00:00.000Z";
    },
  ]) {
    const value = fixture();
    mutate(value);
    assert.throws(() => p.verifyCompositeProof(value));
  }
});

"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const { CANDIDATE_SHA256, nativeCounts } = require("./certops-adcs-store-native-cng.fixture");
const {
  qualifyPendingStoreRecovery, verifyPendingJournalIdentity, verifyPendingOperationCounts, validatePendingCaWindow,
  drainPendingObservations,
} = require("./certops-adcs-store-pending-native");

const counts = (accepts) => nativeCounts({ accepts });

test("native pending Store recovery refuses before opening a fixture when interruption is unavailable", async () => {
  const context = new Proxy({}, {
    get() {
      assert.fail("Native admission read fixture context");
    },
  });
  await assert.rejects(qualifyPendingStoreRecovery(context), /active observation-loss interruption is not implemented/);
});

test("pending approval preserves RequestId, CSR, snapshot and protected key through restart", () => {
  const journal = {
    requestId: "8",
    containerName: "owned",
    snapshotSha256: "a".repeat(64),
    csrSha256: "b".repeat(64),
    csrSpkiSha256: "c".repeat(64),
  };
  verifyPendingJournalIdentity(journal, { ...journal });
  for (const field of ["requestId", "containerName", "snapshotSha256", "csrSha256", "csrSpkiSha256"]) {
    assert.throws(() => verifyPendingJournalIdentity(journal, { ...journal, [field]: "changed" }), new RegExp(field));
  }
});

test("pending restart and approval permit one submission, one generated key and one later accept", () => {
  verifyPendingOperationCounts(counts(0), counts(0), counts(1));
  assert.throws(() => verifyPendingOperationCounts({ ...counts(0), coverageComplete: false }, counts(0), counts(1)));
  assert.throws(() => verifyPendingOperationCounts(counts(0), { ...counts(0), coverageComplete: false }, counts(1)));
  assert.throws(() => verifyPendingOperationCounts(counts(0), { ...counts(0), captureId: "b".repeat(32) }, counts(1)));
  assert.throws(() => verifyPendingOperationCounts(counts(0), counts(1), counts(1)));
  assert.throws(() => verifyPendingOperationCounts(counts(0), counts(0), { ...counts(1), keygens: 2 }));
  assert.throws(() => verifyPendingOperationCounts(counts(0), counts(0), { ...counts(1), submissions: 2 }));
  assert.throws(() => verifyPendingOperationCounts(counts(0), counts(0), counts(2)));
});

test("the independent CA window requires the original pending request throughout restart", () => {
  const observation = {
    observationId: "a".repeat(32), caPublicKeySha256: "b".repeat(64), baselineRequestId: 7,
  };
  const pending = {
    ...observation, coverageComplete: true, lossFree: true, noPurgeProven: true, noRestoreProven: true,
    globalCount: 1, subjectRequestCount: 1, matchingIssuedCount: 0, unknownIssuedCount: 0,
    disposition: 9, requestId: "8",
  };
  assert.doesNotThrow(() => validatePendingCaWindow(pending, observation, "8"));
  for (const change of [
    { coverageComplete: false }, { lossFree: false }, { noPurgeProven: false }, { noRestoreProven: false },
    { observationId: "c".repeat(32) }, { caPublicKeySha256: "d".repeat(64) }, { baselineRequestId: 6 },
    { globalCount: 2 }, { subjectRequestCount: 2 }, { matchingIssuedCount: 1 }, { unknownIssuedCount: 1 },
    { disposition: 20 }, { requestId: "9" },
  ]) {
    assert.throws(() => validatePendingCaWindow({ ...pending, ...change }, observation, "8"), JSON.stringify(change));
  }
  assert.throws(() => validatePendingCaWindow({ ...pending, requestId: "7" }, observation, "7"));
  assert.throws(() => validatePendingCaWindow({ ...pending, requestId: "2147483648" }, observation, "2147483648"));
});

test("pending observation teardown requires independent proof the exact service and its descendants stopped", async () => {
  const calls = [];
  const installedCounts = counts(1);
  const serviceProcess = { pid: 23, created: "2026-11-23T10:30:00.000Z" };
  const caIdentity = { observationId: "b".repeat(32), caPublicKeySha256: "c".repeat(64), baselineRequestId: 7 };
  const issuedWindow = {
    ...caIdentity, coverageComplete: true, lossFree: true, noPurgeProven: true, noRestoreProven: true,
    globalCount: 1, subjectRequestCount: 1, matchingIssuedCount: 1, unknownIssuedCount: 0,
    requestId: "8", fingerprintSha256: "d".repeat(64),
  };
  const context = {
    installedCounts, issuedWindow, candidateArchiveSha256: CANDIDATE_SHA256, serviceProcess,
    capture: {
      captureId: installedCounts.captureId,
      async stop() {
        calls.push("native capture");
        return { drained: true, captureId: installedCounts.captureId, finalCounts: installedCounts };
      },
    },
    caObservation: {
      ...caIdentity,
      async stop() {
        calls.push("CA observation");
        return { drained: true, observationId: caIdentity.observationId, finalWindow: issuedWindow };
      },
    },
  };
  const proof = {
    candidateArchiveSha256: CANDIDATE_SHA256, captureId: installedCounts.captureId, pid: serviceProcess.pid,
    created: serviceProcess.created, independentReader: true, serviceStopped: true, activeDescendants: [],
    evidenceSha256: "e".repeat(64),
  };
  const withServiceProof = (change = {}) => ({
    ...context,
    async stopAndVerifyOwnedService(target) {
      calls.push("service");
      assert.deepEqual(target, { candidateArchiveSha256: CANDIDATE_SHA256, captureId: installedCounts.captureId, ...serviceProcess });
      return { ...proof, ...change };
    },
  });
  for (const invalid of [
    { independentReader: false }, { serviceStopped: false }, { activeDescendants: [42] },
    { created: "other process" }, { captureId: "f".repeat(32) }, { evidenceSha256: undefined },
  ]) {
    await assert.rejects(drainPendingObservations(withServiceProof(invalid)));
    assert.deepEqual(calls.splice(0), ["service"]);
  }
  await assert.rejects(drainPendingObservations({
    ...withServiceProof(),
    capture: { captureId: installedCounts.captureId, async stop() { calls.push("native capture"); return { drained: false }; } },
  }));
  assert.deepEqual(calls.splice(0), ["service", "native capture"]);
  const drained = await drainPendingObservations(withServiceProof());
  assert.deepEqual(calls, ["service", "native capture", "CA observation"]);
  assert.deepEqual(drained, { counts: installedCounts, window: issuedWindow, serviceDrainageSha256: proof.evidenceSha256 });
});

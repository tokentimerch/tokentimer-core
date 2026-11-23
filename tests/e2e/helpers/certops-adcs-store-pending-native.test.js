"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const { nativeCounts } = require("./certops-adcs-store-native-cng.fixture");
const {
  qualifyPendingStoreRecovery, verifyPendingJournalIdentity, verifyPendingOperationCounts,
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

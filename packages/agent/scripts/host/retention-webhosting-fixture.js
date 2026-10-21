/*
 * Qualification notes: webhosting-expiry-reclamation
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Separate Azure-free certops-windows-webhosting-retention.yml manually on trusted
 * main,Server2022/2025. Actual two-cutover short-leaf collector uses LocalMachine
 * WebHosting,unchanged24h policy,real expiry+300s. Independent WebHosting custody/IIS-store receipt
 * required; reject My-only engine before work. Contained post-cert/pre-key interruption/default retry
 * completes immutable ledger and preserves replacement trustedTLS/key. Explicit replacement mirror
 * into WebHosting borrows originalMy key; remove mirror only after original inventory/possession
 * preservation,then owned final cleanup. One real wait/native15m/job20m keeps comprehensive
 * host3wait/40m budget intact. Not full24h or service cadence; supporting proofs do not qualify
 * native.
 */
"use strict";
/** Closed non-default-store retention evidence. Native expiry/grace timing is
 * shared with the established collector fixture; changing a label on its My
 * report cannot establish the required independent WebHosting store receipt. */
const assert = require("node:assert/strict");
const engine = require("./retention-elapsed-fixture");
const STORE = "WebHosting";
const SCENARIOS = Object.freeze([
  "windows-webhosting-retention-real-expiry-grace",
  "windows-webhosting-retention-native-interrupted-delete",
]);
const SCOPE = "native-webhosting-expiry-grace-certificate-key-reclamation";
const FLAGS = Object.freeze([
  "nativeWebHostingCustodyObserved",
  "nativeIisWebHostingStoreObserved",
  "exactOwnedEngineCleanupVerified",
]);
const REQUIRED_SOURCES = Object.freeze([
  "packages/agent/scripts/host/retention-webhosting-fixture.js",
  ...require("./retention-webhosting-replacement").REQUIRED_SOURCES,
  "packages/agent/scripts/host/retention-elapsed-fixture.js",
  "packages/agent/scripts/host/retention-interrupted-child.js",
  ...require("./retention-interrupted-process").REQUIRED_SOURCES,
  "packages/agent/src/index.js",
  "packages/agent/src/windows-retention/index.js",
  "packages/agent/src/windows-cert-store/index.js",
  "packages/agent/src/windows-key-survivors/index.js",
  "packages/agent/src/windows-iis/index.js",
]);
function verifyStoreReceipt(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), ["store", ...FLAGS].sort());
  assert.equal(value.store, STORE);
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  return true;
}
function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "schemaVersion",
      "scope",
      "store",
      "storeReceipt",
      "elapsed",
      "borrowedReplacement",
      "fullRetentionWindowQualified",
      "installedServiceTimerQualified",
    ].sort(),
  );
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.scope, SCOPE);
  assert.equal(value.store, STORE);
  verifyStoreReceipt(value.storeReceipt);
  engine.verifyElapsedProof(value.elapsed);
  verifyBorrowedReplacement(value.borrowedReplacement);
  assert.equal(value.fullRetentionWindowQualified, false);
  assert.equal(value.installedServiceTimerQualified, false);
  return true;
}
function verifyBorrowedReplacement(value) {
  const flags = [
    "sameOriginalMyCustodyAndInventory",
    "sameOriginalMyPrivateKeyPossession",
    "mirrorRemovedWithoutDeletingSharedKey",
    "originalFixtureCertificateAndKeyRemoved",
  ];
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), flags.sort());
  for (const flag of flags) assert.equal(value[flag], true, flag);
  return true;
}
function verifyEngineContract(value) {
  assert.ok(
    Array.isArray(value.SUPPORTED_STORES) &&
      value.SUPPORTED_STORES.includes(STORE),
    "Store-aware native expiry engine is required before any mutation",
  );
  assert.equal(typeof value.qualifyElapsedRetention, "function");
  assert.equal(typeof value.verifyElapsedStoreResult, "function");
}
async function qualifyWebHostingRetention(context) {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_HOST_TESTS, "1");
  verifyEngineContract(engine);
  const local = {};
  const gate = {
    report: local,
    scenario: (id, fn, options) => {
      assert.equal(id, "windows-retention-native-interrupted-delete");
      return context.gate.scenario(SCENARIOS[1], fn, options);
    },
  };
  await context.replacementOwner.verifyBorrowed();
  const result = await engine.qualifyElapsedRetention({
    ...context,
    store: STORE,
    retentionHours: 24,
    gate,
  });
  engine.verifyElapsedStoreResult(result);
  verifyStoreReceipt(result.storeReceipt);
  assert.equal(result.store, STORE);
  assert.deepEqual(result.elapsed, local.nativeElapsedRetention);
  await context.replacementOwner.verifyBorrowed();
  const borrowedReplacement =
    await context.replacementOwner.cleanupAfterSuccessfulCase();
  verifyBorrowedReplacement(borrowedReplacement);
  const proof = {
    schemaVersion: 1,
    scope: SCOPE,
    store: STORE,
    storeReceipt: result.storeReceipt,
    elapsed: result.elapsed,
    borrowedReplacement,
    fullRetentionWindowQualified: false,
    installedServiceTimerQualified: false,
  };
  verifyProof(proof);
  return proof;
}
module.exports = {
  STORE,
  SCENARIOS,
  SCOPE,
  FLAGS,
  REQUIRED_SOURCES,
  verifyStoreReceipt,
  verifyBorrowedReplacement,
  verifyProof,
  verifyEngineContract,
  qualifyWebHostingRetention,
};

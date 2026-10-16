"use strict";
/** Supporting retention-lineage safety checks using public temporary JSON rows.
 * These exercise production bounded traversal and malformed-history refusal;
 * filesystem rows and time are explicit unit prerequisites. No native store,
 * key deletion, live binding or elapsed retention qualification is claimed. */
const { test, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { resolveBoundReplacement, sweepLedger, readLedgerRow } = require("./index");
const A = "A1".repeat(20), B = "B2".repeat(20), C = "C3".repeat(20);
const nowMs = Date.parse("2026-01-03T00:00:00Z");
const directories = [];
function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "retention-lineage-unit-"));
  directories.push(directory);
  return directory;
}
function row(oldThumbprint = A, replacementThumbprint = B, overrides = {}) {
  return { oldThumbprint, replacementThumbprint, cngKeyContainerId: "tokentimer-public-lineage-unit", verifiedCutoverAt: "2026-01-01T00:00:00Z", oldNotAfter: "2026-02-01T00:00:00Z", ownershipProvenance: "tokentimer_installed", store: "My", jobOrRollbackJournalRefs: [], lifecycleState: "pending_retention", deferralReason: null, ...overrides };
}
function persist(directory, value, name = value.oldThumbprint) {
  fs.writeFileSync(path.join(directory, name + ".json"), JSON.stringify(value));
}
afterEach(() => {
  while (directories.length) {
    const directory = path.resolve(directories.pop());
    assert.equal(path.dirname(directory), path.resolve(os.tmpdir()));
    assert.match(path.basename(directory), /^retention-lineage-unit-[A-Za-z0-9]{6}$/);
    assert.equal(fs.lstatSync(directory).isSymbolicLink(), false);
    fs.rmSync(directory, { recursive: true, force: false });
  }
});

test("a bound direct replacement requires no descendant history", () => {
  const directory = fixture();
  assert.equal(resolveBoundReplacement({ ledgerDir: directory, row: row(), isBound: (thumbprint, store) => thumbprint === B && store === "MY", nowMs }), B);
});

test("verified same-store descendants preserve immutable cutover rows and deadlines", () => {
  const directory = fixture(), original = row();
  persist(directory, original);
  persist(directory, row(B, C, { verifiedCutoverAt: "2026-01-02T00:00:00Z", store: "my" }));
  const before = fs.readFileSync(path.join(directory, A + ".json"));
  assert.equal(resolveBoundReplacement({ ledgerDir: directory, row: original, isBound: thumbprint => thumbprint === C, nowMs }), C);
  assert.deepEqual(fs.readFileSync(path.join(directory, A + ".json")), before);
});

test("removed intermediate certificates retain their verified cutover history", () => {
  const directory = fixture();
  persist(directory, row(B, C, { lifecycleState: "removed", store: null }));
  assert.equal(resolveBoundReplacement({ ledgerDir: directory, row: row(), isBound: thumbprint => thumbprint === C, nowMs }), C);
});

test("foreign-store unowned active future and backwards links never authorize a descendant", () => {
  for (const overrides of [
    { store: "WebHosting" },
    { ownershipProvenance: "preexisting" },
    { jobOrRollbackJournalRefs: [{ ref: "actual-active-recovery-prerequisite", active: true }] },
    { verifiedCutoverAt: "2025-12-31T00:00:00Z" },
    { verifiedCutoverAt: "2026-01-04T00:00:00Z" },
    { oldThumbprint: A },
    { replacementThumbprint: "malformed" },
  ]) {
    const directory = fixture();
    persist(directory, row(B, C, overrides), B);
    const checked = [];
    assert.equal(resolveBoundReplacement({ ledgerDir: directory, row: row(), isBound: thumbprint => { checked.push(thumbprint); return thumbprint === C; }, nowMs }), null);
    assert.deepEqual(checked, [B]);
  }
});

test("missing malformed and unrelated history cannot select another live certificate", () => {
  const directory = fixture();
  const resolve = () => resolveBoundReplacement({ ledgerDir: directory, row: row(), isBound: thumbprint => thumbprint === C, nowMs });
  persist(directory, row("D4".repeat(20), C));
  assert.equal(resolve(), null);
  fs.writeFileSync(path.join(directory, B + ".json"), "{incomplete");
  assert.equal(resolve(), null);
});

test("a row named for one predecessor cannot authorize another certificate identity", async () => {
  const directory = fixture();
  persist(directory, row(B, C), A);
  let nativeCalls = 0;
  assert.throws(() => readLedgerRow(directory, A), /thumbprint does not match/);
  await assert.rejects(sweepLedger({
    ledgerDir: directory, retentionHours: 24,
    gatherContext() { nativeCalls += 1; return eligibleFacts(); },
    performCleanup() { nativeCalls += 1; },
  }), /thumbprint does not match/);
  assert.equal(nativeCalls, 0);
});

test("a cycle cannot return the original predecessor even when it is reported bound", () => {
  const directory = fixture();
  persist(directory, row(B, A));
  assert.equal(resolveBoundReplacement({ ledgerDir: directory, row: row(), isBound: thumbprint => thumbprint === A, nowMs }), null);
});

test("lineage traversal is bounded even for valid chronological unique rows", () => {
  const directory = fixture(), thumbprint = value => value.toString(16).toUpperCase().padStart(40, "0");
  for (let index = 1; index <= 65; index += 1) persist(directory, row(thumbprint(index), thumbprint(index + 1)));
  let checks = 0;
  assert.equal(resolveBoundReplacement({ ledgerDir: directory, row: row(thumbprint(0), thumbprint(1)), isBound: value => { checks += 1; return value === thumbprint(66); }, nowMs }), null);
  assert.equal(checks, 64);
});

const eligibleFacts = () => ({ bindingStillReferencesOldThumbprint: false, keyContainerSharedWithSurvivor: false, replacementPassesHandshakeNow: true });

test("an active recovery reference added before lock acquisition is re-read and preserved", async () => {
  const directory = fixture();
  persist(directory, row());
  let locked = false, cleanupCalls = 0;
  const summary = await sweepLedger({
    ledgerDir: directory, retentionHours: 24, now: () => new Date(nowMs),
    async withRowLock(initial, work) {
      assert.equal(initial.jobOrRollbackJournalRefs.length, 0);
      locked = true;
      persist(directory, row(A, B, { jobOrRollbackJournalRefs: [{ ref: "new-active-recovery", active: true }] }));
      try {
        await work({ assertHeld() { assert.equal(locked, true); } });
        assert.equal(readLedgerRow(directory, A).lifecycleState, "deferred");
      } finally { locked = false; }
    },
    gatherContext(fresh) { assert.equal(locked, true); assert.equal(fresh.jobOrRollbackJournalRefs[0].active, true); return eligibleFacts(); },
    performCleanup() { cleanupCalls += 1; },
  });
  assert.equal(cleanupCalls, 0);
  assert.deepEqual(summary.deferred, [{ oldThumbprint: A, reason: "active_reference_present" }]);
  assert.equal(readLedgerRow(directory, A).jobOrRollbackJournalRefs[0].active, true);
});

test("a changed store while acquiring the mutex refuses all native work and state writes", async () => {
  const directory = fixture();
  persist(directory, row());
  let nativeCalls = 0;
  await assert.rejects(sweepLedger({
    ledgerDir: directory, retentionHours: 24,
    withRowLock(_initial, work) { persist(directory, row(A, B, { store: "WebHosting" })); return work(); },
    gatherContext() { nativeCalls += 1; return eligibleFacts(); },
    performCleanup() { nativeCalls += 1; },
  }), /store changed/);
  assert.equal(nativeCalls, 0);
  assert.equal(readLedgerRow(directory, A).store, "WebHosting");
  assert.equal(readLedgerRow(directory, A).lifecycleState, "pending_retention");
});

test("authority lost during fact gathering or deletion cannot write a ledger outcome", async () => {
  for (const phase of ["gather", "cleanup"]) {
    const directory = fixture();
    persist(directory, row());
    const before = fs.readFileSync(path.join(directory, A + ".json"));
    const loss = Object.assign(new Error("Owned supporting mutex authority was lost"), { code: "STORE_LOCK_LOST" });
    let lost = false, cleanupCalls = 0;
    await assert.rejects(sweepLedger({
      ledgerDir: directory, retentionHours: 24, now: () => new Date(nowMs),
      withRowLock(_initial, work) { return work({ assertHeld() { if (lost) throw loss; } }); },
      gatherContext() { if (phase === "gather") lost = true; return eligibleFacts(); },
      performCleanup() { cleanupCalls += 1; lost = true; throw loss; },
    }), error => error === loss);
    assert.equal(cleanupCalls, phase === "cleanup" ? 1 : 0);
    assert.deepEqual(fs.readFileSync(path.join(directory, A + ".json")), before);
  }
});

test("the final removed ledger row is persisted before the lock scope returns", async () => {
  const directory = fixture();
  persist(directory, row());
  let locked = false;
  const summary = await sweepLedger({
    ledgerDir: directory, retentionHours: 24, now: () => new Date(nowMs),
    async withRowLock(_initial, work) {
      locked = true;
      try {
        await work({ assertHeld() { assert.equal(locked, true); } });
        assert.equal(readLedgerRow(directory, A).lifecycleState, "removed");
      } finally { locked = false; }
    },
    gatherContext() { assert.equal(locked, true); return eligibleFacts(); },
    performCleanup() { assert.equal(locked, true); },
  });
  assert.deepEqual(summary.removed, [A]);
  assert.equal(locked, false);
});

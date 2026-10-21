"use strict";
/**
 * Qualification notes: bound before durable completion experiment
 *
 * bound-before-complete observes new native SNI/TLS while journal remains installing/bind; no
 * post-bind/pre-verification marker exists, and verify/retention may already have run. Capture/
 * drain exact SYSTEM tree, refuse later ambiguity; verify accepted key signature with actual leaf
 * and unchanged artifacts. Real-lease/grace recovery rechecks same CSR/key/leaf/RequestId, no
 * extra CA request, finishes claim evidence. Final exactly-one predecessor retention row; existing
 * row/original cutover time unchanged, predecessor key/cert retained. Optional observed window
 * remains experimental/not-qualified, not arbitrary crash timing.
 *
 * Shared setup, evidence and cleanup policy: docs/certops/e2e-qualification.md.
 */
/** Synthetic refusal controls; actual post-bind crash recovery remains pending. */
const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const helper = require("../tests/e2e/helpers/certops-adcs-bound-install-recovery");
const base = require("../tests/e2e/helpers/certops-adcs-accepted-install-recovery");
const { EventEmitter } = require("node:events");
const root = path.resolve(__dirname, "..");
function fixture() {
  const hash = file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") });
  return { schemaVersion: 1, scope: "enterprise-adcs-journal-phase-experimental", phase: helper.PHASE, qualificationStatus: "not-qualified", experimental: true, status: "passed", candidateSha: "c".repeat(40), fixtureSource: hash("tests/e2e/helpers/certops-adcs-bound-install-recovery.js"), fixtureSources: helper.REQUIRED_SOURCES.map(hash), fault: { phase: helper.PHASE, observedDurablePhase: true, unchangedAfterTermination: true, ownedServiceTree: true, ownedNativeChildrenAbsent: true, nativeIdentity: "LocalSystem", acceptedExactLeafAndCng: true, newIisLeafBound: true, enrollmentId: "11111111-1111-1111-1111-111111111111", jobId: "22222222-2222-2222-2222-222222222222", snapshotSha256: "a".repeat(64), requestId: "1", fingerprint: "b".repeat(64) }, leaseRemainingAtFaultMs: 60000, recoveryWaitBudgetMs: 150000, actualLeaseWaitMs: 120000, caRequestsAtFault: 3, caRequestsAfterRecovery: 3, retentionAtFault: "absent", preVerificationWindowClaimed: false, ...Object.fromEntries(helper.FLAGS.map(flag => [flag, true])) };
}
test("bound experiment requires current trusted cutover and honest observed retention state", () => {
  const valid = fixture(); assert.equal(helper.verifyReport(valid), true); assert.equal(helper.verifyReport({ ...valid, retentionAtFault: "matching-existing-row" }), true);
  assert.equal(require("./certops-adcs-journal-phase-report").verify(valid), true);
  for (const flag of helper.FLAGS) { const missing = { ...valid }; delete missing[flag]; assert.throws(() => helper.verifyReport(missing)); for (const value of [false, null, 1, "true"]) assert.throws(() => helper.verifyReport({ ...valid, [flag]: value })); }
  for (const patch of [{ qualificationStatus: "qualified" }, { experimental: false }, { phase: "accepted-before-bind" }, { retentionAtFault: "not-verified-yet" }, { preVerificationWindowClaimed: true }, { caRequestsAfterRecovery: 4 }, { actualLeaseWaitMs: 60000 }, { actualLeaseWaitMs: 152000 }, { privateKey: "private" }]) assert.throws(() => helper.verifyReport({ ...valid, ...patch }));
  for (const source of helper.REQUIRED_SOURCES) {
    assert.throws(() => helper.verifyReport({ ...valid, fixtureSources: valid.fixtureSources.filter(row => row.file !== source) }));
    assert.throws(() => helper.verifyReport({ ...valid, fixtureSources: valid.fixtureSources.map(row => row.file === source ? { ...row, sha256: "0".repeat(64) } : row) }));
  }
});
test("bound observer selects only its fixed script and cannot accept an earlier old-binding receipt", async () => {
  assert.throws(() => base.startObserver({ root, phase: "unrecognized", spawnImpl: () => assert.fail("Must not spawn an unknown phase") }));
  for (const valid of [true, false]) {
    const child = new EventEmitter(); child.stdout = new EventEmitter(); child.stderr = new EventEmitter(); child.stderr.resume = () => {}; child.kill = () => {};
    const observer = base.startObserver({ root, workDir: root, configDir: root, phase: helper.PHASE, spawnImpl: (_command, args) => { assert.ok(args.includes(path.join(root, "infra/certops-adcs/bound-install-phase-fault.ps1"))); return child; } });
    child.stdout.emit("data", Buffer.from("CERTOPS_ACCEPTED_INSTALL_READY")); await observer.ready;
    const fault = fixture().fault;
    if (!valid) { fault.phase = base.PHASE; fault.predecessorIisUnchanged = true; delete fault.newIisLeafBound; }
    child.emit("exit", 0); assert.equal(observer.hasLiveChild(), true);
    child.stdout.emit("data", Buffer.from(JSON.stringify(fault))); child.emit("close", 0);
    if (valid) { assert.deepEqual(await observer.result, fault); await observer.stopAndDrain(); assert.equal(observer.hasLiveChild(), false); }
    else { await assert.rejects(observer.result); await observer.stopAndDrain(); assert.equal(observer.hasLiveChild(), true); }
  }
});
test("accepted-only, completed journal and unknown native custody cannot impersonate bound fault", () => {
  const valid = fixture().fault; assert.equal(helper.verifyFault(valid), true);
  for (const field of Object.keys(valid)) { const missing = { ...valid }; delete missing[field]; assert.throws(() => helper.verifyFault(missing)); }
  for (const patch of [{ newIisLeafBound: false }, { predecessorIisUnchanged: true }, { acceptedExactLeafAndCng: false }, { ownedNativeChildrenAbsent: false }, { phase: "installed" }, { requestId: "4294967296" }]) assert.throws(() => helper.verifyFault({ ...valid, ...patch }));
});

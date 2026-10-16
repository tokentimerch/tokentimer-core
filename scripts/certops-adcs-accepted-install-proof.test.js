"use strict";
/** Synthetic proof/lifecycle refusal controls, never native qualification. */
const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto"), { EventEmitter } = require("node:events");
const helper = require("../tests/e2e/helpers/certops-adcs-accepted-install-recovery");
const root = path.resolve(__dirname, "..");
function fault() { return { phase: helper.PHASE, observedDurablePhase: true, unchangedAfterTermination: true, ownedServiceTree: true, ownedNativeChildrenAbsent: true, nativeIdentity: "LocalSystem", acceptedExactLeafAndCng: true, predecessorIisUnchanged: true, enrollmentId: "11111111-1111-1111-1111-111111111111", jobId: "22222222-2222-2222-2222-222222222222", snapshotSha256: "a".repeat(64), requestId: "1", fingerprint: "b".repeat(64) }; }
function report() {
  const hash = file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") });
  return { schemaVersion: 1, scope: "enterprise-adcs-journal-phase-experimental", phase: helper.PHASE, qualificationStatus: "not-qualified", experimental: true, status: "passed", candidateSha: "c".repeat(40), fixtureSource: hash(helper.REQUIRED_SOURCES[0]), fixtureSources: helper.REQUIRED_SOURCES.map(hash), fault: fault(), leaseRemainingAtFaultMs: 60000, recoveryWaitBudgetMs: 150000, actualLeaseWaitMs: 120000, caRequestsAtFault: 3, caRequestsAfterRecovery: 3, ...Object.fromEntries(helper.FLAGS.map(flag => [flag, true])) };
}
test("accepted install proof remains explicitly experimental and requires every native fact", () => {
  const valid = report(); assert.equal(helper.verifyReport(valid), true);
  for (const flag of helper.FLAGS) {
    const missing = { ...valid }; delete missing[flag]; assert.throws(() => helper.verifyReport(missing));
    for (const value of [false, null, 1, "true"]) assert.throws(() => helper.verifyReport({ ...valid, [flag]: value }));
  }
  for (const patch of [{ experimental: false }, { qualificationStatus: "qualified" }, { phase: "installing" }, { caRequestsAfterRecovery: 4 }, { recoveryWaitBudgetMs: 150001 }, { actualLeaseWaitMs: 1 }, { actualLeaseWaitMs: 900001 }, { rawPrivateKey: "private" }, { fixtureSources: valid.fixtureSources.slice(1) }, { fixtureSources: [...valid.fixtureSources, valid.fixtureSources[0]] }, { fixtureSources: valid.fixtureSources.map((row, index) => index ? row : { ...row, sha256: "0".repeat(64) }) }]) assert.throws(() => helper.verifyReport({ ...valid, ...patch }));
  assert.throws(() => helper.verifyReport({ ...valid, actualLeaseWaitMs: 60000 }), "Lease expiry without actual grace cannot qualify");
  assert.throws(() => helper.verifyReport({ ...valid, actualLeaseWaitMs: 152000 }), "Actual wait outside the reviewed budget cannot qualify");
  for (const source of helper.REQUIRED_SOURCES) {
    assert.throws(() => helper.verifyReport({ ...valid, fixtureSources: valid.fixtureSources.filter(row => row.file !== source) }));
    assert.throws(() => helper.verifyReport({ ...valid, fixtureSources: valid.fixtureSources.map(row => row.file === source ? { ...row, sha256: "0".repeat(64) } : row) }));
  }
  assert.equal(require("./certops-adcs-journal-phase-report").verify(valid), true);
});
test("accepted fault refuses incomplete child drainage, wrong native custody and invalid request identity", () => {
  const valid = fault(); assert.equal(helper.verifyFault(valid), true);
  for (const key of Object.keys(valid)) { const missing = { ...valid }; delete missing[key]; assert.throws(() => helper.verifyFault(missing)); }
  for (const patch of [{ ownedNativeChildrenAbsent: false }, { acceptedExactLeafAndCng: false }, { predecessorIisUnchanged: false }, { phase: "installing" }, { nativeIdentity: "Administrator" }, { requestId: "4294967296" }, { requestId: 1 }, { jobId: "invalid" }, { fingerprint: "invalid" }]) assert.throws(() => helper.verifyFault({ ...valid, ...patch }));
});
function emitter() { const child = new EventEmitter(); child.stdout = new EventEmitter(); child.stderr = new EventEmitter(); child.stderr.resume = () => {}; child.kill = () => { child.killed = true; }; return child; }
test("accepted observer consumes final bytes only after close and preserves failed native-drain guard", async () => {
  const child = emitter(), observer = helper.startObserver({ root, workDir: root, configDir: root, spawnImpl: () => child });
  child.stdout.emit("data", Buffer.from("CERTOPS_ACCEPTED_INSTALL_READY")); await observer.ready;
  child.emit("exit", 0); let resolved = false; observer.result.then(() => { resolved = true; });
  await Promise.resolve(); assert.equal(resolved, false); assert.equal(observer.hasLiveChild(), true);
  child.stdout.emit("data", Buffer.from(JSON.stringify(fault()))); child.emit("close", 0);
  assert.deepEqual(await observer.result, fault()); await observer.stopAndDrain(); assert.equal(observer.hasLiveChild(), false);
  for (const output of ["invalid", JSON.stringify({ ...fault(), ownedNativeChildrenAbsent: false }), "x".repeat(8193)]) {
    const failed = emitter(), owned = helper.startObserver({ root, workDir: root, configDir: root, spawnImpl: () => failed });
    failed.stdout.emit("data", Buffer.from("CERTOPS_ACCEPTED_INSTALL_READY")); await owned.ready; failed.stdout.emit("data", Buffer.from(output)); failed.emit("close", 0);
    await assert.rejects(owned.result); await owned.stopAndDrain(); assert.equal(owned.hasLiveChild(), true, "Native ownership remains unresolved after observer failure");
  }
});

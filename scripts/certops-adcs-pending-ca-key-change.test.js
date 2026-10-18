"use strict";
/** Synthetic proof/source controls only; no native CA rekey or issuance evidence. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  h = require("../tests/e2e/helpers/certops-adcs-pending-ca-key-change");
const {
  proof,
  uuid,
} = require("./fixtures/certops-adcs-pending-ca-key-change.cjs");
test("pending new-key proof distinguishes rejected frozen request from genuine fresh recovery", () => {
  assert.equal(h.verifyProof(proof()), true);
  for (const mutate of [
    (v) => (v.freshEnrollmentId = v.oldEnrollmentId),
    (v) => (v.freshRequestId = v.oldRequestId),
    (v) => (v.newCaKeySha256 = v.oldCaKeySha256),
    (v) => (v.freshSpkiSha256 = v.oldSpkiSha256),
    (v) => (v.freshSnapshotSha256 = v.oldSnapshotSha256),
    (v) => v.subjectCountAfter++,
    (v) => (v.schedulerClock = "injected"),
    (v) => (v.backgroundWorkerIntervalQualified = true),
    (v) => (v.privateExtra = "sentinel"),
  ]) {
    const bad = proof();
    mutate(bad);
    assert.throws(() => h.verifyProof(bad));
  }
});
test("every independently observed pending and recovery condition is mandatory", () => {
  for (const field of Object.keys(proof())) {
    const bad = proof();
    delete bad[field];
    assert.throws(() => h.verifyProof(bad));
  }
  for (const flag of h.FLAGS) {
    const bad = proof();
    bad[flag] = false;
    assert.throws(() => h.verifyProof(bad));
  }
});
test("new-key proof must bind the complete actual prior pending installation control", () => {
  const previous = require("../tests/e2e/helpers/certops-adcs-pending-ca-renewal"),
    control = {
      scope: previous.SCOPE,
      schedulerClock: "supported-scheduler-now-input",
      backgroundWorkerIntervalQualified: false,
      enrollmentId: uuid(21),
      originalJobId: uuid(22),
      continuationJobId: uuid(23),
      requestId: "16",
      caKeySha256: "a".repeat(64),
      caCertificateCountBefore: 1,
      caCertificateCountAfter: 2,
      csrSha256: "a".repeat(64),
      spkiSha256: "b".repeat(64),
      leafFingerprint: proof().predecessorFingerprint,
      predecessorFingerprint: "3".repeat(64),
      ...Object.fromEntries(previous.FLAGS.map((flag) => [flag, true])),
    };
  assert.equal(h.verifyCrossProof(proof(), control), true);
  for (const patch of [
    { leafFingerprint: "4".repeat(64) },
    { caKeySha256: "5".repeat(64) },
    { actualSameRequestApproved: false },
  ])
    assert.throws(() => h.verifyCrossProof(proof(), { ...control, ...patch }));
});
test("source uses one retained rekey callback, owned officer action and one genuine recovery preflight", () => {
  const source = fs.readFileSync(
    path.resolve(
      __dirname,
      "../tests/e2e/helpers/certops-adcs-pending-ca-key-change.js",
    ),
    "utf8",
  );
  assert.equal((source.match(/await rekeyAndObserve\(\)/g) || []).length, 1);
  assert.equal(
    (source.match(/reservePrimaryPreflights\(1\)/g) || []).length,
    1,
  );
  const compact = source.replace(/\s/g, "");
  assert.ok(compact.indexOf("receipt.pendingCaRenewalUnresolved=true") >= 0);
  assert.ok(compact.indexOf("receipt.pendingCaRenewalUnresolved=true") < compact.indexOf("old=awaitpost()"));
  assert.ok(compact.includes('officer(oldRequestId,"deny")'));
  assert.ok(compact.includes('officer(requestId,"approve")'));
  assert.ok(
    compact.includes(
      'refused.result_metadata.enrollmentResult.errorCode,"ADCS_CA_KEY_CHANGED"',
    ),
  );
  assert.ok(compact.includes('rejected.journal.state,"rejected_invalid"'));
  assert.doesNotMatch(
    source,
    /UPDATE\s|DELETE\s|INSERT\s|writeEnrollmentJournal|Set-Date|Stop-Process|Set-Content|utimes/i,
  );
});

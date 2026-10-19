"use strict";
/* Supporting evidence-contract checks only. The real CA, CNG, IIS and scheduler
 * observations must come from the protected disposable Windows forest. */
const assert = require("node:assert/strict");
const test = require("node:test");
const { verifyProof, FLAGS } = require("../tests/e2e/helpers/certops-adcs-two-renewals");
function fixture() {
  return { scope: "two-native-adcs-default-scheduler-cycles-not-expiry-cleanup",
    renewalProtocol: "fresh-enrollment-with-new-key-and-csr", schedulerInvocation: "qualification-invoked-production-default-sweep", workerIntervalQualified: false,
    successfulAutomationCycles: 2, expiryCleanupQualified: false,
    ...Object.fromEntries(FLAGS.map(key => [key, true])), requestIds: ["17", "18", "19"],
    caRequestCounts: [7, 8, 9], fingerprints: ["a", "b", "c"].map(char => char.repeat(64)),
    spkiFingerprints: ["d", "e", "f"].map(char => char.repeat(64)), serialNumbers: ["a1", "b2", "c3"],
    containerNames: ["a", "b", "c"].map(char => `tokentimer-enr-${char.repeat(8)}-${char.repeat(4)}-4${char.repeat(3)}-8${char.repeat(3)}-${char.repeat(12)}`),
    expiryEpochs: [1792497600000, 1792497601000, 1792497602000] };
}
test("two complete native scheduler cycles require all independent bounded observations", () => {
  assert.equal(verifyProof(fixture()), true);
  for (const key of Object.keys(fixture())) {
    const missing = fixture(); delete missing[key]; assert.throws(() => verifyProof(missing), undefined, key);
  }
  for (const key of FLAGS) assert.throws(() => verifyProof({ ...fixture(), [key]: false }), undefined, key);
});
test("duplicate keys, leaves, requests or fabricated expiry generations cannot qualify", () => {
  for (const key of ["requestIds", "fingerprints", "spkiFingerprints", "serialNumbers", "containerNames", "expiryEpochs"]) {
    const proof = fixture(); proof[key][2] = proof[key][1]; assert.throws(() => verifyProof(proof), undefined, key);
    proof[key] = proof[key].slice(0, 2); assert.throws(() => verifyProof(proof), undefined, key);
  }
  for (const change of [{ requestIds: ["17", "18", "4294967296"] }, { caRequestCounts: [7, 8, 10] }, { caRequestCounts: [999, 1000, 1001] }, { expiryEpochs: [3, 2, 1] }]) assert.throws(() => verifyProof({ ...fixture(), ...change }));
});
test("service-call controls, unsupported renewal protocols and broader qualification claims are refused", () => {
  for (const change of [{ successfulAutomationCycles: 1 }, { renewalProtocol: "signed-cmc-same-key-renewal" }, { schedulerInvocation: "direct-renewal-service-call" }, { workerIntervalQualified: true }, { expiryCleanupQualified: true }, { privateKey: "unexpected field" }]) assert.throws(() => verifyProof({ ...fixture(), ...change }));
});

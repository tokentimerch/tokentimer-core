"use strict";
/** Pure report controls: a single actual-candidate producer must never become
 * a lost-response timing, synthetic RequestId or early-lease proof. */
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const h = require("../tests/e2e/helpers/certops-adcs-uncertain-operator-unique"),
  { proof } = require("./fixtures/certops-adcs-unique-candidate.cjs");
test("single native candidate proof needs every exact recovery and custody fact", () => {
  h.verifyProof(proof());
  for (const key of Object.keys(proof())) {
    const bad = proof();
    delete bad[key];
    assert.throws(() => h.verifyProof(bad), key);
  }
  for (const flag of h.FLAGS)
    for (const value of [false, null, 1, "true"]) {
      const bad = proof();
      bad[flag] = value;
      assert.throws(() => h.verifyProof(bad), flag);
    }
});
test("single native candidate proof refuses broader fault claims and spliced identities", () => {
  for (const patch of [
    { responseLossTimingQualified: true },
    { caRequestsAtFault: 1 },
    { caRequestsAfterOperatorSubmission: 2 },
    { caRequestsAfterRecovery: 2 },
    { actualLeaseWaitMs: 60000 },
    { actualLeaseWaitMs: 151001 },
    { resolvedIssuingCaAddress: "10.64.0.7" },
    { requestId: "4294967296" },
    { containerName: "foreign" },
    { fingerprint: "private" },
    { jobIds: [proof().jobIds[0], proof().jobIds[0]] },
    { rawCredential: "never-public" },
  ])
    assert.throws(() => h.verifyProof({ ...proof(), ...patch }));
});

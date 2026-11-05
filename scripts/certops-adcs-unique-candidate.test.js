"use strict";
/** Pure report controls: a single actual-candidate producer must never become
 * a lost-response timing, synthetic RequestId or early-lease proof. */
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const h = require("../tests/e2e/helpers/certops-adcs-uncertain-operator-unique"),
  { proof } = require("./fixtures/certops-adcs-unique-candidate.cjs");
test("recovery proof requires both preceding native scenarios to pass", () => {
  const scenarios = h.REQUIRED_SCENARIOS.slice(0, 2).map((id) => ({ id, status: "passed" }));
  h.assertRecoveryScenariosPassed({ scenarios });
  for (const invalid of [
    [],
    scenarios.slice(0, 1),
    [...scenarios, scenarios[0]],
    [{ ...scenarios[0], status: "failed" }, scenarios[1]],
    [scenarios[0], { ...scenarios[1], status: "failed" }],
  ]) {
    assert.throws(() => h.assertRecoveryScenariosPassed({ scenarios: invalid }));
  }
});
test("terminal recovery failures expose only fixed categories", () => {
  h.assertRecoveryJobNotTerminal({ status: "running" });
  for (const [message, category] of [
    ["could not acquire AD CS enrollment lock: SECRET", "LOCK"],
    ["no local enrollment journal for enrollment SECRET", "JOURNAL_MISSING"],
    ["local AD CS enrollment journal is corrupt: SECRET", "JOURNAL_CORRUPT"],
    ["AD CS tier-2 SECRET", "RECONCILIATION"],
    ["Local enrollment policy SECRET", "LOCAL_POLICY"],
    ["SECRET", "OTHER"],
  ]) {
    assert.throws(() => h.assertRecoveryJobNotTerminal({ status: "failed", error_message: message }), (error) => {
      assert.equal(error.code, `CERTOPS_RECOVERY_${category}`);
      assert.doesNotMatch(error.message, /SECRET/);
      return true;
    });
  }
});
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
    { actualLeaseWaitMs: 58999 },
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

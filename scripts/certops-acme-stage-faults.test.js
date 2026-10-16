"use strict";
/** Pure report/refusal adversaries; no CA, native client or public job executes. */
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const helper = require("../tests/e2e/helpers/certops-acme-stage-faults");
function proof() {
  const id = (c) =>
    `${c.repeat(8)}-${c.repeat(4)}-4${c.repeat(3)}-8${c.repeat(3)}-${c.repeat(12)}`;
  return {
    schemaVersion: 1,
    scope: helper.SCOPE,
    client: "certbot",
    failureOrigin: "owned-proxy-before-upstream-forwarding",
    cases: helper.STAGES.map((stage, index) => ({
      stage,
      jobId: id(index ? "b" : "a"),
      certificateId: id(index ? "d" : "c"),
      refusedRequests: 1,
      forwardedFaultRequests: 0,
      acceptedAccounts: 1,
      acceptedOrders: index,
      authorizationCount: index ? 3 : 0,
      validAuthorizationCount: index ? 3 : 0,
      identifiersSha256: "a".repeat(64),
    })),
    positiveJobId: id("e"),
    positiveFingerprint: "b".repeat(64),
    ...Object.fromEntries(helper.FLAGS.map((flag) => [flag, true])),
  };
}
test("closed stage proof requires actual reached-stage failures and genuine issuance recovery", () => {
  assert.equal(helper.verifyProof(proof()), true);
  for (const flag of helper.FLAGS) {
    const value = proof();
    delete value[flag];
    assert.throws(() => helper.verifyProof(value));
    assert.throws(() => helper.verifyProof({ ...proof(), [flag]: false }));
  }
  for (const change of [
    { client: "mock" },
    { failureOrigin: "real-ca-response" },
    { rawJws: "private" },
  ])
    assert.throws(() => helper.verifyProof({ ...proof(), ...change }));
  const samePositive = proof();
  samePositive.positiveJobId = samePositive.cases[0].jobId;
  assert.throws(() => helper.verifyProof(samePositive));
});
test("unrelated order, premature finalize or forwarded fault cannot satisfy native refusal", () => {
  for (const mutate of [
    (v) => {
      v.cases[0].forwardedFaultRequests = 1;
    },
    (v) => {
      v.cases[0].acceptedAccounts = 0;
    },
    (v) => {
      v.cases[0].acceptedOrders = 1;
    },
    (v) => {
      v.cases[1].acceptedOrders = 0;
    },
    (v) => {
      v.cases[1].validAuthorizationCount = 2;
    },
    (v) => {
      v.cases[1].identifiersSha256 = "b".repeat(64);
    },
    (v) => {
      v.cases[1].jobId = v.cases[0].jobId;
    },
    (v) => {
      v.cases[1].rawRequest = "private";
    },
  ]) {
    const value = proof();
    mutate(value);
    assert.throws(() => helper.verifyProof(value));
  }
});

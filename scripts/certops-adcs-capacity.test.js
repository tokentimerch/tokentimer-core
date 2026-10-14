"use strict";
// Pure proof refusals only. Actual API/CA/CNG/IIS execution belongs to the
// disposable native helper; these checks do not qualify those observations.
const test = require("node:test"), assert = require("node:assert/strict");
const { verifyProof, FLAGS, SCOPE, domains } = require("../tests/e2e/helpers/certops-adcs-capacity");
function proof() { return { scope: SCOPE, cap: 5, initialAccepted: 5, initialRefused: 1, nativeCompleted: 2, ...Object.fromEntries(FLAGS.map(flag => [flag, true])), requestIds: ["17", "18"], fingerprints: ["a".repeat(64), "b".repeat(64)], enrollmentIds: ["11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"], jobIds: ["33333333-3333-3333-3333-333333333333", "44444444-4444-4444-4444-444444444444"] }; }
test("native capacity proof refuses missing approval, CA, custody, release and restoration oracles", () => {
  assert.equal(verifyProof(proof()), true);
  for (const flag of FLAGS) for (const value of [false, undefined, "true", 1]) { const bad = proof(); bad[flag] = value; assert.throws(() => verifyProof(bad), flag); }
  for (const [field, value] of [["scope", "api-only-capacity"], ["cap", 6], ["initialAccepted", 6], ["initialRefused", 0], ["nativeCompleted", 1]]) { const bad = proof(); bad[field] = value; assert.throws(() => verifyProof(bad), field); }
  const bad = proof(); bad.syntheticCaResponse = true; assert.throws(() => verifyProof(bad));
});
test("two genuine installations require distinct bounded actual request, leaf, enrollment and job identities", () => {
  for (const field of ["requestIds", "fingerprints", "enrollmentIds", "jobIds"]) {
    for (const value of [[proof()[field][0], proof()[field][0]], [proof()[field][0]], [], [null, proof()[field][1]]]) { const bad = proof(); bad[field] = value; assert.throws(() => verifyProof(bad), field); }
  }
  for (const id of ["0", "4294967296", 17, "0017", "-1"]) { const bad = proof(); bad.requestIds[0] = id; assert.throws(() => verifyProof(bad)); }
});
test("six source selectors are exact owned subjects and use the unchanged default production capacity", () => {
  const run = "0123456789", selected = domains(run);
  assert.equal(selected.length, 6); assert.equal(new Set(selected).size, 6);
  for (let index = 0; index < 6; index++) assert.equal(selected[index], `certops-adcs-${run}-capacity${index}.example.test`);
  for (const bad of ["", "0123456789'", "../outside", "ABCDEF0123"]) assert.throws(() => domains(bad));
  assert.equal(require("../apps/api/services/certops/renewalCapacity").resolveRenewalPerCaCap({}), 5);
});

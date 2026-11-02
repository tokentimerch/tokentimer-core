"use strict";
/** Offline schema/ownership adversaries only; these tests never contact a
 * cluster and their fixtures are not execution/qualification receipts. */
const { test } = require("node:test"), assert = require("node:assert/strict");
const h = require("./certops-kubernetes-rbac");
const { status } = require("./certops-kubernetes-rbac-incluster");
function ownership() {
  const expected = { namespace: "certops-1234567890abcdef", uid: "11111111-1111-4111-8111-111111111111", owner: "a".repeat(32) };
  return { expected, value: { metadata: { name: expected.namespace, uid: expected.uid, labels: { [h.OWNER_LABEL]: expected.owner } } } };
}
function proof() {
  return { schemaVersion: 1, scope: h.SCOPE, listStatus: 403, watchStatus: 403, createStatus: 403, certificateUid: "11111111-1111-4111-8111-111111111111", createdCertificateUid: "22222222-2222-4222-8222-222222222222", missedResourceVersion: "101", watchedResourceVersion: "105", ...Object.fromEntries(h.FLAGS.map(name => [name, true])) };
}
test("namespace ownership refuses foreign names, tokens, replacement UIDs and terminating resources", () => {
  const { value, expected } = ownership();
  assert.equal(h.verifyNamespace(value, expected), expected.uid);
  for (const mutate of [v => { v.metadata.name = "default"; }, v => { v.metadata.uid = "33333333-3333-4333-8333-333333333333"; }, v => { delete v.metadata.labels[h.OWNER_LABEL]; }, v => { v.metadata.labels[h.OWNER_LABEL] = "b".repeat(32); }, v => { v.metadata.deletionTimestamp = "2026-10-18T00:00:00Z"; }]) {
    const wrong = structuredClone(value); mutate(wrong); assert.throws(() => h.verifyNamespace(wrong, expected));
  }
  for (const change of [{ namespace: "production" }, { owner: "unknown" }, { uid: "unknown" }]) assert.throws(() => h.verifyNamespace(value, { ...expected, ...change }));
});
test("RBAC recovery requires native403, distinct owned certificates, monotonic actual revisions and every recovery fact", () => {
  assert.equal(h.verifyProof(proof()), true);
  for (const flag of h.FLAGS) {
    for (const wrong of [false, "true", 1, null]) assert.throws(() => h.verifyProof({ ...proof(), [flag]: wrong }));
    const missing = proof(); delete missing[flag]; assert.throws(() => h.verifyProof(missing));
  }
  for (const field of ["listStatus", "watchStatus", "createStatus"]) for (const wrong of ["403", 401, 404, 500]) assert.throws(() => h.verifyProof({ ...proof(), [field]: wrong }));
  for (const change of [{ watchedResourceVersion: "100" }, { watchedResourceVersion: "101" }, { missedResourceVersion: "fabricated" }, { createdCertificateUid: proof().certificateUid }, { scope: "local-contract" }, { privateKey: "withheld" }]) assert.throws(() => h.verifyProof({ ...proof(), ...change }));
});
test("native status extraction never infers403 from arbitrary error text", () => {
  assert.equal(status({ statusCode: 403 }), 403);
  assert.equal(status({ body: { code: 403 } }), 403);
  assert.equal(status({ response: { statusCode: 404 } }), 404);
  for (const value of [{ message: "403 forbidden" }, { code: "FORBIDDEN" }, { code: 500 }, { status: true }, null]) assert.equal(status(value), undefined);
});

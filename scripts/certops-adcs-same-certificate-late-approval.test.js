"use strict";
// Public identities exercise closed lineage/proof contracts only. No CA work.
const test = require("node:test"),
  assert = require("node:assert/strict");
const late = require("../tests/e2e/helpers/certops-adcs-cancelled-late-approval");
const subject = require("../tests/e2e/helpers/certops-adcs-same-certificate-late-approval");
const ids = [
  "11111111-1111-4111-8111-111111111111",
  "22222222-2222-4222-8222-222222222222",
  "33333333-3333-4333-8333-333333333333",
];
const proof = () => ({
  scope: late.SAME_CERTIFICATE_SCOPE,
  certificateId: ids[2],
  cancelledEnrollmentId: ids[0],
  successorEnrollmentId: ids[1],
  requestIds: ["71", "72"],
  fingerprints: ["a".repeat(64), "b".repeat(64)],
  sameCertificateRenewalQualified: true,
  backgroundTimerQualified: false,
  ...Object.fromEntries(late.FLAGS.map((key) => [key, true])),
});
test("same-certificate late approval requires distinct actual request lineage of one certificate", () => {
  const old = {
    id: ids[0],
    certificate_id: ids[2],
    request_id: 71,
    state: "cancelled",
  };
  const current = {
    id: ids[1],
    certificate_id: ids[2],
    request_id: 72,
    state: "installed",
  };
  subject.verifyLineage(old, current, ids[2]);
  for (const patch of [
    { id: old.id },
    { certificate_id: ids[1] },
    { request_id: 71 },
    { request_id: 4294967296 },
    { state: "pending_issuance" },
  ])
    assert.throws(() =>
      subject.verifyLineage(old, { ...current, ...patch }, ids[2]),
    );
  assert.throws(() =>
    subject.verifyLineage(
      { ...old, state: "pending_issuance" },
      current,
      ids[2],
    ),
  );
});
test("same-certificate native proof cannot relabel the original distinct-certificate scope", () => {
  assert.deepEqual(late.verifySameCertificateProof(proof()), proof());
  assert.throws(() => late.verifyProof(proof()));
  for (const key of Object.keys(proof())) {
    const changed = proof();
    delete changed[key];
    assert.throws(() => late.verifySameCertificateProof(changed));
  }
  for (const key of late.FLAGS)
    assert.throws(() =>
      late.verifySameCertificateProof({ ...proof(), [key]: false }),
    );
  for (const patch of [
    { scope: late.SCOPE },
    { sameCertificateRenewalQualified: false },
    { rawJournal: "private" },
    { certificateId: "foreign" },
  ])
    assert.throws(() =>
      late.verifySameCertificateProof({ ...proof(), ...patch }),
    );
  const original = {
    ...proof(),
    scope: late.SCOPE,
    sameCertificateRenewalQualified: false,
  };
  delete original.certificateId;
  delete original.backgroundTimerQualified;
  late.verifyProof(original);
});

"use strict";
/**
 * Qualification notes: late approval of same-certificate renewal
 *
 * Keep one actually discovered managed certificate identity bound to trusted leaf/IIS across
 * cancelled pending then successful new renewal, distinct enrollment IDs/CA requests/keys. Guard
 * before admission; real default-clock cancellation cleanup removes old key with prior TLS fixed.
 * Same certificate ID/new pending renewal actually approved/continued at selected eligibility, not
 * timer proof. Only then approve old cancelled row via shared checker: bind requester/
 * template/CSR/SPKI/DER, refuse retry/scheduler revival, old key absent/late leaf never accepted,
 * revoke exact unused issuance. Successor claim/journal/CNG/IIS/HTTP.sys/TLS unchanged. Unknown
 * acceptance/cleanup retains guard. Distinct-identity prior proof stays separate; no elapsed
 * claim.
 *
 * Shared setup, evidence and cleanup policy: docs/certops/e2e-qualification.md.
 */
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

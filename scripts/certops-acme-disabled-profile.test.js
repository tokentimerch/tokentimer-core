"use strict";
const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  crypto = require("node:crypto");
const h = require("../tests/e2e/helpers/certops-acme-disabled-profile");
function fixture() {
  const previous = require("./test-support/acme-stage-artifact.cjs")
    .artifact()
    .events.find((x) => x.nativeAcmeBulkRenewal).nativeAcmeBulkRenewal;
  return {
    previous,
    proof: {
      scope: h.SCOPE,
      certificateId: previous.certificateIds[1],
      profileId: crypto.randomUUID(),
      jobId: crypto.randomUUID(),
      claimId: crypto.randomUUID(),
      fingerprints: [
        previous.fingerprints[3],
        crypto.randomBytes(32).toString("hex"),
      ],
      schedulerSweepQualified: false,
      backgroundWorkerQualified: false,
      ...Object.fromEntries(h.FLAGS.map((x) => [x, true])),
    },
  };
}
test("native disabled-profile proof requires actual native facts without a scheduler or worker claim", () => {
  const { proof } = fixture();
  h.verifyProof(proof);
  for (const k of Object.keys(proof)) {
    const bad = structuredClone(proof);
    delete bad[k];
    assert.throws(() => h.verifyProof(bad));
  }
  for (const flag of h.FLAGS)
    assert.throws(() => h.verifyProof({ ...proof, [flag]: false }));
  for (const patch of [
    { schedulerSweepQualified: true },
    { backgroundWorkerQualified: true },
    { privateKey: "neverpublic" },
  ])
    assert.throws(() => h.verifyProof({ ...proof, ...patch }));
});
test("native manual-while-disabled binds exact genuine second bulk certificate and generation", () => {
  const { proof, previous } = fixture();
  h.verifyAgainstBulk(proof, previous);
  for (const patch of [
    { certificateId: previous.certificateIds[0] },
    { jobId: previous.jobIds[0] },
    { claimId: previous.claimIds[0] },
    { fingerprints: ["f".repeat(64), proof.fingerprints[1]] },
  ])
    assert.throws(() => h.verifyAgainstBulk({ ...proof, ...patch }, previous));
});


test("six-day native leaf needs an explicit lead for immediate selection", () => {
  const { resolveCertificateRenewalThresholdDays } = require("../apps/api/services/certops/renewalThreshold");
  const now = new Date("2026-01-01T00:00:00Z");
  const row = { not_before: now, not_after: new Date(now.getTime() + 6 * 86400000), profile_renew_before_days: null };
  assert.equal(resolveCertificateRenewalThresholdDays(row, {}), 3);
  assert.equal(resolveCertificateRenewalThresholdDays({ ...row, profile_renew_before_days: 30 }, {}), 30);
  assert.ok(h.MILESTONES.includes("disabled-lead-saved"));
  assert.ok(h.MILESTONES.length <= 16);
  assert.equal(new Set(h.MILESTONES).size, h.MILESTONES.length);
});


test("lead edit requires ownership and preserves all other profile fields", () => {
  const before = { id: "owned-profile", status: "active", renew_before_days: null, public_metadata: { renewalProfile: { keyRotationPolicy: { rotateOnRenew: true } }, derivedFrom: { certificateId: "owned" } } };
  const after = { ...structuredClone(before), renew_before_days: 30, public_metadata: { ...structuredClone(before.public_metadata), operatorOwned: true } };
  assert.doesNotThrow(() => h.assertOwnedLeadEdit(before, after));
  assert.throws(() => h.assertOwnedLeadEdit(before, { ...after, public_metadata: before.public_metadata }));
  assert.throws(() => h.assertOwnedLeadEdit(before, { ...after, renew_before_days: 29 }));
  const changed = structuredClone(after); changed.public_metadata.renewalProfile.keyRotationPolicy.rotateOnRenew = false;
  assert.throws(() => h.assertOwnedLeadEdit(before, changed));
  assert.throws(() => h.assertOwnedLeadEdit(before, { ...after, status: "disabled" }));
});

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

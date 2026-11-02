"use strict";
const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  crypto = require("node:crypto");
const h = require("../tests/e2e/helpers/certops-acme-certificate-outbox"),
  a = require("../tests/e2e/helpers/certops-acme-agent-attachment");
function fixture() {
  const e = require("./test-support/acme-stage-artifact.cjs")
    .artifact()
    .events.find((x) => x.nativeAcmeBulkRenewal);
  return {
    p: require("./test-support/acme-certificate-outbox-proof.cjs").proof(
      e.nativeAcmeBulkRenewal,
    ),
    bulk: e.nativeAcmeBulkRenewal,
    adoption: e.nativeAcmeRenewalSetup,
  };
}
test("native certificate result restart requires genuine outcome flags and narrow scope", () => {
  const { p } = fixture();
  h.verifyProof(p);
  for (const key of Object.keys(p)) {
    const bad = structuredClone(p);
    delete bad[key];
    assert.throws(() => h.verifyProof(bad));
  }
  for (const flag of h.FLAGS)
    assert.throws(() => h.verifyProof({ ...p, [flag]: false }));
  for (const change of [
    { attemptCount: 2 },
    { extraCaOrdersAfterRestart: 1 },
    { jobCancellationQualified: true },
    { fixtureStopAfterNativeSuccess: false },
    { privateKey: "private" },
  ])
    assert.throws(() => h.verifyProof({ ...p, ...change }));
});
test("native outcome cannot splice prior certificates jobs claims or served generations", () => {
  const { p, bulk, adoption } = fixture();
  h.verifyAgainstJourney(p, bulk, adoption);
  for (const change of [
    { certificateId: bulk.certificateIds[0] },
    { jobId: adoption.jobIds[0] },
    { claimId: bulk.claimIds[0] },
    { fingerprints: ["f".repeat(64), p.fingerprints[1]] },
    { fingerprints: [p.fingerprints[0], adoption.fingerprints[1]] },
  ])
    assert.throws(() =>
      h.verifyAgainstJourney({ ...p, ...change }, bulk, adoption),
    );
});
test("retained agent receipts bind original kernel identity and require explicit restart drainage", () => {
  const expected = {
    token: crypto.randomBytes(16).toString("hex"),
    pid: 123,
    startTicks: "456",
  };
  for (const closed of [false, true]) {
    const flags = closed
      ? ["rootExited", "noChildAfterStop", "pidfdClosed", "explicitRestartStop"]
      : ["pidfdPinned", "noChildBeforeStop"];
    const p = {
      kind: closed ? "agent-pidfd-closed" : "agent-pidfd-attached",
      ...expected,
      ...Object.fromEntries(flags.map((x) => [x, true])),
    };
    a.validateReceipt(p, expected, closed);
    for (const flag of flags)
      assert.throws(() =>
        a.validateReceipt({ ...p, [flag]: false }, expected, closed),
      );
    assert.throws(() =>
      a.validateReceipt({ ...p, pid: 124 }, expected, closed),
    );
    assert.throws(() =>
      a.validateReceipt({ ...p, startTicks: "457" }, expected, closed),
    );
  }
});

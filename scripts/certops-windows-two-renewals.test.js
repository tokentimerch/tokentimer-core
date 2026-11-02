"use strict";
/** Portable report-contract refusal checks. Actual signed scheduler/CNG/IIS/TLS
 * cycles run only in the opted-in installed Windows journey; these synthetic
 * proof fixtures cannot qualify a native environment or expiry cleanup. */
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const {
  verifyProof,
} = require("../tests/e2e/helpers/certops-windows-two-renewals");
const facts = () => ({
  successfulAutomationCycles: 2,
  automaticSourceAndRealMode: true,
  naturallyDueGenerations: true,
  distinctIdempotencyKeys: true,
  leafAndSpkiChangedTwice: true,
  nativeBindingMatchesLatest: true,
  nativeKeyProfilesVerified: true,
  persistedEvidenceBothCycles: true,
  inventoryMatchesActualLeaf: true,
  profileAndManagementLineagePreserved: true,
  retentionLineageMatchesBothCutovers: true,
  predecessorCustodyPreserved: true,
  noExpiryOrClockOverrides: true,
  expiryCleanupQualified: false,
  scope: "two-unattended-cycles-and-preserved-predecessors-not-expiry-cleanup",
});
test("two unattended renewals require native generation evidence lineage and predecessor custody", () => {
  assert.equal(verifyProof(facts()), true);
  for (const field of Object.keys(facts()).filter(
    (field) => facts()[field] === true,
  )) {
    assert.throws(
      () => verifyProof({ ...facts(), [field]: false }),
      undefined,
      field,
    );
    const missing = facts();
    delete missing[field];
    assert.throws(() => verifyProof(missing), undefined, field);
  }
  for (const successfulAutomationCycles of [0, 1, 3, "2"])
    assert.throws(() =>
      verifyProof({ ...facts(), successfulAutomationCycles }),
    );
});
test("short repeated cutovers cannot qualify elapsed retention cleanup", () => {
  for (const change of [
    { expiryCleanupQualified: true },
    { scope: "expiry-cleanup-qualified" },
    { scope: "one-successful-and-one-interrupted" },
  ])
    assert.throws(() => verifyProof({ ...facts(), ...change }));
});

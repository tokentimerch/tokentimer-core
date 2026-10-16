"use strict";
/** Portable report contract negatives for second-rename qualification. The real
 * filesystem/notification regression is invoked explicitly by Windows PowerShell;
 * these tests establish neither installed service nor native certificate proof. */
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const {
  verifyProof,
} = require("../tests/e2e/helpers/certops-windows-second-rename");
// Independent committed expectation: removing an oracle from the producer's
// own field list must not also remove its regression coverage.
const expectedProof = () => ({
  childIdentityVerifiedBeforeActivation: true,
  actualProductionFunctions: true,
  nativeOrderedRestoreEvents: true,
  originalDirectoryIdentityRestored: true,
  heldStagingIdentityUnchanged: true,
  explicitStagingCleanupFailure: true,
  candidateNeverActivated: true,
  predecessorFilesUnchanged: true,
  sameRunningServicePid: true,
  configurationAndCredentialUnchanged: true,
  cngCustodyUnchanged: true,
  bindingAndTrustedTlsUnchanged: true,
  freshAuthenticatedHeartbeat: true,
  nativeHandleReleased: true,
  ownedStagingRemoved: true,
  ownedChildDrained: true,
});
test("activation proof requires every restoration custody heartbeat and cleanup oracle", () => {
  const facts = {
    ...expectedProof(),
    scope: "production-activation-functions-not-installer-cli",
  };
  assert.equal(verifyProof(facts), true);
  for (const field of Object.keys(expectedProof())) {
    assert.throws(
      () => verifyProof({ ...facts, [field]: false }),
      undefined,
      field,
    );
    const missing = { ...facts };
    delete missing[field];
    assert.throws(() => verifyProof(missing), undefined, field);
  }
});
test("activation-function proof cannot claim full installer CLI execution", () => {
  const facts = expectedProof();
  for (const scope of [
    undefined,
    "full-installer-cli",
    "first-rename-preservation",
  ])
    assert.throws(() => verifyProof({ ...facts, scope }));
});

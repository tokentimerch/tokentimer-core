"use strict";
const {matrixErrors} = require("./test-support/qualification-artifact.cjs");
/** Offline current-source artifacts, never native execution evidence. */
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const fixture = require("./test-support/acme-stage-artifact.cjs"),
  h = require("../tests/e2e/helpers/certops-acme-disabled-profile");
const slot =
  require("./certops-qualification-manifest").slots.find(
    (row) => row.id === "linux-real-acme",
  );
const errors = (value) => matrixErrors(value, slot, fixture.CANDIDATE);
function native(value) {
  return value.events.find(
    (event) => event.name === require("./certops-acme-bulk-report").MAIN,
  );
}
test("actual Ubuntu disabled-profile manual renewal slot requires every native fact and current critical source", () => {
  assert.deepEqual(errors(fixture.artifact()), []);
  for (const flag of h.FLAGS) {
    const value = fixture.artifact();
    delete native(value).nativeAcmeDisabledProfile[flag];
    assert.ok(errors(value).length);
  }
  for (const file of [
    ...h.REQUIRED_SOURCES,
    "scripts/certops-acme-disabled-profile-report.js",
    "scripts/certops_acme_disabled_profile_proof.py",
  ]) {
    const value = fixture.artifact();
    native(value).fixtureSources.find((row) => row.file === file).sha256 =
      "f".repeat(64);
    assert.ok(errors(value).length);
  }
});
test("native disabled-profile manual renewal cannot reuse prior jobs, custody or hidden state", () => {
  for (const mutate of [
    (e) => delete e.nativeAcmeDisabledProfile,
    (e) =>
      (e.nativeAcmeDisabledProfile.jobId = e.nativeAcmeBulkRenewal.jobIds[0]),
    (e) => (e.nativeAcmeDisabledProfile.fingerprints[0] = "f".repeat(64)),
    (e) =>
      (e.nativeAcmeDisabledProfile.fingerprints[1] =
        e.nativeAcmeBulkRenewal.fingerprints[0]),
    (e) => (e.nativeAcmeDisabledProfile.privateKey = "must-not-persist"),
  ]) {
    const value = fixture.artifact();
    mutate(native(value));
    assert.ok(errors(value).length);
  }
});

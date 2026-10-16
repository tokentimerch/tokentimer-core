"use strict";
/** Offline current-source artifacts, never native execution evidence. */
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const fixture = require("./test-support/acme-stage-artifact.cjs"),
  h = require("../tests/e2e/helpers/certops-acme-certificate-outbox"),
  { verifyMatrix } = require("./certops-release-qualification");
const slot =
  require("../docs/certops/release-qualification-matrix.json").slots.find(
    (row) => row.id === "linux-real-acme",
  );
function errors(value) {
  return verifyMatrix([value], {
    candidateSha: fixture.CANDIDATE,
    specification: { schemaVersion: 1, slots: [slot] },
  });
}
function native(value) {
  return value.events.find(
    (event) => event.name === require("./certops-acme-bulk-report").MAIN,
  );
}
test("actual Ubuntu certificate result restart slot requires every native fact and current critical source", () => {
  assert.deepEqual(errors(fixture.artifact()), []);
  for (const flag of h.FLAGS) {
    const value = fixture.artifact();
    delete native(value).nativeAcmeCertificateOutbox[flag];
    assert.ok(errors(value).length);
  }
  for (const file of [
    ...h.REQUIRED_SOURCES,
    "scripts/certops-acme-certificate-outbox-report.js",
    "scripts/certops_acme_certificate_outbox_proof.py",
  ]) {
    const value = fixture.artifact();
    native(value).fixtureSources.find((row) => row.file === file).sha256 =
      "f".repeat(64);
    assert.ok(errors(value).length);
  }
});
test("native result restart cannot reuse prior jobs, custody or hidden state", () => {
  for (const mutate of [
    (e) => delete e.nativeAcmeCertificateOutbox,
    (e) =>
      (e.nativeAcmeCertificateOutbox.jobId = e.nativeAcmeBulkRenewal.jobIds[0]),
    (e) => (e.nativeAcmeCertificateOutbox.fingerprints[0] = "f".repeat(64)),
    (e) =>
      (e.nativeAcmeCertificateOutbox.fingerprints[1] =
        e.nativeAcmeBulkRenewal.fingerprints[0]),
    (e) => (e.nativeAcmeCertificateOutbox.privateKey = "must-not-persist"),
  ]) {
    const value = fixture.artifact();
    mutate(native(value));
    assert.ok(errors(value).length);
  }
});

"use strict";
/** Offline current-source artifacts, never native execution evidence. */
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const fixture = require("./test-support/acme-stage-artifact.cjs"),
  h = require("../tests/e2e/helpers/certops-acme-bulk-renewal"),
  { verifyMatrix } = require("./certops-release-qualification");
const slot =
  require("../docs/certops/qualification-suites.json").slots.find(
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
test("actual Ubuntu bulk slot requires every native fact and current critical source", () => {
  assert.deepEqual(errors(fixture.artifact()), []);
  for (const flag of h.FLAGS) {
    const value = fixture.artifact();
    delete native(value).nativeAcmeBulkRenewal[flag];
    assert.ok(errors(value).length);
  }
  for (const file of [
    ...h.REQUIRED_SOURCES,
    "scripts/certops-acme-bulk-report.js",
    "scripts/certops_acme_bulk_proof.py",
  ]) {
    const value = fixture.artifact();
    native(value).fixtureSources.find((row) => row.file === file).sha256 =
      "f".repeat(64);
    assert.ok(errors(value).length);
  }
});
test("bulk proof cannot splice earlier jobs or serving state, broader environments or hidden scenarios", () => {
  for (const mutate of [
    (value) => delete native(value).nativeAcmeBulkRenewal,
    (value) =>
      (native(value).nativeAcmeBulkRenewal.originalServingFingerprint =
        "9".repeat(64)),
    (value) =>
      (native(value).nativeAcmeBulkRenewal.originalServingProfileId =
        native(value).nativeAcmeBulkRenewal.certificateIds[0]),
    (value) =>
      (native(value).nativeAcmeBulkRenewal.issueJobIds[0] =
        native(value).nativeAcmeKeyReuse.jobIds[0]),
    (value) =>
      (native(value).nativeAcmeBulkRenewal.privateKey = "not public proof"),
    (value) =>
      (native(value).qualificationEnvironment.executionSurface = "container"),
    (value) =>
      (value.events.find((event) => event.name === h.SCENARIO).skip = true),
  ]) {
    const value = fixture.artifact();
    mutate(value);
    assert.ok(errors(value).length);
  }
  const other = fixture.artifact("real-agent-acmesh-filesystem");
  assert.equal(native(other).nativeAcmeBulkRenewal, undefined);
});

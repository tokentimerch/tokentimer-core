"use strict";
// Supporting composition contracts only; no native key or ACL operation.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const subject = require("../packages/agent/scripts/host/orphan-journal-acl-fixture");
function proof() {
  return {
    scope: subject.SCOPE,
    caEnrollmentQualified: false,
    installedServiceQualified: false,
    ...Object.fromEntries(subject.FLAGS.map((flag) => [flag, true])),
  };
}
test("native CNG plus unreadable journal proof requires all facts without CA/service promotion", () => {
  subject.verifyProof(proof());
  for (const field of Object.keys(proof())) {
    const absent = proof();
    delete absent[field];
    assert.throws(() => subject.verifyProof(absent));
  }
  for (const field of subject.FLAGS)
    assert.throws(() => subject.verifyProof({ ...proof(), [field]: false }));
  for (const patch of [
    { caEnrollmentQualified: true },
    { installedServiceQualified: true },
    { rawContainerName: "private" },
    {
      scope:
        "native-temporary-adcs-journal-acl-refusals-not-installed-enrollment",
    },
  ])
    assert.throws(() => subject.verifyProof({ ...proof(), ...patch }));
});
test("composition accepts only exact prepared enrollment-owned native key prerequisites", () => {
  const container = "tokentimer-enr-11111111-1111-4111-8111-111111111111";
  subject.validatePrepared(
    { kind: "valid", journal: { state: "prepared", containerName: container } },
    container,
  );
  for (const value of [
    { kind: "not_found" },
    { kind: "corrupt" },
    { kind: "legacy" },
    {
      kind: "valid",
      journal: { state: "installed", containerName: container },
    },
    { kind: "valid", journal: { state: "prepared", containerName: "foreign" } },
  ])
    assert.throws(() => subject.validatePrepared(value, container));
  assert.throws(() =>
    subject.validatePrepared(
      {
        kind: "valid",
        journal: { state: "prepared", containerName: "foreign" },
      },
      "foreign",
    ),
  );
});
test("private prepared-journal snapshots are bounded and require regular nonempty files", () => {
  const base = path.resolve(__dirname, "../.build");
  fs.mkdirSync(base, { recursive: true });
  const root = fs.mkdtempSync(path.join(base, "orphan-acl-reader-"));
  try {
    const file = path.join(root, "public-journal.json");
    fs.writeFileSync(file, '{"state":"prepared"}', { flag: "wx" });
    assert.equal(
      subject.readJournalBytes(file).toString(),
      '{"state":"prepared"}',
    );
    fs.writeFileSync(file, "");
    assert.throws(() => subject.readJournalBytes(file));
    fs.writeFileSync(file, Buffer.alloc(65537));
    assert.throws(() => subject.readJournalBytes(file));
    assert.throws(() => subject.readJournalBytes(root));
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});

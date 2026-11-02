"use strict";
/** Pure closed-proof/adverse checks and benign local snapshot controls only.
 * These tests never execute Linux trust, native certificate or nonroot jobs. */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path");
const {
  verifyProof,
  FLAGS,
  snapshot,
  assertUnchanged,
} = require("./certops-linux-filesystem-permission");
function proof() {
  return {
    schemaVersion: 1,
    scope: "native-linux-nonroot-backup-dac-refusal",
    uid: 65534,
    gid: 65534,
    ...Object.fromEntries(FLAGS.map((name) => [name, true])),
  };
}
test("DAC proof requires every native refusal, preservation and recovery oracle", () => {
  assert.equal(verifyProof(proof()), true);
  for (const field of FLAGS) {
    const missing = proof();
    delete missing[field];
    assert.throws(() => verifyProof(missing));
    assert.throws(() => verifyProof({ ...proof(), [field]: false }));
  }
  for (const changed of [
    { uid: 0 },
    { gid: 0 },
    { uid: -1 },
    { uid: 1.5 },
    { scope: "signed-api-deployment" },
    { schemaVersion: 2 },
    { rawKey: "private" },
    { nativeHostQualified: true },
  ])
    assert.throws(() => verifyProof({ ...proof(), ...changed }));
});
test("local file snapshot detects same-path byte and inode replacement without diagnostic contents", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "certops-dac-snapshot-"));
  try {
    const file = path.join(root, "public-sentinel");
    fs.writeFileSync(file, "first");
    const before = [snapshot(file)];
    assertUnchanged([file], before);
    fs.writeFileSync(file, "other");
    assert.throws(
      () => assertUnchanged([file], before),
      /private details withheld/,
    );
    fs.writeFileSync(file, "first");
    const next = path.join(root, "replacement");
    fs.writeFileSync(next, "first");
    fs.renameSync(file, path.join(root, "old"));
    fs.renameSync(next, file);
    assert.throws(
      () => assertUnchanged([file], before),
      /private details withheld/,
    );
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});

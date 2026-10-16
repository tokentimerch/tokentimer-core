"use strict";
/** Supporting proof and benign local ownership checks, never host execution. */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path");
const h = require("./certops-filesystem-backup-retention");
function proof() {
  return {
    schemaVersion: 1,
    scope: h.SCOPE,
    retentionCount: 1,
    targetCount: 2,
    actualRotations: 4,
    fingerprints: ["a", "b", "c"].map((c) => c.repeat(64)),
    ...Object.fromEntries(h.FLAGS.map((flag) => [flag, true])),
  };
}
test("retention proof requires every native scoped pruning and preservation observation", () => {
  assert.equal(h.verifyProof(proof()), true);
  for (const flag of h.FLAGS) {
    const value = proof();
    delete value[flag];
    assert.throws(() => h.verifyProof(value));
    assert.throws(() => h.verifyProof({ ...proof(), [flag]: false }));
  }
  for (const changed of [
    { targetCount: 1 },
    { actualRotations: 2 },
    { retentionCount: 64 },
    { scope: "clock-injected-retention" },
    { privateKey: "secret" },
    { fingerprints: ["a", "a", "b"].map((v) => v.repeat(64)) },
  ])
    assert.throws(() => h.verifyProof({ ...proof(), ...changed }));
});
test("unresolved retention ownership prevents broad parent cleanup", () => {
  const root = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "retention-owned-")),
  );
  try {
    h.assertCleanupSafe(root);
    const marker = path.join(
      root,
      ".preserve-filesystem-backup-retention-test.json",
    );
    fs.writeFileSync(marker, "owned");
    assert.throws(() => h.assertCleanupSafe(root));
    assert.equal(fs.readFileSync(marker, "utf8"), "owned");
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});

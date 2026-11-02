"use strict";
/** Offline proof adversaries and benign owned file observations only. */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const h = require("./certops-filesystem-backup-alias");
function proof() {
  return {
    schemaVersion: 1,
    scope: h.SCOPE,
    aliasKind: "junction",
    refusalStage: "realpath-policy",
    fingerprints: ["a", "b"].map((c) => c.repeat(64)),
    ...Object.fromEntries(h.FLAGS.map((name) => [name, true])),
  };
}
test("backup alias proof requires native refusal and actual recovery, without rollback promotion", () => {
  assert.equal(h.verifyProof(proof()), true);
  for (const flag of h.FLAGS) {
    const value = proof();
    delete value[flag];
    assert.throws(() => h.verifyProof(value));
    assert.throws(() => h.verifyProof({ ...proof(), [flag]: false }));
  }
  for (const changed of [
    { aliasKind: "mock" },
    { refusalStage: "backup-key" },
    { rawKey: "secret" },
    { fingerprints: ["a".repeat(64), "a".repeat(64)] },
    { rollbackQualified: true },
  ])
    assert.throws(() => h.verifyProof({ ...proof(), ...changed }));
});
test("unknown backup alias receipt preserves root and exact owned observations detect changes", () => {
  const root = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "backup-alias-proof-")),
  );
  try {
    const file = path.join(root, "public.txt");
    fs.writeFileSync(file, "original", { mode: 0o600 });
    const before = h.observe(file);
    h.assertPreserved(file, before);
    fs.writeFileSync(file, "changed");
    assert.throws(() => h.assertPreserved(file, before));
    h.assertCleanupSafe(root);
    fs.writeFileSync(
      path.join(root, ".preserve-filesystem-backup-alias-test.json"),
      "owned",
    );
    assert.throws(() => h.assertCleanupSafe(root));
    assert.ok(fs.existsSync(file));
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});
module.exports = { proof };

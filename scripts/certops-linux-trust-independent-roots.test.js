"use strict";
/** Offline scope adversaries and benign file observations, no native trust changes. */
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os");
const h = require("./certops-linux-trust-independent-roots");
const proof = () => ({
  schemaVersion: 1,
  scope: h.SCOPE,
  family: "debian",
  derivedReferenceKind: "native-source-symlink",
  rootFingerprints: ["a", "b"].map((c) => c.repeat(64)),
  leafFingerprints: ["c", "d"].map((c) => c.repeat(64)),
  ...Object.fromEntries(h.FLAGS.map((flag) => [flag, true])),
});
test("independent native root proof requires every selective revoke and preserved trust observation", () => {
  assert.equal(h.verifyProof(proof()), true);
  assert.equal(
    h.verifyProof({
      ...proof(),
      family: "rhel",
      derivedReferenceKind: "native-derived-certificate",
    }),
    true,
  );
  for (const flag of h.FLAGS) {
    const value = proof();
    delete value[flag];
    assert.throws(() => h.verifyProof(value));
    assert.throws(() => h.verifyProof({ ...proof(), [flag]: false }));
  }
  for (const change of [
    { family: "windows" },
    { derivedReferenceKind: "declared" },
    { scope: "concurrent-os-refresh" },
    { rootFingerprints: ["a", "a"].map((c) => c.repeat(64)) },
    { leafFingerprints: ["a", "d"].map((c) => c.repeat(64)) },
    { privateKey: "secret" },
  ])
    assert.throws(() => h.verifyProof({ ...proof(), ...change }));
});
test("a durable unresolved trust receipt prevents parent cleanup and changed local identity refuses", () => {
  const root = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "trust-independent-proof-")),
  );
  try {
    h.assertCleanupSafe(root);
    const file = path.join(root, "public.txt");
    fs.writeFileSync(file, "original", { mode: 0o600 });
    const before = h.snapshot(file);
    h.unchanged(file, before);
    fs.writeFileSync(file, "different");
    assert.throws(() => h.unchanged(file, before));
    const receipt = path.join(root, ".preserve-independent-trust-test.json");
    fs.writeFileSync(receipt, "owned");
    assert.throws(() => h.assertCleanupSafe(root));
    assert.ok(fs.existsSync(file));
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});

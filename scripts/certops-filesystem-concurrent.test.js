"use strict";
/** Pure proof/lineage adversaries and owned benign file observations only.
 * Does not run native certificate deployment, TLS qualification or host fixtures. */
const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path");
const h = require("./certops-filesystem-concurrent");
function proof() {
  return {
    schemaVersion: 1,
    scope: h.SCOPE,
    processScope: "one-native-node-process",
    contenderCount: 2,
    completedMutations: 2,
    backupNamespaces: "default-alongside-target",
    fingerprints: ["a", "b", "c"].map((c) => c.repeat(64)),
    spkiFingerprints: ["d", "e", "f"].map((c) => c.repeat(64)),
    completionOrder: ["contender-b", "contender-c"],
    backupPredecessors: ["a", "b"].map((c) => c.repeat(64)),
    servedBeforeFingerprint: "a".repeat(64),
    servedAfterFingerprint: "c".repeat(64),
    ...Object.fromEntries(h.FLAGS.map((name) => [name, true])),
  };
}
test("paired concurrency proof requires every genuine mutation, TLS and cleanup fact", () => {
  assert.equal(h.verifyProof(proof()), true);
  for (const flag of h.FLAGS) {
    const p = proof();
    delete p[flag];
    assert.throws(() => h.verifyProof(p));
    assert.throws(() => h.verifyProof({ ...proof(), [flag]: false }));
  }
  for (const change of [
    { processScope: "separate-processes" },
    { contenderCount: 1 },
    { completedMutations: 1 },
    { backupNamespaces: "distinct-owned-directories" },
    { rawPrivateKey: "withheld" },
  ])
    assert.throws(() => h.verifyProof({ ...proof(), ...change }));
});
test("native invocation order, complete predecessor lineage and final served leaf cannot be swapped", () => {
  const changes = [
    (p) => {
      p.completionOrder.reverse();
      p.backupPredecessors[1] = "c".repeat(64);
      p.servedAfterFingerprint = "b".repeat(64);
    },
    (p) => p.backupPredecessors.reverse(),
    (p) => {
      p.backupPredecessors[0] = "c".repeat(64);
    },
    (p) => {
      p.servedBeforeFingerprint = "b".repeat(64);
    },
    (p) => {
      p.servedAfterFingerprint = "b".repeat(64);
    },
    (p) => {
      p.spkiFingerprints[1] = p.spkiFingerprints[0];
    },
    (p) => {
      p.fingerprints[2] = p.fingerprints[1];
    },
    (p) => p.completionOrder.pop(),
  ];
  for (const change of changes) {
    const p = proof();
    change(p);
    assert.throws(() => h.verifyProof(p));
  }
});
test("owned file observations reject mutation and a durable unknown listener receipt prevents cleanup", () => {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "certops-concurrent-control-"),
  );
  try {
    const file = path.join(root, "public-sentinel");
    fs.writeFileSync(file, "original");
    const before = [h.snapshot(file)];
    h.assertUnchanged([file], before);
    h.assertCleanupSafe(root);
    fs.writeFileSync(file, "changed");
    assert.throws(
      () => h.assertUnchanged([file], before),
      /private diagnostics withheld/,
    );
    const guard = path.join(
      root,
      ".preserve-filesystem-concurrency-unknown.json",
    );
    fs.writeFileSync(guard, "{}");
    assert.throws(() => h.assertCleanupSafe(root), /durable/);
    assert.equal(fs.existsSync(guard), true);
    fs.unlinkSync(guard);
    h.assertCleanupSafe(root);
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});

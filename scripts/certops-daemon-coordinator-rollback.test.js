"use strict";
/** Supporting closed proof and benign file guards; no daemon/native TLS runs. */
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os");
const h = require("./certops-daemon-coordinator-rollback");
function proof() {
  return {
    schemaVersion: 1,
    scope: h.SCOPE,
    service: "nginx",
    evidenceTransport: "read-only-local-recorder-not-signed-api",
    fingerprints: ["a", "b"].map((c) => c.repeat(64)),
    ...Object.fromEntries(h.FLAGS.map((flag) => [flag, true])),
  };
}
test("coordinator rollback requires native deployment, validation, restore and TLS observations", () => {
  for (const service of ["nginx", "apache", "haproxy"])
    assert.equal(h.verifyProof({ ...proof(), service }), true);
  for (const flag of h.FLAGS) {
    const value = proof();
    delete value[flag];
    assert.throws(() => h.verifyProof(value));
    assert.throws(() => h.verifyProof({ ...proof(), [flag]: false }));
  }
  for (const change of [
    { service: "mock" },
    { evidenceTransport: "signed-api" },
    { rawKey: "secret" },
    { fingerprints: ["a", "a"].map((c) => c.repeat(64)) },
  ])
    assert.throws(() => h.verifyProof({ ...proof(), ...change }));
});
test("unknown daemon recovery guard preserves files and snapshot distinguishes replacement semantics", () => {
  const root = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "daemon-rollback-proof-")),
  );
  try {
    const file = path.join(root, "public.txt");
    fs.writeFileSync(file, "original", { mode: 0o600 });
    const before = h.snapshot(file);
    h.assertSnapshot(file, before);
    const replacement = path.join(root, "replacement");
    fs.writeFileSync(replacement, "original", { mode: 0o600 });
    fs.renameSync(replacement, file);
    assert.throws(() => h.assertSnapshot(file, before));
    h.assertSnapshot(file, before, false);
    h.assertCleanupSafe(root);
    fs.writeFileSync(
      path.join(root, ".preserve-daemon-coordinator-owned.json"),
      "owned",
    );
    assert.throws(() => h.assertCleanupSafe(root));
    assert.ok(fs.existsSync(file));
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});

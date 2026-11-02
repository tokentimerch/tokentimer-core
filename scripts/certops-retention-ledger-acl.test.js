"use strict";
/** Supporting proof/ownership guards only; no native ACL operation executes. */
const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os");
const fixture = require("../packages/agent/scripts/host/retention-ledger-read-refusal-fixture");
function proof() {
  return {
    scope: fixture.scope,
    ...Object.fromEntries(fixture.fields.map((field) => [field, true])),
    installedServiceQualified: false,
    nativeCertificateCleanupQualified: false,
    elapsedRetentionQualified: false,
  };
}
test("native ledger access proof requires both actual OS refusals and exact restoration", () => {
  assert.equal(fixture.verifyProof(proof()), true);
  for (const field of fixture.fields) {
    assert.throws(() => fixture.verifyProof({ ...proof(), [field]: false }));
    const missing = proof();
    delete missing[field];
    assert.throws(() => fixture.verifyProof(missing));
  }
  for (const field of [
    "installedServiceQualified",
    "nativeCertificateCleanupQualified",
    "elapsedRetentionQualified",
  ])
    assert.throws(() => fixture.verifyProof({ ...proof(), [field]: true }));
  assert.throws(() =>
    fixture.verifyProof({ ...proof(), scope: "installed-agent" }),
  );
});
test("durable unresolved ownership blocks cleanup even with no live child", () => {
  const directory = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "certops-ledger-acl-guard-")),
  );
  try {
    fixture.assertCleanupSafe(directory);
    const guard = path.join(directory, fixture.preserveGuardName);
    fs.writeFileSync(guard, "unresolved", { flag: "wx" });
    assert.throws(() => fixture.assertCleanupSafe(directory));
    fs.unlinkSync(guard);
    fixture.assertCleanupSafe(directory);
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
});

test("owned receipt reader bounds real bytes and rejects extra protocol fields", () => {
  const directory = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "certops-ledger-acl-receipt-")),
  );
  try {
    const file = path.join(directory, "restored.json"),
      value = {
        schemaVersion: 1,
        nonce: "a".repeat(64),
        fileId: "1:2",
        restored: true,
        originalDacl: "D:P",
      };
    fs.writeFileSync(file, JSON.stringify(value));
    assert.deepEqual(fixture.readReceipt(file, "restored"), value);
    fs.writeFileSync(file, JSON.stringify({ ...value, unexpected: true }));
    assert.throws(() => fixture.readReceipt(file, "restored"));
    fs.writeFileSync(file, "x".repeat(16385));
    assert.throws(() => fixture.readReceipt(file, "restored"));
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
});

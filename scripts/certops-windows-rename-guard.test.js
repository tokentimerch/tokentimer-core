"use strict";
// Portable guard tests use only owned public text files and controlled emitters.
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  { EventEmitter } = require("node:events");
const helper = require("../tests/e2e/helpers/certops-windows-rename-guard");
function fixture(kind) {
  const base = path.resolve(__dirname, "../.build"),
    root = fs.mkdtempSync(path.join(base, "rename-guard-"));
  return {
    root,
    kind,
    receipt: helper.createGuard(root, kind),
    child: new EventEmitter(),
    file: path.join(root, `.preserve-${kind}-holder.json`),
  };
}
test("both rename holders preserve active/missing/tampered custody until actual close and native release", () => {
  for (const kind of helper.KINDS) {
    const f = fixture(kind);
    try {
      assert.throws(() => helper.assertCleanupSafe(f.root, kind));
      assert.throws(() => f.receipt.complete(true));
      f.receipt.attach(f.child);
      assert.throws(() => f.receipt.complete(true));
      f.child.emit("exit", 0);
      assert.throws(() => f.receipt.complete(true));
      const original = fs.readFileSync(f.file);
      fs.writeFileSync(f.file, "tampered");
      f.child.emit("close", 0);
      assert.throws(() => f.receipt.complete(true));
      assert.throws(() => helper.assertCleanupSafe(f.root, kind));
      fs.unlinkSync(f.file);
      assert.throws(() => helper.assertCleanupSafe(f.root, kind));
      fs.writeFileSync(f.file, original);
      // Replacement inode intentionally cannot be adopted even with original bytes.
      assert.throws(() => f.receipt.complete(true));
    } finally {
      fs.rmSync(f.root, { recursive: true, force: true });
    }
  }
});
test("completed holder cannot remove a later owner's receipt", () => {
  for (const kind of helper.KINDS) {
    const f = fixture(kind);
    try {
      f.receipt.attach(f.child);
      f.child.emit("close", 0);
      assert.throws(() => f.receipt.complete(false));
      f.receipt.complete(true);
      assert.equal(helper.assertCleanupSafe(f.root, kind), true);
      const later = helper.createGuard(f.root, kind),
        laterChild = new EventEmitter();
      later.attach(laterChild);
      assert.throws(() => f.receipt.complete(true));
      assert.ok(fs.existsSync(f.file));
      assert.throws(() => helper.assertCleanupSafe(f.root, kind));
      laterChild.emit("close", 0);
      later.complete(true);
      assert.equal(helper.assertCleanupSafe(f.root, kind), true);
    } finally {
      fs.rmSync(f.root, { recursive: true, force: true });
    }
  }
});

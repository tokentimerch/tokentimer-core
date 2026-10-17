"use strict";
/** Sticky lifecycle custody for native directory-holder qualification children.
 * A missing/tampered receipt cannot permit parent native or public cleanup.
 * This module never terminates processes or infers native handle release. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const active = new Map();
const KINDS = Object.freeze(["first-rename", "second-rename", "source-junction"]);
function identity(file) {
  const stat = fs.lstatSync(file, { bigint: true });
  assert.ok(!stat.isSymbolicLink() && stat.ino > 0n);
  assert.equal(
    path.resolve(fs.realpathSync(file)).toLowerCase(),
    path.resolve(file).toLowerCase(),
  );
  return `${stat.dev}:${stat.ino}`;
}
function guardPath(workDir, kind) {
  assert.ok(KINDS.includes(kind));
  return path.join(workDir, `.preserve-${kind}-holder.json`);
}
function createGuard(workDir, kind) {
  const key = path.resolve(workDir),
    file = guardPath(key, kind);
  assert.ok(
    !active.get(key)?.has(kind),
    "Owned rename holder is already active",
  );
  assert.ok(fs.lstatSync(key).isDirectory());
  const rootId = identity(key),
    bytes = Buffer.from(
      JSON.stringify({ kind, nonce: crypto.randomUUID() }) + "\n",
    );
  fs.writeFileSync(file, bytes, { flag: "wx" });
  const fileId = identity(file);
  const entry = { closed: false, attached: false, released: false };
  const entries = active.get(key) || new Map();
  entries.set(kind, entry);
  active.set(key, entries);
  return {
    attach(child) {
      assert.equal(entry.attached, false);
      assert.equal(typeof child?.once, "function");
      entry.attached = true;
      child.once("close", () => {
        entry.closed = true;
      });
    },
    complete(nativeReleaseVerified) {
      assert.equal(
        entry.released,
        false,
        "Released holder cannot authorize a later fixture",
      );
      assert.equal(
        entry.attached,
        true,
        "Unknown holder launch preserves ownership",
      );
      assert.equal(
        entry.closed,
        true,
        "Native holder child must actually close before cleanup",
      );
      assert.equal(
        nativeReleaseVerified,
        true,
        "Independent native release/drain proof required",
      );
      assert.equal(
        identity(key),
        rootId,
        "Owned root replacement preserves native state",
      );
      assert.equal(
        identity(file),
        fileId,
        "Owned holder receipt replacement preserves native state",
      );
      assert.ok(
        fs.readFileSync(file).equals(bytes),
        "Owned holder receipt changed; preserve state",
      );
      fs.unlinkSync(file);
      entry.released = true;
      entries.delete(kind);
      if (entries.size === 0) active.delete(key);
    },
  };
}
function assertCleanupSafe(workDir, kind) {
  const key = path.resolve(workDir);
  assert.ok(
    !active.get(key)?.has(kind) && !fs.existsSync(guardPath(key, kind)),
    "Unresolved rename-holder custody preserves native/public fixture state",
  );
  return true;
}
module.exports = { createGuard, assertCleanupSafe, KINDS };

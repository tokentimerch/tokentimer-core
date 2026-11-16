"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { binaryName, buildOne, targets } = require("./build-observed-revocation-helper");

test("cross-build rejects a binary for the wrong architecture and leaves no artifact", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-revocation-build-"));
  try {
    const target = { os: "linux", arch: "amd64" };
    const run = (_command, args) => {
      const b = Buffer.alloc(64); b.set([0x7f, 0x45, 0x4c, 0x46, 2, 1]); b.writeUInt16LE(183, 18);
      fs.writeFileSync(args[args.indexOf("-o") + 1], b);
      return { status: 0 };
    };
    assert.throws(() => buildOne(target, dir, { run }), /architecture mismatch/);
    assert.equal(fs.existsSync(path.join(dir, binaryName(target))), false);
    assert.deepEqual(fs.readdirSync(dir), []);
    assert.equal(targets.length, 4);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

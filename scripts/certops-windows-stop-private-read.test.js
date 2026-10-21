"use strict";
/** Real bounded public-file observation only; no native Windows APIs execute. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os");
const {
  readPrivate,
} = require("../tests/e2e/helpers/certops-windows-stop-offline");
test("stop fixture reads the original bounded descriptor and refuses same-byte replacement before open", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "certops-stop-read-"));
  const file = path.join(root, "public.json"),
    saved = path.join(root, "original.json");
  assert.ok(
    [file, saved].every((value) =>
      path.resolve(value).startsWith(path.resolve(root) + path.sep),
    ),
  );
  const bytes = Buffer.from('{"public":"fixture"}');
  fs.writeFileSync(file, bytes);
  const originalOpen = fs.openSync;
  try {
    assert.ok(readPrivate(file, 1024).bytes.equals(bytes));
    let replaced = false;
    fs.openSync = function (value, ...args) {
      if (value === file && !replaced) {
        replaced = true;
        fs.renameSync(file, saved);
        fs.writeFileSync(file, bytes);
      }
      return originalOpen.call(fs, value, ...args);
    };
    assert.throws(() => readPrivate(file, 1024));
    fs.openSync = originalOpen;
    assert.ok(
      replaced && fs.existsSync(saved) && fs.readFileSync(file).equals(bytes),
    );
    fs.writeFileSync(file, Buffer.alloc(1025));
    assert.throws(() => readPrivate(file, 1024));
    fs.writeFileSync(file, Buffer.alloc(0));
    assert.throws(() => readPrivate(file, 1024));
    assert.throws(() => readPrivate(root, 1024));
  } finally {
    fs.openSync = originalOpen;
    fs.rmSync(root, { recursive: true });
  }
});

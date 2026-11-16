"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { captureOwnershipReceipt, removeOwnershipReceipt } = require("./certops-linux-systemd-ownership");

const nativeTest = process.platform === "linux" && process.getuid?.() === 0 ? test : test.skip;
function fixture(callback) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tt-owned-receipt-"));
  const file = path.join(root, "receipt.json");
  fs.writeFileSync(file, '{"nonce":"owned"}\n', { mode: 0o600 });
  try { callback({ root, file }); }
  finally {
    assert.ok(path.basename(root).startsWith("tt-owned-receipt-"));
    fs.rmSync(root, { recursive: true, force: true });
  }
}

nativeTest("unchanged owned receipt is removed", () => fixture(({ file }) => {
  const proof = captureOwnershipReceipt(file);
  removeOwnershipReceipt(file, proof);
  assert.equal(fs.lstatSync(file, { throwIfNoEntry: false }), undefined);
}));

nativeTest("byte-identical replacement is refused and preserved", () => fixture(({ root, file }) => {
  const proof = captureOwnershipReceipt(file);
  const bytes = fs.readFileSync(file);
  const original = path.join(root, "original.json");
  fs.renameSync(file, original);
  fs.writeFileSync(file, bytes, { mode: 0o600 });
  assert.throws(() => removeOwnershipReceipt(file, proof));
  assert.ok(fs.readFileSync(file).equals(bytes));
  assert.ok(fs.readFileSync(original).equals(bytes));
}));

nativeTest("altered receipt is refused and preserved", () => fixture(({ file }) => {
  const proof = captureOwnershipReceipt(file);
  const changed = Buffer.from('{"nonce":"different"}\n');
  fs.writeFileSync(file, changed);
  assert.throws(() => removeOwnershipReceipt(file, proof));
  assert.ok(fs.readFileSync(file).equals(changed));
}));

nativeTest("a missing receipt cannot be accepted as a successful removal", () => fixture(({ file }) => {
  const proof = captureOwnershipReceipt(file);
  fs.unlinkSync(file);
  assert.throws(() => removeOwnershipReceipt(file, proof));
}));

nativeTest("a receipt with broad permissions is refused and preserved", () => fixture(({ file }) => {
  fs.chmodSync(file, 0o644);
  assert.throws(() => captureOwnershipReceipt(file));
  assert.ok(fs.existsSync(file));
}));

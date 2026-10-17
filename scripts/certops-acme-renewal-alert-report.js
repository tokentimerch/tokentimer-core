"use strict";
/** Bounded reader for the native renewal-failure SMTP sidecar. Offline bytes are not a native run. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path");
const helper = require("../tests/e2e/helpers/certops-acme-renewal-alert");
const { SCOPE, MAIN } = require("./certops-acme-bulk-report");
const { FIELD, SIDECAR } = helper;
function readProof(scope, name, root = path.resolve(__dirname, "..")) {
  if (scope !== SCOPE || name !== MAIN) return undefined;
  const file = path.join(root, SIDECAR),
    original = fs.lstatSync(file, { bigint: true });
  assert.ok(
    original.isFile() &&
      !original.isSymbolicLink() &&
      original.ino > 0n &&
      original.nlink === 1n &&
      original.size > 0n &&
      original.size <= 32768n,
  );
  const fd = fs.openSync(
      file,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
    ),
    bytes = Buffer.alloc(32769);
  let length = 0;
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    assert.ok(
      opened.isFile() &&
        opened.dev === original.dev &&
        opened.ino === original.ino,
    );
    while (length < bytes.length) {
      const n = fs.readSync(fd, bytes, length, bytes.length - length, null);
      if (!n) break;
      length += n;
    }
    const final = fs.fstatSync(fd, { bigint: true }),
      current = fs.lstatSync(file, { bigint: true });
    assert.ok(
      length > 0 &&
        length <= 32768 &&
        BigInt(length) === opened.size &&
        final.size === opened.size &&
        final.mtimeNs === opened.mtimeNs &&
        final.ctimeNs === opened.ctimeNs &&
        current.dev === opened.dev &&
        current.ino === opened.ino &&
        !current.isSymbolicLink(),
      "Owned native renewal alert proof changed during read",
    );
  } finally {
    fs.closeSync(fd);
  }
  const proof = JSON.parse(bytes.subarray(0, length).toString("utf8"));
  helper.verifyProof(proof);
  return proof;
}
module.exports = { SCOPE, MAIN, FIELD, SIDECAR, readProof };


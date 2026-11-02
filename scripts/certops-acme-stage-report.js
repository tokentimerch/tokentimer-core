"use strict";
/** Read only closed native stage proof from the selected client's fixed sidecar. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path");
const helper = require("../tests/e2e/helpers/certops-acme-stage-faults");
const SCOPES = [
  "real-agent-acme-filesystem",
  "real-agent-acme-eab-filesystem",
  "real-agent-acmesh-filesystem",
  "real-agent-acmesh-eab-filesystem",
  "real-agent-alpine-acmesh",
];
const JOURNEY =
  "real ACME: agent discovers public files registers claims issues renews deploys and persists independently verified certificate evidence";
function verifyForScope(proof, scope) {
  assert.ok(SCOPES.includes(scope));
  helper.verifyProof(proof);
  assert.equal(proof.client, scope.includes("acmesh") ? "acme.sh" : "certbot");
  return true;
}
function readProof(scope, name, root = path.resolve(__dirname, "..")) {
  if (!SCOPES.includes(scope) || name !== JOURNEY) return undefined;
  const file = path.join(
    root,
    "qualification-results",
    `acme-stage-faults-${scope.includes("acmesh") ? "acmesh" : "certbot"}.json`,
  );
  const original = fs.lstatSync(file, { bigint: true });
  assert.ok(
    original.isFile() &&
      !original.isSymbolicLink() &&
      original.size > 0n &&
      original.size <= 65536n,
  );
  const fd = fs.openSync(file, "r"),
    bytes = Buffer.alloc(65537);
  let length = 0;
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    assert.ok(
      opened.isFile() &&
        opened.dev === original.dev &&
        opened.ino === original.ino,
    );
    while (length < bytes.length) {
      const count = fs.readSync(fd, bytes, length, bytes.length - length, null);
      if (count === 0) break;
      length += count;
    }
    assert.ok(
      length > 0 && length <= 65536,
      "Native stage sidecar exceeds bound",
    );
  } finally {
    fs.closeSync(fd);
  }
  const proof = JSON.parse(bytes.subarray(0, length).toString("utf8"));
  verifyForScope(proof, scope);
  return proof;
}
module.exports = { SCOPES, JOURNEY, verifyForScope, readProof };

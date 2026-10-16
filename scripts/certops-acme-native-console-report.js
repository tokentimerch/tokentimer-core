"use strict";
/** Closed proof reader for the explicit Ubuntu native console qualification.
 * The sidecar is produced only by the actual agent/browser actor. No arbitrary
 * report paths or caller-supplied replacement native observations are allowed. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path");
const helper = require("../tests/e2e/helpers/certops-acme-browser-console");
const SUITE = "linux-native-acme-browser-console";
const SCENARIO = "real-native-acme-console-live-and-completed-claim";
const NATIVE_CASES = Object.freeze([
  "real-acme-native-console-live-claimed-output",
  "real-acme-native-console-completed-output-and-native-leaf",
]);
const SIDECAR = "qualification-results/acme-native-console-proof.json";
function readProof(root = path.resolve(__dirname, "..")) {
  const file = path.join(root, SIDECAR),
    original = fs.lstatSync(file, { bigint: true });
  assert.ok(
    original.isFile() &&
      !original.isSymbolicLink() &&
      original.ino > 0n &&
      original.size > 0n &&
      original.size <= 65536n,
    "Native console proof file refused",
  );
  const fd = fs.openSync(
      file,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
    ),
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
      if (!count) break;
      length += count;
    }
    assert.ok(length > 0 && length <= 65536);
  } finally {
    fs.closeSync(fd);
  }
  const proof = JSON.parse(bytes.subarray(0, length).toString("utf8"));
  helper.verifyProof(proof);
  return proof;
}
function verifyActualJourney(events, proof, candidateSha) {
  helper.verifyProof(proof);
  assert.match(candidateSha, /^[a-f0-9]{40}$/);
  const required = [
    ...NATIVE_CASES,
    require("./certops-acme-stage-report").JOURNEY,
  ];
  require("./certops-stack-report").verify(
    events,
    required,
    "certops-agent-e2e.test.js",
    "real-agent-acme-filesystem",
    candidateSha,
  );
  return true;
}
module.exports = {
  SUITE,
  SCENARIO,
  NATIVE_CASES,
  SIDECAR,
  readProof,
  verifyActualJourney,
};

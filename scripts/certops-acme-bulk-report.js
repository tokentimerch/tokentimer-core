"use strict";
/** Strict fixed-path reader for public facts emitted by the real bulk journey.
 * An offline fixture may test this reader but never constitutes native evidence. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path");
const helper = require("../tests/e2e/helpers/certops-acme-bulk-renewal");
const SCOPE = "real-agent-acme-filesystem";
const MAIN =
  "real ACME: agent discovers public files registers claims issues renews deploys and persists independently verified certificate evidence";
const FIELD = "nativeAcmeBulkRenewal",
  SIDECAR = "qualification-results/acme-bulk-native-proof.json";
function verifyForScope(proof, scope, environment) {
  assert.equal(scope, SCOPE);
  helper.verifyProof(proof);
  if (environment) {
    assert.equal(environment.measurement, "native");
    assert.equal(environment.osFamily, "linux");
    assert.equal(environment.distributionId, "ubuntu");
    assert.equal(environment.distributionVersion, "24.04");
    assert.equal(environment.executionSurface, "host");
  }
  return true;
}
// Shared bounded sidecar reader; each journey retains its own verifier and failure text.
function createProofReader(sidecar, verify, changedMessage) {
  return function readProof(scope, name, root = path.resolve(__dirname, "..")) {
    if (scope !== SCOPE || name !== MAIN) return undefined;
    const file = path.join(root, sidecar),
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
        changedMessage,
      );
    } finally {
      fs.closeSync(fd);
    }
    const proof = JSON.parse(bytes.subarray(0, length).toString("utf8"));
    verify(proof, scope);
    return proof;
  };
}
const readProof = createProofReader(
  SIDECAR,
  verifyForScope,
  "Owned native bulk proof changed during read",
);

function verifyCrossJourney(proof, reuse, background) {
  helper.verifyProof(proof);
  require("../tests/e2e/helpers/certops-acme-key-reuse").verifyProof(reuse);
  require("../tests/e2e/helpers/certops-acme-background-renewals").verifyProof(
    background,
  );
  assert.equal(reuse.client, "certbot");
  assert.equal(background.client, "certbot");
  assert.equal(proof.originalServingFingerprint, reuse.fingerprints[2]);
  assert.equal(proof.originalServingSpki, reuse.spkiFingerprint);
  assert.equal(
    proof.originalServingProfileId.toLowerCase(),
    reuse.sourceProfileId.toLowerCase(),
  );
  const jobs = [
    ...proof.issueJobIds,
    ...proof.jobIds,
    ...reuse.jobIds,
    ...background.jobIds,
  ];
  assert.equal(
    new Set(jobs.map((id) => id.toLowerCase())).size,
    8,
    "Bulk cannot reuse earlier native jobs",
  );
  return true;
}
module.exports = {
  SCOPE,
  MAIN,
  FIELD,
  SIDECAR,
  readProof,
  createProofReader,
  verifyForScope,
  verifyCrossJourney,
};

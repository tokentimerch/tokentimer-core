"use strict";
/** Bounded public proof contract for actual cross-store CNG survivor cases.
 * Source/build evidence alone cannot satisfy these five native observations.
 * Reports deliberately contain no store inventory, key names or native paths.
 */
const assert = require("node:assert/strict");
const FIELDS = Object.freeze([
  "differentCertificateCrossStoreProtected", "sameCertificateCrossStoreProtected",
  "originalKeyPreserved", "replacementTrustedTlsPreserved", "ownedCrossStoreCopiesRemoved",
]);
const REQUIRED_SOURCES = Object.freeze([
  "scripts/certops-native-key-survivor-proof.js",
  "packages/agent/scripts/host/retention-fixture.js",
  "packages/agent/src/windows-key-survivors/index.js",
  "packages/agent/src/issuers/chain-helper.js",
  "packages/agent/src/windows-cert-store/index.js",
  "packages/agent/src/index.js",
  "packages/agent/scripts/build-windows-chain-helper.js",
  "packages/agent/reference/adcs-chain/main.go",
  "packages/agent/reference/adcs-chain/keyrefs/result.go",
  "packages/agent/reference/adcs-chain/keyrefs/scan_windows.go",
]);
function verifyProof(proof) {
  assert.ok(proof && typeof proof === "object" && !Array.isArray(proof), "Native cross-store proof required");
  assert.deepEqual(Object.keys(proof).sort(), [...FIELDS].sort(), "Only bounded native survivor facts are accepted");
  for (const field of FIELDS) assert.equal(proof[field], true, field);
  return true;
}
module.exports = { FIELDS, REQUIRED_SOURCES, verifyProof };

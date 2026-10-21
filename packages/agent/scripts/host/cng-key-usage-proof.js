/*
 * Qualification notes: native-key-usage
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Parse actual accepted DER X509KeyUsageExtension: RSA exactly160/0xa0 (signature+key encipherment),EC
 * exactly128/0x80(signature);missing/extra bits fail. Certificate KeyUsage differs from NCrypt
 * KeyUsageProperty. Request sets no exact operation mask:require signing,accept known
 * decrypt/sign/agreement combinations and documentedAllUsages0x00ffffff,reject unknown bits. No exact
 * default mask or EC decryption claim. nativeKeyUsage requires10 profile/store identities/current
 * hashes.
 * For every supported RSA/EC profile independently require actual requested key size/curve, machine
 * Software-KSP identity, nonexportability and fresh native signing verified against public
 * CSR/certificate. Encryption/key-usage controls must observe actual native behavior rather than
 * accept capability metadata alone; keep private material/native inventories out of public proof.
 * Owned keys/controls are recorded before creation and absence checked after cleanup. Portable
 * signature/proof checks do not qualify native CNG/architecture/provider execution.
 */
"use strict";
/* Pure validation of independently read native certificate/KSP usage metadata.
 * X.509 KeyUsage flags differ from the private-key NCrypt operations bitmask.
 * certreq's current INF promises certificate usage and signing capability;
 * it does not promise a particular default KeyUsageProperty policy mask. */
const assert = require("node:assert/strict");
const CERTIFICATE_USAGE = Object.freeze({ "rsa-2048": 160, "rsa-3072": 160, "rsa-4096": 160, "ec-p256": 128, "ec-p384": 128 });
const CASES = Object.freeze(["My", "WebHosting"].flatMap(store => Object.keys(CERTIFICATE_USAGE).map(profile => `${profile}/${store}`)));
const SCOPE = "native-copied-csr-x509-usage-and-cng-signing-permission";
function verifyCase(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), ["caseId", "certificateUsageFlags", "cngAllowedOperations"].sort());
  assert.ok(CASES.includes(value.caseId));
  assert.equal(value.certificateUsageFlags, CERTIFICATE_USAGE[value.caseId.split("/")[0]]);
  assert.ok(Number.isInteger(value.cngAllowedOperations) && value.cngAllowedOperations >= 0 && value.cngAllowedOperations <= 0xffffffff);
  assert.ok(value.cngAllowedOperations === 0x00ffffff || (value.cngAllowedOperations & ~7) === 0, "Unknown native CNG operation bits");
  // NCrypt NCRYPT_ALLOW_SIGNING_FLAG is 2; AllUsages (0x00ffffff) includes
  // that bit and must remain accepted. Other native operations are observed,
  // not treated as an exact product restriction or as ECDSA decryption support.
  assert.equal(value.cngAllowedOperations & 2, 2);
  return true;
}
function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), ["scope", "copiedActualCsrExtensions", "privateKeyUsageClaim", "cases"].sort());
  assert.equal(value.scope, SCOPE); assert.equal(value.copiedActualCsrExtensions, true);
  assert.equal(value.privateKeyUsageClaim, "signing-permitted-not-exact-default-ncrypt-mask");
  assert.ok(Array.isArray(value.cases)); assert.equal(value.cases.length, CASES.length);
  const seen = new Set();
  for (const item of value.cases) { verifyCase(item); assert.equal(seen.has(item.caseId), false); seen.add(item.caseId); }
  return true;
}
module.exports = { CERTIFICATE_USAGE, CASES, SCOPE, verifyCase, verifyProof };

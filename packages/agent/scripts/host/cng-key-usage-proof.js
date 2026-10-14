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

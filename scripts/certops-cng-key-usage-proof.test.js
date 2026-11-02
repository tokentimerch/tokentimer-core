"use strict";
/* Supporting usage-proof refusals only; no key, certificate or native process
 * is created. Ten actual host cases must supply their own measured metadata. */
const assert = require("node:assert/strict");
const test = require("node:test");
const { CERTIFICATE_USAGE, CASES, SCOPE, verifyCase, verifyProof } = require("../packages/agent/scripts/host/cng-key-usage-proof");
function fixture() { return { scope: SCOPE, copiedActualCsrExtensions: true, privateKeyUsageClaim: "signing-permitted-not-exact-default-ncrypt-mask", cases: CASES.map(caseId => ({ caseId, certificateUsageFlags: CERTIFICATE_USAGE[caseId.split("/")[0]], cngAllowedOperations: 0x00ffffff })) }; }
test("all five profiles in both stores accept native AllUsages and permitted signing combinations", () => {
  assert.equal(verifyProof(fixture()), true);
  for (const caseId of CASES) for (const cngAllowedOperations of [2, 3, 6, 7, 0x00ffffff]) assert.equal(verifyCase({ caseId, certificateUsageFlags: CERTIFICATE_USAGE[caseId.split("/")[0]], cngAllowedOperations }), true);
});
test("incorrect certificate usage and non-signing or malformed native policy refuse qualification", () => {
  for (const item of fixture().cases) {
    for (const certificateUsageFlags of [0, 4, item.certificateUsageFlags | 4, item.certificateUsageFlags === 128 ? 160 : 128]) assert.throws(() => verifyCase({ ...item, certificateUsageFlags }));
    for (const cngAllowedOperations of [0, 1, 4, 2 | 8, 0xffffffff, -1, 0x100000000, true, "Signing"]) assert.throws(() => verifyCase({ ...item, cngAllowedOperations }));
  }
});
test("missing duplicate unknown and private proof fields cannot satisfy the complete host matrix", () => {
  const missing = fixture(); missing.cases.pop(); assert.throws(() => verifyProof(missing));
  const duplicate = fixture(); duplicate.cases[9] = duplicate.cases[0]; assert.throws(() => verifyProof(duplicate));
  for (const change of [{ scope: "exact-cng-default-policy-qualified" }, { copiedActualCsrExtensions: false }, { privateKeyUsageClaim: "ecdsa-decryption-qualified" }, { secret: "unexpected" }]) assert.throws(() => verifyProof({ ...fixture(), ...change }));
  for (const key of Object.keys(fixture().cases[0])) { const value = { ...fixture().cases[0] }; delete value[key]; assert.throws(() => verifyCase(value)); }
});

"use strict";
// Supporting protocol and bounded-file tests; no native chain, firewall or CA.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const subject = require("../tests/e2e/helpers/certops-adcs-http-intermediate-crl");
function proof() {
  return {
    scope: subject.SCOPE,
    transport: "http",
    revocationTarget: "intermediate",
    nativeHelperSha256: "a".repeat(64),
    publicCrlSha256: "b".repeat(64),
    leafFingerprint: "c".repeat(64),
    nativeVerdicts: ["valid", "revocation_unknown", "valid"],
    installedAgentQualified: false,
    httpOnlyLeafQualified: false,
    ocspQualified: false,
    ...Object.fromEntries(subject.FLAGS.map((flag) => [flag, true])),
  };
}
test("HTTP intermediate proof requires actual native sequence and cannot promote leaf/agent/OCSP", () => {
  subject.verifyProof(proof());
  for (const key of Object.keys(proof())) {
    const candidate = proof();
    delete candidate[key];
    assert.throws(() => subject.verifyProof(candidate));
  }
  for (const flag of subject.FLAGS)
    assert.throws(() => subject.verifyProof({ ...proof(), [flag]: false }));
  for (const patch of [
    { installedAgentQualified: true },
    { httpOnlyLeafQualified: true },
    { ocspQualified: true },
    { nativeVerdicts: ["valid", "invalid", "valid"] },
    { nativeVerdicts: ["valid", "revocation_unknown", "revocation_unknown"] },
    { rawCachePolicy: "private" },
  ])
    assert.throws(() => subject.verifyProof({ ...proof(), ...patch }));
});
test("actual native CDP rendering accepts only existing isolated HTTP root publication", () => {
  assert.equal(
    subject.publicCdp(`URL=${subject.HTTP_CRL}\r\n`),
    subject.HTTP_CRL,
  );
  assert.equal(
    subject.publicCdp(`URL=${subject.HTTP_CRL}\nURL=${subject.HTTP_CRL}`),
    subject.HTTP_CRL,
  );
  for (const value of [
    "ldap://10.64.0.4/owned",
    "http://10.64.0.4/other.crl",
    `${subject.HTTP_CRL}\nldap://alternate`,
    `${subject.HTTP_CRL}\nhttps://other.invalid/alternate.crl`,
    "",
  ])
    assert.throws(() => subject.publicCdp(value));
});
test("bounded private policy reads use exact regular file identities and refuse oversize", () => {
  const base = path.resolve(__dirname, "../.build");
  fs.mkdirSync(base, { recursive: true });
  const root = fs.mkdtempSync(path.join(base, "http-crl-reader-"));
  try {
    const file = path.join(root, "receipt.json");
    fs.writeFileSync(file, "owned", { flag: "wx" });
    const result = subject.ownedBytes(file, 8);
    assert.equal(result.bytes.toString(), "owned");
    assert.match(result.identity, /^\d+:\d+$/);
    assert.throws(() => subject.ownedBytes(file, 4));
    assert.throws(() => subject.ownedBytes(root, 8));
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});

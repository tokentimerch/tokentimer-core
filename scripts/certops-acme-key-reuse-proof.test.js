"use strict";
/** Bounded public proof controls only; these do not claim ACME execution. */
const test = require("node:test"), assert = require("node:assert/strict");
const { verifyProof, fields, scope } = require("../tests/e2e/helpers/certops-acme-key-reuse");
const fixture = client => ({ scope, client, ...Object.fromEntries(fields.map(field => [field, true])), fingerprints: ["1", "2", "3"].map(v => v.repeat(64)), serials: ["01", "02", "03"], spkiFingerprint: "4".repeat(64), jobIds: ["11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"], sourceProfileId: "33333333-3333-3333-3333-333333333333", sourceProfileFingerprint: "5".repeat(64) });
test("both real CSR client variants require all exact reuse facts", () => {
  for (const client of ["certbot", "acme.sh"]) {
    const proof = fixture(client); assert.equal(verifyProof(proof), true);
    for (const field of fields) {
      for (const value of [false, null, 1, "true"]) assert.throws(() => verifyProof({ ...proof, [field]: value }));
      const missing = { ...proof }; delete missing[field]; assert.throws(() => verifyProof(missing));
    }
    assert.throws(() => verifyProof({ ...proof, privateKey: "private" }));
  }
});
test("rotating, duplicated and unsupported public identities cannot qualify reuse", () => {
  const proof = fixture("certbot");
  for (const field of ["scope", "client", "spkiFingerprint", "sourceProfileId", "sourceProfileFingerprint"]) {
    const missing = { ...proof }; delete missing[field]; assert.throws(() => verifyProof(missing));
    for (const value of [null, false, "unsupported"]) assert.throws(() => verifyProof({ ...proof, [field]: value }));
  }
  for (const field of ["jobIds", "serials", "fingerprints"]) {
    assert.throws(() => verifyProof({ ...proof, [field]: [] }));
    assert.throws(() => verifyProof({ ...proof, [field]: proof[field].map(() => proof[field][0]) }));
    assert.throws(() => verifyProof({ ...proof, [field]: [...proof[field], proof[field][0]] }));
    assert.throws(() => verifyProof({ ...proof, [field]: proof[field].map(() => "invalid") }));
  }
});

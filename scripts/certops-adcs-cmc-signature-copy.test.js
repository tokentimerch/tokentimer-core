"use strict";
// Supporting DER-copy mechanics against genuine committed CA response fixtures.
// Native signature refusal is measured separately by the protected AD CS lane.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { tamperCmsSignerSignature, responseDerBytes } = require("../tests/e2e/helpers/certops-adcs-cmc-signature-copy");
const directory = path.resolve(__dirname, "../packages/agent/reference/adcs-cmc/testdata");
for (const name of ["pending", "issued", "denied"]) {
  test(`actual ${name} CMS response changes exactly one signer signature byte`, () => {
    const input = responseDerBytes(fs.readFileSync(path.join(directory, `${name}.rsp`)));
    const before = Buffer.from(input);
    const result = tamperCmsSignerSignature(input);
    assert.deepEqual(input, before);
    assert.equal(result.bytes.length, input.length);
    const changed = [];
    for (let i = 0; i < input.length; i++) if (input[i] !== result.bytes[i]) changed.push(i);
    assert.deepEqual(changed, [result.signatureOffset]);
    assert.equal(input[result.signatureOffset] ^ result.bytes[result.signatureOffset], 1);
  });
}
test("malformed and unbounded CMS input cannot select arbitrary mutation bytes", () => {
  const input = fs.readFileSync(path.join(directory, "pending.rsp"));
  for (const bad of [undefined, Buffer.alloc(0), Buffer.alloc(65537), input.subarray(0, input.length - 1), Buffer.concat([input, Buffer.from([0])]), Buffer.from(input).fill(0, 0, 2)])
    assert.throws(() => tamperCmsSignerSignature(bad));
});
test("strict public native proof refuses absent, false, synthetic and out-of-bound facts", () => {
  const contract = require("../tests/e2e/helpers/certops-adcs-cmc-signature-copy");
  const proof = {
    scope: contract.scope,
    ...Object.fromEntries(contract.flags.map(field => [field, true])),
    caRequestId: "4294967295",
    responseSha256: "a".repeat(64),
    nativeHelperSha256: "b".repeat(64),
    originalResponseDerSha256: "c".repeat(64),
    tamperedResponseDerSha256: "d".repeat(64),
    refusedVariants: [...contract.refusedVariants],
    syntheticCaResponse: false,
  };
  assert.equal(contract.verifyProof(proof), true);
  for (const field of contract.flags) {
    const absent = { ...proof }; delete absent[field];
    assert.throws(() => contract.verifyProof(absent));
    assert.throws(() => contract.verifyProof({ ...proof, [field]: false }));
  }
  for (const patch of [{ scope: "signed-cmc-renewal" }, { syntheticCaResponse: true }, { caRequestId: "4294967296" }, { caRequestId: "0" }, { tamperedResponseDerSha256: proof.originalResponseDerSha256 }, { refusedVariants: contract.refusedVariants.slice(0, -1) }, { privateResponse: "forbidden" }])
    assert.throws(() => contract.verifyProof({ ...proof, ...patch }));
});

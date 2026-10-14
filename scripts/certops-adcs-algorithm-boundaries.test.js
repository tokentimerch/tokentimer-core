"use strict";
/** Pure production policy/descriptor and proof adversaries. Static public CA
 * test material never constitutes native template observation or host execution. */
const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path");
const helper = require("../tests/e2e/helpers/certops-adcs-algorithm-boundaries"), inventory = require("./certops-adcs-safety-inventory");
const definition = require("../infra/certops-adcs/safety-cases.json");
const { evaluateEnrollmentSafety } = require("../packages/agent/src/issuers/adcs-safety"), { computeSpkiSha256Hex } = require("../packages/agent/src/issuers/adcs-enrollment");
const ca = fs.readFileSync(path.resolve(__dirname, "../packages/agent/reference/adcs-cmc/testdata/ca.cer")), pin = computeSpkiSha256Hex(ca);
test("all four descriptors exercise real policy boundaries and admit matching positive profiles", () => {
  assert.equal(inventory.validate().snapshotKey, 10);
  for (const selected of helper.CASES) {
    const descriptor = definition.keyConstraintCases.find(item => item.id === selected.id); assert.equal(helper.verifyDescriptor(descriptor, selected), true);
    const snapshot = { kind: "adcs", transport: "dcom", caConfig: "ca.example.test\\Owned CA", template: selected.template, caKeySha256: pin, authorizedDnsNames: ["app.example.test"], keyAlgorithm: selected.algorithm, keySize: selected.size };
    const preflightResult = { caConfig: snapshot.caConfig, template: selected.template, templateCheck: { verdict: "safe", reasons: [], schemaVersion: selected.schema, minimalKeySize: selected.minimum, asymmetricAlgorithm: selected.nativeAlgorithm, enrolleeSuppliesSubject: true, templateOid: "1.3.6.1.4.1.311.21.8.2" }, caCheck: { verdict: "safe", reasons: [], operatorAttested: false }, caCertificates: [{ keySha256: pin, certificateB64: ca.toString("base64") }] };
    assert.equal(evaluateEnrollmentSafety({ preflightResult, snapshot }).errorCode, "ADCS_TEMPLATE_UNSAFE");
    assert.equal(evaluateEnrollmentSafety({ preflightResult, snapshot: { ...snapshot, keySize: selected.minimum } }).ok, true);
    for (const field of ["template", "algorithm", "size", "schema"]) assert.throws(() => helper.verifyDescriptor({ ...descriptor, [field]: null }, selected));
    const missing = structuredClone(definition); missing.keyConstraintCases = missing.keyConstraintCases.filter(item => item.id !== selected.id); assert.throws(() => inventory.validate(missing));
  }
});
test("native algorithm proof requires genuine mapped positive identities and every closed observation", () => {
  const proof = () => helper.CASES.map((item,index) => ({ caseId: item.id, positiveScenario: `adcs-real-${item.positiveId}-issued-cng-iis`, positiveFingerprintSha256: (index+10).toString(16).repeat(64), positiveRequestId: String(17+index), ...Object.fromEntries(helper.FLAGS.map(flag => [flag, true])) }));
  assert.equal(helper.verifyProof(proof()), true);
  for (const flag of helper.FLAGS) for (const wrong of [false, 1, null, "true"]) { const value = proof(); value[0][flag] = wrong; assert.throws(() => helper.verifyProof(value)); }
  for (const mutate of [value => value.pop(), value => value[1] = value[0], value => value[1].positiveRequestId=value[0].positiveRequestId, value=>value[1].positiveFingerprintSha256=value[0].positiveFingerprintSha256, value => value[0].positiveScenario = "synthetic", value => value[0].positiveRequestId = "0", value => value[0].positiveFingerprintSha256 = "unknown", value => value[0].rawKey = "unwanted"]) { const value = proof(); mutate(value); assert.throws(() => helper.verifyProof(value)); }
});

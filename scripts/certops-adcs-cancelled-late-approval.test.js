"use strict";
// Supporting public-proof/ownership controls. Software CSR material stays in
// memory; no native certificate, key, service, IIS, CA or browser is operated.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const helper = require("../tests/e2e/helpers/certops-adcs-cancelled-late-approval");
const {
  extractSpkiFromCsr,
} = require("../packages/agent/src/issuers/der-extensions");
function proof() {
  return {
    scope: helper.SCOPE,
    cancelledEnrollmentId: "11111111-1111-1111-1111-111111111111",
    successorEnrollmentId: "22222222-2222-2222-2222-222222222222",
    requestIds: ["17", "18"],
    fingerprints: ["a".repeat(64), "b".repeat(64)],
    sameCertificateRenewalQualified: false,
    ...Object.fromEntries(helper.FLAGS.map((flag) => [flag, true])),
  };
}

test("late cancelled approval proof requires every native fact and refuses scope promotion", () => {
  assert.equal(helper.verifyProof(proof()), true);
  for (const field of Object.keys(proof())) {
    const missing = proof();
    delete missing[field];
    assert.throws(() => helper.verifyProof(missing));
  }
  for (const field of helper.FLAGS)
    for (const invalid of [false, 1, "true", null]) {
      assert.throws(() => helper.verifyProof({ ...proof(), [field]: invalid }));
    }
  for (const change of [
    { scope: "expired-request-before-any-installation" },
    { sameCertificateRenewalQualified: true },
    { cancelledEnrollmentId: proof().successorEnrollmentId },
    { requestIds: ["17", "17"] },
    { requestIds: ["17", "4294967296"] },
    { requestIds: [17, "18"] },
    { fingerprints: ["a".repeat(64), "a".repeat(64)] },
    { rawCsr: "private" },
  ])
    assert.throws(() => helper.verifyProof({ ...proof(), ...change }));
});

function csr() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const tlv = (tag, value) =>
    Buffer.concat([
      Buffer.from([tag]),
      value.length < 128
        ? Buffer.from([value.length])
        : Buffer.from([0x82, value.length >> 8, value.length & 255]),
      value,
    ]);
  const info = tlv(
    0x30,
    Buffer.concat([
      Buffer.from([2, 1, 0, 0x30, 0]),
      publicKey.export({ type: "spki", format: "der" }),
      Buffer.from([0xa0, 0]),
    ]),
  );
  const signature = crypto.sign("sha256", info, privateKey);
  const der = tlv(
    0x30,
    Buffer.concat([
      info,
      Buffer.from("300d06092a864886f70d01010b0500", "hex"),
      tlv(3, Buffer.concat([Buffer.from([0]), signature])),
    ]),
  );
  return {
    der,
    pem: `-----BEGIN CERTIFICATE REQUEST-----\n${der.toString("base64")}\n-----END CERTIFICATE REQUEST-----\n`,
  };
}

test("native CA ownership binds exact original CSR, SPKI, requester, template and request before officer action", () => {
  const original = csr(),
    foreign = csr();
  const expected = {
    requestId: "17",
    domain: "certops-adcs-0123456789-cancel.example.test",
    journal: {
      templateOid: "1.3.6.1.4.1.311.21.8.17",
      csrSpkiSha256: crypto
        .createHash("sha256")
        .update(extractSpkiFromCsr(original.der))
        .digest("hex"),
    },
    csrPem: original.pem,
    disposition: 9,
  };
  const native = {
    requestId: 17,
    commonName: expected.domain,
    requester: "TTQUAL\\tt-agent$",
    disposition: 9,
    templateOid: expected.journal.templateOid,
    csrDerB64: original.der.toString("base64"),
  };
  for (const disposition of [9, 20, 21])
    assert.equal(
      helper.verifyCaOwnership(
        { ...native, disposition },
        { ...expected, disposition },
      ),
      true,
    );
  for (const change of [
    { requestId: 18 },
    { commonName: "foreign.example.test" },
    { requester: "TTQUAL\\another-agent$" },
    { disposition: 20 },
    { templateOid: "1.2.3.4" },
    { csrDerB64: foreign.der.toString("base64") },
    { csrDerB64: "invalid" },
  ])
    assert.throws(() =>
      helper.verifyCaOwnership({ ...native, ...change }, expected),
    );
  assert.throws(() =>
    helper.verifyCaOwnership(native, {
      ...expected,
      journal: { ...expected.journal, csrSpkiSha256: "0".repeat(64) },
    }),
  );
});

test("an unresolved late approval guard preserves all parent native and durable cleanup", () => {
  helper.assertCleanupSafe([]);
  const guard = {
    enrollmentId: proof().cancelledEnrollmentId,
    resolved: false,
  };
  assert.throws(() => helper.assertCleanupSafe([guard]));
  assert.equal(guard.resolved, false);
  assert.throws(() =>
    helper.assertCleanupSafe([{ enrollmentId: guard.enrollmentId }]),
  );
  guard.resolved = true;
  helper.assertCleanupSafe([guard]);
});

test("native successor custody script accepts only exact owned selector and public DER input", () => {
  const value = {
    thumbprint: "A".repeat(40),
    containerName: "tokentimer-enr-11111111-1111-1111-1111-111111111111",
    certificateDerB64: "YWJj",
    domain: "certops-adcs-0123456789-cancel.example.test",
    site: "TTADCS-0123456789-cancel",
    port: 44321,
  };
  const script = helper.nativeCustodyScript(value);
  assert.match(script, /SslSniBindingInfo/);
  assert.match(script, /VerifyData/);
  assert.match(script, /IsMachineKey/);
  for (const change of [
    { site: "Foreign" },
    { domain: "foreign.example.test" },
    { port: 0 },
    { containerName: "foreign" },
    { certificateDerB64: "';Write-Output secret;'" },
  ])
    assert.throws(() => helper.nativeCustodyScript({ ...value, ...change }));
});

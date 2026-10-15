"use strict";
// Real in-memory software signatures validate public DER safety only. These
// fixtures are not native AD CS requests, Windows CRL observations or CA proof.
const test = require("node:test"),
  assert = require("node:assert/strict"),
  crypto = require("node:crypto");
const subject = require("../tests/e2e/helpers/certops-adcs-http-leaf-crl-der");
function der(tag, ...parts) {
  const value = Buffer.concat(
    parts.map((value) => (Buffer.isBuffer(value) ? value : Buffer.from(value))),
  );
  let length = Buffer.from([value.length]);
  if (value.length >= 128) {
    let hex = value.length.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    const bytes = Buffer.from(hex, "hex");
    length = Buffer.concat([Buffer.from([128 + bytes.length]), bytes]);
  }
  return Buffer.concat([Buffer.from([tag]), length, value]);
}
const sequence = (...parts) => der(0x30, ...parts),
  algorithm = Buffer.from("300d06092a864886f70d01010b0500", "hex");
const keys = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const name = (text) =>
  sequence(
    der(
      0x31,
      sequence(Buffer.from("0603550403", "hex"), der(0x0c, Buffer.from(text))),
    ),
  );
function time(value) {
  const d = new Date(value),
    text = d
      .toISOString()
      .replace(/[-:]/g, "")
      .replace("T", "")
      .replace(/\.\d{3}Z$/, "Z")
      .slice(2);
  return der(0x17, Buffer.from(text));
}
function certificate(cn = "Owned software CA") {
  const now = Date.now(),
    subjectName = name(cn),
    tbs = sequence(
      Buffer.from("a003020102020101", "hex"),
      algorithm,
      subjectName,
      sequence(time(now - 86400000), time(now + 7 * 86400000)),
      subjectName,
      keys.publicKey.export({ format: "der", type: "spki" }),
      der(
        0xa3,
        sequence(
          sequence(
            Buffer.from("0603551d130101ff", "hex"),
            der(0x04, sequence(Buffer.from("0101ff", "hex"))),
          ),
        ),
      ),
    );
  return sequence(
    tbs,
    algorithm,
    der(0x03, Buffer.from([0]), crypto.sign("sha256", tbs, keys.privateKey)),
  );
}
function crl({
  cn = "Owned software CA",
  thisUpdate = Date.now() - 60000,
  nextUpdate = Date.now() + 2 * 86400000,
} = {}) {
  const tbs = sequence(
    Buffer.from("020101", "hex"),
    algorithm,
    name(cn),
    time(thisUpdate),
    time(nextUpdate),
  );
  return sequence(
    tbs,
    algorithm,
    der(0x03, Buffer.from([0]), crypto.sign("sha256", tbs, keys.privateKey)),
  );
}
const pin = crypto
  .createHash("sha256")
  .update(keys.publicKey.export({ format: "der", type: "spki" }))
  .digest("hex");
function withCdp(urls) {
  const certificateNode = subject.item(certificate());
  const fields = subject.children(subject.children(certificateNode)[0]);
  const extension = fields.pop();
  assert.equal(extension.tag, 0xa3);
  const original = subject.children(subject.item(extension.value));
  const points = sequence(
    ...urls.map((url) =>
      sequence(der(0xa0, der(0xa0, der(0x86, Buffer.from(url))))),
    ),
  );
  const tbs = sequence(
    ...fields.map((field) => field.raw),
    der(
      0xa3,
      sequence(
        ...original.map((field) => field.raw),
        sequence(Buffer.from("0603551d1f", "hex"), der(0x04, points)),
      ),
    ),
  );
  return sequence(
    tbs,
    algorithm,
    der(0x03, Buffer.from([0]), crypto.sign("sha256", tbs, keys.privateKey)),
  );
}
test("actual leaf CDP DER allows only one exact owned HTTP endpoint", () => {
  const url = "http://10.64.0.6:18443/TTQualificationRoot.crl";
  subject.assertHttpOnlyLeafCdp(withCdp([url]), url);
  for (const alternatives of [
    [url, "ldap://tt-ca.example/CRL"],
    ["ldap://tt-ca.example/CRL"],
    ["http://10.64.0.7:18443/TTQualificationRoot.crl"],
  ])
    assert.throws(() =>
      subject.assertHttpOnlyLeafCdp(withCdp(alternatives), url),
    );
  assert.throws(() => subject.assertHttpOnlyLeafCdp(certificate(), url));
  for (const invalid of [
    url + "?x=1",
    url.replace("10.64.0.6", "user@10.64.0.6"),
    url.replace("10.64.0.6", "127.0.0.1"),
  ])
    assert.throws(() =>
      subject.assertHttpOnlyLeafCdp(withCdp([invalid]), invalid),
    );
});
test("only a genuine current CRL signed by the exact pinned CA can be served", () => {
  const actual = crl(),
    proof = subject.verifyCrl(actual, certificate(), pin);
  assert.equal(
    proof.sha256,
    crypto.createHash("sha256").update(actual).digest("hex"),
  );
  assert.ok(Date.parse(proof.nextUpdate) > Date.now());
  const damaged = Buffer.from(actual);
  damaged[damaged.length - 1] ^= 1;
  assert.throws(() => subject.verifyCrl(damaged, certificate(), pin));
  assert.throws(() => subject.verifyCrl(actual, certificate(), "0".repeat(64)));
  assert.throws(() =>
    subject.verifyCrl(actual, certificate("Other issuer with same key"), pin),
  );
});
test("expired future truncated and noncanonical public CRLs fail closed", () => {
  const ca = certificate();
  for (const bytes of [
    crl({ nextUpdate: Date.now() - 1000 }),
    crl({ thisUpdate: Date.now() + 60000 }),
    crl().subarray(0, -1),
    Buffer.concat([crl(), Buffer.from([0])]),
    Buffer.alloc(1048577),
  ])
    assert.throws(() => subject.verifyCrl(bytes, ca, pin));
  for (const bytes of [
    Buffer.from("30800000", "hex"),
    Buffer.from("30810100", "hex"),
    Buffer.from("30820100", "hex"),
  ])
    assert.throws(() => subject.children(subject.item(bytes)));
});

test("owned HTTP GET accepts an explicit empty body but no alternate target or body", () => {
  const {
    acceptsRequest,
  } = require("../tests/e2e/helpers/certops-adcs-http-leaf-crl-server");
  const request = {
    method: "GET",
    url: "/TTQualificationRoot.crl",
    headers: { host: "10.64.0.6:24001" },
  };
  assert.equal(acceptsRequest(request, 24001), true);
  assert.equal(
    acceptsRequest(
      { ...request, headers: { ...request.headers, "content-length": "0" } },
      24001,
    ),
    true,
  );
  for (const headers of [
    { ...request.headers, "content-length": "1" },
    { ...request.headers, "content-length": "00" },
    { ...request.headers, "transfer-encoding": "chunked" },
    { host: "127.0.0.1:24001" },
  ])
    assert.equal(acceptsRequest({ ...request, headers }, 24001), false);
  for (const url of [
    "/TTQualificationRoot.crl?x=1",
    "http://10.64.0.6:24001/TTQualificationRoot.crl",
    "/other.crl",
  ])
    assert.equal(acceptsRequest({ ...request, url }, 24001), false);
  assert.equal(acceptsRequest({ ...request, method: "POST" }, 24001), false);
});

test("publication receipt admits only the original signed CRL and exact restore ownership", () => {
  const {
    verifyPublication,
  } = require("../tests/e2e/helpers/certops-adcs-http-leaf-crl-server");
  const caBytes = certificate(),
    bytes = crl();
  const expected = {
    runId: "a".repeat(10),
    token: "10000000-0000-4000-8000-000000000001",
    caThumbprint: new crypto.X509Certificate(caBytes).fingerprint.replace(
      /:/g,
      "",
    ),
    httpUrl: "http://10.64.0.6:24001/TTQualificationRoot.crl",
    caBytes,
    caKeySha256: pin,
  };
  const applied = {
    scope: "owned-enterprise-ca-http-leaf-publication",
    action: "Apply",
    runId: expected.runId,
    token: expected.token,
    caThumbprint: expected.caThumbprint,
    httpUrl: expected.httpUrl,
    originalSha256: "1".repeat(64),
    appliedSha256: "2".repeat(64),
    caReady: true,
    publicationRestored: false,
    crlBase64: bytes.toString("base64"),
    caCertificateBase64: caBytes.toString("base64"),
  };
  assert.ok(verifyPublication(applied, expected, "Apply").crl.equals(bytes));
  for (const patch of [
    { token: "foreign" },
    { httpUrl: expected.httpUrl + "?x=1" },
    { caReady: false },
    { crlBase64: applied.crlBase64 + "\n" },
    { caCertificateBase64: certificate("Other CA").toString("base64") },
    { unexpected: true },
  ])
    assert.throws(() =>
      verifyPublication({ ...applied, ...patch }, expected, "Apply"),
    );
  const restored = { ...applied, action: "Restore", publicationRestored: true };
  delete restored.crlBase64;
  delete restored.caCertificateBase64;
  const original = {
    ...expected,
    originalSha256: applied.originalSha256,
    appliedSha256: applied.appliedSha256,
  };
  assert.equal(verifyPublication(restored, original, "Restore"), restored);
  assert.throws(() =>
    verifyPublication(
      { ...restored, originalSha256: "3".repeat(64) },
      original,
      "Restore",
    ),
  );
  assert.throws(() =>
    verifyPublication(
      { ...restored, crlBase64: applied.crlBase64 },
      original,
      "Restore",
    ),
  );
});

test("leaf CRL native proof requires every observation and refuses broader claims", () => {
  const runtime = require("../tests/e2e/helpers/certops-adcs-http-leaf-crl");
  const proof = {
    scope: runtime.SCOPE,
    enrollmentId: "10000000-0000-4000-8000-000000000001",
    jobId: "10000000-0000-4000-8000-000000000002",
    requestId: 42,
    restoredEnrollmentId: "10000000-0000-4000-8000-000000000003",
    restoredJobId: "10000000-0000-4000-8000-000000000004",
    restoredRequestId: 43,
    restoredLeafFingerprint: "6".repeat(64),
    leafFingerprint: "1".repeat(64),
    publicCrlSha256: "2".repeat(64),
    nativeHelperSha256: "3".repeat(64),
    originalPublicationSha256: "4".repeat(64),
    appliedPublicationSha256: "5".repeat(64),
    caRequestCounts: [10, 11, 12],
    nativeVerdicts: ["valid", "revocation_unknown", "valid"],
    endpointStatusCodes: [200, 503, 200],
    ocspQualified: false,
    caOutageQualified: false,
    signedCmcRenewalQualified: false,
    deferredRecovery: {
      originalJobId: "10000000-0000-4000-8000-000000000005",
      originalClaimId: "10000000-0000-4000-8000-000000000006",
      continuationJobId: "10000000-0000-4000-8000-000000000002",
      continuationClaimId: "10000000-0000-4000-8000-000000000007",
      requestId: 42,
    },
    ...Object.fromEntries(runtime.FLAGS.map((flag) => [flag, true])),
  };
  assert.equal(runtime.verifyProof(proof), proof);
  for (const flag of runtime.FLAGS) {
    assert.throws(() => runtime.verifyProof({ ...proof, [flag]: false }));
    const missing = { ...proof };
    delete missing[flag];
    assert.throws(() => runtime.verifyProof(missing));
  }
  for (const flag of [
    "ocspQualified",
    "caOutageQualified",
    "signedCmcRenewalQualified",
  ])
    assert.throws(() => runtime.verifyProof({ ...proof, [flag]: true }));
  for (const value of [0, 4294967296, 1.5])
    assert.throws(() => runtime.verifyProof({ ...proof, requestId: value }));
  assert.throws(() =>
    runtime.verifyProof({ ...proof, caRequestCounts: [10, 12] }),
  );
  assert.throws(() =>
    runtime.verifyProof({ ...proof, scope: "firewall-or-ca-outage" }),
  );
  for (const [field, value] of [
    ["restoredEnrollmentId", proof.enrollmentId.toUpperCase()],
    ["restoredJobId", proof.jobId.toUpperCase()],
    ["restoredRequestId", proof.requestId],
    ["restoredLeafFingerprint", proof.leafFingerprint],
    ["caRequestCounts", [10, 11, 13]],
  ])
    assert.throws(() => runtime.verifyProof({ ...proof, [field]: value }));
  for (const patch of [
    { requestId: 43 },
    { originalJobId: proof.jobId },
    { continuationJobId: proof.restoredJobId },
    { originalClaimId: proof.deferredRecovery.continuationClaimId },
    { rawContainer: "private" },
  ])
    assert.throws(() =>
      runtime.verifyProof({
        ...proof,
        deferredRecovery: { ...proof.deferredRecovery, ...patch },
      }),
    );
});

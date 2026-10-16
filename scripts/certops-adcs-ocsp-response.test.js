"use strict";
// In-memory software signatures test public parsing only. No Microsoft
// responder, native CA, HTTP endpoint or qualification result is simulated.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const subject = require("../tests/e2e/helpers/certops-adcs-ocsp-response");
const {
  item,
  children,
} = require("../tests/e2e/helpers/certops-adcs-http-leaf-crl-der");
function der(tag, ...parts) {
  const body = Buffer.concat(parts);
  let length = Buffer.from([body.length]);
  if (body.length >= 128) {
    let hex = body.length.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    const value = Buffer.from(hex, "hex");
    length = Buffer.concat([Buffer.from([128 + value.length]), value]);
  }
  return Buffer.concat([Buffer.from([tag]), length, body]);
}
const seq = (...parts) => der(0x30, ...parts);
const algorithm = Buffer.from("300d06092a864886f70d01010b0500", "hex");
const pairs = Array.from({ length: 3 }, () =>
  crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }),
);
const name = (text) =>
  seq(
    der(
      0x31,
      seq(Buffer.from("0603550403", "hex"), der(0x0c, Buffer.from(text))),
    ),
  );
const caName = name("Software OCSP CA");
const generalized = (value) =>
  der(
    0x18,
    Buffer.from(
      new Date(value)
        .toISOString()
        .replace(/[-:T]/g, "")
        .replace(/\.\d{3}Z$/, "Z"),
    ),
  );
const utc = (value) => der(0x17, generalized(value).subarray(4));
const extension = (oidHex, content) =>
  seq(Buffer.from(oidHex, "hex"), der(0x04, content));
function certificate(
  index,
  { noCheck = true, eku = "06082b06010505070309", additional = [] } = {},
) {
  const now = Date.now(),
    ca = index === 0;
  const extensions = [
    seq(
      Buffer.from("0603551d130101ff", "hex"),
      der(0x04, ca ? seq(Buffer.from([1, 1, 255])) : seq()),
    ),
  ];
  if (!ca)
    extensions.push(extension("0603551d0f", Buffer.from([3, 2, 7, 128])));
  if (index === 1) {
    extensions.push(extension("0603551d25", seq(Buffer.from(eku, "hex"))));
    if (noCheck)
      extensions.push(extension("06092b0601050507300105", Buffer.from([5, 0])));
  }
  extensions.push(...additional);
  const tbs = seq(
    Buffer.from([0xa0, 3, 2, 1, 2]),
    der(2, Buffer.from([index + 1])),
    algorithm,
    caName,
    seq(utc(now - 86400000), utc(now + 7 * 86400000)),
    ca
      ? caName
      : name(index === 1 ? "Software delegated signer" : "Software owned leaf"),
    pairs[index].publicKey.export({ type: "spki", format: "der" }),
    der(0xa3, seq(...extensions)),
  );
  return seq(
    tbs,
    algorithm,
    der(3, Buffer.from([0]), crypto.sign("sha256", tbs, pairs[0].privateKey)),
  );
}
const issuerBytes = certificate(0),
  signerBytes = certificate(1),
  leafBytes = certificate(2);
const pin = crypto
  .createHash("sha256")
  .update(pairs[0].publicKey.export({ type: "spki", format: "der" }))
  .digest("hex");
const options = {
  issuerBytes,
  signerBytes,
  leafBytes,
  expectedCaKeySha256: pin,
};
test("nonce-free public request binds exact issuer hashes and actual positive serial", () => {
  const request = subject.createRequest(leafBytes, issuerBytes);
  const tbs = children(item(request));
  assert.equal(tbs.length, 1);
  const list = children(tbs[0]);
  assert.equal(list.length, 1);
  const requests = children(list[0]);
  assert.equal(requests.length, 1);
  const certId = children(children(requests[0])[0]);
  assert.equal(certId.length, 4);
  const parts = subject.certificateParts(
    new crypto.X509Certificate(issuerBytes),
  );
  assert.ok(
    certId[1].value.equals(
      crypto.createHash("sha1").update(parts.subject).digest(),
    ),
  );
  assert.ok(
    certId[2].value.equals(
      crypto.createHash("sha1").update(parts.publicBits).digest(),
    ),
  );
  assert.equal(subject.serial(certId[3]), "3");
  assert.throws(() => subject.createRequest(leafBytes, signerBytes));
});
const bits = (pair) =>
  children(
    item(pair.publicKey.export({ type: "spki", format: "der" })),
  )[1].value.subarray(1);
const sha1 = (bytes) => crypto.createHash("sha1").update(bytes).digest();
function response({
  status = "good",
  number = 3,
  next = Date.now() + 3600000,
  issuerHash = sha1(caName),
  keyHash = sha1(bits(pairs[0])),
  signerHash = sha1(bits(pairs[1])),
} = {}) {
  const now = Date.now();
  const id = seq(
    Buffer.from("300906052b0e03021a0500", "hex"),
    der(4, issuerHash),
    der(4, keyHash),
    der(2, Buffer.from([number])),
  );
  const state =
    status === "revoked"
      ? der(0xa1, generalized(now - 60000))
      : der(status === "good" ? 0x80 : 0x82);
  const data = seq(
    der(0xa2, der(4, signerHash)),
    generalized(now - 1000),
    seq(seq(id, state, generalized(now - 30000), der(0xa0, generalized(next)))),
  );
  const basic = seq(
    data,
    algorithm,
    der(3, Buffer.from([0]), crypto.sign("sha256", data, pairs[1].privateKey)),
    der(0xa0, seq(signerBytes)),
  );
  return seq(
    Buffer.from([0x0a, 1, 0]),
    der(0xa0, seq(Buffer.from("06092b0601050507300101", "hex"), der(4, basic))),
  );
}

test("public OCSP facts require actual delegated signatures and exact issuer/certificate identity", () => {
  for (const status of ["good", "revoked", "unknown"]) {
    const result = subject.verifyResponse(response({ status }), options);
    assert.equal(result.status, status);
    assert.equal(result.serialNumber, "3");
    assert.equal(result.issuerKeySha256, pin);
  }
  for (const patch of [
    { number: 4 },
    { issuerHash: Buffer.alloc(20) },
    { keyHash: Buffer.alloc(20) },
    { signerHash: Buffer.alloc(20) },
    { next: Date.now() - 1000 },
  ])
    assert.throws(() => subject.verifyResponse(response(patch), options));
});

test("signature tampering, wrong signer purpose, missing no-check and broader CA pin fail closed", () => {
  assert.equal(
    subject.verifySignerCertificate(
      options.signerBytes,
      options.issuerBytes,
      options.expectedCaKeySha256,
    ).issuerKeySha256,
    options.expectedCaKeySha256,
  );
  assert.throws(() =>
    subject.verifySignerCertificate(
      Buffer.concat([options.signerBytes, Buffer.from([0])]),
      options.issuerBytes,
      options.expectedCaKeySha256,
    ),
  );
  const bytes = response(),
    top = children(item(bytes));
  const encoded = children(item(top[1].value)),
    basic = children(item(encoded[1].value));
  const signature = Buffer.from(basic[2].raw);
  signature[signature.length - 1] ^= 1;
  const tampered = seq(basic[0].raw, basic[1].raw, signature, basic[3].raw);
  const altered = seq(
    top[0].raw,
    der(0xa0, seq(encoded[0].raw, der(4, tampered))),
  );
  assert.throws(() => subject.verifyResponse(altered, options));
  for (const signer of [
    certificate(1, { noCheck: false }),
    certificate(1, {
      noCheck: false,
      additional: [
        seq(
          Buffer.from("06092b0601050507300105", "hex"),
          Buffer.from([1, 1, 255]),
          der(4, Buffer.from([5, 0])),
        ),
      ],
    }),
    certificate(1, { eku: "06082b06010505070301" }),
    issuerBytes,
  ])
    assert.throws(() =>
      subject.verifyResponse(bytes, { ...options, signerBytes: signer }),
    );
  assert.throws(() =>
    subject.verifyResponse(bytes, {
      ...options,
      leafBytes: Buffer.concat([options.leafBytes, Buffer.from([0])]),
    }),
  );
  assert.throws(() =>
    subject.verifyResponse(bytes, {
      ...options,
      expectedCaKeySha256: "0".repeat(64),
    }),
  );
  for (const invalid of [
    bytes.subarray(0, -1),
    Buffer.concat([bytes, Buffer.from([0])]),
    Buffer.alloc(1048577),
  ])
    assert.throws(() => subject.verifyResponse(invalid, options));
});

test("native OCSP-only leaf facts refuse CRL fallback, no-check and alternate responders", () => {
  const { encodeOid } = require("../packages/agent/src/issuers/der-extensions");
  const templateOid = "1.3.6.1.4.1.311.21.8.12345.67890";
  const nativeTemplate = extension(
    "06092b0601040182371507",
    seq(der(6, encodeOid(templateOid)), der(2, Buffer.from([100]))),
  );
  const signer = certificate(1, { additional: [nativeTemplate] });
  assert.equal(subject.verifySignerTemplate(signer, templateOid), true);
  assert.throws(() => subject.verifySignerTemplate(signer, templateOid + ".1"));
  assert.throws(() =>
    subject.verifySignerTemplate(certificate(1), templateOid),
  );
  const url = "http://10.64.0.4/ocsp";
  const aia = (...urls) =>
    extension(
      "06082b06010505070101",
      seq(
        ...urls.map((value) =>
          seq(
            Buffer.from("06082b06010505073001", "hex"),
            der(0x86, Buffer.from(value, "ascii")),
          ),
        ),
      ),
    );
  const leaf = certificate(2, { additional: [aia(url)] });
  assert.equal(subject.assertOcspOnlyLeaf(leaf, url), true);
  assert.deepEqual(subject.ocspUrls(leaf), [url]);
  for (const additional of [
    [],
    [aia(url, "http://10.64.0.4/other")],
    [aia(url), extension("0603551d1f", seq())],
    [aia(url), extension("0603551d2e", seq())],
    [aia(url), extension("06092b0601050507300105", Buffer.from([5, 0]))],
  ])
    assert.throws(() =>
      subject.assertOcspOnlyLeaf(certificate(2, { additional }), url),
    );
  for (const invalid of [
    "http://10.64.0.5/ocsp",
    "http://10.64.0.4/ocsp?other=1",
    "http://user@10.64.0.4/ocsp",
    "http://10.64.0.4:8080/ocsp",
  ])
    assert.throws(() => subject.assertOcspOnlyLeaf(leaf, invalid));
});

test("native signer template requests the documented no-check flag without autoenrollment", () => {
  const source = fs.readFileSync(
    path.join(__dirname, "../infra/certops-adcs/ocsp-responder-fixture.ps1"),
    "utf8",
  );
  const flags = source.match(
    /'msPKI-Enrollment-Flag'\s*=\s*(0x[0-9a-f]+|\d+)\s*(?:;|\r?\n)/i,
  );
  assert.ok(flags, "Native signer enrollment flags must be explicit");
  // Microsoft MS-CRTD 2.26 defines ADD_OCSP_NOCHECK=0x1000 and
  // NOREVOCATIONINFOINISSUEDCERTS=0x4000. They are not interchangeable.
  assert.equal(Number(flags[1]), 0x1000);
  const declaredRange = source.match(
    /\[ValidateRange\(1,\s*(\d+)\)\]\[int\]\$TimeoutSeconds/,
  );
  assert.ok(
    declaredRange,
    "Contained command timeout unit must remain explicit",
  );
  const calls = [...source.matchAll(/\$Owner\.directory\s+(\d+)\)/g)];
  assert.ok(calls.length >= 5, "Actual native command sites must be checked");
  for (const call of calls)
    assert.ok(
      Number(call[1]) >= 1 && Number(call[1]) <= Number(declaredRange[1]),
      "Native command callsite must pass bounded seconds, not milliseconds",
    );
});

test("signer deletion remains behind fresh stopped consumers and complete native survivor scan", () => {
  const source = fs.readFileSync(
    path.join(__dirname, "../infra/certops-adcs/ocsp-responder-fixture.ps1"),
    "utf8",
  );
  const body = source.slice(
    source.indexOf("function Remove-OwnedOcspSigner("),
    source.indexOf("function Remove-OwnedOcspConfiguration("),
  );
  function verifyOrder(value) {
    const firstGuard = value.indexOf("Assert-OwnedOcspStoppedConsumers ");
    const daclRestore = value.indexOf("Restore-OwnedOcspKeyDacl ");
    const publicRemoval = value.indexOf(
      "Remove-Item -LiteralPath $certificatePath",
    );
    const scan = value.indexOf("$scan=Invoke-OwnedOcspSurvivorCapture ");
    const secondGuard = value.indexOf(
      "Assert-OwnedOcspStoppedConsumers ",
      firstGuard + 1,
    );
    const keyDeletion = value.indexOf("$key.Delete()");
    assert.ok(firstGuard >= 0 && firstGuard < daclRestore);
    assert.ok(daclRestore < publicRemoval);
    assert.ok(publicRemoval < scan && scan < secondGuard);
    assert.ok(secondGuard < keyDeletion);
  }
  verifyOrder(body);
  assert.throws(() =>
    verifyOrder(
      body.replace(
        /\$scan=Invoke-OwnedOcspSurvivorCapture[^\r\n]+\r?\n\s*Assert-OwnedOcspStoppedConsumers[^\r\n]+/,
        "$scan=Invoke-OwnedOcspSurvivorCapture",
      ),
    ),
  );
});

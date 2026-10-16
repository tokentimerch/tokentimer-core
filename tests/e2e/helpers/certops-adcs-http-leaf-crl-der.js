"use strict";
/** Bounded public DER validation before an owned fixture serves CA CRL bytes.
 * This does not replace the actual Windows chain verdict. It independently
 * checks the original CA pin, CRL issuer, SHA256/RSA signature and current dates.
 * The qualification CA is explicitly RSA/SHA256; unsupported algorithms refuse.
 */
const assert = require("node:assert/strict"),
  crypto = require("node:crypto");
const SHA256_RSA = Buffer.from("300d06092a864886f70d01010b0500", "hex");
function item(bytes, offset = 0) {
  assert.ok(
    Buffer.isBuffer(bytes) && offset >= 0 && offset + 2 <= bytes.length,
    "Bounded DER item required",
  );
  const tag = bytes[offset];
  assert.ok((tag & 31) !== 31, "High-tag DER is outside this fixture contract");
  let cursor = offset + 1,
    length = bytes[cursor++];
  if (length & 128) {
    const count = length & 127;
    assert.ok(
      count > 0 &&
        count <= 4 &&
        cursor + count <= bytes.length &&
        bytes[cursor] !== 0,
      "Canonical finite DER length required",
    );
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + bytes[cursor++];
    assert.ok(length >= 128, "Nonminimal DER length refused");
  }
  const end = cursor + length;
  assert.ok(end <= bytes.length, "Truncated DER item refused");
  return {
    tag,
    start: offset,
    end,
    raw: bytes.subarray(offset, end),
    value: bytes.subarray(cursor, end),
  };
}
function children(node) {
  assert.equal(node.tag, 0x30, "DER sequence required");
  const result = [];
  let cursor = 0;
  while (cursor < node.value.length) {
    assert.ok(result.length < 2048, "Bounded DER child count required");
    const child = item(node.value, cursor);
    result.push(child);
    cursor = child.end;
  }
  return result;
}
function timestamp(node) {
  assert.ok(node.tag === 0x17 || node.tag === 0x18, "CRL timestamp required");
  const text = node.value.toString("ascii");
  let year, tail;
  if (node.tag === 0x17) {
    assert.match(text, /^[0-9]{12}Z$/);
    const short = Number(text.slice(0, 2));
    year = short >= 50 ? 1900 + short : 2000 + short;
    tail = text.slice(2, -1);
  } else {
    assert.match(text, /^[0-9]{14}Z$/);
    year = Number(text.slice(0, 4));
    tail = text.slice(4, -1);
  }
  const parts = [year, ...tail.match(/../g).map(Number)],
    date = new Date(Date.UTC(parts[0], parts[1] - 1, ...parts.slice(2)));
  assert.deepEqual(
    [
      date.getUTCFullYear(),
      date.getUTCMonth() + 1,
      date.getUTCDate(),
      date.getUTCHours(),
      date.getUTCMinutes(),
      date.getUTCSeconds(),
    ],
    parts,
    "Canonical real CRL date required",
  );
  return date.getTime();
}
function verifyCrl(crlBytes, caBytes, expectedCaKeySha256) {
  for (const bytes of [crlBytes, caBytes])
    assert.ok(
      Buffer.isBuffer(bytes) && bytes.length >= 100 && bytes.length <= 1048576,
      "Bounded public CRL/CA bytes required",
    );
  assert.match(expectedCaKeySha256, /^[a-f0-9]{64}$/);
  const ca = new crypto.X509Certificate(caBytes);
  assert.equal(ca.ca, true, "Actual issuing CA certificate required");
  const key = ca.publicKey;
  assert.equal(key.asymmetricKeyType, "rsa");
  assert.equal(
    crypto
      .createHash("sha256")
      .update(key.export({ type: "spki", format: "der" }))
      .digest("hex"),
    expectedCaKeySha256,
    "Original issuing CA pin mismatch",
  );
  const cert = item(ca.raw);
  assert.equal(cert.end, ca.raw.length);
  const certFields = children(children(cert)[0]);
  const subject = certFields[certFields[0].tag === 0xa0 ? 5 : 4];
  assert.equal(subject.tag, 0x30);
  const outer = item(crlBytes);
  assert.equal(outer.end, crlBytes.length, "Trailing CRL bytes refused");
  const fields = children(outer);
  assert.equal(fields.length, 3);
  const [tbs, algorithm, signature] = fields;
  assert.ok(
    algorithm.raw.equals(SHA256_RSA),
    "Owned qualification CA SHA256/RSA CRL required",
  );
  const body = children(tbs),
    index = body[0].tag === 0x02 ? 1 : 0;
  if (index)
    assert.ok(
      body[0].value.equals(Buffer.from([1])),
      "Only v2 CRL version supported",
    );
  assert.ok(
    body[index].raw.equals(algorithm.raw),
    "Inner/outer CRL signature algorithm differs",
  );
  assert.ok(
    body[index + 1].raw.equals(subject.raw),
    "CRL issuer differs from original issuing CA",
  );
  const thisUpdate = timestamp(body[index + 2]),
    nextUpdate = timestamp(body[index + 3]),
    now = Date.now();
  assert.ok(
    thisUpdate <= now && nextUpdate > now + 1800000 && nextUpdate > thisUpdate,
    "Current CRL must cover the bounded native fault journey",
  );
  assert.equal(signature.tag, 0x03);
  assert.ok(
    signature.value.length > 1 && signature.value[0] === 0,
    "Canonical CRL signature bit string required",
  );
  assert.equal(
    crypto.verify("sha256", tbs.raw, key, signature.value.subarray(1)),
    true,
    "Actual issuing CA CRL signature invalid",
  );
  return {
    sha256: crypto.createHash("sha256").update(crlBytes).digest("hex"),
    thisUpdate: new Date(thisUpdate).toISOString(),
    nextUpdate: new Date(nextUpdate).toISOString(),
  };
}
function assertHttpOnlyLeafCdp(certificateBytes, expectedUrl) {
  const url = new URL(expectedUrl);
  assert.equal(url.protocol, "http:");
  assert.equal(url.hostname, "10.64.0.6");
  assert.ok(Number(url.port) >= 1024 && Number(url.port) <= 65535);
  assert.equal(url.pathname, "/TTQualificationRoot.crl");
  for (const field of ["search", "hash", "username", "password"])
    assert.equal(url[field], "");
  assert.equal(url.href, expectedUrl);
  const extensions =
    require("../../../packages/agent/src/issuers/der-extensions")
      .listCertificateExtensions(certificateBytes)
      .filter((extension) => extension.oid === "2.5.29.31");
  assert.equal(
    extensions.length,
    1,
    "Exactly one native leaf CDP extension required",
  );
  const outer = item(extensions[0].value);
  assert.equal(outer.end, extensions[0].value.length);
  const points = children(outer);
  assert.equal(points.length, 1, "Alternate leaf distribution points refused");
  const point = children(points[0]);
  assert.equal(point.length, 1, "Scoped or alternate CRL issuer refused");
  assert.equal(point[0].tag, 0xa0);
  const fullName = item(point[0].value);
  assert.equal(fullName.tag, 0xa0);
  assert.equal(fullName.end, point[0].value.length);
  const uri = item(fullName.value);
  assert.equal(uri.tag, 0x86, "Leaf CDP must contain only one URI GeneralName");
  assert.equal(uri.end, fullName.value.length);
  assert.ok(
    uri.value.equals(Buffer.from(expectedUrl, "ascii")),
    "Leaf CDP differs from exact owned HTTP endpoint",
  );
  return true;
}
module.exports = {
  item,
  children,
  timestamp,
  verifyCrl,
  assertHttpOnlyLeafCdp,
};

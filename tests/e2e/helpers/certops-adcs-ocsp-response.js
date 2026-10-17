"use strict";
/* Public response inspection for the planned real Microsoft Online Responder
 * fixture. Revoked, good, and unknown are parsed here; authoritative revoked
 * status is a separate proof. Native lab execution is still pending.
 * This is NOT a responder, an HTTP interception or a chain verdict.
 * Node crypto uses OpenSSL for independent signature verification over the
 * exact received bytes. The caller must also obtain the actual CryptoAPI chain
 * verdict and bind the signer to the owned native responder configuration.
 * Only the fixture's RSA/SHA256 signer and one exact issued certificate qualify.
 */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const {
  item,
  children,
  timestamp,
} = require("./certops-adcs-http-leaf-crl-der");
const {
  decodeOid,
  listCertificateExtensions,
  readExtKeyUsageOids,
  readKeyUsageNames,
  readCertificateTemplateOid,
} = require("../../../packages/agent/src/issuers/der-extensions");
const SHA256_RSA = Buffer.from("300d06092a864886f70d01010b0500", "hex");
const hash = (name, bytes) => crypto.createHash(name).update(bytes).digest();

function encode(tag, ...parts) {
  const body = Buffer.concat(parts);
  assert.ok(body.length <= 4096);
  let size = Buffer.from([body.length]);
  if (body.length >= 128) {
    let hex = body.length.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    const value = Buffer.from(hex, "hex");
    size = Buffer.concat([Buffer.from([0x80 | value.length]), value]);
  }
  return Buffer.concat([Buffer.from([tag]), size, body]);
}

// A public, nonce-free RFC 6960 request. This does not create a responder or
// manufacture a status: only the received native responder's signed bytes can
// satisfy verifyResponse. SHA-1 here is the CertID lookup hash, not a signature.
function createRequest(leafBytes, issuerBytes) {
  const leaf = new crypto.X509Certificate(leafBytes);
  const issuer = new crypto.X509Certificate(issuerBytes);
  assert.ok(leaf.raw.equals(leafBytes) && issuer.raw.equals(issuerBytes));
  assert.ok(issuer.ca && !leaf.ca && leaf.verify(issuer.publicKey));
  const issuerParts = certificateParts(issuer);
  const fields = children(children(item(leaf.raw))[0]);
  const serialNode = fields[fields[0].tag === 0xa0 ? 1 : 0];
  serial(serialNode);
  const certId = encode(
    0x30,
    Buffer.from("300906052b0e03021a0500", "hex"),
    encode(0x04, hash("sha1", issuerParts.subject)),
    encode(0x04, hash("sha1", issuerParts.publicBits)),
    serialNode.raw,
  );
  return encode(0x30, encode(0x30, encode(0x30, encode(0x30, certId))));
}

function explicit(node, tag) {
  assert.equal(node.tag, tag);
  const inner = item(node.value);
  assert.equal(
    inner.end,
    node.value.length,
    "Trailing explicit OCSP value refused",
  );
  return inner;
}

function certificateParts(certificate) {
  const fields = children(children(item(certificate.raw))[0]);
  const versioned = fields[0].tag === 0xa0;
  const subject = fields[versioned ? 5 : 4];
  const spki = fields[versioned ? 6 : 5];
  assert.equal(subject.tag, 0x30);
  const publicBits = children(spki)[1];
  assert.equal(publicBits.tag, 0x03);
  assert.equal(publicBits.value[0], 0);
  return { subject: subject.raw, publicBits: publicBits.value.subarray(1) };
}

function ocspUrls(certificateBytes) {
  assert.ok(
    Buffer.isBuffer(certificateBytes) &&
      certificateBytes.length >= 100 &&
      certificateBytes.length <= 1048576,
  );
  const certificate = item(certificateBytes);
  assert.equal(certificate.tag, 0x30);
  assert.equal(certificate.end, certificateBytes.length);
  assert.ok(
    new crypto.X509Certificate(certificateBytes).raw.equals(certificateBytes),
  );
  const extensions = listCertificateExtensions(certificateBytes).filter(
    (extension) => extension.oid === "1.3.6.1.5.5.7.1.1",
  );
  assert.ok(extensions.length <= 1, "Duplicate native AIA extensions refused");
  if (!extensions.length) return [];
  assert.equal(extensions[0].critical, false);
  const outer = item(extensions[0].value);
  assert.equal(outer.tag, 0x30);
  assert.equal(outer.end, extensions[0].value.length);
  const descriptions = children(outer);
  assert.ok(descriptions.length >= 1 && descriptions.length <= 16);
  const urls = [];
  for (const description of descriptions) {
    const fields = children(description);
    assert.equal(fields.length, 2);
    assert.equal(fields[0].tag, 0x06);
    const method = decodeOid(fields[0].value);
    assert.ok(
      ["1.3.6.1.5.5.7.48.1", "1.3.6.1.5.5.7.48.2"].includes(method),
      "Unsupported native authority access method",
    );
    assert.equal(fields[1].tag, 0x86);
    assert.ok(fields[1].value.length >= 1 && fields[1].value.length <= 4096);
    assert.ok(
      [...fields[1].value].every((value) => value >= 0x21 && value <= 0x7e),
      "Noncanonical native authority URI refused",
    );
    if (method === "1.3.6.1.5.5.7.48.1")
      urls.push(fields[1].value.toString("ascii"));
  }
  return urls;
}

function assertOcspOnlyLeaf(certificateBytes, expectedUrl) {
  const url = new URL(expectedUrl);
  assert.equal(url.href, expectedUrl);
  assert.equal(url.protocol, "http:");
  assert.equal(url.hostname, "10.64.0.4");
  assert.equal(url.pathname, "/ocsp");
  for (const field of ["port", "search", "hash", "username", "password"])
    assert.equal(url[field], "");
  const extensions = listCertificateExtensions(certificateBytes);
  assert.equal(
    extensions.some((extension) =>
      ["2.5.29.31", "2.5.29.46", "1.3.6.1.5.5.7.48.1.5"].includes(
        extension.oid,
      ),
    ),
    false,
    "Alternate leaf CRL retrieval or leaf no-check refused",
  );
  assert.deepEqual(ocspUrls(certificateBytes), [expectedUrl]);
  return true;
}

function serial(node) {
  assert.equal(node.tag, 0x02);
  assert.ok(node.value.length > 0 && node.value.length <= 21);
  assert.equal(node.value[0] & 0x80, 0, "Negative certificate serial refused");
  if (node.value.length > 1 && node.value[0] === 0)
    assert.ok(node.value[1] & 0x80, "Noncanonical serial refused");
  const value = node.value.toString("hex").replace(/^0+/, "").toUpperCase();
  assert.ok(value.length > 0 && value.length <= 40);
  return value;
}

function noncriticalExtensions(node, tag) {
  const extensions = children(explicit(node, tag));
  assert.ok(extensions.length > 0 && extensions.length <= 8);
  const seen = new Set();
  for (const extension of extensions) {
    const fields = children(extension);
    assert.equal(
      fields.length,
      2,
      "Critical or malformed OCSP extension refused",
    );
    assert.equal(fields[0].tag, 0x06);
    const oid = decodeOid(fields[0].value);
    assert.equal(
      oid,
      "1.3.6.1.5.5.7.48.1.9",
      "Unexpected OCSP extension refused",
    );
    assert.equal(seen.has(oid), false);
    seen.add(oid);
    assert.equal(fields[1].tag, 0x04);
    assert.ok(fields[1].value.equals(Buffer.from([0x05, 0x00])));
  }
}

function verifySignerCertificate(
  signerBytes,
  issuerBytes,
  expectedCaKeySha256,
) {
  for (const value of [issuerBytes, signerBytes])
    assert.ok(
      Buffer.isBuffer(value) && value.length >= 100 && value.length <= 1048576,
    );
  const issuer = new crypto.X509Certificate(issuerBytes);
  const signer = new crypto.X509Certificate(signerBytes);
  assert.ok(issuer.raw.equals(issuerBytes) && signer.raw.equals(signerBytes));
  const now = Date.now();
  assert.equal(issuer.ca, true);
  assert.equal(signer.ca, false);
  for (const cert of [issuer, signer])
    assert.ok(
      Date.parse(cert.validFrom) <= now && Date.parse(cert.validTo) > now,
      "Actual OCSP certificates must be current",
    );
  assert.equal(signer.checkIssued(issuer), true);
  assert.equal(signer.verify(issuer.publicKey), true);
  assert.equal(signer.publicKey.asymmetricKeyType, "rsa");
  const issuerSpki = issuer.publicKey.export({ type: "spki", format: "der" });
  const signerSpki = signer.publicKey.export({ type: "spki", format: "der" });
  assert.match(expectedCaKeySha256, /^[a-f0-9]{64}$/);
  assert.equal(hash("sha256", issuerSpki).toString("hex"), expectedCaKeySha256);
  assert.equal(
    issuerSpki.equals(signerSpki),
    false,
    "A delegated signer must not borrow the CA key",
  );
  assert.deepEqual(readExtKeyUsageOids(signer.raw), ["1.3.6.1.5.5.7.3.9"]);
  assert.deepEqual(readKeyUsageNames(signer.raw), ["digitalSignature"]);
  const noCheck = listCertificateExtensions(signer.raw).filter(
    (extension) => extension.oid === "1.3.6.1.5.5.7.48.1.5",
  );
  assert.equal(noCheck.length, 1);
  assert.equal(noCheck[0].critical, false);
  assert.ok(noCheck[0].value.equals(Buffer.from([0x05, 0x00])));
  return {
    signerFingerprint: signer.fingerprint256.replace(/:/g, "").toLowerCase(),
    issuerKeySha256: expectedCaKeySha256,
  };
}

function verifySignerTemplate(signerBytes, expectedTemplateOid) {
  assert.match(expectedTemplateOid, /^1\.3\.6\.1\.4\.1\.311\.21\.8(?:\.\d+)+$/);
  assert.ok(Buffer.isBuffer(signerBytes) && signerBytes.length <= 1048576);
  const signer = new crypto.X509Certificate(signerBytes);
  assert.ok(signer.raw.equals(signerBytes));
  assert.equal(readCertificateTemplateOid(signer.raw), expectedTemplateOid);
  return true;
}

function verifyResponse(
  bytes,
  { leafBytes, issuerBytes, signerBytes, expectedCaKeySha256 },
) {
  verifySignerCertificate(signerBytes, issuerBytes, expectedCaKeySha256);
  for (const value of [bytes, leafBytes])
    assert.ok(
      Buffer.isBuffer(value) && value.length >= 100 && value.length <= 1048576,
    );
  const leaf = new crypto.X509Certificate(leafBytes);
  assert.ok(leaf.raw.equals(leafBytes));
  const issuer = new crypto.X509Certificate(issuerBytes);
  const signer = new crypto.X509Certificate(signerBytes);
  const now = Date.now();
  assert.ok(
    Date.parse(leaf.validFrom) <= now && Date.parse(leaf.validTo) > now,
  );
  assert.equal(leaf.checkIssued(issuer), true);
  assert.equal(leaf.verify(issuer.publicKey), true);

  const outer = item(bytes);
  assert.equal(outer.end, bytes.length);
  const response = children(outer);
  assert.equal(response.length, 2);
  assert.equal(response[0].tag, 0x0a);
  assert.ok(
    response[0].value.equals(Buffer.from([0])),
    "A successful real OCSP response is required",
  );
  const encoded = children(explicit(response[1], 0xa0));
  assert.equal(encoded.length, 2);
  assert.equal(encoded[0].tag, 0x06);
  assert.equal(decodeOid(encoded[0].value), "1.3.6.1.5.5.7.48.1.1");
  assert.equal(encoded[1].tag, 0x04);
  const basicNode = item(encoded[1].value);
  assert.equal(basicNode.end, encoded[1].value.length);
  const basic = children(basicNode);
  assert.ok(basic.length === 3 || basic.length === 4);
  const [data, algorithm, signature] = basic;
  assert.ok(
    algorithm.raw.equals(SHA256_RSA),
    "Native responder SHA256/RSA required",
  );
  assert.equal(signature.tag, 0x03);
  assert.equal(signature.value[0], 0);
  assert.equal(
    crypto.verify(
      "sha256",
      data.raw,
      signer.publicKey,
      signature.value.subarray(1),
    ),
    true,
    "Actual OCSP response signature refused",
  );
  if (basic[3]) {
    const embedded = children(explicit(basic[3], 0xa0));
    assert.ok(embedded.length > 0 && embedded.length <= 2);
    assert.ok(
      embedded.some((cert) => cert.raw.equals(signer.raw)),
      "Actual delegated signer missing from response",
    );
    assert.ok(
      embedded.every(
        (cert) => cert.raw.equals(signer.raw) || cert.raw.equals(issuer.raw),
      ),
      "Unexpected embedded OCSP certificate refused",
    );
  }
  const fields = children(data);
  if (fields[0].tag === 0xa0) {
    const version = explicit(fields.shift(), 0xa0);
    assert.equal(version.tag, 0x02);
    assert.ok(version.value.equals(Buffer.from([0])));
  }
  assert.ok(fields.length === 3 || fields.length === 4);
  const keyHash = explicit(fields[0], 0xa2);
  assert.equal(keyHash.tag, 0x04);
  assert.ok(
    keyHash.value.equals(hash("sha1", certificateParts(signer).publicBits)),
    "Actual OCSP responder ID mismatch",
  );
  assert.equal(fields[1].tag, 0x18);
  const producedAt = timestamp(fields[1]);
  const answers = children(fields[2]);
  assert.equal(
    answers.length,
    1,
    "Only the exact owned leaf response is admitted",
  );
  const answer = children(answers[0]);
  assert.ok(answer.length === 4 || answer.length === 5);
  const certId = children(answer[0]);
  assert.equal(certId.length, 4);
  const idAlgorithm = children(certId[0]);
  assert.ok(idAlgorithm.length === 1 || idAlgorithm.length === 2);
  assert.equal(idAlgorithm[0].tag, 0x06);
  if (idAlgorithm[1])
    assert.ok(idAlgorithm[1].raw.equals(Buffer.from([0x05, 0x00])));
  const idHash = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
  }[decodeOid(idAlgorithm[0].value)];
  assert.ok(idHash, "Unsupported OCSP CertID hash refused");
  const original = certificateParts(issuer);
  assert.equal(certId[1].tag, 0x04);
  assert.equal(certId[2].tag, 0x04);
  assert.ok(certId[1].value.equals(hash(idHash, original.subject)));
  assert.ok(certId[2].value.equals(hash(idHash, original.publicBits)));
  const serialNumber = serial(certId[3]);
  assert.equal(
    serialNumber,
    leaf.serialNumber.replace(/^0+/, "").toUpperCase(),
  );
  let status, revocationTime;
  if (answer[1].tag === 0x80 || answer[1].tag === 0x82) {
    assert.equal(answer[1].value.length, 0);
    status = answer[1].tag === 0x80 ? "good" : "unknown";
  } else {
    assert.equal(answer[1].tag, 0xa1);
    const revoked = children({ tag: 0x30, value: answer[1].value });
    assert.ok(revoked.length === 1 || revoked.length === 2);
    assert.equal(revoked[0].tag, 0x18);
    revocationTime = timestamp(revoked[0]);
    assert.ok(revocationTime <= producedAt && revocationTime <= now);
    if (revoked[1]) {
      const reason = explicit(revoked[1], 0xa0);
      assert.equal(reason.tag, 0x0a);
      assert.ok(
        reason.value.length === 1 &&
          [0, 1, 2, 3, 4, 5, 6, 8, 9, 10].includes(reason.value[0]),
      );
    }
    status = "revoked";
  }
  assert.equal(answer[2].tag, 0x18);
  const thisUpdate = timestamp(answer[2]);
  const next = explicit(answer[3], 0xa0);
  assert.equal(next.tag, 0x18);
  const nextUpdate = timestamp(next);
  assert.ok(
    thisUpdate <= producedAt &&
      producedAt <= now &&
      nextUpdate > now + 60000 &&
      producedAt < nextUpdate,
    "Stale or future OCSP status refused",
  );
  if (answer[4]) noncriticalExtensions(answer[4], 0xa1);
  if (fields[3]) noncriticalExtensions(fields[3], 0xa1);
  return {
    status,
    ...(revocationTime !== undefined
      ? { revocationTime: new Date(revocationTime).toISOString() }
      : {}),
    serialNumber,
    producedAt: new Date(producedAt).toISOString(),
    thisUpdate: new Date(thisUpdate).toISOString(),
    nextUpdate: new Date(nextUpdate).toISOString(),
    responseSha256: hash("sha256", bytes).toString("hex"),
    signerFingerprint: signer.fingerprint256.replace(/:/g, "").toLowerCase(),
    issuerKeySha256: expectedCaKeySha256,
  };
}

module.exports = {
  createRequest,
  verifyResponse,
  verifySignerCertificate,
  verifySignerTemplate,
  certificateParts,
  serial,
  ocspUrls,
  assertOcspOnlyLeaf,
};

"use strict";
const crypto = require("node:crypto");

// RFC 7292, one encrypted PKCS#8 key bag plus certificate bags. Uses the
// platform's PKCS#8 encryption (PBES2/AES-256) and password integrity. This is
// strictly a customer-local import format, never a wire/control-plane type.
function der(tag, ...parts) {
  const value = Buffer.concat(parts);
  let length = Buffer.from([value.length]);
  if (value.length > 127) {
    let hex = value.length.toString(16);
    if (hex.length % 2) hex = `0${hex}`;
    const bytes = Buffer.from(hex, "hex");
    length = Buffer.concat([Buffer.from([0x80 | bytes.length]), bytes]);
  }
  return Buffer.concat([Buffer.from([tag]), length, value]);
}
const seq = (...values) => der(0x30, ...values);
const octet = (value) => der(4, value);
function integer(value) {
  let hex = value.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  if (parseInt(hex.slice(0, 2), 16) > 127) hex = `00${hex}`;
  return der(2, Buffer.from(hex, "hex"));
}
function oid(value) {
  const numbers = value.split(".").map(Number);
  const bytes = [40 * numbers[0] + numbers[1]];
  for (const number of numbers.slice(2)) {
    let n = number;
    const segment = [n & 127];
    while ((n = Math.floor(n / 128)) > 0) segment.unshift((n & 127) | 128);
    bytes.push(...segment);
  }
  return der(6, Buffer.from(bytes));
}
function data(value) {
  return seq(oid("1.2.840.113549.1.7.1"), der(0xa0, octet(value)));
}
function macKey(password, salt, iterations) {
  const wide = Buffer.alloc((password.length + 1) * 2);
  for (let i = 0; i < password.length; i++)
    wide.writeUInt16BE(password.charCodeAt(i), i * 2);
  const expand = (value) =>
    Buffer.from(
      Array.from(
        { length: 64 * Math.ceil(value.length / 64) },
        (_, i) => value[i % value.length],
      ),
    );
  const input = Buffer.concat([expand(salt), expand(wide)]);
  const diversifier = Buffer.alloc(64, 3);
  let digest = Buffer.concat([diversifier, input]);
  for (let i = 0; i < iterations; i++)
    digest = crypto.createHash("sha256").update(digest).digest();
  wide.fill(0);
  input.fill(0);
  // Only one SHA-256 block is needed for the 32-byte HMAC key.
  return digest;
}
function makePkcs12(bundle, password) {
  const certs = bundle.certificatePem
    .match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)
    .map((pem) => new crypto.X509Certificate(pem).raw);
  // PKCS#12 localKeyId pairs the leaf/key bags using the Windows thumbprint
  // convention. It is an interoperability label, never an integrity check.
  // Bundle/native/TLS identity and signing proofs use SHA-256; the PFX MAC
  // below uses HMAC-SHA-256. Keep this identifier stable for CryptoAPI import.
  const id = crypto.createHash("sha1").update(certs[0]).digest();
  const attribute = der(
    0x31,
    seq(oid("1.2.840.113549.1.9.21"), der(0x31, octet(id))),
  );
  const encrypted = crypto
    .createPrivateKey(bundle.privateKeyPem)
    .export({
      type: "pkcs8",
      format: "der",
      cipher: "aes-256-cbc",
      passphrase: password,
    });
  try {
    const bags = [
      seq(oid("1.2.840.113549.1.12.10.1.2"), der(0xa0, encrypted), attribute),
      ...certs.map((cert, i) =>
        seq(
          oid("1.2.840.113549.1.12.10.1.3"),
          der(
            0xa0,
            seq(oid("1.2.840.113549.1.9.22.1"), der(0xa0, octet(cert))),
          ),
          ...(i === 0 ? [attribute] : []),
        ),
      ),
    ];
    const safe = seq(data(seq(...bags)));
    const salt = crypto.randomBytes(32),
      iterations = 100000;
    const key = macKey(password, salt, iterations);
    try {
      const mac = crypto.createHmac("sha256", key).update(safe).digest();
      return seq(
        integer(3),
        data(safe),
        seq(
          seq(
            seq(oid("2.16.840.1.101.3.4.2.1"), der(5, Buffer.alloc(0))),
            octet(mac),
          ),
          octet(salt),
          integer(iterations),
        ),
      );
    } finally {
      key.fill(0);
    }
  } finally {
    encrypted.fill(0);
  }
}
module.exports = { makePkcs12 };

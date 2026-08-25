"use strict";

// Minimal, dependency-free self-signed X.509 certificate generator for the
// proxy smoke test's local HTTPS target. Node's `crypto` module has no
// built-in "issue a certificate" API (only `X509Certificate` for parsing),
// and this repo has no `openssl` binary requirement for a dev/CI Node
// script, so this hand-rolls the small ASN.1 DER subset needed for a
// leaf certificate: SEQUENCE/SET/INTEGER/BIT STRING/OCTET STRING/OID/
// BOOLEAN/NULL/UTF8String/IA5String, context tags, and UTCTime.
//
// This is test-fixture-only code (see TEST-ONLY convention used elsewhere
// in this repo, e.g. packages/agent/src/verify/fixtures) and is not reused
// by any shipped runtime path.
const crypto = require("node:crypto");

function encodeLength(length) {
  if (length < 0x80) return Buffer.from([length]);
  const bytes = [];
  let remaining = length;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining = Math.floor(remaining / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag, content) {
  return Buffer.concat([Buffer.from([tag]), encodeLength(content.length), content]);
}

function derSequence(...parts) {
  return tlv(0x30, Buffer.concat(parts));
}

function derSet(...parts) {
  return tlv(0x31, Buffer.concat(parts));
}

function derInteger(value) {
  let buf;
  if (Buffer.isBuffer(value)) {
    buf = value;
  } else {
    const bytes = [];
    let n = value;
    if (n === 0) bytes.push(0);
    while (n > 0) {
      bytes.unshift(n & 0xff);
      n = Math.floor(n / 256);
    }
    buf = Buffer.from(bytes);
  }
  // Strip leading zero bytes (but keep at least one), then re-add a single
  // leading zero if the high bit is set so this isn't misread as negative.
  let start = 0;
  while (start < buf.length - 1 && buf[start] === 0x00 && (buf[start + 1] & 0x80) === 0) {
    start += 1;
  }
  buf = buf.subarray(start);
  if (buf[0] & 0x80) buf = Buffer.concat([Buffer.from([0x00]), buf]);
  return tlv(0x02, buf);
}

function derBitString(buf, unusedBits = 0) {
  return tlv(0x03, Buffer.concat([Buffer.from([unusedBits]), buf]));
}

function derOctetString(buf) {
  return tlv(0x04, buf);
}

function derNull() {
  return Buffer.from([0x05, 0x00]);
}

function derOid(oid) {
  const parts = oid.split(".").map(Number);
  const bytes = [parts[0] * 40 + parts[1]];
  for (let i = 2; i < parts.length; i += 1) {
    let value = parts[i];
    const chunk = [value & 0x7f];
    value = Math.floor(value / 128);
    while (value > 0) {
      chunk.unshift((value & 0x7f) | 0x80);
      value = Math.floor(value / 128);
    }
    bytes.push(...chunk);
  }
  return tlv(0x06, Buffer.from(bytes));
}

function derUtf8String(str) {
  return tlv(0x0c, Buffer.from(str, "utf8"));
}

function derBoolean(value) {
  return tlv(0x01, Buffer.from([value ? 0xff : 0x00]));
}

function derContext(tagNumber, content, { constructed = true } = {}) {
  const tag = (constructed ? 0xa0 : 0x80) | tagNumber;
  return tlv(tag, content);
}

function derUtcTime(date) {
  const pad = (n) => String(n).padStart(2, "0");
  const text =
    `${pad(date.getUTCFullYear() % 100)}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}` +
    `${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
  return tlv(0x17, Buffer.from(text, "ascii"));
}

const OID_COMMON_NAME = "2.5.4.3";
const OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11";
const OID_BASIC_CONSTRAINTS = "2.5.29.19";
const OID_KEY_USAGE = "2.5.29.15";
const OID_EXT_KEY_USAGE = "2.5.29.37";
const OID_SUBJECT_ALT_NAME = "2.5.29.17";
const OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";

function derName(commonName) {
  const attribute = derSequence(derOid(OID_COMMON_NAME), derUtf8String(commonName));
  return derSequence(derSet(attribute));
}

function signatureAlgorithmIdentifier() {
  return derSequence(derOid(OID_SHA256_WITH_RSA), derNull());
}

function derExtension(oid, critical, valueDer) {
  const parts = [derOid(oid)];
  if (critical) parts.push(derBoolean(true));
  parts.push(derOctetString(valueDer));
  return derSequence(...parts);
}

function buildExtensions({ dnsNames, ipAddresses }) {
  // basicConstraints: CA:FALSE (empty SEQUENCE = default cA=FALSE).
  const basicConstraints = derExtension(OID_BASIC_CONSTRAINTS, true, derSequence());

  // keyUsage: digitalSignature (bit 0) + keyEncipherment (bit 2) => 0xa0,
  // 5 unused bits in the trailing byte.
  const keyUsage = derExtension(
    OID_KEY_USAGE,
    true,
    derBitString(Buffer.from([0xa0]), 5),
  );

  const extKeyUsage = derExtension(
    OID_EXT_KEY_USAGE,
    false,
    derSequence(derOid(OID_SERVER_AUTH)),
  );

  const generalNames = [];
  for (const name of dnsNames) {
    // dNSName [2] IMPLICIT IA5String (primitive context tag wraps raw bytes).
    generalNames.push(derContext(2, Buffer.from(name, "ascii"), { constructed: false }));
  }
  for (const ip of ipAddresses) {
    // iPAddress [7] IMPLICIT OCTET STRING (raw 4-byte IPv4 address).
    const octets = Buffer.from(ip.split(".").map((part) => Number(part)));
    generalNames.push(derContext(7, octets, { constructed: false }));
  }
  const subjectAltName = derExtension(
    OID_SUBJECT_ALT_NAME,
    false,
    derSequence(...generalNames),
  );

  return derContext(3, derSequence(basicConstraints, keyUsage, extKeyUsage, subjectAltName));
}

/**
 * Generate a minimal self-signed RSA/SHA-256 X.509v3 certificate for local
 * test fixtures only. Not for any production or shipped code path.
 *
 * @param {{ commonName?: string, dnsNames?: string[], ipAddresses?: string[], days?: number }} [options]
 * @returns {{ certPem: string, keyPem: string }}
 */
function generateSelfSignedCert({
  commonName = "localhost",
  dnsNames = ["localhost"],
  ipAddresses = ["127.0.0.1"],
  days = 2,
} = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });

  const spkiDer = publicKey.export({ type: "spki", format: "der" });

  const now = new Date();
  const notBefore = new Date(now.getTime() - 5 * 60 * 1000);
  const notAfter = new Date(now.getTime() + days * 24 * 60 * 60 * 1000);

  const serial = crypto.randomBytes(8);
  serial[0] &= 0x7f;

  const issuerAndSubject = derName(commonName);
  const version = derContext(0, derInteger(2));
  const serialNumber = derInteger(serial);
  const signature = signatureAlgorithmIdentifier();
  const validity = derSequence(derUtcTime(notBefore), derUtcTime(notAfter));
  const extensions = buildExtensions({
    dnsNames,
    ipAddresses,
  });

  const tbsCertificate = derSequence(
    version,
    serialNumber,
    signature,
    issuerAndSubject,
    validity,
    issuerAndSubject,
    spkiDer,
    extensions,
  );

  const signatureValue = crypto.sign("sha256", tbsCertificate, privateKey);

  const certDer = derSequence(
    tbsCertificate,
    signatureAlgorithmIdentifier(),
    derBitString(signatureValue, 0),
  );

  const certPem = derToPem(certDer, "CERTIFICATE");
  const keyPem = privateKey.export({ type: "pkcs8", format: "pem" });

  return { certPem, keyPem };
}

function derToPem(der, label) {
  const base64 = der.toString("base64");
  const lines = base64.match(/.{1,64}/g) || [base64];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

module.exports = { generateSelfSignedCert };

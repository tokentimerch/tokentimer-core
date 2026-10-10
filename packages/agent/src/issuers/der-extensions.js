"use strict";

/**
 * Minimal X.509 extension reader for decision-6 leaf checks.
 * Parses Certificate.tbsCertificate.extensions only; no full ASN.1 library.
 */

const OID_KEY_USAGE = "2.5.29.15";
const OID_BASIC_CONSTRAINTS = "2.5.29.19";
const OID_EKU = "2.5.29.37";
const OID_CERTIFICATE_TEMPLATE = "1.3.6.1.4.1.311.21.7";
const OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";

function readLength(buf, offset) {
  if (offset >= buf.length) throw new Error("DER truncated at length");
  const first = buf[offset];
  if (first < 0x80) return { length: first, offset: offset + 1 };
  const nbytes = first & 0x7f;
  if (nbytes === 0 || nbytes > 4) throw new Error("DER length form not supported");
  if (offset + 1 + nbytes > buf.length) throw new Error("DER truncated in length");
  let length = 0;
  for (let i = 0; i < nbytes; i += 1) length = (length << 8) | buf[offset + 1 + i];
  return { length, offset: offset + 1 + nbytes };
}

function readTlv(buf, offset) {
  if (offset >= buf.length) throw new Error("DER truncated at tag");
  const tag = buf[offset];
  const len = readLength(buf, offset + 1);
  const start = len.offset;
  const end = start + len.length;
  if (end > buf.length) throw new Error("DER truncated in value");
  return { tag, value: buf.subarray(start, end), offset: end };
}

function expectTag(tlv, tag, label) {
  if (tlv.tag !== tag) {
    throw new Error(`DER expected ${label} tag 0x${tag.toString(16)}, got 0x${tlv.tag.toString(16)}`);
  }
  return tlv.value;
}

function decodeOid(bytes) {
  if (bytes.length === 0) throw new Error("empty OID");
  const first = bytes[0];
  const parts = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (let i = 1; i < bytes.length; i += 1) {
    value = (value << 7) | (bytes[i] & 0x7f);
    if ((bytes[i] & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join(".");
}

function encodeOid(oid) {
  const parts = oid.split(".").map((p) => Number(p));
  if (parts.length < 2 || parts.some((n) => !Number.isInteger(n) || n < 0)) {
    throw new Error(`invalid OID ${oid}`);
  }
  const out = [40 * parts[0] + parts[1]];
  for (let i = 2; i < parts.length; i += 1) {
    let n = parts[i];
    const stack = [n & 0x7f];
    n >>= 7;
    while (n > 0) {
      stack.push((n & 0x7f) | 0x80);
      n >>= 7;
    }
    for (let j = stack.length - 1; j >= 0; j -= 1) out.push(stack[j]);
  }
  return Buffer.from(out);
}

function asCertificateDer(certPemOrDer) {
  if (typeof certPemOrDer === "string") return pemToDer(certPemOrDer);
  if (!Buffer.isBuffer(certPemOrDer)) {
    throw new TypeError("certPemOrDer must be a Buffer or string");
  }
  const text = certPemOrDer.toString("utf8");
  if (/BEGIN CERTIFICATE/.test(text)) return pemToDer(text);
  return certPemOrDer;
}

/**
 * Walk Certificate DER and return extensions as { oid, critical, value }[].
 * @param {Buffer|string} certPemOrDer
 */
function listCertificateExtensions(certPemOrDer) {
  const certDer = asCertificateDer(certPemOrDer);
  const cert = expectTag(readTlv(certDer, 0), 0x30, "Certificate");
  const tbs = expectTag(readTlv(cert, 0), 0x30, "TBSCertificate");
  let offset = 0;
  // optional [0] EXPLICIT Version
  if (tbs[offset] === 0xa0) {
    offset = readTlv(tbs, offset).offset;
  }
  // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
  for (let i = 0; i < 6; i += 1) {
    offset = readTlv(tbs, offset).offset;
  }
  // optional issuerUniqueID [1], subjectUniqueID [2]
  while (offset < tbs.length && (tbs[offset] === 0xa1 || tbs[offset] === 0xa2)) {
    offset = readTlv(tbs, offset).offset;
  }
  if (offset >= tbs.length || tbs[offset] !== 0xa3) return [];
  const extsExplicit = expectTag(readTlv(tbs, offset), 0xa3, "extensions");
  const extsSeq = expectTag(readTlv(extsExplicit, 0), 0x30, "Extensions");
  const extensions = [];
  let eoff = 0;
  while (eoff < extsSeq.length) {
    const ext = expectTag(readTlv(extsSeq, eoff), 0x30, "Extension");
    eoff = readTlv(extsSeq, eoff).offset;
    let ioff = 0;
    const oidTlv = readTlv(ext, ioff);
    const oid = decodeOid(expectTag(oidTlv, 0x06, "extnID"));
    ioff = oidTlv.offset;
    let critical = false;
    if (ioff < ext.length && ext[ioff] === 0x01) {
      const crit = readTlv(ext, ioff);
      critical = crit.value.length === 1 && crit.value[0] !== 0;
      ioff = crit.offset;
    }
    const valTlv = readTlv(ext, ioff);
    const value = expectTag(valTlv, 0x04, "extnValue");
    extensions.push({ oid, critical, value: Buffer.from(value) });
  }
  return extensions;
}

function findExtension(certDer, oid) {
  return listCertificateExtensions(certDer).find((e) => e.oid === oid) || null;
}

/**
 * @param {Buffer} certDer
 * @returns {string[]} key-usage names from the KeyUsage bit string
 */
function readKeyUsageNames(certDer) {
  const ext = findExtension(certDer, OID_KEY_USAGE);
  if (!ext) return [];
  const bitString = expectTag(readTlv(ext.value, 0), 0x03, "KeyUsage");
  if (bitString.length < 2) return [];
  const unused = bitString[0];
  const bits = bitString.subarray(1);
  const names = [];
  const map = [
    [0, 0x80, "digitalSignature"],
    [0, 0x40, "nonRepudiation"],
    [0, 0x20, "keyEncipherment"],
    [0, 0x10, "dataEncipherment"],
    [0, 0x08, "keyAgreement"],
    [0, 0x04, "keyCertSign"],
    [0, 0x02, "cRLSign"],
    [0, 0x01, "encipherOnly"],
    [1, 0x80, "decipherOnly"],
  ];
  for (const [byteIndex, mask, name] of map) {
    if (byteIndex >= bits.length) continue;
    // Ignore unused trailing bits in the last byte.
    if (byteIndex === bits.length - 1) {
      const usedMask = 0xff << unused;
      if ((bits[byteIndex] & mask & usedMask) === 0) continue;
    } else if ((bits[byteIndex] & mask) === 0) {
      continue;
    }
    names.push(name);
  }
  return names;
}

/**
 * @param {Buffer} certDer
 * @returns {string[]} EKU OIDs
 */
function readExtKeyUsageOids(certDer) {
  const ext = findExtension(certDer, OID_EKU);
  if (!ext) return [];
  const seq = expectTag(readTlv(ext.value, 0), 0x30, "ExtKeyUsage");
  const oids = [];
  let offset = 0;
  while (offset < seq.length) {
    const tlv = readTlv(seq, offset);
    oids.push(decodeOid(expectTag(tlv, 0x06, "KeyPurposeId")));
    offset = tlv.offset;
  }
  return oids;
}

/**
 * Certificate Template Information (1.3.6.1.4.1.311.21.7).
 * @param {Buffer} certDer
 * @returns {string|null} template OID
 */
function readCertificateTemplateOid(certDer) {
  const ext = findExtension(certDer, OID_CERTIFICATE_TEMPLATE);
  if (!ext) return null;
  const seq = expectTag(readTlv(ext.value, 0), 0x30, "CertificateTemplate");
  const oidTlv = readTlv(seq, 0);
  return decodeOid(expectTag(oidTlv, 0x06, "templateID"));
}

function encodeTlv(tag, value) {
  const len =
    value.length < 0x80
      ? Buffer.from([value.length])
      : value.length <= 0xff
        ? Buffer.from([0x81, value.length])
        : value.length <= 0xffff
          ? Buffer.from([0x82, (value.length >> 8) & 0xff, value.length & 0xff])
          : (() => {
              throw new Error("TLV too large");
            })();
  return Buffer.concat([Buffer.from([tag]), len, value]);
}

/**
 * @param {Buffer|string} csrPemOrDer
 * @returns {Buffer} DER-encoded SubjectPublicKeyInfo
 */
function extractSpkiFromCsr(csrPemOrDer) {
  let der;
  if (Buffer.isBuffer(csrPemOrDer)) {
    const asText = csrPemOrDer.toString("utf8");
    if (/BEGIN .*CERTIFICATE REQUEST/.test(asText)) der = pemToDer(asText);
    else der = csrPemOrDer;
  } else {
    der = pemToDer(csrPemOrDer);
  }
  const csr = expectTag(readTlv(der, 0), 0x30, "CertificationRequest");
  const info = expectTag(readTlv(csr, 0), 0x30, "CertificationRequestInfo");
  let offset = 0;
  offset = readTlv(info, offset).offset; // version
  offset = readTlv(info, offset).offset; // subject
  const spkiTlv = readTlv(info, offset);
  const spkiValue = expectTag(spkiTlv, 0x30, "SubjectPublicKeyInfo");
  return encodeTlv(0x30, spkiValue);
}

function pemToDer(pem) {
  const match = String(pem).match(
    /-----BEGIN [^-]+-----([A-Za-z0-9+/=\s]+)-----END [^-]+-----/,
  );
  if (!match) throw new Error("input is not PEM");
  return Buffer.from(match[1].replace(/\s+/g, ""), "base64");
}

/**
 * SubjectPublicKeyInfo from an X.509 certificate DER/PEM.
 * @param {Buffer|string} certPemOrDer
 * @returns {Buffer}
 */
function extractSpkiFromCertificate(certPemOrDer) {
  let der;
  if (typeof certPemOrDer === "string") {
    der = pemToDer(certPemOrDer);
  } else if (Buffer.isBuffer(certPemOrDer)) {
    const text = certPemOrDer.toString("utf8");
    der = /BEGIN CERTIFICATE/.test(text) ? pemToDer(text) : certPemOrDer;
  } else {
    throw new TypeError("certPemOrDer must be a Buffer or string");
  }
  const cert = expectTag(readTlv(der, 0), 0x30, "Certificate");
  const tbs = expectTag(readTlv(cert, 0), 0x30, "TBSCertificate");
  let offset = 0;
  if (tbs[offset] === 0xa0) offset = readTlv(tbs, offset).offset;
  for (let i = 0; i < 5; i += 1) offset = readTlv(tbs, offset).offset;
  const spkiTlv = readTlv(tbs, offset);
  const spkiValue = expectTag(spkiTlv, 0x30, "SubjectPublicKeyInfo");
  return encodeTlv(0x30, spkiValue);
}

module.exports = {
  OID_KEY_USAGE,
  OID_BASIC_CONSTRAINTS,
  OID_EKU,
  OID_CERTIFICATE_TEMPLATE,
  OID_SERVER_AUTH,
  listCertificateExtensions,
  readKeyUsageNames,
  readExtKeyUsageOids,
  readCertificateTemplateOid,
  extractSpkiFromCsr,
  extractSpkiFromCertificate,
  encodeOid,
  pemToDer,
};
